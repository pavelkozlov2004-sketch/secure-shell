"""Авторизация на сервере и атомарное обновление локального users.db."""
import socket
import sys
import time
import uuid

from auth.login_manager import LoginManager, User
from auth.password_utils import PasswordUtils
from network.client import (
    NetworkClient, NetworkError, AuthenticationError, AuthorizationError, RequestError,
)
from network.settings import load_settings, validate_settings

AUTH_CACHE_SECONDS = 2.0


def _revision(value):
    if type(value) is not int or value < 0:
        raise NetworkError('Сервер вернул некорректную версию учётных записей.')
    return value


def _user(value):
    try:
        if not isinstance(value, dict):
            raise ValueError
        for key in ('id', 'direction_id', 'secrecy_level_id'):
            if type(value[key]) is not int or value[key] < 1:
                raise ValueError
        if (not isinstance(value['login'], str) or not value['login']
                or len(value['login']) > 200 or type(value['is_admin']) not in (bool, int)
                or value['is_admin'] not in (False, True, 0, 1)):
            raise ValueError
        return User(value['id'], value['login'], value['direction_id'],
                    value['secrecy_level_id'], bool(value['is_admin']))
    except (KeyError, ValueError, TypeError):
        raise NetworkError('Сервер вернул некорректные данные учётной записи.') from None


class NetworkLoginManager(LoginManager):
    """Пароли проверяются исключительно на сервере; локальная БД — метаданные."""
    is_remote = True

    def __init__(self, db_manager, settings=None, *, client=None, clock=None):
        super().__init__(db_manager)
        self.settings = validate_settings(load_settings() if settings is None else settings)
        if not self.settings['enabled']:
            raise ValueError('Сетевой режим не включён.')
        self.server_url = self.settings['server_url']
        self.client_name = self.settings['client_name'] or socket.gethostname()[:128]
        self.client = client or NetworkClient(self.server_url, self.settings['ca_file'])
        self._clock = clock or time.monotonic
        self._last_check = float('-inf')
        self._authoritative_user = None
        self._snapshot_user = None
        self.last_error = ''
        self.last_sync_at = None

    @property
    def last_sync(self):
        return self.last_sync_at

    def _source_revision(self):
        row = self.db.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')
        return row['revision'] if row else -1

    def _validate_server_state(self, state):
        revision = _revision(state.get('revision'))
        identity = state.get('server_id')
        try:
            if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
                raise ValueError
        except (ValueError, AttributeError):
            raise NetworkError('Сервер вернул некорректный идентификатор базы учётных записей.') from None
        previous = self.db.fetch_one('SELECT server_id,revision FROM lan_sync_state WHERE id=1')
        if previous and previous['server_id'] is not None and previous['server_id'] != identity:
            raise NetworkError('На сервере заменена база учётных записей. '
                               'Настройте новый клиентский каталог данных перед подключением.')
        if previous and revision < previous['revision']:
            raise NetworkError('Версия базы на сервере старше локальной копии. '
                               'Обратитесь к администратору сервера.')
        return revision

    def _request(self, endpoint, data=None):
        if self._session_id is None:
            raise AuthenticationError('Требуется действующий сеанс на сервере.')
        return self.client.request(endpoint, data, session_id=self._session_id)

    def _sync_accounts(self):
        self._snapshot_user = None
        snapshot = self._request('/api/sync', {'revision': self._source_revision()})
        self._validate_server_state(snapshot)
        if type(snapshot.get('changed')) is not bool:
            raise NetworkError('Сервер вернул некорректное обновление учётных записей.')
        try:
            self.db.apply_account_snapshot(snapshot)
        except (ValueError, KeyError, TypeError) as exc:
            raise NetworkError('Не удалось применить обновление учётных записей.') from exc
        if snapshot['changed']:
            for row in snapshot['users']:
                if row['id'] == self._user_id:
                    self._snapshot_user = _user(row)
                    break
        self.last_sync_at = time.time()
        return snapshot['revision']

    def _invalidate(self, reason):
        self.last_error = reason
        self._authoritative_user = None
        self._last_check = float('-inf')
        # Только локальный logout: недоступность сервера не должна задерживать выход.
        LoginManager.logout(self)

    def _local_session_live(self):
        return self.db.fetch_one(
            'SELECT 1 FROM live_sessions s JOIN users u ON u.id=s.user_id '
            'WHERE s.id=? AND s.user_id=? AND s.ended_at IS NULL '
            'AND u.active=1 AND u.network_blocked=0',
            (self._session_id, self._user_id)) is not None

    @property
    def current_user(self):
        if self._session_id is None or self._user_id is None:
            return None
        if not self._local_session_live():
            self._invalidate('Локальный сеанс завершён или учётная запись деактивирована.')
            return None
        if not self.refresh_remote_state():
            return None
        # Права берутся из HTTPS-ответа, изменение локального is_admin их не повышает.
        user = self._authoritative_user
        if user is not None:
            self.db.execute(
                'UPDATE users SET login=?,direction_id=?,secrecy_level_id=?,is_admin=? '
                'WHERE id=? AND (login<>? OR direction_id<>? OR secrecy_level_id<>? OR is_admin<>?)',
                (user.login, user.direction_id, user.secrecy_level_id, int(user.is_admin), user.id,
                 user.login, user.direction_id, user.secrecy_level_id, int(user.is_admin)))
        return self._authoritative_user

    def _transaction_user(self, cursor, *, admin=False):
        # Внутри уже открытой транзакции нельзя выполнять heartbeat/commit.
        # Вызывающий сервис проверяет current_user перед BEGIN.
        user = self._authoritative_user
        if (user is None or self._clock() - self._last_check >= AUTH_CACHE_SECONDS
                or (admin and not user.is_admin)):
            return None
        row = cursor.execute(
            'SELECT 1 FROM live_sessions s JOIN users u ON u.id=s.user_id '
            'WHERE s.id=? AND s.user_id=? AND s.ended_at IS NULL '
            'AND u.active=1 AND u.network_blocked=0',
            (self._session_id, user.id)).fetchone()
        return user.to_dict() if row else None

    def refresh_remote_state(self, force=False):
        if self._session_id is None:
            return False
        if not force and self._clock() - self._last_check < AUTH_CACHE_SECONDS:
            return self._authoritative_user is not None
        try:
            state = self._request('/api/heartbeat')
            user = _user(state.get('user'))
            revision = self._validate_server_state(state)
            if user.id != self._user_id:
                raise NetworkError('Сервер вернул данные другого сеанса.')
            if revision != self._source_revision():
                self._sync_accounts()
                # Снимок мог получить более свежие права после ответа heartbeat.
                if self._snapshot_user is not None:
                    user = self._snapshot_user
            if not self._local_session_live():
                raise AuthenticationError('Учётная запись деактивирована или сеанс завершён.')
            self._authoritative_user = user
            self._last_check = self._clock()
            self.last_error = ''
            self.db.execute('UPDATE live_sessions SET last_seen_at=? WHERE id=? AND ended_at IS NULL',
                            (time.time(), self._session_id))
            return True
        except (AuthenticationError, AuthorizationError, RequestError, NetworkError) as exc:
            self._invalidate(str(exc))
            return False

    def refresh_session(self):
        return self.refresh_remote_state(force=True)

    def login(self, login, password):
        self.logout()
        if (not isinstance(login, str) or not isinstance(password, str)
                or not login.strip() or len(login) > 200 or len(password) > 1024):
            return False
        try:
            result = self.client.request('/api/login', {
                'login': login, 'password': password, 'client_name': self.client_name,
            })
            user = _user(result.get('user'))
            self._validate_server_state(result)
            token = result.get('session_id')
            if (not isinstance(token, str) or not token or len(token) > 512
                    or any(ord(char) < 33 or ord(char) > 126 for char in token)):
                raise NetworkError('Сервер вернул некорректный идентификатор сеанса.')
            self._session_id, self._user_id = token, user.id
            self._sync_accounts()
            if self._snapshot_user is not None:
                user = self._snapshot_user
            row = self.db.fetch_one('SELECT active,network_blocked FROM users WHERE id=?', (user.id,))
            if not row or not row['active'] or row['network_blocked']:
                raise AuthenticationError('Учётная запись недоступна.')
            now = time.time()
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    'INSERT INTO live_sessions(id,user_id,started_at,last_seen_at) VALUES (?,?,?,?) '
                    'ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,'
                    'started_at=excluded.started_at,last_seen_at=excluded.last_seen_at,'
                    'ended_at=NULL,end_reason=NULL', (token, user.id, now, now))
            self._authoritative_user = user
            self._last_check = self._clock()
            self.last_error = ''
            self.audit_logger.session_id = token
            self.audit_logger.log_login(user.id)
            self.audit_logger.log_action(user.id, 'SESSION_PROCESS',
                'Исполняемый файл клиента Вуали', executable_path=sys.executable)
            return True
        except (AuthenticationError, AuthorizationError, RequestError) as exc:
            self._invalidate(str(exc))
            return False
        except (NetworkError, OSError) as exc:
            self._invalidate(str(exc))
            raise

    def logout(self):
        token = self._session_id
        try:
            if token is not None:
                self.client.request('/api/logout', {}, session_id=token)
        except (OSError, PermissionError, RequestError):
            pass
        finally:
            self._authoritative_user = None
            self._last_check = float('-inf')
            LoginManager.logout(self)

    def _account_action(self, action, kwargs):
        if self.current_user is None:
            return False
        try:
            result = self._request('/api/accounts/action', {'action': action, 'kwargs': kwargs})
            if type(result.get('success')) is not bool:
                raise NetworkError('Сервер вернул некорректный результат операции.')
            if result['success']:
                self._sync_accounts()
                # Роль самого администратора могла измениться этой операцией.
                self.refresh_remote_state(force=True)
            return result['success']
        except (AuthenticationError, AuthorizationError, RequestError) as exc:
            self.last_error = str(exc)
            if isinstance(exc, AuthenticationError):
                self._invalidate(str(exc))
            else:
                self.refresh_remote_state(force=True)
            return False
        except NetworkError as exc:
            self._invalidate(str(exc))
            raise

    def register_user(self, login, password, direction_id, secrecy_level_id, is_admin=False):
        return self._account_action('register_user', dict(
            login=login, password=password, direction_id=direction_id,
            secrecy_level_id=secrecy_level_id, is_admin=is_admin))

    def update_user(self, user_id, direction_id=None, secrecy_level_id=None, is_admin=None):
        return self._account_action('update_user', dict(
            user_id=user_id, direction_id=direction_id,
            secrecy_level_id=secrecy_level_id, is_admin=is_admin))

    def reset_password(self, user_id, new_password):
        return self._account_action('reset_password', dict(user_id=user_id, new_password=new_password))

    def delete_user(self, user_id):
        return self._account_action('delete_user', dict(user_id=user_id))

    def reactivate_user(self, user_id):
        return self._account_action('reactivate_user', dict(user_id=user_id))

    def change_password(self, user_id, old_password, new_password):
        if not PasswordUtils.is_valid_password(new_password):
            return False
        return self._account_action('change_password', dict(
            user_id=user_id, old_password=old_password, new_password=new_password))

    def get_all_users(self):
        if self.current_user is None:
            return []
        try:
            result = self._request('/api/accounts/list')
            _revision(result.get('revision'))
            if not isinstance(result.get('users'), list):
                raise NetworkError('Сервер вернул некорректный список пользователей.')
            return [_user(row) for row in result['users']]
        except AuthenticationError as exc:
            self._invalidate(str(exc))
            return []
        except (AuthorizationError, RequestError):
            self.refresh_remote_state(force=True)
            return []
        except NetworkError as exc:
            self._invalidate(str(exc))
            raise


class NetworkConnectivityMonitor:
    """Статусы от реальных HTTPS-heartbeat, видимые администратору сервера."""
    def __init__(self, manager, clock=None):
        self.manager = manager
        self.db = manager.db

    def respond(self):
        return self.manager.refresh_remote_state(force=True)

    def _admin_request(self, endpoint, data=None):
        # Окончательная проверка роли всегда выполняется сервером на каждом запросе.
        if self.manager.current_user is None:
            raise PermissionError('Требуется действующий сеанс администратора.')
        try:
            return self.manager._request(endpoint, data)
        except AuthenticationError as exc:
            self.manager._invalidate(str(exc))
            raise PermissionError(str(exc)) from None
        except AuthorizationError as exc:
            self.manager.refresh_remote_state(force=True)
            raise PermissionError(str(exc)) from None
        except NetworkError as exc:
            self.manager._invalidate(str(exc))
            raise

    def user_statuses(self):
        result = self._admin_request('/api/connections')
        rows = result.get('users')
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            self.manager._invalidate('Сервер вернул некорректные статусы пользователей.')
            raise NetworkError(self.manager.last_error)
        for row in rows:
            raw_code = row.get('status_code', row.get('status'))
            code = 'deactivated' if not row.get('active') else (
                'online' if raw_code == 'online' and not row.get('network_blocked') else 'offline')
            row['status_code'] = code
            if row.get('status') in ('online', 'offline', 'deactivated') or not row.get('status'):
                row['status'] = {
                    'online': 'Работает', 'offline': 'Нет подключения', 'deactivated': 'Деактивирован',
                }[code]
        return rows

    def offline_users(self):
        return [row for row in self.user_statuses() if row.get('status_code') != 'online']

    def poll(self):
        # Сервер ведёт присутствие сам; администратор не запускает сетевые блокировки.
        user = self.manager.current_user
        if user is None or not user.is_admin:
            raise PermissionError('Требуется действующий сеанс администратора.')
        return []

    def unblock(self, user_id):
        result = self._admin_request('/api/connections/restore', {'user_id': user_id})
        if type(result.get('success')) is not bool:
            raise NetworkError('Сервер вернул некорректный результат разблокировки.')
        if result['success']:
            try:
                self.manager._sync_accounts()
                self.manager.refresh_remote_state(force=True)
            except (NetworkError, AuthenticationError) as exc:
                self.manager._invalidate(str(exc))
                raise
        return result['success']


def create_login_manager(db, settings=None):
    settings = validate_settings(load_settings() if settings is None else settings)
    return NetworkLoginManager(db, settings) if settings['enabled'] else LoginManager(db)

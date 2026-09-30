"""Центральная авторизация и фактические HTTPS heartbeat клиентов Вуали."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import re
import sqlite3
import threading
import time
from time import monotonic

from auth.login_manager import LoginManager
from database.db_manager import DatabaseManager
from network.tls import server_context

ONLINE_SECONDS = 10
SESSION_IDLE_SECONDS = 300
MAX_BODY_BYTES = 64 * 1024
_USER_COLUMNS = ('id,login,direction_id,secrecy_level_id,is_admin,active,'
                 'network_blocked,created_at,updated_at')
_LOG = logging.getLogger('vual.network.server')


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def _integer(value, field, minimum=1):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 2**63 - 1:
        raise APIError(400, 'Некорректное поле: ' + field)
    return value


def _text(value, field, maximum=128, minimum=1):
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or '\x00' in value:
        raise APIError(400, 'Некорректное поле: ' + field)
    return value


def _exact_fields(payload, allowed, required=()):
    if set(payload) - set(allowed) or set(required) - set(payload):
        raise APIError(400, 'Некорректные поля запроса')


def _validate_action(payload):
    _exact_fields(payload, ('action', 'kwargs'), ('action', 'kwargs'))
    action, kwargs = payload['action'], payload['kwargs']
    specifications = {
        'register_user': (('login', 'password', 'direction_id', 'secrecy_level_id', 'is_admin'),
                          ('login', 'password', 'direction_id', 'secrecy_level_id')),
        'update_user': (('user_id', 'direction_id', 'secrecy_level_id', 'is_admin'), ('user_id',)),
        'reset_password': (('user_id', 'new_password'), ('user_id', 'new_password')),
        'delete_user': (('user_id',), ('user_id',)),
        'reactivate_user': (('user_id',), ('user_id',)),
        'change_password': (('user_id', 'old_password', 'new_password'),
                            ('user_id', 'old_password', 'new_password')),
    }
    if not isinstance(action, str) or action not in specifications or not isinstance(kwargs, dict):
        raise APIError(400, 'Неизвестное действие с учётной записью')
    _exact_fields(kwargs, *specifications[action])
    for field, value in kwargs.items():
        if field in ('user_id', 'direction_id', 'secrecy_level_id'):
            if field == 'user_id' or value is not None or action != 'update_user':
                _integer(value, field)
        elif field == 'is_admin':
            if value is not None or action != 'update_user':
                if not isinstance(value, bool):
                    raise APIError(400, 'Некорректное поле: is_admin')
        elif field == 'login':
            _text(value, field, maximum=200)
            if not value.strip():
                raise APIError(400, 'Пустой логин')
        else:
            _text(value, field, maximum=1024, minimum=0 if field == 'old_password' else 8)
    return action, kwargs


class AccountServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def __init__(self, address, db_path, tls_context):
        self.db_path = str(Path(db_path).resolve())
        self.db_init_lock = threading.Lock()
        self._presence_stop = threading.Event()
        self._presence_thread = None
        self.tls_context = tls_context
        self._request_slots = threading.BoundedSemaphore(32)
        # Все менеджеры создаются и закрываются в том же потоке, где используются.
        with self.database():
            pass
        super().__init__(address, AccountRequestHandler)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(self, request, client_address):
        # Не выводить traceback или данные неудавшегося TLS-запроса.
        _LOG.debug('Сетевой запрос завершён до обработки')

    @contextmanager
    def database(self):
        with self.db_init_lock:
            database = DatabaseManager(self.db_path)
        try:
            yield database
        finally:
            database.close()

    def _expire_sessions(self, database, now=None):
        now = time.time() if now is None else now
        database.execute("UPDATE live_sessions SET ended_at=?,end_reason='lan_idle_timeout' "
            'WHERE ended_at IS NULL AND id IN '
            '(SELECT session_id FROM lan_presence WHERE last_heartbeat<=?)',
            (now, now - SESSION_IDLE_SECONDS))

    def _presence_worker(self):
        try:
            with self.database() as database:
                while not self._presence_stop.is_set():
                    try:
                        self._expire_sessions(database)
                    except sqlite3.Error:
                        _LOG.error('Не удалось завершить просроченные сетевые сеансы')
                    self._presence_stop.wait(1)
        except Exception:
            _LOG.error('Не удалось запустить проверку сетевых сеансов')

    def serve_forever(self, poll_interval=0.25):
        self._presence_stop.clear()
        self._presence_thread = threading.Thread(target=self._presence_worker,
            name='vual-lan-presence', daemon=True)
        self._presence_thread.start()
        try:
            super().serve_forever(poll_interval=poll_interval)
        finally:
            self._presence_stop.set()
            self._presence_thread.join(timeout=6)

    def server_close(self):
        self._presence_stop.set()
        super().server_close()


class AccountRequestHandler(BaseHTTPRequestHandler):
    server_version = 'Vual'
    sys_version = ''

    def setup(self):
        # Рукопожатие выполняется в потоке запроса с ограничением времени;
        # неподключившийся TCP-клиент не останавливает приём других соединений.
        self.request.settimeout(5)
        self.request = self.server.tls_context.wrap_socket(self.request, server_side=True)
        super().setup()
        self.connection.settimeout(5)

    def finish(self):
        try:
            super().finish()
        finally:
            # wrap_socket отсоединяет исходный raw socket, которым владеет
            # ThreadingHTTPServer: TLS-сокет нужно закрыть здесь явно.
            self.request.close()

    def log_message(self, *_args):
        # URL, Authorization и тела запросов не попадают в HTTP-журнал.
        pass

    def _reply(self, status, payload):
        content = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(content)

    def _body(self):
        if self.headers.get('Transfer-Encoding'):
            raise APIError(400, 'Неподдерживаемый формат запроса')
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            raise APIError(400, 'Некорректная длина запроса')
        if length < 0:
            raise APIError(400, 'Не указана длина запроса')
        if length > MAX_BODY_BYTES:
            self._rejected_body_length = length
            raise APIError(413, 'Слишком большой запрос')
        if self.headers.get_content_type() != 'application/json':
            self._rejected_body_length = length
            raise APIError(400, 'Требуется JSON')
        try:
            payload = json.loads(self.rfile.read(length).decode('utf-8'))
        except (UnicodeError, ValueError, RecursionError):
            raise APIError(400, 'Некорректный JSON')
        if not isinstance(payload, dict):
            raise APIError(400, 'Требуется JSON-объект')
        return payload

    def _discard_rejected_body(self):
        # Ответ уже отправлен. Коротко дочитываем только ограниченный объём,
        # чтобы TCP reset из-за непрочитанного тела не потерял JSON-ошибку.
        remaining = min(getattr(self, '_rejected_body_length', 0), MAX_BODY_BYTES * 16)
        deadline = monotonic() + 0.2
        try:
            while remaining and monotonic() < deadline:
                self.connection.settimeout(max(0.001, deadline - monotonic()))
                discarded = self.rfile.read1(min(16 * 1024, remaining))
                if not discarded:
                    break
                remaining -= len(discarded)
        except (OSError, ValueError):
            pass

    def do_GET(self):
        self._reply(405, {'error': 'Требуется POST-запрос'})

    def do_POST(self):
        try:
            payload = self._body()
            with self.server.database() as database:
                result = self._dispatch(database, payload)
            self._reply(200, result)
        except APIError as exc:
            self._reply(exc.status, {'error': exc.message})
            self._discard_rejected_body()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except sqlite3.Error:
            self._reply(503, {'error': 'База данных временно недоступна'})
        except Exception:
            # Не выдавать traceback, SQL или данные аккаунтов клиенту.
            _LOG.error('Ошибка обработки запроса службы учётных записей')
            self._reply(500, {'error': 'Ошибка службы учётных записей'})

    def _manager(self, database):
        header = self.headers.get('Authorization', '')
        if not re.fullmatch(r'Bearer [0-9a-f]{32}', header):
            raise APIError(401, 'Требуется вход в систему')
        session_id, now = header[7:], time.time()
        with database.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            row = cursor.execute('SELECT s.user_id,p.last_heartbeat FROM live_sessions s '
                'JOIN users u ON u.id=s.user_id JOIN lan_presence p ON p.session_id=s.id '
                'WHERE s.id=? AND s.ended_at IS NULL AND u.active=1 AND u.network_blocked=0',
                (session_id,)).fetchone()
            if row and row['last_heartbeat'] <= now - SESSION_IDLE_SECONDS:
                cursor.execute("UPDATE live_sessions SET ended_at=?,end_reason='lan_idle_timeout' "
                               'WHERE id=? AND ended_at IS NULL', (now, session_id))
                row = None
        if row is None:
            raise APIError(401, 'Сеанс завершён. Войдите снова')
        manager = LoginManager(database)
        manager._user_id = row['user_id']
        manager._session_id = session_id
        manager.audit_logger.session_id = session_id
        if manager.current_user is None:
            raise APIError(401, 'Сеанс завершён. Войдите снова')
        return manager

    def _admin(self, manager):
        actor = manager.current_user
        if actor is None:
            raise APIError(401, 'Сеанс завершён. Войдите снова')
        if not actor.is_admin:
            raise APIError(403, 'Требуются права администратора')
        return actor

    def _heartbeat(self, manager, client_name=None):
        now = time.time()
        with manager.db.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            if not manager._transaction_user(cursor):
                raise APIError(401, 'Сеанс завершён. Войдите снова')
            if client_name is None:
                cursor.execute('UPDATE lan_presence SET address=?,last_heartbeat=? WHERE session_id=?',
                    (self.client_address[0], now, manager._session_id))
            else:
                cursor.execute('INSERT INTO lan_presence(session_id,address,client_name,last_heartbeat) '
                    'VALUES (?,?,?,?)', (manager._session_id, self.client_address[0], client_name, now))
            cursor.execute('UPDATE live_sessions SET last_seen_at=? WHERE id=?', (now, manager._session_id))

    def _sync(self, manager, revision):
        with manager.db.get_cursor() as cursor:
            cursor.execute('BEGIN')
            if not manager._transaction_user(cursor):
                raise APIError(401, 'Сеанс завершён. Войдите снова')
            current = manager.db.account_revision()
            result = {'revision': current, 'changed': revision != current,
                      'server_id': manager.db.server_identity()}
            if result['changed']:
                result.update(users=[dict(row) for row in cursor.execute(
                    'SELECT ' + _USER_COLUMNS + ' FROM users ORDER BY id').fetchall()],
                    directions=[dict(row) for row in cursor.execute(
                        'SELECT id,name FROM directions ORDER BY id').fetchall()],
                    secrecy_levels=[dict(row) for row in cursor.execute(
                        'SELECT id,name,level_order FROM secrecy_levels ORDER BY id').fetchall()])
            return result

    def _connections(self, manager):
        now = time.time()
        with manager.db.get_cursor() as cursor:
            cursor.execute('BEGIN')
            actor = manager._transaction_user(cursor, admin=True)
            if not actor:
                raise APIError(403, 'Требуются права администратора')
            users = cursor.execute('SELECT u.id,u.login,u.active,u.network_blocked,'
                '(SELECT MAX(s.started_at) FROM live_sessions s JOIN lan_presence p ON p.session_id=s.id '
                'WHERE s.user_id=u.id) AS last_login,'
                '(SELECT MAX(p.last_heartbeat) FROM lan_presence p JOIN live_sessions s ON s.id=p.session_id '
                'WHERE s.user_id=u.id) AS last_seen FROM users u WHERE u.id<>? ORDER BY u.login',
                (actor['id'],)).fetchall()
            result = []
            for row in users:
                item = dict(row)
                presence = cursor.execute('SELECT p.address,p.client_name,p.last_heartbeat,s.ended_at '
                    'FROM lan_presence p JOIN live_sessions s ON s.id=p.session_id '
                    'WHERE s.user_id=? ORDER BY p.last_heartbeat DESC LIMIT 1', (row['id'],)).fetchone()
                online = cursor.execute('SELECT 1 FROM lan_presence p JOIN live_sessions s ON s.id=p.session_id '
                    'WHERE s.user_id=? AND s.ended_at IS NULL AND p.last_heartbeat>? LIMIT 1',
                    (row['id'], now - ONLINE_SECONDS)).fetchone()
                item['status_code'] = ('deactivated' if not row['active'] else
                    'offline' if row['network_blocked'] else 'online' if online else 'offline')
                item['status'] = ('Деактивирован' if item['status_code'] == 'deactivated' else
                    'Нет подключения — заблокирован' if row['network_blocked'] else
                    'Работает' if item['status_code'] == 'online' else 'Нет подключения')
                item['address'] = presence['address'] if presence else None
                item['client_name'] = presence['client_name'] if presence else None
                item['files'] = [dict(event) for event in cursor.execute(
                    "SELECT action,details,timestamp FROM audit_logs WHERE user_id=? "
                    "AND action IN ('FILE_OPEN','FILE_SAVE','FILE_CREATE','FILE_DELETE','FILE_RENAME',"
                    "'EXECUTE_FILE','TRANSFER_FILE') ORDER BY id DESC LIMIT 5", (row['id'],)).fetchall()]
                result.append(item)
            return {'users': result}

    def _dispatch(self, database, payload):
        if self.path == '/api/login':
            _exact_fields(payload, ('login', 'password', 'client_name'), ('login', 'password'))
            login = _text(payload['login'], 'login', maximum=200)
            password = _text(payload['password'], 'password', maximum=1024, minimum=0)
            client_name = _text(payload.get('client_name', ''), 'client_name', maximum=128, minimum=0)
            manager = LoginManager(database)
            if not manager.login(login, password):
                raise APIError(401, 'Неверные учётные данные или учётная запись недоступна')
            self._heartbeat(manager, client_name)
            return {'session_id': manager._session_id, 'user': manager.current_user.to_dict(),
                    'revision': database.account_revision(), 'server_id': database.server_identity()}
        manager = self._manager(database)
        if self.path == '/api/logout':
            _exact_fields(payload, ())
            manager.logout()
            return {'success': True}
        if self.path == '/api/heartbeat':
            _exact_fields(payload, ())
            self._heartbeat(manager)
            return {'user': manager.current_user.to_dict(), 'revision': database.account_revision(),
                    'server_id': database.server_identity()}
        if self.path == '/api/sync':
            _exact_fields(payload, ('revision',), ('revision',))
            revision = _integer(payload['revision'], 'revision', minimum=-1)
            return self._sync(manager, revision)
        if self.path == '/api/accounts/list':
            _exact_fields(payload, ())
            self._admin(manager)
            return {'users': [user.to_dict() for user in manager.get_all_users()],
                    'revision': database.account_revision()}
        if self.path == '/api/accounts/action':
            action, kwargs = _validate_action(payload)
            if action != 'change_password':
                self._admin(manager)
            elif kwargs['user_id'] != manager._user_id:
                raise APIError(403, 'Можно изменить только собственный пароль')
            success = getattr(manager, action)(**kwargs)
            return {'success': bool(success), 'revision': database.account_revision()}
        if self.path == '/api/connections':
            _exact_fields(payload, ())
            self._admin(manager)
            return self._connections(manager)
        if self.path == '/api/connections/restore':
            _exact_fields(payload, ('user_id',), ('user_id',))
            user_id = _integer(payload['user_id'], 'user_id')
            self._admin(manager)
            success = manager.reactivate_user(user_id)
            return {'success': bool(success), 'revision': database.account_revision()}
        raise APIError(404, 'Неизвестный адрес запроса')


def create_server(db_path, host='127.0.0.1', port=8765, *, certfile, keyfile):
    """Возвращает HTTPS-сервер; serve_forever/shutdown управляет вызывающий код."""
    if str(db_path) == ':memory:':
        raise ValueError('Сетевой сервер требует постоянный файл users.db')
    return AccountServer((host, port), db_path, server_context(certfile, keyfile))

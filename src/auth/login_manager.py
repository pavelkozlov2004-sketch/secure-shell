"""Авторизация, блокировка попыток и управление актуальными правами."""
import sqlite3
import time
import uuid
import sys
from dataclasses import dataclass, asdict
from auth.password_utils import PasswordUtils
from app_audit.audit_logger import AuditLogger
from config import MAX_LOGIN_ATTEMPTS, LOCK_TIMEOUT


@dataclass(frozen=True)
class User:
    id: int
    login: str
    direction_id: int
    secrecy_level_id: int
    is_admin: bool

    def to_dict(self):
        return asdict(self)


class LoginManager:
    def __init__(self, db_manager):
        self.db = db_manager
        self._user_id = None
        self._session_id = None
        self.audit_logger = AuditLogger(db_manager)

    @property
    def current_user(self):
        if self._user_id is None or self._session_id is None:
            return None
        session = self.db.fetch_one(
            'SELECT 1 FROM live_sessions s JOIN users u ON u.id=s.user_id '
            'WHERE s.id=? AND s.user_id=? AND s.ended_at IS NULL AND u.active=1 AND u.network_blocked=0',
            (self._session_id, self._user_id))
        if not session:
            self._user_id = self._session_id = None
            self.audit_logger.session_id = None
            return None
        self.db.execute('UPDATE live_sessions SET last_seen_at=? WHERE id=? AND ended_at IS NULL',
                        (time.time(), self._session_id))
        return self.get_user_by_id(self._user_id)

    def get_current_user(self):
        return self.current_user

    def is_logged_in(self):
        return self.current_user is not None

    def _admin(self):
        user = self.current_user
        return user if user and user.is_admin else None

    def _transaction_user(self, cursor, *, admin=False):
        """Проверить сеанс внутри транзакции, не фиксируя её heartbeat-записью."""
        row = cursor.execute(
            'SELECT u.id,u.login,u.direction_id,u.secrecy_level_id,u.is_admin '
            'FROM users u JOIN live_sessions s ON s.user_id=u.id '
            'WHERE u.id=? AND s.id=? AND s.ended_at IS NULL '
            'AND u.active=1 AND u.network_blocked=0',
            (self._user_id, self._session_id)).fetchone()
        return row if row and (not admin or row['is_admin']) else None

    def register_user(self, login, password, direction_id, secrecy_level_id, is_admin=False):
        actor = self._admin()
        if not actor or not isinstance(login, str) or not login.strip() or not PasswordUtils.is_valid_password(password):
            return False
        digest, salt = PasswordUtils.hash_password(password)
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute('BEGIN IMMEDIATE')
                authorized = self._transaction_user(cursor, admin=True)
                if not authorized or authorized['id'] != actor.id:
                    return False
                cursor.execute('INSERT INTO users(login,password_hash,direction_id,secrecy_level_id,is_admin) VALUES (?,?,?,?,?)',
                               (login.strip(), f'{digest}${salt}', direction_id, secrecy_level_id, int(is_admin)))
        except sqlite3.IntegrityError:
            return False
        self.audit_logger.log_action(actor.id, 'CREATE_USER', login.strip())
        return True

    def login(self, login, password):
        self.logout()
        if not isinstance(login, str) or not isinstance(password, str) or len(password) > 1024:
            return False
        now = time.time()
        # Транзакция сериализует счётчик между экземплярами приложения.
        with self.db.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            attempt = cursor.execute('SELECT failures,locked_until FROM login_attempts WHERE login=?', (login,)).fetchone()
            locked = bool(attempt and attempt['locked_until'] > now)
            row = cursor.execute('SELECT * FROM users WHERE login=?', (login,)).fetchone()
            success = False
            if not locked and row and row['active'] and not row['network_blocked']:
                try:
                    digest, salt = row['password_hash'].split('$')
                    success = PasswordUtils.verify_password(password, digest, salt)
                except (ValueError, AttributeError):
                    pass
            if success:
                session_id = uuid.uuid4().hex
                cursor.execute('INSERT INTO live_sessions(id,user_id,started_at,last_seen_at) VALUES (?,?,?,?)',
                               (session_id, row['id'], now, now))
                cursor.execute('DELETE FROM login_attempts WHERE login=?', (login,))
                if not digest.startswith('pbkdf2_sha256:'):
                    digest, salt = PasswordUtils.hash_password(password)
                    cursor.execute('UPDATE users SET password_hash=? WHERE id=?', (f'{digest}${salt}', row['id']))
            elif not locked:
                failures = (attempt['failures'] if attempt and not attempt['locked_until'] else 0) + 1
                until = now + LOCK_TIMEOUT if failures >= MAX_LOGIN_ATTEMPTS else 0
                cursor.execute('INSERT INTO login_attempts(login,failures,locked_until) VALUES (?,?,?) '
                               'ON CONFLICT(login) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until',
                               (login, failures, until))
        if success:
            self._user_id = row['id']
            self._session_id = session_id
            self.audit_logger.session_id = session_id
            self.audit_logger.log_login(self._user_id)
            self.audit_logger.log_action(self._user_id, 'SESSION_PROCESS',
                'Исполняемый файл приложения, обслуживающего сеанс', executable_path=sys.executable)
        else:
            self.audit_logger.log_action(row['id'] if row else None,
                                         'LOGIN_LOCKED' if locked else 'LOGIN_FAILED', login)
        return success

    def logout(self):
        user_id, session_id = self._user_id, self._session_id
        self._user_id = self._session_id = None
        try:
            if session_id is not None:
                ended = self.db.execute(
                    "UPDATE live_sessions SET ended_at=?,end_reason='logout' WHERE id=? AND ended_at IS NULL",
                    (time.time(), session_id)).rowcount
                if ended and user_id is not None:
                    self.audit_logger.log_logout(user_id)
        finally:
            self.audit_logger.session_id = None

    def get_user_by_id(self, user_id):
        row = self.db.fetch_one('SELECT id,login,direction_id,secrecy_level_id,is_admin FROM users WHERE id=? AND active=1', (user_id,))
        return User(row['id'], row['login'], row['direction_id'], row['secrecy_level_id'], bool(row['is_admin'])) if row else None

    def get_all_users(self):
        if not self._admin():
            return []
        with self.db.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            if not self._transaction_user(cursor, admin=True):
                return []
            rows = cursor.execute(
                'SELECT id,login,direction_id,secrecy_level_id,is_admin FROM users WHERE active=1 ORDER BY id').fetchall()
            return [User(r['id'], r['login'], r['direction_id'], r['secrecy_level_id'], bool(r['is_admin'])) for r in rows]

    def change_password(self, user_id, old_password, new_password):
        user = self.current_user
        if not user or user.id != user_id or not PasswordUtils.is_valid_password(new_password):
            return False
        row = self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (user_id,))
        try:
            digest, salt = row['password_hash'].split('$')
        except (ValueError, TypeError):
            return False
        if not PasswordUtils.verify_password(old_password, digest, salt):
            return False
        digest, salt = PasswordUtils.hash_password(new_password)
        with self.db.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            authorized = self._transaction_user(cursor)
            if not authorized or authorized['id'] != user_id:
                return False
            cursor.execute('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP '
                           'WHERE id=? AND password_hash=?', (f'{digest}${salt}', user_id, row['password_hash']))
            if cursor.rowcount != 1:
                return False
        self.audit_logger.log_action(user.id, 'CHANGE_PASSWORD')
        return True

    def reset_password(self, user_id, new_password):
        actor = self._admin()
        target = self.get_user_by_id(user_id)
        if not actor or not target or not PasswordUtils.is_valid_password(new_password):
            return False
        digest, salt = PasswordUtils.hash_password(new_password)
        with self.db.get_cursor() as c:
            c.execute('BEGIN IMMEDIATE')
            authorized = self._transaction_user(c, admin=True)
            if not authorized or authorized['id'] != actor.id:
                return False
            c.execute('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND active=1', (f'{digest}${salt}', user_id))
            if c.rowcount != 1:
                return False
            c.execute('DELETE FROM login_attempts WHERE login=?', (target.login,))
        self.audit_logger.log_action(actor.id, 'RESET_PASSWORD', f'ID={user_id}')
        return True

    def delete_user(self, user_id):
        """Деактивация сохраняет владельцев документов и историю аудита."""
        actor = self._admin()
        if not actor or user_id == actor.id:
            return False
        with self.db.get_cursor() as c:
            c.execute('BEGIN IMMEDIATE')
            authorized = self._transaction_user(c, admin=True)
            if not authorized or authorized['id'] != actor.id:
                return False
            c.execute('UPDATE users SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND active=1', (user_id,))
            if c.rowcount != 1:
                return False
            c.execute('DELETE FROM user_sessions WHERE user_id=?', (user_id,))
            c.execute("UPDATE live_sessions SET ended_at=?,end_reason='deactivated' WHERE user_id=? AND ended_at IS NULL", (time.time(), user_id))
        self.audit_logger.log_action(actor.id, 'DEACTIVATE_USER', f'ID={user_id}')
        return True

    def update_user(self, user_id, direction_id=None, secrecy_level_id=None, is_admin=None):
        actor = self._admin()
        if not actor:
            return False
        changes = {k: v for k, v in dict(direction_id=direction_id, secrecy_level_id=secrecy_level_id,
                                         is_admin=None if is_admin is None else int(is_admin)).items() if v is not None}
        if not changes:
            return False
        try:
            with self.db.get_cursor() as c:
                c.execute('BEGIN IMMEDIATE')
                authorized = self._transaction_user(c, admin=True)
                if not authorized or authorized['id'] != actor.id:
                    return False
                target = c.execute('SELECT is_admin FROM users WHERE id=? AND active=1', (user_id,)).fetchone()
                if not target:
                    return False
                if target['is_admin'] and changes.get('is_admin') == 0:
                    if c.execute('SELECT count(*) FROM users WHERE active=1 AND is_admin=1').fetchone()[0] <= 1:
                        return False
                c.execute('UPDATE users SET ' + ','.join(k+'=?' for k in changes) +
                          ',updated_at=CURRENT_TIMESTAMP WHERE id=? AND active=1', (*changes.values(), user_id))
                if c.rowcount != 1:
                    return False
        except sqlite3.IntegrityError:
            return False
        self.audit_logger.log_action(actor.id, 'UPDATE_USER', f'ID={user_id}')
        return True

    def reactivate_user(self, user_id):
        """Восстановить аккаунт, сохранив пароль и завершив прежние сеансы."""
        actor = self._admin()
        if not actor:
            return False
        with self.db.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            authorized = self._transaction_user(cursor, admin=True)
            if not authorized or authorized['id'] != actor.id:
                return False
            target = cursor.execute('SELECT login FROM users WHERE id=? '
                                    'AND (active=0 OR network_blocked=1)', (user_id,)).fetchone()
            if not target:
                return False
            cursor.execute('UPDATE users SET active=1,network_blocked=0,updated_at=CURRENT_TIMESTAMP '
                           'WHERE id=? AND (active=0 OR network_blocked=1)', (user_id,))
            if cursor.rowcount != 1:
                return False
            cursor.execute('DELETE FROM login_attempts WHERE login=?', (target['login'],))
            cursor.execute('DELETE FROM user_sessions WHERE user_id=?', (user_id,))
            cursor.execute("UPDATE live_sessions SET ended_at=?,end_reason='reactivated' "
                           'WHERE user_id=? AND ended_at IS NULL', (time.time(), user_id))
            cursor.execute("INSERT INTO audit_logs(user_id,action,details,session_id) "
                           "VALUES (?,'REACTIVATE_USER',?,?)",
                           (actor.id, f'ID={user_id}', self._session_id))
        return True

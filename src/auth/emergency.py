"""Одноразовые резервные пароли, отзыв сеансов и снимок аудита."""
import base64
import json
import os
import secrets
import string
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from auth.password_utils import PasswordUtils
from config import DATA_DIR

ALPHABET = string.digits + string.punctuation


def generate_password():
    while True:
        password = ''.join(secrets.choice(ALPHABET) for _ in range(50))
        if any(c in string.digits for c in password) and any(c in string.punctuation for c in password):
            return password


def _key(phrase, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(phrase.encode('utf-8'))


def encrypt_vault(data, phrase):
    if not isinstance(phrase, str) or len(phrase) < 12:
        raise ValueError('Парольная фраза резервного файла: минимум 12 символов.')
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    encrypted = AESGCM(_key(phrase, salt)).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), b'SecureShellRecovery-v1')
    return json.dumps({'format': 'SecureShellRecovery-v1',
                       'salt': base64.b64encode(salt).decode(),
                       'nonce': base64.b64encode(nonce).decode(),
                       'ciphertext': base64.b64encode(encrypted).decode()}, indent=2).encode()


def decrypt_vault(path, phrase):
    # Формат и параметры KDF фиксированы, содержимое файла не задаёт стоимость KDF.
    from cryptography.exceptions import InvalidTag
    try:
        with open(path, 'rb') as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('Слишком большой резервный файл')
        envelope = json.loads(raw)
        if envelope['format'] != 'SecureShellRecovery-v1':
            raise ValueError('Неизвестный формат')
        salt = base64.b64decode(envelope['salt'], validate=True)
        nonce = base64.b64decode(envelope['nonce'], validate=True)
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError('Неверный формат')
        ciphertext = base64.b64decode(envelope['ciphertext'], validate=True)
        clear = AESGCM(_key(phrase, salt)).decrypt(nonce, ciphertext, b'SecureShellRecovery-v1')
        result = json.loads(clear)
        if not isinstance(result.get('accounts'), list):
            raise ValueError('Неверное содержимое')
        return result
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise ValueError('Неверная парольная фраза или повреждён резервный файл.') from exc


def _write_new(path, content):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class EmergencyManager:
    def __init__(self, login_manager):
        self.login = login_manager
        self.db = login_manager.db

    def _require_admin(self, cursor):
        row = cursor.execute('''SELECT u.id FROM users u JOIN live_sessions s ON s.user_id=u.id
            WHERE s.id=? AND s.ended_at IS NULL AND u.active=1 AND u.is_admin=1''',
            (self.login._session_id,)).fetchone()
        if not row:
            raise PermissionError('Требуется действующий сеанс администратора.')
        return row['id']

    @staticmethod
    def _roster(cursor):
        return [(r['id'], r['login']) for r in cursor.execute('SELECT id,login FROM users WHERE active=1 ORDER BY id')]

    def status(self):
        actor = self.login.current_user
        if not actor or not actor.is_admin:
            return False, 'Требуются права администратора.'
        state = self.db.fetch_one('SELECT * FROM emergency_state WHERE id=1')
        if not state or state['consumed_at'] is not None:
            return False, 'Сначала подготовьте и сохраните резервные пароли.'
        roster = [(r['id'], r['login']) for r in self.db.fetch_all('SELECT id,login FROM users WHERE active=1 ORDER BY id')]
        prepared = [(r['user_id'], r['login']) for r in self.db.fetch_all(
            'SELECT user_id,login FROM emergency_credentials WHERE batch_id=? ORDER BY user_id', (state['batch_id'],))]
        if not roster or roster != prepared:
            return False, 'Состав аккаунтов изменился. Подготовьте новый резервный файл.'
        return True, 'Резервные пароли подготовлены. Команда завершит все сеансы, включая ваш.'

    def prepare(self, path, phrase):
        actor = self.login.current_user
        if not actor or not actor.is_admin:
            raise PermissionError('Требуется администратор.')
        if len(phrase) < 12:
            raise ValueError('Парольная фраза резервного файла: минимум 12 символов.')
        roster = [(r['id'], r['login']) for r in self.db.fetch_all('SELECT id,login FROM users WHERE active=1 ORDER BY id')]
        batch_id, now = uuid.uuid4().hex, time.time()
        accounts, hashes = [], []
        for user_id, login in roster:
            password = generate_password()
            digest, salt = PasswordUtils.hash_password(password)
            accounts.append({'id': user_id, 'login': login, 'password': password})
            hashes.append((user_id, login, f'{digest}${salt}', batch_id))
        blob = encrypt_vault({'batch_id': batch_id, 'created_at_utc': _utc(now), 'accounts': accounts}, phrase)
        written = False
        try:
            with self.db.get_cursor() as c:
                c.execute('BEGIN IMMEDIATE')
                actor_id = self._require_admin(c)
                if self._roster(c) != roster:
                    raise ValueError('Состав аккаунтов изменился. Повторите подготовку.')
                _write_new(path, blob)
                written = True
                c.execute('DELETE FROM emergency_credentials')
                c.executemany('INSERT INTO emergency_credentials(user_id,login,password_hash,batch_id) VALUES (?,?,?,?)', hashes)
                c.execute('INSERT OR REPLACE INTO emergency_state(id,batch_id,prepared_at,consumed_at) VALUES (1,?,?,NULL)', (batch_id, now))
                c.execute('INSERT INTO audit_logs(user_id,action,details,session_id) VALUES (?,?,?,?)',
                          (actor_id, 'EMERGENCY_PREPARED', 'batch_id=' + batch_id, self.login._session_id))
        except Exception:
            if written:
                Path(path).unlink(missing_ok=True)
            raise
        return batch_id

    def activate(self):
        now, incident_id = time.time(), uuid.uuid4().hex
        with self.db.get_cursor() as c:
            c.execute('BEGIN IMMEDIATE')
            actor_id = self._require_admin(c)
            state = c.execute('SELECT * FROM emergency_state WHERE id=1').fetchone()
            if not state or state['consumed_at'] is not None:
                raise ValueError('Нет неиспользованного набора резервных паролей.')
            credentials = c.execute('SELECT * FROM emergency_credentials WHERE batch_id=? ORDER BY user_id', (state['batch_id'],)).fetchall()
            if self._roster(c) != [(r['user_id'], r['login']) for r in credentials] or not credentials:
                raise ValueError('Состав аккаунтов изменился. Подготовьте резервные пароли заново.')
            # Собираем полную доступную историю аккаунтов с незавершёнными сеансами.
            sessions = [dict(r) for r in c.execute('''SELECT s.*,u.login FROM live_sessions s
                JOIN users u ON u.id=s.user_id WHERE s.ended_at IS NULL''')]
            live_ids = {s['user_id'] for s in sessions}
            events = [dict(r) for r in c.execute('SELECT * FROM audit_logs ORDER BY id') if r['user_id'] in live_ids]
            for s in sessions:
                s['login_time_utc'] = _utc(s['started_at'])
                s['last_seen_utc'] = _utc(s['last_seen_at'])
                s['connected_duration_seconds'] = max(0, round(now - s['started_at'], 3))
                s['recent_heartbeat'] = now - s['last_seen_at'] <= 30
            report = {
                'incident_id': incident_id, 'created_at_utc': _utc(now),
                'actor_id': actor_id, 'batch_id': state['batch_id'],
                'reset_accounts': [{'id': r['user_id'], 'login': r['login']} for r in credentials],
                'sessions_before_revocation': sessions,
                'activities': events,
                'scope': 'Все экземпляры приложения, использующие эту SQLite-базу.',
                'duration_note': 'Длительность открытого сеанса, включая простой; не измерение активной работы. '
                                 'У аварийно закрытых экземпляров может остаться незавершённый сеанс; смотрите last_seen_utc.',
                'execution_and_transfer_coverage': 'Только события, зарегистрированные сервисами приложения. '
                    'Внешние процессы и сетевой трафик не отслеживаются. '
                    'Пустые executable_path/transfer_source/transfer_destination означают отсутствие зарегистрированных сведений.',
                'legacy_note': 'Сеансы до обновления не восстановлены; старые события могут не иметь session_id. '
                               'Временные метки SQLite audit_logs указаны в UTC.',
            }
            for r in credentials:
                c.execute('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND active=1',
                          (r['password_hash'], r['user_id']))
            c.execute("UPDATE live_sessions SET ended_at=?,end_reason='compromise' WHERE ended_at IS NULL", (now,))
            c.execute('DELETE FROM user_sessions')
            c.execute('DELETE FROM login_attempts')
            c.execute('UPDATE emergency_state SET consumed_at=? WHERE id=1', (now,))
            c.execute('DELETE FROM emergency_credentials')
            c.execute('INSERT INTO emergency_reports(id,created_at,actor_id,report_json) VALUES (?,?,?,?)',
                      (incident_id, now, actor_id, json.dumps(report, ensure_ascii=False)))
            c.execute('INSERT INTO audit_logs(user_id,action,details,session_id) VALUES (?,?,?,?)',
                      (actor_id, 'COMPROMISE', 'incident_id=' + incident_id, self.login._session_id))
        # Авторитетная копия отчёта уже сохранена атомарно со сбросом в БД.
        self.login._user_id = self.login._session_id = None
        self.login.audit_logger.session_id = None
        path = DATA_DIR / 'incident-reports' / f'{incident_id}.json'
        export_error = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_new(path, json.dumps(report, ensure_ascii=False, indent=2).encode())
        except OSError as exc:
            export_error = str(exc)
        return {'incident_id': incident_id, 'report_path': str(path) if export_error is None else None,
                'export_error': export_error}

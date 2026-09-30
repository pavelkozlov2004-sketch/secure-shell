"""Реальные HTTPS-запросы: авторизация, права, presence и срок жизни токена."""
import atexit
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
_ENV = tempfile.TemporaryDirectory()
atexit.register(_ENV.cleanup)
os.environ.setdefault('VUAL_DATA_DIR', _ENV.name)

from auth.login_manager import LoginManager
from database.db_manager import DatabaseManager
from network.server import create_server, MAX_BODY_BYTES, SESSION_IDLE_SECONDS
from network.tls import client_context, generate_server_certificate


class LANServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls_directory = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.tls_directory.name) / 'server.crt'
        cls.key = Path(cls.tls_directory.name) / 'server.key'
        generate_server_certificate(cls.cert, cls.key)
        cls.context = client_context(cls.cert)

    @classmethod
    def tearDownClass(cls):
        cls.tls_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'users.db'
        self.db = DatabaseManager(self.path)
        self.db.bootstrap_admin('admin-password')
        admin = LoginManager(self.db)
        self.assertTrue(admin.login('admin_admin', 'admin-password'))
        self.assertTrue(admin.register_user('worker', 'worker-password', 1, 1))
        self.uid = self.db.fetch_one("SELECT id FROM users WHERE login='worker'")[0]
        admin.logout()
        self.server = create_server(self.path, port=0, certfile=self.cert, keyfile=self.key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'https://127.0.0.1:{self.server.server_address[1]}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=6)
        self.db.close()
        self.directory.cleanup()

    def request(self, path, payload, token=None, context=None, raw=None):
        data = json.dumps(payload).encode() if raw is None else raw
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = Request(self.url + path, data=data, headers=headers, method='POST')
        try:
            with urlopen(request, context=context or self.context, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def login(self, login='admin_admin', password='admin-password'):
        status, response = self.request('/api/login', {
            'login': login, 'password': password, 'client_name': 'Тестовый компьютер'})
        self.assertEqual(status, 200, response)
        return response['session_id'], response

    def connections(self, token):
        status, response = self.request('/api/connections', {}, token)
        self.assertEqual(status, 200, response)
        return {item['login']: item for item in response['users']}

    def test_login_snapshot_heartbeat_and_logout(self):
        token, response = self.login()
        self.assertEqual(response['user']['login'], 'admin_admin')
        self.assertEqual(response['server_id'], self.db.server_identity())
        status, snapshot = self.request('/api/sync', {'revision': -1}, token)
        self.assertEqual(status, 200)
        self.assertTrue(snapshot['changed'])
        self.assertEqual(len(snapshot['users']), 2)
        self.assertNotIn('password', json.dumps(snapshot))
        self.assertNotIn('emergency', json.dumps(snapshot))
        self.assertTrue(all(set(user) == {'id', 'login', 'direction_id', 'secrecy_level_id',
            'is_admin', 'active', 'network_blocked', 'created_at', 'updated_at'} for user in snapshot['users']))
        status, unchanged = self.request('/api/sync', {'revision': snapshot['revision']}, token)
        self.assertEqual(status, 200)
        self.assertFalse(unchanged['changed'])
        self.assertNotIn('users', unchanged)
        self.assertEqual(self.request('/api/heartbeat', {}, token)[0], 200)
        self.assertEqual(self.request('/api/logout', {}, token), (200, {'success': True}))
        self.assertEqual(self.request('/api/heartbeat', {}, token)[0], 401)

    def test_nonadmin_denied_and_cannot_choose_actor(self):
        token, _ = self.login('worker', 'worker-password')
        for path, payload in (('/api/accounts/list', {}), ('/api/connections', {}),
            ('/api/connections/restore', {'user_id': self.uid}),
            ('/api/accounts/action', {'action': 'delete_user', 'kwargs': {'user_id': 1}}),
            ('/api/accounts/action', {'action': 'change_password', 'kwargs': {
                'user_id': 1, 'old_password': 'admin-password', 'new_password': 'another-password'}})):
            self.assertEqual(self.request(path, payload, token)[0], 403, path)
        self.assertEqual(self.request('/api/heartbeat', {'user_id': 1}, token)[0], 400)
        self.assertEqual(self.request('/api/heartbeat', {}, '0' * 32)[0], 401)
        self.assertEqual(self.request('/api/heartbeat', {})[0], 401)

    def test_presence_changes_without_changing_accounts(self):
        admin, _ = self.login()
        worker, _ = self.login('worker', 'worker-password')
        revision = self.db.account_revision()
        item = self.connections(admin)['worker']
        self.assertEqual(item['status_code'], 'online')
        self.assertEqual(item['address'], '127.0.0.1')
        self.assertEqual(item['client_name'], 'Тестовый компьютер')
        self.db.execute('UPDATE lan_presence SET last_heartbeat=? WHERE session_id=?',
                        (time.time() - 11, worker))
        self.assertEqual(self.connections(admin)['worker']['status_code'], 'offline')
        self.assertEqual(self.request('/api/heartbeat', {}, worker)[0], 200)
        self.assertEqual(self.connections(admin)['worker']['status_code'], 'online')
        self.assertEqual(self.db.account_revision(), revision)
        self.assertEqual(self.request('/api/logout', {}, worker)[0], 200)
        self.assertEqual(self.connections(admin)['worker']['status_code'], 'offline')

    def test_deactivation_and_restore_preserve_password_revoke_old_token(self):
        admin, _ = self.login()
        worker, _ = self.login('worker', 'worker-password')
        old_hash = self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (self.uid,))[0]
        before = self.db.account_revision()
        status, action = self.request('/api/accounts/action', {
            'action': 'delete_user', 'kwargs': {'user_id': self.uid}}, admin)
        self.assertEqual(status, 200)
        self.assertTrue(action['success'])
        self.assertGreater(action['revision'], before)
        self.assertEqual(self.connections(admin)['worker']['status_code'], 'deactivated')
        self.assertEqual(self.request('/api/heartbeat', {}, worker)[0], 401)
        self.db.execute('INSERT INTO login_attempts(login,failures,locked_until) VALUES (?,?,?)',
                        ('worker', 3, time.time() + 300))
        status, restored = self.request('/api/connections/restore', {'user_id': self.uid}, admin)
        self.assertEqual(status, 200)
        self.assertTrue(restored['success'])
        self.assertEqual(self.connections(admin)['worker']['status_code'], 'offline')
        self.assertEqual(self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (self.uid,))[0], old_hash)
        self.assertIsNone(self.db.fetch_one("SELECT 1 FROM login_attempts WHERE login='worker'"))
        self.assertEqual(self.request('/api/heartbeat', {}, worker)[0], 401)
        self.login('worker', 'worker-password')

    def test_active_network_block_is_gray_and_restore_unblocks(self):
        admin, _ = self.login()
        worker, _ = self.login('worker', 'worker-password')
        self.db.execute('UPDATE users SET network_blocked=1 WHERE id=?', (self.uid,))
        item = self.connections(admin)['worker']
        self.assertEqual(item['status_code'], 'offline')
        self.assertIn('заблокирован', item['status'])
        self.assertEqual(self.request('/api/heartbeat', {}, worker)[0], 401)
        self.assertTrue(self.request('/api/connections/restore', {'user_id': self.uid}, admin)[1]['success'])
        self.assertEqual(self.request('/api/heartbeat', {}, worker)[0], 401)
        self.login('worker', 'worker-password')

    def test_session_cannot_reconnect_after_idle_expiry(self):
        worker, _ = self.login('worker', 'worker-password')
        self.db.execute('UPDATE lan_presence SET last_heartbeat=? WHERE session_id=?',
                        (time.time() - SESSION_IDLE_SECONDS - 1, worker))
        self.assertEqual(self.request('/api/heartbeat', {}, worker)[0], 401)
        self.assertEqual(self.db.fetch_one('SELECT end_reason FROM live_sessions WHERE id=?',
                                         (worker,))[0], 'lan_idle_timeout')
        self.login('worker', 'worker-password')

    def test_idle_sweep_works_without_admin_window_or_requests(self):
        worker, _ = self.login('worker', 'worker-password')
        self.db.execute('UPDATE lan_presence SET last_heartbeat=? WHERE session_id=?',
                        (time.time() - SESSION_IDLE_SECONDS - 1, worker))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.db.fetch_one('SELECT ended_at FROM live_sessions WHERE id=?', (worker,))[0]:
                break
            time.sleep(0.05)
        self.assertIsNotNone(self.db.fetch_one('SELECT ended_at FROM live_sessions WHERE id=?', (worker,))[0])
        self.assertEqual(self.db.fetch_one('SELECT active,network_blocked FROM users WHERE id=?', (self.uid,))[:], (1, 0))

    def test_request_bounds_allowlist_and_field_validation(self):
        admin, _ = self.login()
        status, _ = self.request('/api/accounts/action', {'action': 'execute', 'kwargs': {'sql': 'DROP TABLE users'}}, admin)
        self.assertEqual(status, 400)
        self.assertEqual(self.request('/api/accounts/action', {'action': 'update_user',
            'kwargs': {'user_id': True, 'is_admin': True}}, admin)[0], 400)
        self.assertEqual(self.request('/api/accounts/action', {'action': 'update_user',
            'kwargs': {'user_id': self.uid, 'password_hash': 'forged'}}, admin)[0], 400)
        self.assertEqual(self.request('/api/login', {'login': 'worker', 'password': 'x' * 1025})[0], 400)
        self.assertEqual(self.request('/api/sync', {'revision': '0'}, admin)[0], 400)
        self.assertEqual(self.request('/api/no-such-path', {}, admin)[0], 404)
        self.assertEqual(self.request('/api/login', {}, raw=b'{' * (MAX_BODY_BYTES + 8192))[0], 413)
        self.assertEqual(self.request('/api/login', {}, raw=b'[]')[0], 400)

    def test_untrusted_tls_rejected_and_unfinished_handshake_does_not_block(self):
        with self.assertRaises(URLError):
            self.request('/api/login', {'login': 'worker', 'password': 'worker-password'},
                         context=ssl.create_default_context())
        with socket.create_connection(('127.0.0.1', self.server.server_address[1]), timeout=2):
            # Первая TCP-сессия не присылает TLS ClientHello. Второй клиент проходит.
            token, _ = self.login('worker', 'worker-password')
            self.assertEqual(self.request('/api/heartbeat', {}, token)[0], 200)

    def test_existing_certificate_never_overwritten(self):
        before_certificate, before_key = self.cert.read_bytes(), self.key.read_bytes()
        with self.assertRaises(FileExistsError):
            generate_server_certificate(self.cert, self.key)
        self.assertEqual(self.cert.read_bytes(), before_certificate)
        self.assertEqual(self.key.read_bytes(), before_key)
        if os.name == 'posix':
            self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()

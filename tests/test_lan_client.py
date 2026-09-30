"""Безопасные сетевые настройки, HTTPS-транспорт и закрытие клиентского сеанса."""
import io
import atexit
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from urllib.error import HTTPError, URLError

_ENV = tempfile.TemporaryDirectory()
atexit.register(_ENV.cleanup)
os.environ.setdefault('VUAL_DATA_DIR', _ENV.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from auth.login_manager import LoginManager
from database.db_manager import DatabaseManager
from network.client import (NetworkClient, NetworkError, AuthenticationError,
                            AuthorizationError, RequestError, REQUEST_TIMEOUT)
from network.manager import NetworkLoginManager, NetworkConnectivityMonitor, create_login_manager
from network.settings import load_settings, save_settings, validate_server_url
from network.tls import generate_server_certificate


class RecordingOpener:
    def __init__(self, response=None, error=None):
        self.response = {} if response is None else response
        self.error = error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error is not None:
            raise self.error
        return io.BytesIO(json.dumps(self.response).encode('utf-8'))


class FakeServer:
    def __init__(self):
        source = DatabaseManager(':memory:')
        try:
            source.bootstrap_admin('admin-password')
            self.user = dict(source.fetch_one('SELECT * FROM users WHERE id=1'))
            self.snapshot = {
                'revision': 1, 'server_id': source.server_identity(), 'changed': True,
                'users': [{k: v for k, v in self.user.items() if k != 'password_hash'}],
                'directions': source.fetch_all_dict('SELECT * FROM directions'),
                'secrecy_levels': source.fetch_all_dict('SELECT * FROM secrecy_levels'),
            }
        finally:
            source.close()
        self.user = {key: self.user[key] for key in (
            'id', 'login', 'direction_id', 'secrecy_level_id', 'is_admin')}
        self.error = None
        self.requests = []
        self.connections = []

    def request(self, endpoint, data=None, session_id=None):
        self.requests.append((endpoint, data, session_id))
        if self.error is not None:
            raise self.error
        state = {'revision': self.snapshot['revision'], 'server_id': self.snapshot['server_id']}
        if endpoint == '/api/login':
            if data['password'] != 'admin-password':
                raise AuthenticationError('Неверные учётные данные')
            return dict(state, user=dict(self.user), session_id='a' * 32)
        if endpoint == '/api/heartbeat':
            return dict(state, user=dict(self.user))
        if endpoint == '/api/sync':
            if data['revision'] == self.snapshot['revision']:
                return dict(state, changed=False)
            return json.loads(json.dumps(self.snapshot))
        if endpoint == '/api/accounts/list':
            return dict(state, users=[dict(self.user)])
        if endpoint == '/api/connections':
            return {'users': [dict(row) for row in self.connections]}
        if endpoint in ('/api/accounts/action', '/api/connections/restore'):
            return dict(state, success=True)
        if endpoint == '/api/logout':
            return {'success': True}
        raise AssertionError(endpoint)


class LANSettingsAndTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.tmp.name) / 'server.pem'
        generate_server_certificate(cls.cert, Path(cls.tmp.name) / 'server-key.pem')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def settings(self):
        return dict(enabled=True, server_url='https://127.0.0.1:8443/',
                    ca_file=str(self.cert), client_name='Рабочее место')

    def test_settings_atomic_roundtrip_has_only_permitted_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            saved = save_settings(self.settings(), directory)
            self.assertEqual(saved['server_url'], 'https://127.0.0.1:8443')
            self.assertEqual(load_settings(directory), saved)
            path = Path(directory) / 'lan-settings.json'
            self.assertEqual(set(json.loads(path.read_text(encoding='utf-8'))),
                             {'enabled', 'server_url', 'ca_file', 'client_name'})
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(list(Path(directory).glob('.lan-settings-*')))

    def test_settings_cannot_persist_password_or_session_token(self):
        with tempfile.TemporaryDirectory() as directory:
            for secret in ('password', 'session_id', 'token'):
                with self.subTest(secret=secret), self.assertRaises(ValueError):
                    save_settings(dict(self.settings(), **{secret: 'private-secret'}), directory)
            self.assertFalse((Path(directory) / 'lan-settings.json').exists())

    def test_invalid_existing_certificate_is_rejected_before_save(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / 'invalid.pem'
            invalid.write_text('not a certificate', encoding='utf-8')
            with self.assertRaises(ValueError):
                save_settings(dict(self.settings(), ca_file=str(invalid)), directory)
            self.assertFalse((Path(directory) / 'lan-settings.json').exists())

    def test_invalid_or_insecure_urls_cannot_be_saved(self):
        invalid = (
            'http://127.0.0.1:8443', 'https://admin:password@server',
            'https://server/api', 'https://server?password=x', 'https://server#fragment',
            'https://server?', 'https://server#', 'https://server:0', 'https://server:65536',
            'https://server:invalid', 'https://', 'https://server\\host',
            ' https://server', 'https://server\n', 'https://%73erver',
        )
        for address in invalid:
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate_server_url(address)
        for address in ('https://server', 'https://192.168.1.5:8443', 'https://[::1]:8443'):
            self.assertEqual(validate_server_url(address), address)

    def test_transport_checks_certificate_and_uses_finite_timeout(self):
        opener = RecordingOpener({'success': True})
        client = NetworkClient('https://server:8443', str(self.cert), opener=opener)
        self.assertEqual(client.ssl_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client.ssl_context.check_hostname)
        self.assertEqual(client.ssl_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(client.request('/api/heartbeat', session_id='session-token'), {'success': True})
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, REQUEST_TIMEOUT)
        self.assertLessEqual(timeout, 3)
        self.assertEqual(request.method, 'POST')
        self.assertEqual(request.get_header('Authorization'), 'Bearer session-token')

    def test_credentials_are_json_body_and_never_added_to_url(self):
        opener = RecordingOpener()
        client = NetworkClient('https://server:8443', str(self.cert), opener=opener)
        client.request('/api/login', {'login': 'worker', 'password': 'private-secret'})
        request = opener.requests[0][0]
        self.assertEqual(request.full_url, 'https://server:8443/api/login')
        self.assertNotIn('private-secret', request.full_url)
        self.assertEqual(json.loads(request.data)['password'], 'private-secret')

    def test_errors_have_distinct_safe_types(self):
        for status, error_type in ((401, AuthenticationError), (403, AuthorizationError),
                                   (400, RequestError), (503, NetworkError), (302, NetworkError)):
            with self.subTest(status=status):
                error = HTTPError('https://server/api', status, 'private-server-error', {}, None)
                client = NetworkClient('https://server', str(self.cert), opener=RecordingOpener(error=error))
                with self.assertRaises(error_type) as caught:
                    client.request('/api/heartbeat')
                self.assertNotIn('private-server-error', str(caught.exception))
        client = NetworkClient('https://server', str(self.cert),
                               opener=RecordingOpener(error=URLError('private-ca-detail')))
        with self.assertRaises(NetworkError) as caught:
            client.request('/api/heartbeat')
        self.assertNotIn('private-ca-detail', str(caught.exception))

    def test_unexpected_response_and_header_injection_are_rejected(self):
        client = NetworkClient('https://server', str(self.cert), opener=RecordingOpener([]))
        with self.assertRaises(NetworkError):
            client.request('/api/heartbeat')
        with self.assertRaises(ValueError):
            client.request('/api/heartbeat', session_id='a\r\nInjected: header')


class LANManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.tmp.name) / 'server.pem'
        generate_server_certificate(cls.cert, Path(cls.tmp.name) / 'key.pem')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.addCleanup(self.db.close)
        self.server = FakeServer()
        self.now = 100.0
        self.settings = dict(enabled=True, server_url='https://127.0.0.1:8443',
                             ca_file=str(self.cert), client_name='client')
        self.manager = NetworkLoginManager(self.db, self.settings, client=self.server, clock=lambda: self.now)

    def test_login_requires_server_and_mirror_contains_no_credential_hashes(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.assertEqual(self.manager.current_user.id, 1)
        self.assertEqual(self.db.fetch_one('SELECT password_hash FROM users WHERE id=1')[0],
                         '!remote-authentication-only!')
        self.assertFalse(LoginManager(self.db).login('admin_admin', 'admin-password'))
        self.assertEqual(self.server.requests[0][0], '/api/login')

    def test_repeated_current_user_calls_use_short_cache(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        count = len(self.server.requests)
        for _ in range(10):
            self.assertIsNotNone(self.manager.current_user)
        self.assertEqual(len(self.server.requests), count)
        self.now += 2.01
        self.assertIsNotNone(self.manager.current_user)
        self.assertEqual(self.server.requests[-1][0], '/api/heartbeat')

    def test_network_loss_closes_local_session_without_offline_login(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        token = self.manager._session_id
        self.server.error = NetworkError('Сервер недоступен')
        self.now += 3
        self.assertIsNone(self.manager.current_user)
        self.assertIsNone(self.manager._session_id)
        self.assertIsNotNone(self.db.fetch_one('SELECT ended_at FROM live_sessions WHERE id=?', (token,))[0])
        with self.assertRaises(NetworkError):
            self.manager.login('admin_admin', 'admin-password')

    def test_server_role_downgrade_and_local_role_tamper_use_authoritative_user(self):
        self.server.user['is_admin'] = False
        self.server.snapshot['users'][0]['is_admin'] = False
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.db.execute('UPDATE users SET is_admin=1 WHERE id=1')
        self.assertFalse(self.manager.current_user.is_admin)
        self.assertEqual(self.db.fetch_one('SELECT is_admin FROM users WHERE id=1')[0], 0)
        self.server.user['is_admin'] = True
        self.server.snapshot['users'][0]['is_admin'] = True
        self.server.snapshot['revision'] += 1
        self.assertTrue(self.manager.refresh_session())
        self.assertTrue(self.manager.current_user.is_admin)

    def test_mutation_immediately_fetches_new_snapshot(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        before = len(self.server.requests)
        self.assertTrue(self.manager.update_user(1, direction_id=2))
        requests = [request[0] for request in self.server.requests[before:]]
        self.assertIn('/api/accounts/action', requests)
        self.assertIn('/api/sync', requests)
        self.assertIn('/api/heartbeat', requests)

    def test_newer_snapshot_cannot_restore_role_revoked_after_heartbeat(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        # Между heartbeat и снимком администратор теряет права на сервере.
        self.server.snapshot['users'][0]['is_admin'] = False
        self.server.snapshot['revision'] += 1
        self.assertTrue(self.manager.refresh_session())
        self.assertFalse(self.manager.current_user.is_admin)
        self.assertEqual(self.db.fetch_one('SELECT is_admin FROM users WHERE id=1')[0], 0)

    def test_server_replacement_and_revision_rollback_close_session(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.server.snapshot['revision'] = 0
        self.assertFalse(self.manager.refresh_session())
        self.assertIn('старше', self.manager.last_error)
        self.server.snapshot['revision'] = 1
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.server.snapshot['server_id'] = '00000000-0000-0000-0000-000000000000'
        self.assertFalse(self.manager.refresh_session())
        self.assertIn('заменена', self.manager.last_error)

    def test_connection_status_colors_have_stable_machine_codes(self):
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.server.connections = [
            dict(id=2, active=1, network_blocked=0, status='online'),
            dict(id=3, active=1, network_blocked=1, status='deactivated'),
            dict(id=4, active=0, network_blocked=0, status='offline'),
        ]
        monitor = NetworkConnectivityMonitor(self.manager)
        self.assertEqual([row['status_code'] for row in monitor.user_statuses()],
                         ['online', 'offline', 'deactivated'])
        self.assertEqual([row['id'] for row in monitor.offline_users()], [3, 4])
        self.assertTrue(monitor.unblock(4))

    def test_local_factory_keeps_local_mode_when_network_disabled(self):
        self.assertIsInstance(create_login_manager(self.db, {'enabled': False}), LoginManager)
        self.assertNotIsInstance(create_login_manager(self.db, {'enabled': False}), NetworkLoginManager)


if __name__ == '__main__':
    unittest.main()

"""Real HTTPS round trips against a loopback server with independent client DBs."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('VUAL_DATA_DIR', _TMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from auth.login_manager import LoginManager
from database.db_manager import DatabaseManager
from network.client import AuthorizationError, NetworkClient, NetworkError
from network.manager import NetworkConnectivityMonitor, NetworkLoginManager
from network.server import ONLINE_SECONDS, SESSION_IDLE_SECONDS, create_server
from network.tls import generate_server_certificate
from storage.document_storage import DocumentStorage
from storage.report_format import EXAMPLE_REPORT


class LANIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.databases, self.managers = [], []
        self.server = self.thread = self.clock_patch = None
        self.addCleanup(self._cleanup)
        self.now = time.time()
        # Replace only the server module's binding; keep every other clock real.
        self.clock_patch = patch('network.server.time', SimpleNamespace(time=lambda: self.now))
        self.clock_patch.start()
        self.central = self._database('server')
        self.central.bootstrap_admin('admin-password')
        local_admin = LoginManager(self.central)
        self.assertTrue(local_admin.login('admin_admin', 'admin-password'))
        self.assertTrue(local_admin.register_user('worker', 'worker-password', 1, 1))
        local_admin.logout()
        self.worker_id = self.central.fetch_one('SELECT id FROM users WHERE login=?', ('worker',))[0]
        self.cert, self.key = self.root / 'server.pem', self.root / 'server-key.pem'
        generate_server_certificate(self.cert, self.key)
        self.server = create_server(self.central.db_path, port=0, certfile=self.cert, keyfile=self.key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'https://127.0.0.1:{self.server.server_address[1]}'
        self.admin_db, self.worker_db = self._database('admin-client'), self._database('worker-client')
        self.admin = self._manager(self.admin_db, 'admin-computer')
        self.worker = self._manager(self.worker_db, 'worker-computer')
        self.assertTrue(self.admin.login('admin_admin', 'admin-password'))
        self.assertTrue(self.worker.login('worker', 'worker-password'))
        self.monitor = NetworkConnectivityMonitor(self.admin)

    def _database(self, name):
        database = DatabaseManager(self.root / name / 'users.db')
        self.databases.append(database)
        return database

    def _manager(self, database, name, ca_file=None):
        manager = NetworkLoginManager(database, settings={
            'enabled': True, 'server_url': self.url, 'ca_file': str(ca_file or self.cert),
            'client_name': name,
        })
        self.managers.append(manager)
        return manager

    def _cleanup(self):
        for manager in reversed(self.managers):
            manager.logout()
        if self.server is not None:
            if self.thread is not None and self.thread.is_alive():
                self.server.shutdown()
                self.thread.join(timeout=10)
            self.server.server_close()
        for database in reversed(self.databases):
            database.close()
        if self.clock_patch is not None:
            self.clock_patch.stop()
        self.tmp.cleanup()

    def _statuses(self):
        return {row['id']: row for row in self.monitor.user_statuses()}

    @staticmethod
    def _status(row):
        return row.get('status_code', row['status'])

    def _assert_mirror_revision(self, database):
        self.assertEqual(database.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')[0],
                         self.central.account_revision())

    def test_admin_changes_reach_both_independent_user_databases(self):
        self.assertEqual(len({self.central.db_path, self.admin_db.db_path, self.worker_db.db_path}), 3)
        initial = self.central.account_revision()
        self.assertTrue(self.admin.register_user('new-user', 'new-user-password', 2, 2))
        self.assertGreater(self.central.account_revision(), initial)
        self._assert_mirror_revision(self.admin_db)
        self.assertTrue(self.worker.refresh_remote_state(force=True))
        self._assert_mirror_revision(self.worker_db)
        self.assertIsNotNone(self.worker_db.fetch_one('SELECT id FROM users WHERE login=?', ('new-user',)))

        self.assertTrue(self.admin.update_user(self.worker_id, direction_id=3, secrecy_level_id=2))
        self.assertTrue(self.worker.refresh_remote_state(force=True))
        self.assertEqual((self.worker.current_user.direction_id, self.worker.current_user.secrecy_level_id),
                         (3, 2))
        for database in (self.admin_db, self.worker_db):
            self._assert_mirror_revision(database)
            row = database.fetch_one('SELECT direction_id,secrecy_level_id FROM users WHERE id=?',
                                     (self.worker_id,))
            self.assertEqual(tuple(row), (3, 2))

        self.assertTrue(self.admin.reset_password(self.worker_id, 'updated-worker-password'))
        self.assertTrue(self.worker.refresh_remote_state(force=True))
        self._assert_mirror_revision(self.worker_db)
        self.assertFalse(self.worker.login('worker', 'worker-password'))
        self.assertTrue(self.worker.login('worker', 'updated-worker-password'))
        self.assertTrue(self.worker.change_password(self.worker_id, 'updated-worker-password',
                                                    'own-updated-password'))
        self.assertTrue(self.admin.refresh_remote_state(force=True))
        self._assert_mirror_revision(self.admin_db)
        self.worker.logout()
        self.assertTrue(self.worker.login('worker', 'own-updated-password'))

    def test_presence_comes_from_network_heartbeat_then_deactivation_and_restore(self):
        row = self._statuses()[self.worker_id]
        self.assertEqual(self._status(row), 'online')
        self.assertEqual(row['address'], '127.0.0.1')
        self.assertEqual(row['client_name'], 'worker-computer')
        self.now += ONLINE_SECONDS + 1
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'offline')
        # Admin polling must not make the worker appear connected.
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'offline')
        self.assertTrue(self.worker.refresh_remote_state(force=True))
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'online')

        previous_session = self.worker._session_id
        self.assertTrue(self.admin.delete_user(self.worker_id))
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'deactivated')
        self.assertEqual(self.admin_db.fetch_one('SELECT active FROM users WHERE id=?',
                                                 (self.worker_id,))[0], 0)
        self.assertFalse(self.worker.refresh_remote_state(force=True))
        self.assertIsNone(self.worker.current_user)
        self.assertFalse(self.worker.login('worker', 'worker-password'))
        self.assertTrue(self.monitor.unblock(self.worker_id))
        self._assert_mirror_revision(self.admin_db)
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'offline')
        self.assertIsNotNone(self.central.fetch_one('SELECT ended_at FROM live_sessions WHERE id=?',
                                                    (previous_session,))[0])
        self.assertTrue(self.worker.login('worker', 'worker-password'))
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'online')

    def test_server_rejects_worker_admin_actions_even_with_forged_local_role(self):
        self.worker_db.execute('UPDATE users SET is_admin=1 WHERE id=?', (self.worker_id,))
        self.assertFalse(self.worker.current_user.is_admin)
        initial = self.central.account_revision()
        payload = {'action': 'register_user', 'kwargs': {
            'login': 'forged-admin', 'password': 'forged-password',
            'direction_id': 1, 'secrecy_level_id': 1, 'is_admin': True,
        }}
        with self.assertRaises(AuthorizationError):
            self.worker.client.request('/api/accounts/action', payload,
                                       session_id=self.worker._session_id)
        self.assertFalse(self.worker.register_user('forged-admin', 'forged-password', 1, 1, True))
        with self.assertRaises(PermissionError):
            NetworkConnectivityMonitor(self.worker).unblock(self.worker_id)
        self.assertEqual(self.central.account_revision(), initial)
        self.assertIsNone(self.central.fetch_one('SELECT id FROM users WHERE login=?', ('forged-admin',)))

    def test_local_role_tamper_cannot_read_cached_administrator_source_documents(self):
        # Local cache permissions also use the current server identity.
        self.worker_db.execute('INSERT INTO documents_store.documents(title,content,original_name,owner_id) '
                               "VALUES ('Admin source','private data','source.txt',1)")
        self.worker_db.execute('UPDATE users SET is_admin=1,secrecy_level_id=4 WHERE id=?',
                               (self.worker_id,))
        with self.assertRaises(PermissionError):
            DocumentStorage(self.worker_db, self.worker).list_documents()

    def test_sync_metadata_never_transfers_password_hashes_or_overwrites_saved_documents(self):
        storage = DocumentStorage(self.admin_db, self.admin)
        document = storage.create_document('Saved source', json.dumps(EXAMPLE_REPORT), 'saved.json')
        table = storage.convert_document(document['id'], direction_id=1, secrecy_level_id=1)
        snapshot = self.admin.client.request('/api/sync', {'revision': -1},
                                             session_id=self.admin._session_id)
        serialized = json.dumps(snapshot)
        self.assertNotIn('password_hash', serialized)
        self.assertNotIn('salt', serialized)
        central_hashes = [row[0] for row in self.central.fetch_all('SELECT password_hash FROM users')]
        for value in central_hashes:
            self.assertNotIn(value, serialized)
            self.assertNotIn(value.encode(), Path(self.admin_db.db_path).read_bytes())
            self.assertNotIn(value.encode(), Path(self.worker_db.db_path).read_bytes())
        self.assertTrue(self.admin.register_user('another-user', 'another-password', 1, 1))
        self.assertEqual(storage.get_document(document['id'])['content'], document['content'])
        saved = storage.get_table(table['id'])
        self.assertEqual(saved['report'], EXAMPLE_REPORT)
        self.assertEqual(saved['source_document_id'], document['id'])
        self._assert_mirror_revision(self.admin_db)

    def test_untrusted_certificate_is_rejected_and_http_is_never_accepted(self):
        wrong_cert, wrong_key = self.root / 'other.pem', self.root / 'other-key.pem'
        generate_server_certificate(wrong_cert, wrong_key)
        wrong_client = NetworkClient(self.url, str(wrong_cert))
        with self.assertRaises(NetworkError):
            wrong_client.request('/api/login', {'login': 'admin_admin', 'password': 'admin-password'})
        with self.assertRaises(ValueError):
            NetworkClient(self.url.replace('https://', 'http://'), str(self.cert))
        wrong_database = self._database('untrusted-client')
        wrong_manager = self._manager(wrong_database, 'untrusted', ca_file=wrong_cert)
        with self.assertRaises(NetworkError):
            wrong_manager.login('admin_admin', 'admin-password')
        self.assertIsNone(wrong_manager.current_user)
        self.assertEqual(wrong_database.fetch_one('SELECT COUNT(*) FROM users')[0], 0)

    def test_stale_network_session_is_revoked_without_deactivating_account(self):
        session_id = self.worker._session_id
        self.central.execute('UPDATE lan_presence SET last_heartbeat=? WHERE session_id=?',
                             (self.now - SESSION_IDLE_SECONDS - 1, session_id))
        self.server._expire_sessions(self.central, self.now)
        self.assertFalse(self.worker.refresh_remote_state(force=True))
        self.assertIsNone(self.worker.current_user)
        self.assertEqual(self.central.fetch_one('SELECT active FROM users WHERE id=?',
                                                (self.worker_id,))[0], 1)
        self.assertEqual(self._status(self._statuses()[self.worker_id]), 'offline')
        self.assertTrue(self.worker.login('worker', 'worker-password'))
        self.assertNotEqual(self.worker._session_id, session_id)

    def test_incomplete_tls_handshake_does_not_block_existing_clients(self):
        pending = socket.create_connection(self.server.server_address, timeout=2)
        try:
            self.assertTrue(self.worker.refresh_remote_state(force=True))
            self.assertEqual(self._status(self._statuses()[self.worker_id]), 'online')
        finally:
            pending.close()

    def test_another_server_cannot_replace_cached_account_owners(self):
        storage = DocumentStorage(self.admin_db, self.admin)
        saved = storage.create_document('Existing source', 'Preserve its owner', 'saved.txt')
        previous_identity = self.admin_db.fetch_one('SELECT server_id FROM lan_sync_state WHERE id=1')[0]
        previous_revision = self.admin_db.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')[0]
        another = self._database('another-server')
        another.bootstrap_admin('admin-password')
        registrar = LoginManager(another)
        self.assertTrue(registrar.login('admin_admin', 'admin-password'))
        self.assertTrue(registrar.register_user('unrelated-user', 'unrelated-password', 1, 1))
        registrar.logout()
        other_server = create_server(another.db_path, port=0, certfile=self.cert, keyfile=self.key)
        thread = threading.Thread(target=other_server.serve_forever, daemon=True)
        thread.start()
        try:
            other_url = f'https://127.0.0.1:{other_server.server_address[1]}'
            self.admin.client = NetworkClient(other_url, str(self.cert))
            with self.assertRaises(NetworkError):
                self.admin.login('admin_admin', 'admin-password')
            self.assertIsNone(self.admin.current_user)
            self.assertEqual(self.admin_db.fetch_one('SELECT server_id,revision FROM lan_sync_state '
                                                     'WHERE id=1')[:],
                             (previous_identity, previous_revision))
            self.assertEqual(self.admin_db.fetch_one('SELECT content,owner_id FROM '
                                                     'documents_store.documents WHERE id=?',
                                                     (saved['id'],))[:],
                             ('Preserve its owner', saved['owner_id']))
            self.assertIsNotNone(self.admin_db.fetch_one('SELECT id FROM users WHERE login=?', ('worker',)))
            self.assertIsNone(self.admin_db.fetch_one('SELECT id FROM users WHERE login=?', ('unrelated-user',)))
        finally:
            other_server.shutdown()
            thread.join(timeout=10)
            other_server.server_close()


if __name__ == '__main__':
    unittest.main()

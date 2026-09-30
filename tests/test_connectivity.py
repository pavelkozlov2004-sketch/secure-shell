import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('SECURE_SHELL_DATA_DIR', _TMP.name)
from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager
from auth.connectivity import ConnectivityMonitor


class ConnectivityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'test.db'
        self.db = DatabaseManager(self.path)
        self.db.bootstrap_admin('admin-password')
        self.admin = LoginManager(self.db)
        self.admin.login('admin_admin', 'admin-password')
        self.admin.register_user('worker', 'worker-password', 1, 1)
        self.worker = LoginManager(self.db)
        self.worker.login('worker', 'worker-password')
        self.uid = self.worker.current_user.id
        self.now = 1000.0
        self.monitor = ConnectivityMonitor(self.admin, lambda: self.now)
        self.client = ConnectivityMonitor(self.worker, lambda: self.now)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_response_and_five_minute_cadence(self):
        self.monitor.poll()
        nonce = self.db.fetch_one('SELECT nonce FROM connectivity_challenges')[0]
        self.client.respond()
        self.now += 60
        self.assertEqual(self.monitor.poll(), [])
        self.now = 1299
        self.monitor.poll()
        self.assertEqual(self.db.fetch_one('SELECT nonce FROM connectivity_challenges')[0], nonce)
        self.now = 1300
        self.monitor.poll()
        self.assertNotEqual(self.db.fetch_one('SELECT nonce FROM connectivity_challenges')[0], nonce)

    def test_timeout_revokes_all_sessions_and_blocks_login(self):
        other = LoginManager(self.db)
        other.login('worker', 'worker-password')
        self.monitor.poll()
        self.client.respond()
        self.now += 60
        self.assertEqual(self.monitor.poll(), [self.uid])
        self.assertIsNone(self.worker.current_user)
        self.assertIsNone(other.current_user)
        self.assertFalse(other.login('worker', 'worker-password'))
        self.assertEqual(self.monitor.poll(), [])
        self.assertEqual(self.db.fetch_one("SELECT count(*) FROM audit_logs WHERE action='NETWORK_BLOCK'")[0], 1)

    def test_late_reply_does_not_prevent_block(self):
        self.monitor.poll()
        self.now += 61
        self.client.respond()
        self.assertEqual(self.monitor.poll(), [self.uid])

    def test_clean_logout_not_blocked(self):
        self.monitor.poll()
        self.worker.logout()
        self.now += 61
        self.assertEqual(self.monitor.poll(), [])
        self.assertTrue(self.worker.login('worker', 'worker-password'))

    def test_permissions_and_revocation(self):
        for operation in (self.client.poll, self.client.offline_users, lambda: self.client.unblock(self.uid)):
            with self.assertRaises(PermissionError):
                operation()
        self.admin.logout()
        with self.assertRaises(PermissionError):
            self.monitor.poll()

    def test_unblock_does_not_restore_old_session(self):
        self.monitor.poll()
        self.now += 60
        self.monitor.poll()
        self.assertTrue(self.monitor.unblock(self.uid))
        self.assertIsNone(self.worker.current_user)
        self.assertTrue(self.worker.login('worker', 'worker-password'))

    def test_persistent_block_and_schema_migration(self):
        self.monitor.poll()
        self.now += 60
        self.monitor.poll()
        other_db = DatabaseManager(self.path)
        try:
            self.assertFalse(LoginManager(other_db).login('worker', 'worker-password'))
            self.assertEqual(other_db.fetch_one('PRAGMA foreign_keys')[0], 1)
        finally:
            other_db.close()

    def test_multiple_admins_dont_overwrite_challenge(self):
        self.monitor.poll()
        before = dict(self.db.fetch_one('SELECT * FROM connectivity_challenges'))
        other = LoginManager(self.db)
        other.login('admin_admin', 'admin-password')
        ConnectivityMonitor(other, lambda: self.now).poll()
        self.assertEqual(dict(self.db.fetch_one('SELECT * FROM connectivity_challenges')), before)

    def test_offline_board_never_logged_in_and_recent_files(self):
        self.admin.register_user('never', 'worker-password', 1, 1)
        self.worker.audit_logger.log_file_open(self.uid, '/documents/example.txt')
        self.worker.logout()
        rows = {r['login']: r for r in self.monitor.offline_users()}
        self.assertIsNone(rows['never']['last_login'])
        self.assertIsNotNone(rows['worker']['last_login'])
        self.assertEqual(rows['worker']['files'][0]['details'], '/documents/example.txt')

    def test_only_own_session_answers(self):
        self.monitor.poll()
        self.monitor.respond()
        self.assertIsNone(self.db.fetch_one('SELECT answered_at FROM connectivity_challenges')[0])

    def test_block_transaction_rollback(self):
        self.monitor.poll()
        self.now += 60
        self.db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs WHEN NEW.action='NETWORK_BLOCK' BEGIN SELECT RAISE(ABORT,'test'); END")
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.monitor.poll()
        self.assertEqual(self.db.fetch_one('SELECT network_blocked FROM users WHERE id=?', (self.uid,))[0], 0)
        self.assertIsNotNone(self.worker.current_user)


if __name__ == '__main__':
    unittest.main()

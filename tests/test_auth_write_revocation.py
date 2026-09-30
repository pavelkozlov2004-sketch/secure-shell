"""Account writes cannot outlive authorization or overwrite a concurrent reset."""
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('SECURE_SHELL_DATA_DIR', _TMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from auth.login_manager import LoginManager
from auth.password_utils import PasswordUtils
from database.db_manager import DatabaseManager


class AccountWriteRevocationTests(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.addCleanup(self.db.close)
        self.db.bootstrap_admin('admin-password')
        self.manager = LoginManager(self.db)
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.assertTrue(self.manager.register_user('worker', 'worker-password', 1, 1))
        self.worker_id = self.db.fetch_one("SELECT id FROM users WHERE login='worker'")[0]

    def test_register_rechecks_admin_after_password_hashing(self):
        hash_password = PasswordUtils.hash_password

        def revoke(password):
            result = hash_password(password)
            self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
            return result

        with patch.object(PasswordUtils, 'hash_password', side_effect=revoke):
            self.assertFalse(self.manager.register_user('forbidden', 'valid-password', 1, 1))
        self.assertIsNone(self.db.fetch_one("SELECT id FROM users WHERE login='forbidden'"))

    def test_reset_rechecks_session_after_password_hashing(self):
        before = self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (self.worker_id,))[0]
        hash_password = PasswordUtils.hash_password

        def revoke(password):
            result = hash_password(password)
            self.db.execute('UPDATE live_sessions SET ended_at=1 WHERE id=?', (self.manager._session_id,))
            return result

        with patch.object(PasswordUtils, 'hash_password', side_effect=revoke):
            self.assertFalse(self.manager.reset_password(self.worker_id, 'replacement-password'))
        self.assertEqual(self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (self.worker_id,))[0], before)

    def test_update_delete_and_account_list_recheck_admin_inside_transaction(self):
        original = self.db.get_cursor

        @contextmanager
        def revoke_before_begin():
            self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
            with original() as cursor:
                yield cursor

        operations = (
            lambda: self.manager.update_user(self.worker_id, is_admin=True),
            lambda: self.manager.delete_user(self.worker_id),
            self.manager.get_all_users,
        )
        for operation in operations:
            self.db.execute('UPDATE users SET is_admin=1 WHERE id=1')
            with patch.object(self.db, 'get_cursor', revoke_before_begin):
                self.assertFalse(operation())
        target = self.db.fetch_one('SELECT active,is_admin FROM users WHERE id=?', (self.worker_id,))
        self.assertEqual(tuple(target), (1, 0))

    def test_own_password_change_rechecks_network_block(self):
        before = self.db.fetch_one('SELECT password_hash FROM users WHERE id=1')[0]
        hash_password = PasswordUtils.hash_password

        def block(password):
            result = hash_password(password)
            self.db.execute('UPDATE users SET network_blocked=1 WHERE id=1')
            return result

        with patch.object(PasswordUtils, 'hash_password', side_effect=block):
            self.assertFalse(self.manager.change_password(1, 'admin-password', 'replacement-password'))
        self.assertEqual(self.db.fetch_one('SELECT password_hash FROM users WHERE id=1')[0], before)

    def test_own_password_change_does_not_overwrite_concurrent_admin_reset(self):
        hash_password = PasswordUtils.hash_password
        replacement, salt = hash_password('admin-reset-password')
        concurrent_hash = f'{replacement}${salt}'

        def reset(password):
            result = hash_password(password)
            self.db.execute('UPDATE users SET password_hash=? WHERE id=1', (concurrent_hash,))
            return result

        with patch.object(PasswordUtils, 'hash_password', side_effect=reset):
            self.assertFalse(self.manager.change_password(1, 'admin-password', 'stale-replacement'))
        self.assertEqual(self.db.fetch_one('SELECT password_hash FROM users WHERE id=1')[0], concurrent_hash)


if __name__ == '__main__':
    unittest.main()

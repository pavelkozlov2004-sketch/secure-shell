"""Регрессии найденных ошибок. Только stdlib; отдельная временная БД на тест."""
import hashlib
import logging
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ['SECURE_SHELL_DATA_DIR'] = _TMP.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager
from auth.password_utils import PasswordUtils
from access_control.permissions import PermissionManager, canonical_path
from file_manager.file_ops import FileOperations
from app_audit.audit_logger import AuditLogger


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = DatabaseManager(self.root / 'test.db')
        self.db.bootstrap_admin('admin-password')
        self.manager = LoginManager(self.db)
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def user(self, name='worker', direction=1, level=1, admin=False):
        self.assertTrue(self.manager.register_user(name, 'worker-password', direction, level, admin))
        return self.db.fetch_one('SELECT id FROM users WHERE login=?', (name,))[0]

    def directory(self):
        path = self.root / 'documents'
        path.mkdir()
        ops = FileOperations(self.db, self.manager)
        ops.register_directory(path, 1, 1)
        return path, ops

    def file(self, parent, name='test.txt', direction=1, level=1):
        path = parent / name
        path.write_text('original')
        self.db.execute('INSERT INTO files_metadata(path,direction_id,secrecy_level_id,owner_id) VALUES (?,?,?,1)',
                        (canonical_path(path), direction, level))
        return path

    def test_accessible_roots_hide_other_directions_and_nested_directories(self):
        root, ops = self.directory()
        nested = root / 'nested'
        ops.create_directory(nested)
        other = self.root / 'other'
        other.mkdir()
        ops.register_directory(other, 2, 1)
        self.assertEqual(ops.list_accessible_roots(), [canonical_path(root)])
        self.user()
        self.assertTrue(self.manager.login('worker', 'worker-password'))
        self.assertEqual(ops.list_accessible_roots(), [canonical_path(root)])
        self.assertNotIn(canonical_path(other), ops.list_accessible_roots())
        self.manager.logout()
        with self.assertRaises(PermissionError):
            ops.list_accessible_roots()

    def test_import_and_single_audit_handler(self):
        logger = AuditLogger(self.db).file_logger
        AuditLogger(self.db)
        self.assertEqual(len(logger.handlers), 1)
        self.assertTrue(hasattr(logging, 'getLogger'))

    def test_registration_requires_admin(self):
        self.manager.logout()
        self.assertFalse(self.manager.register_user('bad', 'password1', 1, 1, True))
        self.manager.login('admin_admin', 'admin-password')
        self.user()
        self.manager.login('worker', 'worker-password')
        self.assertFalse(self.manager.register_user('bad', 'password1', 1, 1, True))

    def test_invalid_foreign_keys(self):
        self.assertEqual(self.db.fetch_one('PRAGMA foreign_keys')[0], 1)
        self.assertFalse(self.manager.register_user('bad', 'password1', 999, 999))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('INSERT INTO user_sessions(user_id) VALUES(99999)')

    def test_existing_empty_database(self):
        path = self.root / 'empty.db'
        path.touch()
        db = DatabaseManager(path)
        self.assertEqual(db.fetch_one('SELECT count(*) FROM users')[0], 0)
        db.close()

    def test_legacy_schema_and_password_migration(self):
        path = self.root / 'legacy.db'
        con = sqlite3.connect(path)
        schema = (Path(__file__).parents[1]/'src/database/schema.sql').read_text()
        con.executescript(schema.replace('    active INTEGER NOT NULL DEFAULT 1,\n', ''))
        con.execute("INSERT INTO directions VALUES(1,'Север')")
        con.execute("INSERT INTO secrecy_levels VALUES(1,'Несекретно',1)")
        salt = 'a' * 32
        digest = hashlib.sha256(('legacy-password' + salt).encode()).hexdigest()
        con.execute('INSERT INTO users(login,password_hash,direction_id,secrecy_level_id,is_admin) VALUES(?,?,1,1,1)',
                    ('legacy', digest + '$' + salt))
        con.commit(); con.close()
        db = DatabaseManager(path)
        self.assertTrue(LoginManager(db).login('legacy', 'legacy-password'))
        self.assertTrue(db.fetch_one('SELECT password_hash FROM users')[0].startswith('pbkdf2_sha256:'))
        db.close()

    def test_default_password_absent_and_bootstrap_once(self):
        self.assertFalse(LoginManager(self.db).login('admin_admin', '12345678'))
        with self.assertRaises(ValueError):
            self.db.bootstrap_admin('another-password')

    def test_failed_login_clears_session(self):
        self.assertFalse(self.manager.login('missing', 'incorrect'))
        self.assertIsNone(self.manager.current_user)

    def test_lock_persists_and_expires(self):
        for _ in range(3):
            self.assertFalse(self.manager.login('admin_admin', 'incorrect'))
        other = LoginManager(self.db)
        self.assertFalse(other.login('admin_admin', 'admin-password'))
        self.db.execute('UPDATE login_attempts SET locked_until=1')
        self.assertTrue(other.login('admin_admin', 'admin-password'))
        self.assertGreater(self.db.fetch_one("SELECT count(*) FROM audit_logs WHERE action='LOGIN_FAILED'")[0], 0)

    def test_missing_targets_false(self):
        self.assertFalse(self.manager.reset_password(999, 'password1'))
        self.assertFalse(self.manager.update_user(999, direction_id=1))
        self.assertFalse(self.manager.delete_user(999))

    def test_deactivation_preserves_history_and_revokes_session(self):
        uid = self.user()
        other = LoginManager(self.db)
        other.login('worker', 'worker-password')
        self.db.execute('INSERT INTO user_sessions(user_id) VALUES(?)', (uid,))
        self.assertTrue(self.manager.delete_user(uid))
        self.assertIsNone(other.current_user)
        self.assertFalse(other.login('worker', 'worker-password'))
        self.assertIsNone(self.db.fetch_one('SELECT * FROM user_sessions WHERE user_id=?', (uid,)))
        self.assertIsNotNone(self.db.fetch_one('SELECT * FROM audit_logs WHERE user_id=?', (uid,)))
        self.assertEqual(self.db.fetch_all('PRAGMA foreign_key_check'), [])

    def test_live_admin_revocation(self):
        uid = self.user(admin=True)
        other = LoginManager(self.db)
        other.login('worker', 'worker-password')
        self.assertTrue(self.manager.update_user(uid, is_admin=False))
        self.assertFalse(other.current_user.is_admin)
        self.assertFalse(other.reset_password(1, 'hacked-password'))

    def test_last_admin_cannot_be_demoted(self):
        self.assertFalse(self.manager.update_user(1, is_admin=False))
        self.assertFalse(self.manager.delete_user(1))

    def test_change_password_requires_own_session(self):
        uid = self.user()
        self.assertFalse(self.manager.change_password(uid, 'worker-password', 'new-password'))
        self.assertTrue(self.manager.change_password(1, 'admin-password', 'new-password'))
        self.assertTrue(self.manager.login('admin_admin', 'new-password'))

    def test_denied_delete_does_not_touch_file(self):
        directory, ops = self.directory()
        path = self.file(directory, direction=2)
        with self.assertRaises(PermissionError):
            ops.delete_file(path)
        self.assertTrue(path.exists())

    def test_delete_removes_metadata(self):
        directory, ops = self.directory()
        path = self.file(directory)
        self.assertTrue(ops.delete_file(path))
        self.assertFalse(path.exists())
        self.assertIsNone(self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(path),)))

    def test_delete_os_failure_rolls_back_metadata(self):
        directory, ops = self.directory()
        path = self.file(directory)
        with patch('file_manager.file_ops.os.rename', side_effect=OSError('test')):
            with self.assertRaises(OSError):
                ops.delete_file(path)
        self.assertTrue(path.exists())
        self.assertIsNotNone(self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(path),)))

    def test_directory_inherits_metadata(self):
        directory, ops = self.directory()
        child = directory/'child'
        ops.create_directory(child)
        meta = self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(child),))
        self.assertEqual((meta['direction_id'], meta['secrecy_level_id'], meta['is_directory']), (1, 1, 1))

    def test_list_filters_inaccessible_entries(self):
        directory, ops = self.directory()
        self.file(directory, 'visible.txt')
        self.file(directory, 'hidden.txt', direction=2)
        (directory/'unregistered.txt').touch()
        self.assertEqual(ops.list_directory(directory), ['visible.txt'])

    def test_read_and_write_text_are_audited(self):
        directory, ops = self.directory()
        path = self.file(directory)
        self.assertEqual(ops.read_text(path), 'original')
        self.assertTrue(ops.write_text(path, 'updated'))
        self.assertEqual(path.read_text(), 'updated')
        actions = [r['action'] for r in self.db.fetch_all(
            "SELECT action FROM audit_logs WHERE user_id=1 AND action IN ('FILE_OPEN','FILE_SAVE') ORDER BY id")]
        self.assertEqual(actions[-2:], ['FILE_OPEN', 'FILE_SAVE'])

    def test_create_file_inherits_parent_metadata(self):
        directory, ops = self.directory()
        path = directory / 'created.txt'
        self.assertTrue(ops.create_text_file(path, 'hello'))
        self.assertEqual(path.read_text(), 'hello')
        meta = self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(path),))
        self.assertEqual((meta['direction_id'], meta['secrecy_level_id'], meta['owner_id'], meta['is_directory']),
                         (1, 1, 1, 0))
        self.assertIsNotNone(self.db.fetch_one(
            "SELECT 1 FROM audit_logs WHERE user_id=1 AND action='FILE_CREATE' AND details=?",
            (canonical_path(path),)))

    def test_create_file_never_overwrites_existing_unregistered_file(self):
        directory, ops = self.directory()
        path = directory / 'outside.txt'
        path.write_text('outside')
        with self.assertRaises(FileExistsError):
            ops.create_text_file(path, 'replacement')
        self.assertEqual(path.read_text(), 'outside')
        self.assertIsNone(self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(path),)))

    def test_create_file_write_failure_cleans_partial_file_and_metadata(self):
        directory, ops = self.directory()
        path = directory / 'broken.txt'
        with patch('file_manager.file_ops.os.fsync', side_effect=OSError('test')):
            with self.assertRaises(OSError):
                ops.create_text_file(path, 'partial')
        self.assertFalse(path.exists())
        self.assertIsNone(self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(path),)))

    def test_denied_write_does_not_touch_file(self):
        directory, ops = self.directory()
        path = self.file(directory, direction=2)
        with self.assertRaises(PermissionError):
            ops.write_text(path, 'changed')
        self.assertEqual(path.read_text(), 'original')

    def test_write_replace_failure_preserves_original_and_cleans_temp(self):
        directory, ops = self.directory()
        path = self.file(directory)
        with patch('file_manager.file_ops.os.replace', side_effect=OSError('test')):
            with self.assertRaises(OSError):
                ops.write_text(path, 'changed')
        self.assertEqual(path.read_text(), 'original')
        self.assertEqual(list(directory.glob('.pending-save-*')), [])
        self.assertIsNone(self.db.fetch_one(
            "SELECT 1 FROM audit_logs WHERE user_id=1 AND action='FILE_SAVE' AND details=?",
            (canonical_path(path),)))

    def test_read_limit_rejects_large_file_without_open_audit(self):
        directory, ops = self.directory()
        path = self.file(directory)
        with self.assertRaises(ValueError):
            ops.read_bytes(path, max_bytes=3)
        self.assertIsNone(self.db.fetch_one(
            "SELECT 1 FROM audit_logs WHERE user_id=1 AND action='FILE_OPEN' AND details=?",
            (canonical_path(path),)))

    def test_rename_and_no_overwrite(self):
        directory, ops = self.directory()
        source = self.file(directory)
        target = directory/'new.txt'
        ops.rename_file(source, target)
        self.assertTrue(target.exists())
        self.assertIsNotNone(self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(target),)))
        source.write_text('keep')
        with self.assertRaises(FileExistsError):
            ops.rename_file(target, source)
        self.assertEqual(source.read_text(), 'keep')
        self.assertTrue(target.exists())
        self.assertIsNotNone(self.db.fetch_one('SELECT * FROM files_metadata WHERE path=?', (canonical_path(target),)))

    def test_symlink_rejected(self):
        directory, ops = self.directory()
        path = self.file(directory)
        link = directory/'alias'
        try:
            link.symlink_to(path)
        except OSError:
            self.skipTest('Symlinks unavailable')
        with self.assertRaises(PermissionError):
            ops.delete_file(link)
        self.assertTrue(path.exists())

    def test_levels_use_order_not_id(self):
        directory, ops = self.directory()
        path = self.file(directory)
        self.db.execute("INSERT INTO secrecy_levels(id,name,level_order) VALUES(100,'Custom low',0)")
        self.db.execute('UPDATE files_metadata SET secrecy_level_id=100 WHERE path=?', (canonical_path(path),))
        self.assertTrue(PermissionManager(self.db).can_access_file(self.manager.current_user, path))

    def test_password_round_trip(self):
        digest, salt = PasswordUtils.hash_password('example-password')
        self.assertTrue(PasswordUtils.verify_password('example-password', digest, salt))
        self.assertFalse(PasswordUtils.verify_password('wrong', digest, salt))
        self.assertFalse(PasswordUtils.verify_password('wrong', 'pbkdf2_sha256:bad:hash', salt))


if __name__ == '__main__':
    unittest.main()

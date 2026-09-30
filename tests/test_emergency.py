import json
import os
import string
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_TEMP = tempfile.TemporaryDirectory()
os.environ.setdefault('SECURE_SHELL_DATA_DIR', _TEMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager
from auth.emergency import EmergencyManager, decrypt_vault, generate_password


class EmergencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = DatabaseManager(self.root/'db.sqlite')
        self.db.bootstrap_admin('admin-password')
        self.admin = LoginManager(self.db)
        self.assertTrue(self.admin.login('admin_admin', 'admin-password'))
        self.assertTrue(self.admin.register_user('worker', 'worker-password', 1, 1))
        self.other_db = DatabaseManager(self.root/'db.sqlite')
        self.worker = LoginManager(self.other_db)
        self.assertTrue(self.worker.login('worker', 'worker-password'))
        self.emergency = EmergencyManager(self.admin)
        self.path = self.root/'recovery.json'
        self.phrase = 'independent recovery phrase'

    def tearDown(self):
        self.other_db.close()
        self.db.close()
        self.tmp.cleanup()

    def prepare(self):
        self.emergency.prepare(self.path, self.phrase)
        return decrypt_vault(self.path, self.phrase)

    def test_random_password_format(self):
        values = {generate_password() for _ in range(100)}
        self.assertEqual(len(values), 100)
        for value in values:
            self.assertEqual(len(value), 50)
            self.assertTrue(all(c in string.digits + string.punctuation for c in value))
            self.assertTrue(any(c in string.digits for c in value))
            self.assertTrue(any(c in string.punctuation for c in value))

    def test_encrypted_file_and_bad_phrase(self):
        clear = self.prepare()
        for account in clear['accounts']:
            self.assertNotIn(account['password'], self.path.read_text())
        with self.assertRaises(ValueError):
            decrypt_vault(self.path, 'incorrect phrase')
        envelope = json.loads(self.path.read_text())
        envelope['ciphertext'] = 'AAAA'
        self.path.write_text(json.dumps(envelope))
        with self.assertRaises(ValueError):
            decrypt_vault(self.path, self.phrase)

    def test_all_sessions_and_passwords_revoked_across_connections(self):
        clear = self.prepare()
        second_admin = LoginManager(self.other_db)
        self.assertTrue(second_admin.login('admin_admin', 'admin-password'))
        self.worker.audit_logger.log_execution(2, '/example/tool.exe')
        self.worker.audit_logger.log_transfer(2, '/example/source.txt', '/destination/target.txt')
        with patch('auth.emergency.DATA_DIR', self.root):
            result = self.emergency.activate()
        self.assertIsNone(self.admin.current_user)
        self.assertIsNone(second_admin.current_user)
        self.assertIsNone(self.worker.current_user)
        self.assertFalse(self.worker.login('worker', 'worker-password'))
        report = json.loads(Path(result['report_path']).read_text())
        self.assertEqual(len(report['sessions_before_revocation']), 3)
        self.assertTrue(all(r['connected_duration_seconds'] >= 0 for r in report['sessions_before_revocation']))
        self.assertTrue(any(r['executable_path'] == '/example/tool.exe' for r in report['activities']))
        self.assertTrue(any(r['transfer_destination'] == '/destination/target.txt' for r in report['activities']))
        for account in clear['accounts']:
            self.assertNotIn(account['password'], json.dumps(report))
            self.assertTrue(self.worker.login(account['login'], account['password']))
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM emergency_credentials')[0], 0)
        self.assertFalse(EmergencyManager(self.worker).status()[0])

    def test_non_admin_cannot_prepare_or_activate(self):
        with self.assertRaises(PermissionError):
            EmergencyManager(self.worker).prepare(self.path, self.phrase)
        self.prepare()
        with self.assertRaises(PermissionError):
            EmergencyManager(self.worker).activate()
        self.assertIsNotNone(self.admin.current_user)

    def test_roster_change_requires_new_batch(self):
        self.prepare()
        self.admin.register_user('another', 'user-password', 1, 1)
        self.assertFalse(self.emergency.status()[0])
        with self.assertRaises(ValueError):
            self.emergency.activate()
        self.assertIsNotNone(self.worker.current_user)

    def test_prepare_file_failure_does_not_arm(self):
        with self.assertRaises(OSError):
            self.emergency.prepare(self.root/'missing'/'recovery.json', self.phrase)
        self.assertFalse(self.emergency.status()[0])

    def test_existing_file_never_overwritten(self):
        self.path.write_text('keep')
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(self.path.read_text(), 'keep')
        self.assertFalse(self.emergency.status()[0])

    def test_report_failure_rolls_back_passwords_and_revocation(self):
        self.prepare()
        self.db.execute("CREATE TRIGGER fail_incident BEFORE INSERT ON emergency_reports BEGIN SELECT RAISE(ABORT, 'test'); END")
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.emergency.activate()
        self.assertIsNotNone(self.admin.current_user)
        self.assertIsNotNone(self.worker.current_user)
        self.assertTrue(self.emergency.status()[0])
        self.assertTrue(self.worker.login('worker', 'worker-password'))

    def test_export_failure_preserves_database_report(self):
        self.prepare()
        with patch('auth.emergency._write_new', side_effect=OSError('full disk')):
            result = self.emergency.activate()
        self.assertIsNone(result['report_path'])
        self.assertIsNotNone(self.db.fetch_one('SELECT report_json FROM emergency_reports WHERE id=?', (result['incident_id'],)))
        self.assertIsNone(self.worker.current_user)

    def test_consumed_batch_cannot_be_reused(self):
        clear = self.prepare()
        with patch('auth.emergency.DATA_DIR', self.root):
            self.emergency.activate()
        password = next(a['password'] for a in clear['accounts'] if a['login'] == 'admin_admin')
        self.assertTrue(self.admin.login('admin_admin', password))
        with self.assertRaises(ValueError):
            self.emergency.activate()

    def test_revoked_admin_cannot_activate(self):
        self.prepare()
        self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
        with self.assertRaises(PermissionError):
            self.emergency.activate()


if __name__ == '__main__':
    unittest.main()

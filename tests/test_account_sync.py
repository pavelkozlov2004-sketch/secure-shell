"""Transactional account revisions, credentialless LAN replicas and restoration."""
import copy
import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('VUAL_DATA_DIR', _TMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from auth.login_manager import LoginManager
from database.db_manager import DatabaseManager


class AccountSyncTests(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.addCleanup(self.db.close)
        self.db.bootstrap_admin('admin-password')
        self.admin = LoginManager(self.db)
        self.assertTrue(self.admin.login('admin_admin', 'admin-password'))
        self.assertTrue(self.admin.register_user('worker', 'worker-password', 1, 1))
        self.worker_id = self.db.fetch_one("SELECT id FROM users WHERE login='worker'")[0]

    def snapshot(self, revision=10):
        return {
            'revision': revision, 'changed': True, 'server_id': self.db.server_identity(),
            'users': self.db.fetch_all_dict('SELECT id,login,direction_id,secrecy_level_id,'
                'is_admin,active,network_blocked,created_at,updated_at FROM users ORDER BY id'),
            'directions': self.db.fetch_all_dict('SELECT id,name FROM directions ORDER BY id'),
            'secrecy_levels': self.db.fetch_all_dict('SELECT id,name,level_order FROM secrecy_levels ORDER BY id'),
        }

    def test_revision_changes_once_per_actual_account_update(self):
        revision = self.db.account_revision()
        operations = (
            lambda: self.admin.register_user('extra', 'worker-password', 1, 1),
            lambda: self.admin.reset_password(self.worker_id, 'replacement-password'),
            lambda: self.admin.change_password(1, 'admin-password', 'replacement-admin-password'),
            lambda: self.admin.update_user(self.worker_id, direction_id=2, secrecy_level_id=2),
            lambda: self.admin.delete_user(self.worker_id),
            lambda: self.admin.reactivate_user(self.worker_id),
        )
        for operation in operations:
            self.assertTrue(operation())
            revision += 1
            self.assertEqual(self.db.account_revision(), revision)
        self.db.execute('UPDATE users SET network_blocked=1 WHERE id=?', (self.worker_id,))
        revision += 1
        self.assertEqual(self.db.account_revision(), revision)
        self.db.execute('UPDATE users SET network_blocked=1,updated_at=CURRENT_TIMESTAMP WHERE id=?',
                        (self.worker_id,))
        self.assertEqual(self.db.account_revision(), revision)
        self.assertFalse(self.admin.register_user('worker', 'valid-password', 1, 1))
        self.assertEqual(self.db.account_revision(), revision)

    def test_revision_ignores_sessions_audit_and_timestamp_only_updates(self):
        revision = self.db.account_revision()
        self.assertIsNotNone(self.admin.current_user)
        self.admin.audit_logger.log_action(1, 'TEST_HEARTBEAT')
        self.db.execute('UPDATE users SET updated_at=? WHERE id=1', ('2099-01-01 00:00:00',))
        self.db.execute('UPDATE live_sessions SET last_seen_at=123 WHERE id=?', (self.admin._session_id,))
        worker = LoginManager(self.db)
        self.assertTrue(worker.login('worker', 'worker-password'))
        worker.logout()
        self.assertEqual(self.db.account_revision(), revision)

    def test_revision_rolls_back_with_failed_transaction(self):
        revision = self.db.account_revision()
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.get_cursor() as cursor:
                cursor.execute('BEGIN IMMEDIATE')
                cursor.execute('UPDATE users SET active=0 WHERE id=?', (self.worker_id,))
                cursor.execute('INSERT INTO users(login,password_hash,direction_id,secrecy_level_id) '
                               "VALUES ('broken','hash',999,1)")
        self.assertEqual(self.db.account_revision(), revision)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (self.worker_id,))[0], 1)

    def test_snapshot_has_no_password_hashes_and_disables_local_authentication(self):
        snapshot = self.snapshot()
        self.assertTrue(self.db.apply_account_snapshot(snapshot))
        hashes = self.db.fetch_all('SELECT password_hash FROM users')
        self.assertEqual({row[0] for row in hashes}, {'!remote-authentication-only!'})
        self.assertFalse(LoginManager(self.db).login('worker', 'worker-password'))
        self.assertEqual(self.db.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')[0], 10)

    def test_validation_finishes_before_transaction_and_preserves_database(self):
        invalids = []
        for mutate in (
            lambda s: s['users'][-1].update(direction_id=999),
            lambda s: s['users'][-1].update(id=0),
            lambda s: s['users'][-1].update(id=True),
            lambda s: s['users'][-1].update(active=2),
            lambda s: s['users'][-1].update(password_hash='never-send-this'),
            lambda s: s['users'].append(dict(s['users'][0])),
            lambda s: s['users'][-1].update(login=s['users'][0]['login']),
            lambda s: s['directions'][-1].update(name=s['directions'][0]['name']),
            lambda s: s.update(revision=-1),
            lambda s: s.update(revision=True),
            lambda s: s.update(changed=1),
            lambda s: s.update(server_id='invalid-server'),
            lambda s: s['users'][-1].update(login='x' * 4097),
            lambda s: s['users'][-1].update(login='bad\x00login'),
        ):
            item = self.snapshot()
            mutate(item)
            invalids.append(item)
        before = self.db.fetch_all_dict('SELECT * FROM users')
        revision = self.db.account_revision()
        for item in invalids:
            statements = []
            self.db.connection.set_trace_callback(statements.append)
            with self.assertRaises(ValueError):
                self.db.apply_account_snapshot(item)
            self.db.connection.set_trace_callback(None)
            self.assertFalse(any(sql.startswith('BEGIN') for sql in statements))
            self.assertEqual(self.db.fetch_all_dict('SELECT * FROM users'), before)
            self.assertEqual(self.db.account_revision(), revision)
            self.assertEqual(self.db.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')[0], -1)

    def test_missing_owners_and_local_classification_remain_linked(self):
        self.db.execute("INSERT INTO directions(id,name) VALUES (42,'Локальное направление')")
        self.db.execute("INSERT INTO secrecy_levels(id,name,level_order) VALUES (42,'Локальный уровень',42)")
        self.db.execute('INSERT INTO documents_store.documents(title,content,owner_id) VALUES (?,?,?)',
                        ('Исходник', 'исходные данные', self.worker_id))
        self.db.execute('INSERT INTO tables_store.converted_tables(title,report_json,owner_id,'
                        'direction_id,secrecy_level_id,source_document_id,source_revision) VALUES (?,?,?,?,?,?,?)',
                        ('Таблица', '{}', self.worker_id, 42, 42, 1, 1))
        snapshot = self.snapshot()
        snapshot['users'] = [item for item in snapshot['users'] if item['id'] != self.worker_id]
        snapshot['directions'] = [item for item in snapshot['directions'] if item['id'] != 42]
        snapshot['secrecy_levels'] = [item for item in snapshot['secrecy_levels'] if item['id'] != 42]
        self.assertTrue(self.db.apply_account_snapshot(snapshot))
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (self.worker_id,))[0], 0)
        self.assertEqual(self.db.fetch_one('SELECT owner_id FROM documents_store.documents')[0], self.worker_id)
        self.assertEqual(tuple(self.db.fetch_one('SELECT owner_id,direction_id,secrecy_level_id '
                                                 'FROM tables_store.converted_tables')), (self.worker_id, 42, 42))
        self.assertEqual(self.db.fetch_one('SELECT name FROM directions WHERE id=42')[0], 'Локальное направление')
        self.db._check_database_links()

    def test_omitted_user_login_can_be_reused_without_losing_owner(self):
        self.db.execute('INSERT INTO documents_store.documents(title,content,owner_id) VALUES (?,?,?)',
                        ('Исходник', 'text', self.worker_id))
        snapshot = self.snapshot()
        worker = next(item for item in snapshot['users'] if item['id'] == self.worker_id)
        worker['id'] = 99
        self.assertTrue(self.db.apply_account_snapshot(snapshot))
        self.assertEqual(self.db.fetch_one("SELECT id FROM users WHERE login='worker'")[0], 99)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (self.worker_id,))[0], 0)
        self.assertEqual(self.db.fetch_one('SELECT owner_id FROM documents_store.documents')[0], self.worker_id)

    def test_changed_snapshot_revokes_disabled_sessions_and_applies_role_revocation(self):
        worker = LoginManager(self.db)
        self.assertTrue(worker.login('worker', 'worker-password'))
        self.db.execute('INSERT INTO user_sessions(user_id,last_directory) VALUES (?,?)', (self.worker_id, '/saved'))
        snapshot = self.snapshot()
        snapshot['users'][0]['is_admin'] = 0
        snapshot['users'][1]['network_blocked'] = 1
        self.assertTrue(self.db.apply_account_snapshot(snapshot))
        self.assertIsNone(worker.current_user)
        self.assertFalse(self.admin.current_user.is_admin)
        self.assertFalse(self.admin.register_user('forbidden', 'valid-password', 1, 1))
        self.assertIsNone(self.db.fetch_one('SELECT user_id FROM user_sessions WHERE user_id=?', (self.worker_id,)))

    def test_stale_and_duplicate_snapshots_cannot_restore_revoked_account(self):
        old = self.snapshot(revision=5)
        new = copy.deepcopy(old)
        new['revision'] = 6
        new['users'][1]['active'] = 0
        self.assertTrue(self.db.apply_account_snapshot(new))
        revision = self.db.account_revision()
        self.assertFalse(self.db.apply_account_snapshot(old))
        old['revision'] = 6
        self.assertFalse(self.db.apply_account_snapshot(old))
        self.assertEqual(self.db.account_revision(), revision)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (self.worker_id,))[0], 0)
        self.assertFalse(self.db.apply_account_snapshot({
            'revision': 6, 'changed': False, 'server_id': self.db.server_identity()}))

    def test_server_identity_mismatch_cannot_replace_cached_owners_or_restore_users(self):
        snapshot = self.snapshot(revision=100)
        self.assertTrue(self.db.apply_account_snapshot(snapshot))
        before = self.db.fetch_all_dict('SELECT * FROM users')
        replacement = self.snapshot(revision=1)
        replacement['server_id'] = str(uuid.uuid4())
        for changed in (True, False):
            reply = replacement if changed else {
                'revision': 1, 'changed': False, 'server_id': replacement['server_id']}
            with self.assertRaises(ValueError):
                self.db.apply_account_snapshot(reply)
        self.assertEqual(self.db.fetch_all_dict('SELECT * FROM users'), before)
        self.assertEqual(self.db.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')[0], 100)

    def test_snapshot_updates_are_atomic_on_sql_failure(self):
        before = self.db.fetch_all_dict('SELECT * FROM users')
        revision = self.db.account_revision()
        self.db.execute("CREATE TRIGGER reject_remote_user BEFORE UPDATE ON users "
                        "WHEN NEW.password_hash='!remote-authentication-only!' "
                        "BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END")
        snapshot = self.snapshot()
        snapshot['directions'][0]['name'] = 'Новое направление'
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.apply_account_snapshot(snapshot)
        self.assertEqual(self.db.fetch_all_dict('SELECT * FROM users'), before)
        self.assertNotEqual(self.db.fetch_one('SELECT name FROM directions WHERE id=1')[0], 'Новое направление')
        self.assertEqual(self.db.account_revision(), revision)
        self.assertEqual(self.db.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1')[0], -1)

    def test_snapshot_swapped_logins_are_applied_without_changing_ids(self):
        snapshot = self.snapshot()
        snapshot['users'][0]['login'], snapshot['users'][1]['login'] = (
            snapshot['users'][1]['login'], snapshot['users'][0]['login'])
        self.assertTrue(self.db.apply_account_snapshot(snapshot))
        self.assertEqual(self.db.fetch_one("SELECT id FROM users WHERE login='worker'")[0], 1)
        self.assertEqual(self.db.fetch_one("SELECT id FROM users WHERE login='admin_admin'")[0], self.worker_id)

    def test_reactivation_preserves_credentials_and_requires_new_login(self):
        worker = LoginManager(self.db)
        self.assertTrue(worker.login('worker', 'worker-password'))
        old_session = worker._session_id
        password_hash = self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (self.worker_id,))[0]
        self.assertTrue(self.admin.delete_user(self.worker_id))
        # Model a stale imported session and a failed-login lock that restoration must clear.
        self.db.execute('UPDATE live_sessions SET ended_at=NULL WHERE id=?', (old_session,))
        self.db.execute('UPDATE users SET network_blocked=1 WHERE id=?', (self.worker_id,))
        self.db.execute('INSERT INTO login_attempts(login,failures,locked_until) VALUES (?,?,?)',
                        ('worker', 5, 9999999999))
        self.assertTrue(self.admin.reactivate_user(self.worker_id))
        self.assertEqual(tuple(self.db.fetch_one('SELECT active,network_blocked FROM users WHERE id=?',
                                                 (self.worker_id,))), (1, 0))
        self.assertEqual(self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (self.worker_id,))[0], password_hash)
        self.assertIsNone(worker.current_user)
        self.assertIsNone(self.db.fetch_one("SELECT login FROM login_attempts WHERE login='worker'"))
        self.assertTrue(worker.login('worker', 'worker-password'))
        self.assertNotEqual(worker._session_id, old_session)
        self.assertEqual(self.db.fetch_one("SELECT count(*) FROM audit_logs WHERE action='REACTIVATE_USER'")[0], 1)
        self.assertFalse(self.admin.reactivate_user(self.worker_id))

    def test_reactivation_rechecks_admin_and_does_not_grant_access_to_worker(self):
        self.assertTrue(self.admin.delete_user(self.worker_id))
        unauthenticated = LoginManager(self.db)
        self.assertFalse(unauthenticated.reactivate_user(self.worker_id))
        original = self.db.get_cursor

        @contextmanager
        def revoke_before_begin():
            self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
            with original() as cursor:
                yield cursor

        with patch.object(self.db, 'get_cursor', revoke_before_begin):
            self.assertFalse(self.admin.reactivate_user(self.worker_id))
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (self.worker_id,))[0], 0)

    def test_reactivation_rolls_back_when_audit_cannot_be_saved(self):
        self.assertTrue(self.admin.delete_user(self.worker_id))
        revision = self.db.account_revision()
        self.db.execute("CREATE TRIGGER reject_restore_audit BEFORE INSERT ON audit_logs "
                        "WHEN NEW.action='REACTIVATE_USER' BEGIN SELECT RAISE(ABORT,'audit failed'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.admin.reactivate_user(self.worker_id)
        self.assertEqual(self.db.account_revision(), revision)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (self.worker_id,))[0], 0)


class AccountRevisionPersistenceTests(unittest.TestCase):
    def test_existing_database_migrates_and_revision_is_shared_between_connections(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'users.db'
            original = sqlite3.connect(path)
            original.executescript('''
                CREATE TABLE directions(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE);
                CREATE TABLE secrecy_levels(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,level_order INTEGER NOT NULL);
                CREATE TABLE users(id INTEGER PRIMARY KEY,login TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,
                    direction_id INTEGER NOT NULL,secrecy_level_id INTEGER NOT NULL,is_admin INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            ''')
            original.close()
            first = DatabaseManager(path)
            try:
                first.bootstrap_admin('admin-password')
                revision = first.account_revision()
                second = DatabaseManager(path)
                try:
                    self.assertEqual(second.account_revision(), revision)
                    self.assertEqual(second.server_identity(), first.server_identity())
                    second.execute('UPDATE users SET network_blocked=1 WHERE id=1')
                    self.assertEqual(first.account_revision(), revision + 1)
                    self.assertIsNotNone(second.fetch_one('SELECT revision FROM lan_sync_state WHERE id=1'))
                finally:
                    second.close()
            finally:
                first.close()


if __name__ == '__main__':
    unittest.main()

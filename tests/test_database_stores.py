"""Persistence, migration and integrity checks for the three linked stores."""
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('SECURE_SHELL_DATA_DIR', _TMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from auth.login_manager import LoginManager
from database import db_manager
from database.db_manager import DatabaseManager


class DatabaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'account-data.db'
        self.db = DatabaseManager(self.path)
        self.addCleanup(lambda: self.db.close())
        self.db.execute(
            'INSERT INTO users(login,password_hash,direction_id,secrecy_level_id,is_admin) '
            "VALUES('owner','test$test',1,1,1)")

    def document(self, db=None, owner_id=1, revision=1):
        db = db or self.db
        return db.execute(
            'INSERT INTO documents_store.documents(title,content,owner_id,revision) VALUES(?,?,?,?)',
            ('Original document', 'One;Two\n1;2', owner_id, revision)).lastrowid

    def table(self, db=None, **changes):
        db = db or self.db
        values = dict(title='Converted table', report_json='{}', owner_id=1,
                      direction_id=2, secrecy_level_id=2,
                      source_document_id=None, source_revision=None)
        values.update(changes)
        return db.execute(
            'INSERT INTO tables_store.converted_tables '
            '(' + ','.join(values) + ') VALUES (' + ','.join('?' for _ in values) + ')',
            tuple(values.values())).lastrowid

    @staticmethod
    def schema_tables(path):
        with closing(sqlite3.connect(path)) as connection:
            return {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}

    def test_three_physical_stores_keep_their_data_after_restart(self):
        document_id = self.document()
        table_id = self.table(source_document_id=document_id, source_revision=1)
        attached = {row['name']: Path(row['file']) for row in self.db.fetch_all('PRAGMA database_list')}
        self.assertEqual(attached['main'], self.path)
        self.assertEqual(attached['tables_store'], self.root / 'tables.db')
        self.assertEqual(attached['documents_store'], self.root / 'documents.db')
        self.db.close()

        user_tables = self.schema_tables(self.path)
        self.assertIn('users', user_tables)
        self.assertIn('audit_logs', user_tables)
        self.assertNotIn('documents', user_tables)
        self.assertNotIn('converted_tables', user_tables)
        table_tables = self.schema_tables(self.root / 'tables.db')
        self.assertIn('converted_tables', table_tables)
        self.assertNotIn('users', table_tables)
        self.assertNotIn('documents', table_tables)
        document_tables = self.schema_tables(self.root / 'documents.db')
        self.assertIn('documents', document_tables)
        self.assertNotIn('users', document_tables)
        self.assertNotIn('converted_tables', document_tables)

        self.db = DatabaseManager(self.path)
        self.assertEqual(self.db.fetch_one('SELECT login FROM users WHERE id=1')[0], 'owner')
        self.assertEqual(self.db.fetch_one(
            'SELECT content FROM documents_store.documents WHERE id=?', (document_id,))[0], 'One;Two\n1;2')
        saved = self.db.fetch_one('SELECT * FROM tables_store.converted_tables WHERE id=?', (table_id,))
        self.assertEqual((saved['owner_id'], saved['source_document_id'], saved['source_revision']),
                         (1, document_id, 1))

    def test_memory_managers_use_three_independent_ephemeral_stores(self):
        first = DatabaseManager(':memory:')
        second = DatabaseManager(':memory:')
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        databases = {row['name']: row['file'] for row in first.fetch_all('PRAGMA database_list')}
        self.assertEqual({name: databases[name] for name in ('main', 'tables_store', 'documents_store')},
                         {'main': '', 'tables_store': '', 'documents_store': ''})
        first.execute("INSERT INTO users(login,password_hash,direction_id,secrecy_level_id) VALUES('memory','x',1,1)")
        self.document(first)
        self.table(first)
        self.assertEqual(second.fetch_one('SELECT count(*) FROM users')[0], 0)
        self.assertEqual(second.fetch_one('SELECT count(*) FROM documents_store.documents')[0], 0)
        self.assertEqual(second.fetch_one('SELECT count(*) FROM tables_store.converted_tables')[0], 0)

    def legacy_database(self, directory, keep_wal=False):
        directory.mkdir()
        legacy = directory / 'secure_shell.db'
        connection = sqlite3.connect(legacy)
        self.addCleanup(connection.close)
        if keep_wal:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
        schema = (Path(__file__).parents[1] / 'src/database/schema.sql').read_text(encoding='utf-8')
        connection.executescript(schema.replace('    active INTEGER NOT NULL DEFAULT 1,\n', ''))
        connection.execute("INSERT INTO directions(id,name) VALUES(1,'Север')")
        connection.execute("INSERT INTO secrecy_levels(id,name,level_order) VALUES(1,'Несекретно',1)")
        salt = 'a' * 32
        digest = hashlib.sha256(('legacy-password' + salt).encode()).hexdigest()
        password_hash = digest + '$' + salt
        connection.execute(
            'INSERT INTO users(login,password_hash,direction_id,secrecy_level_id,is_admin) VALUES(?,?,1,1,1)',
            ('legacy-admin', password_hash))
        connection.execute("INSERT INTO audit_logs(user_id,action,details) VALUES(1,'LEGACY_HISTORY','keep me')")
        connection.execute("INSERT INTO user_sessions(user_id,last_directory) VALUES(1,'/legacy-directory')")
        connection.execute("INSERT INTO login_attempts(login,failures,locked_until) VALUES('other-login',2,0)")
        connection.commit()
        return legacy, connection, password_hash

    def default_paths(self, directory):
        return patch.multiple(db_manager, DB_PATH=directory / 'users.db',
                              TABLES_DB_PATH=directory / 'tables.db',
                              DOCUMENTS_DB_PATH=directory / 'documents.db',
                              LEGACY_DB_PATH=directory / 'secure_shell.db')

    def test_default_migration_copies_wal_data_and_preserves_legacy_login_and_history(self):
        directory = self.root / 'migration'
        legacy, source, original_hash = self.legacy_database(directory, keep_wal=True)
        self.assertTrue(Path(str(legacy) + '-wal').exists())
        with self.default_paths(directory):
            migrated = DatabaseManager()
            self.addCleanup(migrated.close)
            self.assertTrue(LoginManager(migrated).login('legacy-admin', 'legacy-password'))
            self.assertEqual(migrated.fetch_one(
                "SELECT details FROM audit_logs WHERE action='LEGACY_HISTORY'")[0], 'keep me')
            self.assertEqual(migrated.fetch_one('SELECT last_directory FROM user_sessions WHERE user_id=1')[0],
                             '/legacy-directory')
            self.assertEqual(migrated.fetch_one(
                "SELECT failures FROM login_attempts WHERE login='other-login'")[0], 2)
            self.assertTrue(migrated.fetch_one('SELECT password_hash FROM users')[0].startswith('pbkdf2_sha256:'))
            self.assertTrue((directory / 'users.db').is_file())
            self.assertTrue((directory / 'tables.db').is_file())
            self.assertTrue((directory / 'documents.db').is_file())
        self.assertTrue(legacy.is_file())
        self.assertEqual(source.execute('SELECT password_hash FROM users').fetchone()[0], original_hash)
        self.assertEqual(source.execute('SELECT count(*) FROM audit_logs').fetchone()[0], 1)
        self.assertNotIn('active', {row[1] for row in source.execute('PRAGMA table_info(users)')})

    def test_explicit_custom_path_does_not_import_legacy_database(self):
        directory = self.root / 'custom'
        self.legacy_database(directory)
        with self.default_paths(directory):
            custom = DatabaseManager(directory / 'custom.db')
            self.addCleanup(custom.close)
            self.assertEqual(custom.fetch_one('SELECT count(*) FROM users')[0], 0)
            self.assertFalse((directory / 'users.db').exists())

    def test_existing_default_database_takes_priority_over_legacy_database(self):
        directory = self.root / 'existing'
        self.legacy_database(directory)
        with self.default_paths(directory):
            existing = DatabaseManager(directory / 'users.db')
            existing.execute("INSERT INTO users(login,password_hash,direction_id,secrecy_level_id) VALUES('current','x',1,1)")
            existing.close()
            default = DatabaseManager()
            self.addCleanup(default.close)
            self.assertEqual([row[0] for row in default.fetch_all('SELECT login FROM users')], ['current'])

    def test_invalid_document_and_table_references_are_rejected_on_insert(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.document(owner_id=999)
        document_id = self.document()
        invalid = (
            dict(owner_id=999), dict(direction_id=999), dict(secrecy_level_id=999),
            dict(source_document_id=999, source_revision=1),
            dict(source_document_id=document_id, source_revision=2),
            dict(source_document_id=document_id, source_revision=None),
            dict(source_document_id=None, source_revision=1),
            dict(source_document_id=document_id, source_revision=0),
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(sqlite3.IntegrityError):
                self.table(**values)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM tables_store.converted_tables')[0], 0)

    def test_invalid_reference_updates_preserve_the_previous_records(self):
        document_id = self.document()
        table_id = self.table(source_document_id=document_id, source_revision=1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('UPDATE documents_store.documents SET owner_id=999 WHERE id=?', (document_id,))
        for column, value in (('owner_id', 999), ('direction_id', 999), ('secrecy_level_id', 999),
                              ('source_document_id', 999), ('source_revision', 2)):
            with self.subTest(column=column), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f'UPDATE tables_store.converted_tables SET {column}=? WHERE id=?', (value, table_id))
        saved = self.db.fetch_one('SELECT * FROM tables_store.converted_tables WHERE id=?', (table_id,))
        self.assertEqual((saved['owner_id'], saved['direction_id'], saved['secrecy_level_id'],
                          saved['source_document_id'], saved['source_revision']), (1, 2, 2, document_id, 1))

    def test_referenced_entities_cannot_be_deleted_renumbered_or_replaced(self):
        document_id = self.document(revision=2)
        self.table(source_document_id=document_id, source_revision=2)
        mutations = (
            ('DELETE FROM users WHERE id=1', ()),
            ('UPDATE users SET id=100 WHERE id=1', ()),
            ('DELETE FROM directions WHERE id=2', ()),
            ('UPDATE directions SET id=100 WHERE id=2', ()),
            ('DELETE FROM secrecy_levels WHERE id=2', ()),
            ('UPDATE secrecy_levels SET id=100 WHERE id=2', ()),
            ('DELETE FROM documents_store.documents WHERE id=?', (document_id,)),
            ('UPDATE documents_store.documents SET id=100 WHERE id=?', (document_id,)),
            ('UPDATE documents_store.documents SET revision=1 WHERE id=?', (document_id,)),
            ('INSERT OR REPLACE INTO documents_store.documents(id,title,content,owner_id) VALUES(?,?,?,?)',
             (document_id, 'Replacement', 'content', 1)),
        )
        for query, params in mutations:
            with self.subTest(query=query), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(query, params)
        self.assertEqual(self.db.fetch_one('SELECT revision FROM documents_store.documents WHERE id=?',
                                          (document_id,))[0], 2)

    def test_failed_transaction_rolls_back_changes_in_all_three_stores(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.get_cursor() as cursor:
                cursor.execute('BEGIN IMMEDIATE')
                cursor.execute("UPDATE users SET login='temporary' WHERE id=1")
                cursor.execute(
                    "INSERT INTO documents_store.documents(title,content,owner_id) VALUES('Temporary','content',1)")
                document_id = cursor.lastrowid
                cursor.execute(
                    'INSERT INTO tables_store.converted_tables '
                    '(title,report_json,owner_id,direction_id,secrecy_level_id,source_document_id,source_revision) '
                    "VALUES('Temporary','{}',1,1,1,?,1)", (document_id,))
                cursor.execute('UPDATE tables_store.converted_tables SET owner_id=999')
        self.db.close()
        self.db = DatabaseManager(self.path)
        self.assertEqual(self.db.fetch_one('SELECT login FROM users WHERE id=1')[0], 'owner')
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM documents_store.documents')[0], 0)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM tables_store.converted_tables')[0], 0)

    def test_each_connection_installs_cross_database_constraints(self):
        document_id = self.document()
        self.table(source_document_id=document_id, source_revision=1)
        other = DatabaseManager(self.path)
        self.addCleanup(other.close)
        with self.assertRaises(sqlite3.IntegrityError):
            self.document(other, owner_id=999)
        with self.assertRaises(sqlite3.IntegrityError):
            self.table(other, direction_id=999)
        with self.assertRaises(sqlite3.IntegrityError):
            other.execute('DELETE FROM documents_store.documents WHERE id=?', (document_id,))

    def test_startup_rejects_orphan_references_created_outside_the_application(self):
        document_id = self.document()
        table_id = self.table(source_document_id=document_id, source_revision=1)
        mutations = (
            ('documents.db', 'documents', document_id, 'owner_id', 1),
            ('tables.db', 'converted_tables', table_id, 'owner_id', 1),
            ('tables.db', 'converted_tables', table_id, 'direction_id', 2),
            ('tables.db', 'converted_tables', table_id, 'secrecy_level_id', 2),
            ('tables.db', 'converted_tables', table_id, 'source_document_id', document_id),
            ('tables.db', 'converted_tables', table_id, 'source_revision', 1),
        )
        self.db.close()
        for filename, table, record_id, column, original in mutations:
            with self.subTest(column=column):
                with closing(sqlite3.connect(self.root / filename)) as raw:
                    raw.execute(f'UPDATE {table} SET {column}=999 WHERE id=?', (record_id,))
                    raw.commit()
                with self.assertRaises(RuntimeError):
                    DatabaseManager(self.path)
                with closing(sqlite3.connect(self.root / filename)) as raw:
                    raw.execute(f'UPDATE {table} SET {column}=? WHERE id=?', (original, record_id))
                    raw.commit()
        self.db = DatabaseManager(self.path)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM tables_store.converted_tables')[0], 1)


if __name__ == '__main__':
    unittest.main()

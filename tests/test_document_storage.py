"""Headless storage tests: live authorization, persisted links, and conversion."""
import copy
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.TemporaryDirectory()
os.environ['SECURE_SHELL_DATA_DIR'] = _TMP.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from auth.login_manager import LoginManager
from database.db_manager import DatabaseManager
from storage.document_storage import DocumentStorage, MAX_DOCUMENT_BYTES, convert_text
from storage.report_format import COLUMNS, EXAMPLE_REPORT, FORMAT, validate_report


def delimited(rows, delimiter=';', header=False):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter=delimiter)
    if header:
        writer.writerow([name for name, _ in COLUMNS])
    writer.writerows(rows)
    return stream.getvalue()


def row(value='value'):
    return [value] * len(COLUMNS)


class DocumentStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'users.db'
        self.db = DatabaseManager(self.path)
        self.db.bootstrap_admin('admin-password')
        self.login = LoginManager(self.db)
        self.assertTrue(self.login.login('admin_admin', 'admin-password'))
        self.storage = DocumentStorage(self.db, self.login)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def worker(self, *, direction=1, level=1, admin=False):
        self.assertTrue(self.login.register_user('worker', 'worker-password', direction, level, admin))
        manager = LoginManager(self.db)
        self.assertTrue(manager.login('worker', 'worker-password'))
        return manager, DocumentStorage(self.db, manager)

    def test_document_roundtrip_persists_and_metadata_omits_content(self):
        text = 'Исходное содержимое с переводом строки\nДокумент № 1'
        document = self.storage.create_document('Документ', text, 'source.txt')
        self.assertEqual(document['content'], text)
        self.assertEqual(document['revision'], 1)
        self.assertEqual(document['owner_id'], self.login.current_user.id)
        listed = self.storage.list_documents()
        self.assertEqual(listed[0]['id'], document['id'])
        self.assertNotIn('content', listed[0])
        self.login.logout()
        self.db.close()
        self.db = DatabaseManager(self.path)
        self.login = LoginManager(self.db)
        self.assertTrue(self.login.login('admin_admin', 'admin-password'))
        self.storage = DocumentStorage(self.db, self.login)
        self.assertEqual(self.storage.get_document(document['id'])['content'], text)

    def test_empty_drafts_allowed_but_cannot_convert(self):
        document = self.storage.create_document('Черновик', '')
        with self.assertRaisesRegex(ValueError, 'Пустой документ'):
            self.storage.convert_document(document['id'])
        self.assertEqual(self.storage.list_tables(), [])

    def test_all_document_operations_and_table_mutations_are_admin_only(self):
        document = self.storage.create_document('Secret', delimited([row()]))
        table = self.storage.convert_document(document['id'], secrecy_level_id=1)
        _, worker = self.worker()
        operations = (
            lambda: worker.list_documents(), lambda: worker.get_document(document['id']),
            lambda: worker.create_document('New', 'text'),
            lambda: worker.update_document(document['id'], 'Changed', 'text', 1),
            lambda: worker.delete_document(document['id']),
            lambda: worker.convert_document(document['id']),
            lambda: worker.import_table('Imported', EXAMPLE_REPORT),
            lambda: worker.delete_table(table['id']),
            lambda: worker.set_table_access(table['id'], 2, 1),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(PermissionError):
                    operation()
        self.assertEqual(worker.get_table(table['id'])['id'], table['id'])

    def test_logout_and_session_revocation_block_even_preexisting_service(self):
        document = self.storage.create_document('Document', 'text')
        session = self.login._session_id
        self.db.execute('UPDATE live_sessions SET ended_at=1 WHERE id=?', (session,))
        with self.assertRaises(PermissionError):
            self.storage.get_document(document['id'])
        with self.assertRaises(PermissionError):
            self.storage.list_tables()
        self.assertIsNone(self.login.current_user)

    def test_admin_demotion_and_deactivation_take_effect_immediately(self):
        document = self.storage.create_document('Document', 'text')
        manager, storage = self.worker(admin=True)
        uid = manager.current_user.id
        self.assertEqual(storage.get_document(document['id'])['id'], document['id'])
        self.assertTrue(self.login.update_user(uid, is_admin=False))
        with self.assertRaises(PermissionError):
            storage.get_document(document['id'])
        self.assertTrue(self.login.delete_user(uid))
        with self.assertRaises(PermissionError):
            storage.list_tables()

    def test_mutation_rechecks_admin_after_initial_current_user_lookup(self):
        original = self.db.get_cursor

        @contextmanager
        def revoke_before_begin():
            self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
            with original() as cursor:
                yield cursor

        with patch.object(self.db, 'get_cursor', revoke_before_begin):
            with self.assertRaises(PermissionError):
                self.storage.create_document('Race', 'must not be written')
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM documents_store.documents')[0], 0)

    def test_mutation_rechecks_session_after_initial_current_user_lookup(self):
        original = self.db.get_cursor

        @contextmanager
        def revoke_before_begin():
            self.db.execute('UPDATE live_sessions SET ended_at=1 WHERE id=?', (self.login._session_id,))
            with original() as cursor:
                yield cursor

        with patch.object(self.db, 'get_cursor', revoke_before_begin):
            with self.assertRaises(PermissionError):
                self.storage.import_table('Race', EXAMPLE_REPORT)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM tables_store.converted_tables')[0], 0)

    def test_optimistic_revision_prevents_lost_updates(self):
        document = self.storage.create_document('First', 'original')
        updated = self.storage.update_document(document['id'], 'Second', 'changed', document['revision'])
        self.assertEqual(updated['revision'], 2)
        with self.assertRaisesRegex(ValueError, 'уже изменён'):
            self.storage.update_document(document['id'], 'Stale', 'lost update', document['revision'])
        stored = self.storage.get_document(document['id'])
        self.assertEqual((stored['title'], stored['content'], stored['revision']), ('Second', 'changed', 2))

    def test_conversion_keeps_provenance_and_immutable_older_snapshot(self):
        source = self.storage.create_document('Source', delimited([row('old')]))
        first = self.storage.convert_document(source['id'])
        self.assertEqual((first['source_document_id'], first['source_revision']), (source['id'], 1))
        self.storage.update_document(source['id'], 'Source updated', delimited([row('new')]), 1)
        self.assertEqual(self.storage.get_table(first['id'])['report']['sections'][0]['groups'][0]['rows'][0], row('old'))
        second = self.storage.convert_document(source['id'])
        self.assertEqual(second['source_revision'], 2)
        self.assertEqual(second['report']['sections'][0]['groups'][0]['rows'][0], row('new'))
        with self.assertRaisesRegex(ValueError, 'связан'):
            self.storage.delete_document(source['id'])
        self.storage.delete_table(first['id'])
        self.storage.delete_table(second['id'])
        self.assertTrue(self.storage.delete_document(source['id']))

    def test_table_acl_filters_direction_and_uses_order_not_level_id(self):
        self.db.execute("INSERT INTO secrecy_levels(id,name,level_order) VALUES(100,'Custom low',0)")
        visible = self.storage.import_table('Visible', EXAMPLE_REPORT, secrecy_level_id=100)
        self.storage.import_table('Higher level', EXAMPLE_REPORT, secrecy_level_id=2)
        other = self.storage.import_table('Other direction', EXAMPLE_REPORT, direction_id=2, secrecy_level_id=1)
        _, worker = self.worker()
        metadata = worker.list_tables()
        self.assertEqual([table['id'] for table in metadata], [visible['id']])
        self.assertNotIn('report', metadata[0])
        self.assertNotIn('report_json', metadata[0])
        self.assertEqual(worker.get_table(visible['id'])['report']['format'], FORMAT)
        with self.assertRaises(PermissionError):
            worker.get_table(other['id'])
        self.storage.set_table_access(visible['id'], 2, 1)
        self.assertEqual(worker.list_tables(), [])
        with self.assertRaises(PermissionError):
            worker.get_table(visible['id'])

    def test_table_read_rechecks_changed_user_direction_and_clearance(self):
        table = self.storage.import_table('Visible', EXAMPLE_REPORT, secrecy_level_id=1)
        manager, worker = self.worker()
        uid = manager.current_user.id
        self.assertEqual(len(worker.list_tables()), 1)
        self.assertTrue(self.login.update_user(uid, direction_id=2))
        self.assertEqual(worker.list_tables(), [])
        with self.assertRaises(PermissionError):
            worker.get_table(table['id'])

    def test_table_access_metadata_validation_is_atomic(self):
        table = self.storage.import_table('Table', EXAMPLE_REPORT)
        for kwargs in ({'direction_id': 999}, {'secrecy_level_id': 999}, {'direction_id': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.storage.import_table('Invalid', EXAMPLE_REPORT, **kwargs)
        with self.assertRaises(ValueError):
            self.storage.set_table_access(table['id'], 2, 999)
        stored = self.storage.get_table(table['id'])
        self.assertEqual((stored['direction_id'], stored['secrecy_level_id']), (1, 4))
        self.assertEqual(len(self.storage.list_tables()), 1)

    def test_visible_table_never_contains_original_document_content(self):
        source_secret = 'ADMIN_ONLY_SOURCE_DETAILS'
        source = self.storage.create_document('Original', source_secret, 'secret.txt')
        table = self.storage.import_table('Public table', EXAMPLE_REPORT, source['id'], secrecy_level_id=1)
        _, worker = self.worker()
        payload = json.dumps({'metadata': worker.list_tables(), 'table': worker.get_table(table['id'])})
        self.assertNotIn(source_secret, payload)
        self.assertNotIn('secret.txt', payload)
        self.assertNotIn('content', worker.get_table(table['id']))
        with self.assertRaises(PermissionError):
            worker.get_document(source['id'])

    def test_document_inputs_and_ids_are_bounded(self):
        for title, content in (('', 'x'), ('x' * 501, 'x'), ('Title', b'binary'),
                               ('Title', 'x' * (MAX_DOCUMENT_BYTES + 1)), ('Title', '\ud800'),
                               ('Title', '\x00binary')):
            with self.subTest(title=title[:10], content_type=type(content)), self.assertRaises(ValueError):
                self.storage.create_document(title, content)
        for invalid in ('1 OR 1=1', True, 0, -1, 2 ** 63, None):
            with self.subTest(identifier=invalid), self.assertRaises(ValueError):
                self.storage.get_document(invalid)
        self.assertEqual(self.storage.list_documents(), [])

    def test_literal_sql_text_stays_data_and_audit_omits_sensitive_text(self):
        title = "'); DELETE FROM users; --"
        secret = "top-secret-content'; DROP TABLE documents; --"
        document = self.storage.create_document(title, secret)
        self.assertEqual(self.storage.get_document(document['id'])['content'], secret)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM users')[0], 1)
        details = '\n'.join(item['details'] or '' for item in self.db.fetch_all('SELECT details FROM audit_logs'))
        self.assertNotIn(secret, details)
        self.assertNotIn(title, details)
        self.assertNotIn('admin-password', details)

    def test_audit_failure_rolls_back_document_and_conversion(self):
        with patch.object(DocumentStorage, '_audit', side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError):
                self.storage.create_document('Rollback', 'text')
        self.assertEqual(self.storage.list_documents(), [])
        source = self.storage.create_document('Source', delimited([row()]))
        with patch.object(DocumentStorage, '_audit', side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError):
                self.storage.convert_document(source['id'])
        self.assertEqual(self.storage.list_tables(), [])
        self.assertEqual(self.storage.get_document(source['id'])['revision'], 1)

    def test_import_report_and_missing_source_validation(self):
        with self.assertRaises(ValueError):
            self.storage.import_table('Invalid', {'format': 'unknown'})
        with self.assertRaises(LookupError):
            self.storage.import_table('Missing source', EXAMPLE_REPORT, 999)
        self.assertEqual(self.storage.list_tables(), [])


class ConverterTests(unittest.TestCase):
    def test_csv_tsv_semicolon_headers_unicode_and_quoted_multiline_cells(self):
        data = row('Пример')
        data[2] = 'Значение, с запятой; и табуляцией\t'
        data[12] = 'Первая строка\nВторая строка'
        for delimiter in (',', ';', '\t'):
            with self.subTest(delimiter=repr(delimiter)):
                report = convert_text('\ufeff' + delimited([data], delimiter, header=True), 'Название')
                self.assertEqual(report['sections'][0]['groups'][0]['rows'], [data])
                self.assertEqual(convert_text(delimited([data], delimiter), 'Название', delimiter), report)

    def test_json_format_uses_same_headless_validator(self):
        serialized = json.dumps(EXAMPLE_REPORT, ensure_ascii=False)
        self.assertEqual(convert_text(serialized, 'Name'), EXAMPLE_REPORT)
        self.assertIs(validate_report(EXAMPLE_REPORT), EXAMPLE_REPORT)

    def test_unstructured_malformed_empty_and_ambiguous_input_rejected(self):
        invalid = ('', 'Произвольный текст без структуры', 'a;b;c',
                   '{not-json}', json.dumps({'format': 'unknown'}),
                   delimited([], header=True), delimited([row('x' * 501)]))
        for text in invalid:
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                convert_text(text, 'Title')
        # Both comma and semicolon parse into exactly 13 cells.
        ambiguous = 'a,' * 12 + 'b;' * 12 + 'c'
        with self.assertRaisesRegex(ValueError, 'Неоднозначный'):
            convert_text(ambiguous, 'Title')
        self.assertEqual(len(convert_text(ambiguous, 'Title', ',')['sections'][0]['groups'][0]['rows'][0]), 13)

    def test_rendered_rows_limit_includes_headers_bands_and_totals(self):
        report = convert_text(delimited([row()] * 393), 'Largest')
        self.assertEqual(sum(len(group['rows']) for group in report['sections'][0]['groups']), 393)
        with self.assertRaisesRegex(ValueError, '400'):
            convert_text(delimited([row()] * 394), 'Too large')
        report = copy.deepcopy(report)
        report['summary'] = 'One additional row'
        with self.assertRaisesRegex(ValueError, '400'):
            validate_report(report)


if __name__ == '__main__':
    unittest.main()

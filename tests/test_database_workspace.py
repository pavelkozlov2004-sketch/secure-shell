"""Storage UI checks with live rights and concurrent document edits."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('SECURE_SHELL_DATA_DIR', _TMP.name)
try:
    from PyQt5.QtWidgets import QApplication, QMessageBox, QDialog, QComboBox
    from ui.login_window import LoginWindow
    QT_AVAILABLE = True
except ModuleNotFoundError as exc:
    if not exc.name.startswith('PyQt5'):
        raise
    QT_AVAILABLE = False

from database.db_manager import DatabaseManager
from storage.report_format import EXAMPLE_REPORT


@unittest.skipUnless(QT_AVAILABLE, 'Install PyQt5 to run UI checks')
class DatabaseWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.db.bootstrap_admin('admin-password')
        self.window = LoginWindow(self.db)
        self.window.login_edit.setText('admin_admin')
        self.window.password_edit.setText('admin-password')
        self.window._login()
        self.workspace = self.window.database_workspace
        self.storage = self.workspace.storage

    def tearDown(self):
        self.window.close()
        self.db.close()

    def create_and_convert(self):
        self.workspace.new_document()
        self.workspace.document_title.setText('Текстовая ведомость')
        self.workspace.editor.setPlainText(';'.join(str(number) for number in range(13)))
        self.workspace.convert_document()
        document_id = self.workspace._document_id
        table_id = self.storage.list_tables()[0]['id']
        return document_id, table_id

    def test_create_convert_and_session_cleanup(self):
        document_id, table_id = self.create_and_convert()
        record = self.storage.get_table(table_id)
        self.assertEqual(record['source_document_id'], document_id)
        self.assertEqual(record['source_revision'], 1)
        self.assertEqual(record['report']['sections'][0]['groups'][0]['rows'][0][12], '12')
        self.assertIs(self.window.session_tabs.currentWidget(), self.window.report_table)
        self.assertEqual(self.window.report_table._stored_id, table_id)
        self.window._logout()
        self.assertEqual(self.workspace.editor.toPlainText(), '')
        self.assertEqual(self.workspace.document_list.count(), 0)
        self.assertEqual(self.workspace.table_list.count(), 0)
        self.assertEqual(self.window.report_table.table.rowCount(), 0)

    def test_role_demotion_hides_and_wipes_sources(self):
        self.create_and_convert()
        self.workspace.editor.insertPlainText(' private draft')
        self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
        self.window._refresh_session()
        self.assertEqual(self.workspace.tabs.indexOf(self.workspace.documents_page), -1)
        self.assertEqual(self.workspace.editor.toPlainText(), '')
        self.assertEqual(self.workspace.document_list.count(), 0)
        self.assertTrue(self.workspace.import_table_button.isHidden())
        self.assertTrue(self.workspace.table_access_button.isHidden())
        self.assertIsNotNone(self.window.manager.current_user)
        self.assertGreater(self.window.report_table.table.rowCount(), 0)

    def test_concurrent_document_edit_is_not_overwritten(self):
        document_id, _ = self.create_and_convert()
        self.workspace.editor.setPlainText('my unsaved draft')
        other = self.storage.get_document(document_id)
        self.storage.update_document(document_id, other['title'], 'external revision', other['revision'])
        self.workspace.validate_session()
        self.assertEqual(self.workspace.editor.toPlainText(), 'my unsaved draft')
        with patch('ui.database_workspace.QMessageBox.warning'):
            self.assertFalse(self.workspace.save_document())
        self.assertEqual(self.storage.get_document(document_id)['content'], 'external revision')

    def test_worker_opens_shared_table_without_source_access(self):
        _, table_id = self.create_and_convert()
        self.storage.set_table_access(table_id, 1, 1)
        self.window.manager.register_user('worker', 'worker-password', 1, 1)
        self.window._logout()
        self.window.login_edit.setText('worker')
        self.window.password_edit.setText('worker-password')
        self.window._login()
        self.assertEqual(self.workspace.table_list.count(), 1)
        self.assertEqual(self.workspace.tabs.indexOf(self.workspace.documents_page), -1)
        self.workspace.table_list.setCurrentRow(0)
        self.workspace.open_table()
        self.assertEqual(self.window.report_table._stored_id, table_id)
        self.db.execute('UPDATE tables_store.converted_tables SET direction_id=2 WHERE id=?', (table_id,))
        self.window._refresh_session()
        self.assertEqual(self.window.report_table.table.rowCount(), 0)
        with self.assertRaises(PermissionError):
            self.storage.list_documents()

    def test_access_dialog_changes_labels_without_changing_admin(self):
        table = self.storage.import_table('Образец', EXAMPLE_REPORT)
        admin = self.window.manager.current_user
        self.workspace.refresh()
        self.workspace.table_list.setCurrentRow(0)

        def choose_access(dialog):
            direction, level = dialog.findChildren(QComboBox)
            direction.setCurrentIndex(direction.findData(2))
            level.setCurrentIndex(level.findData(1))
            return QDialog.Accepted

        with patch('ui.database_workspace.QDialog.exec_', choose_access):
            self.workspace.change_table_access()
        changed = self.storage.get_table(table['id'])
        self.assertEqual((changed['direction_id'], changed['secrecy_level_id']), (2, 1))
        self.assertEqual(self.window.manager.current_user, admin)

    def test_import_document_copies_content_into_database(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.csv'
            text = ';'.join(str(number) for number in range(13))
            path.write_text('\ufeff' + text, encoding='utf-8')
            with patch('ui.database_workspace.QFileDialog.getOpenFileName', return_value=(str(path), '')):
                self.workspace.import_document()
            path.unlink()
            self.assertEqual(self.storage.get_document(self.workspace._document_id)['content'], text)
            self.workspace.convert_document()
            self.assertEqual(self.workspace.table_list.count(), 1)


if __name__ == '__main__':
    unittest.main()

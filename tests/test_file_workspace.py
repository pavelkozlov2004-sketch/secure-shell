"""Integration checks for the authorized graphical editor."""
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
    from PyQt5.QtWidgets import QApplication
    from ui.login_window import LoginWindow
    QT_AVAILABLE = True
except ModuleNotFoundError as exc:
    if not exc.name.startswith('PyQt5'):
        raise
    QT_AVAILABLE = False
from database.db_manager import DatabaseManager
from file_manager.file_ops import FileOperations


@unittest.skipUnless(QT_AVAILABLE, 'Install PyQt5 to run UI checks')
class FileWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.temp.name) / 'test.db')
        self.db.bootstrap_admin('admin-password')
        self.window = LoginWindow(self.db)
        self.window.login_edit.setText('admin_admin')
        self.window.password_edit.setText('admin-password')
        self.window._login()
        self.root = Path(self.temp.name) / 'documents'
        self.root.mkdir()
        self.ops = FileOperations(self.db, self.window.manager)
        self.ops.register_directory(self.root, 1, 1)
        self.file = self.root / 'note.txt'
        self.ops.create_text_file(self.file, 'original')
        self.workspace = self.window.file_workspace
        self.workspace.refresh()

    def tearDown(self):
        self.window.close()
        self.db.close()
        self.temp.cleanup()

    def test_open_edit_save_and_logout_clears_content(self):
        self.workspace.open_file(str(self.file))
        self.assertEqual(self.workspace.editor.toPlainText(), 'original')
        self.workspace.editor.setPlainText('changed')
        self.workspace.save()
        self.assertEqual(self.file.read_text(), 'changed')
        self.assertFalse(self.workspace.editor.document().isModified())
        self.window._logout()
        self.assertEqual(self.workspace.editor.toPlainText(), '')
        self.assertEqual(self.workspace.tree.topLevelItemCount(), 0)

    def test_revoked_session_and_external_change_prevent_save(self):
        self.workspace.open_file(str(self.file))
        self.workspace.editor.setPlainText('my changes')
        self.file.write_text('other changes')
        with patch('ui.file_workspace.QMessageBox.warning'):
            self.workspace.save()
        self.assertEqual(self.file.read_text(), 'other changes')
        self.db.execute('UPDATE users SET active=0 WHERE id=1')
        self.window._refresh_session()
        self.assertEqual(self.workspace.editor.toPlainText(), '')
        self.assertIsNone(self.workspace._path)

    def test_browser_registration_and_folder_creation(self):
        extra = Path(self.temp.name) / 'new-root'
        extra.mkdir()
        with patch('ui.file_workspace.QFileDialog.getExistingDirectory', return_value=str(extra)), \
             patch('ui.file_workspace.QInputDialog.getItem', side_effect=[('Север', True), ('Несекретно', True)]):
            self.workspace.register_root()
        self.assertEqual(self.workspace.tree.topLevelItemCount(), 2)
        item = self.workspace.tree.topLevelItem(0)
        selected_path = Path(item.data(0, 256))
        self.workspace.tree.setCurrentItem(item)
        with patch('ui.file_workspace.QInputDialog.getText', return_value=('subfolder', True)):
            self.workspace.create_folder()
        self.assertTrue((selected_path / 'subfolder').is_dir())

    def test_report_example_creation_merge_and_session_cleanup(self):
        from ui.report_table import COLUMNS
        item = self.workspace.tree.topLevelItem(0)
        self.workspace.tree.setCurrentItem(item)
        self.workspace.create_table_example()
        report = self.window.report_table
        self.assertIs(self.window.session_tabs.currentWidget(), report)
        self.assertEqual(report.table.columnCount(), len(COLUMNS))
        self.assertEqual(report.table.columnSpan(0, 5), 4)
        self.assertEqual(report.table.rowSpan(4, 2), 4)
        self.assertTrue((self.root / 'Пример таблицы.json').exists())
        self.window._logout()
        self.assertEqual(report.table.rowCount(), 0)

    def test_report_rejects_bad_schema_and_revoked_access(self):
        from ui.report_table import validate_report
        with self.assertRaises(ValueError):
            validate_report({'format': 'secure-shell-table-v1', 'title': 'X', 'sections': []})
        self.workspace.tree.setCurrentItem(self.workspace.tree.topLevelItem(0))
        self.workspace.create_table_example()
        report = self.window.report_table
        self.assertGreater(report.table.rowCount(), 0)
        self.db.execute('UPDATE files_metadata SET direction_id=2 WHERE path=?', (str(self.root / 'Пример таблицы.json'),))
        self.window._refresh_session()
        self.assertEqual(report.table.rowCount(), 0)
        with patch('ui.report_table.QMessageBox.warning'):
            self.assertFalse(report.load_file(str(self.root / 'Пример таблицы.json')))


if __name__ == '__main__':
    unittest.main()

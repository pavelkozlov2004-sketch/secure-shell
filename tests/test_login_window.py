"""UI integration tests with real Qt widgets (offscreen)."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('SECURE_SHELL_DATA_DIR', _TMP.name)
try:
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtTest import QTest
    from PyQt5.QtCore import Qt
    from ui.login_window import LoginWindow
    QT_AVAILABLE = True
except ModuleNotFoundError as exc:
    if not exc.name.startswith('PyQt5'):
        raise
    QT_AVAILABLE = False
from database.db_manager import DatabaseManager


@unittest.skipUnless(QT_AVAILABLE, 'Install PyQt5 to run UI checks')
class LoginWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.window = LoginWindow(self.db)
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()
        self.app.processEvents()
        self.db.close()

    def setup_admin(self):
        w = self.window
        w.setup_password.setText('new-password')
        w.setup_repeat.setText('new-password')
        QTest.mouseClick(w.setup_button, Qt.LeftButton)
        self.assertIs(w.pages.currentWidget(), w.login_page)

    def login(self):
        w = self.window
        w.login_edit.setText('admin_admin')
        w.password_edit.setText('new-password')
        QTest.keyClick(w.password_edit, Qt.Key_Return)
        self.assertIs(w.pages.currentWidget(), w.session_page)

    def test_connectivity_board_and_unblock(self):
        self.setup_admin()
        self.login()
        w = self.window
        self.assertTrue(w.manager.register_user('offline', 'worker-password', 1, 1))
        uid = self.db.fetch_one("SELECT id FROM users WHERE login='offline'")[0]
        self.db.execute('UPDATE users SET network_blocked=1 WHERE id=?', (uid,))
        w._show_connections()
        board = w.connectivity_window
        self.assertEqual(board.table.rowCount(), 1)
        self.assertEqual(board.table.item(0, 0).text(), 'offline')
        board.table.selectRow(0)
        QTest.mouseClick(board.unblock_button, Qt.LeftButton)
        self.assertEqual(self.db.fetch_one('SELECT network_blocked FROM users WHERE id=?', (uid,))[0], 0)
        w._logout()
        self.assertFalse(board.isVisible())
        self.assertEqual(board.table.rowCount(), 0)

    def test_connectivity_board_two_second_schedule(self):
        self.setup_admin()
        with patch('ui.login_window.time.monotonic', return_value=100):
            self.login()
        self.assertEqual(self.window._next_board, 102)
        with patch('ui.login_window.time.monotonic', return_value=101), patch.object(self.window, '_show_connections') as show:
            self.window._refresh_session()
            show.assert_not_called()
        with patch('ui.login_window.time.monotonic', return_value=102), patch.object(self.window, '_show_connections') as show:
            self.window._refresh_session()
            show.assert_called_once_with(automatic=True)

    def test_setup_mismatch_and_success(self):
        w = self.window
        self.assertIs(w.pages.currentWidget(), w.setup_page)
        w.setup_password.setText('new-password')
        w.setup_repeat.setText('different')
        QTest.mouseClick(w.setup_button, Qt.LeftButton)
        self.assertIsNone(self.db.fetch_one('SELECT * FROM users'))
        self.setup_admin()
        self.assertEqual(w.setup_password.text(), '')

    def test_login_logout_and_clear_password(self):
        self.setup_admin()
        self.login()
        w = self.window
        self.assertIn('admin_admin', w.identity_label.text())
        self.assertEqual(w.password_edit.text(), '')
        QTest.mouseClick(w.logout_button, Qt.LeftButton)
        self.assertIs(w.pages.currentWidget(), w.login_page)
        self.assertIsNone(w.manager.current_user)

    def test_wrong_password_and_lock(self):
        self.setup_admin()
        w = self.window
        for password in ['wrong'] * 3 + ['new-password']:
            w.password_edit.setText(password)
            QTest.mouseClick(w.login_button, Qt.LeftButton)
            self.assertIs(w.pages.currentWidget(), w.login_page)
            self.assertIsNone(w.manager.current_user)
        self.assertTrue(w.login_status.text())

    def test_change_password(self):
        self.setup_admin()
        self.login()
        w = self.window
        w.old_password.setText('new-password')
        w.new_password.setText('changed-password')
        w.repeat_password.setText('changed-password')
        QTest.mouseClick(w.change_button, Qt.LeftButton)
        self.assertEqual(w.session_status.text(), 'Пароль изменён.')
        QTest.mouseClick(w.logout_button, Qt.LeftButton)
        w.password_edit.setText('changed-password')
        QTest.mouseClick(w.login_button, Qt.LeftButton)
        self.assertIs(w.pages.currentWidget(), w.session_page)

    def test_disabled_account_ends_session(self):
        self.setup_admin()
        self.login()
        self.db.execute('UPDATE users SET active=0 WHERE id=1')
        self.window._refresh_session()
        self.assertIs(self.window.pages.currentWidget(), self.window.login_page)
        self.assertIsNone(self.window.manager.current_user)

    def test_close_ends_session(self):
        self.setup_admin()
        self.login()
        self.window.close()
        self.assertIsNone(self.window.manager.current_user)

    def test_password_toggle_removed(self):
        from PyQt5.QtWidgets import QCheckBox, QLineEdit
        self.assertEqual(self.window.findChildren(QCheckBox), [])
        self.assertEqual(self.window.password_edit.echoMode(), QLineEdit.Password)

    def test_emergency_admin_visibility(self):
        self.setup_admin()
        self.login()
        w = self.window
        self.assertFalse(w.emergency_panel.isHidden())
        self.assertFalse(w.compromise_button.isEnabled())
        w.manager.register_user('normal', 'normal-password', 1, 1)
        w._logout()
        w.login_edit.setText('normal')
        w.password_edit.setText('normal-password')
        w._login()
        self.assertTrue(w.emergency_panel.isHidden())

    def test_emergency_button_logs_out_and_saves_report(self):
        from PyQt5.QtWidgets import QMessageBox
        self.setup_admin()
        self.login()
        w = self.window
        with tempfile.TemporaryDirectory() as folder:
            w.emergency.prepare(Path(folder)/'vault.json', 'phrase-for-recovery')
            w._refresh_session()
            self.assertTrue(w.compromise_button.isEnabled())
            with patch('ui.login_window.QMessageBox.question', return_value=QMessageBox.Yes), \
                 patch('ui.login_window.QMessageBox.information'), \
                 patch('auth.emergency.DATA_DIR', Path(folder)):
                QTest.mouseClick(w.compromise_button, Qt.LeftButton)
            self.assertIs(w.pages.currentWidget(), w.login_page)
            self.assertIsNone(w.manager.current_user)
            self.assertEqual(self.db.fetch_one('SELECT count(*) FROM emergency_reports')[0], 1)

    def test_emergency_cancel_preserves_session(self):
        from PyQt5.QtWidgets import QMessageBox
        self.setup_admin()
        self.login()
        w = self.window
        with tempfile.TemporaryDirectory() as folder:
            w.emergency.prepare(Path(folder)/'vault.json', 'phrase-for-recovery')
            w._refresh_session()
            with patch('ui.login_window.QMessageBox.question', return_value=QMessageBox.No):
                QTest.mouseClick(w.compromise_button, Qt.LeftButton)
            self.assertIsNotNone(w.manager.current_user)
            self.assertEqual(self.db.fetch_one('SELECT count(*) FROM emergency_reports')[0], 0)


if __name__ == '__main__':
    unittest.main()

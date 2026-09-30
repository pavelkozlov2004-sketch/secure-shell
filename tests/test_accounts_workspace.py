"""Integration checks for account editing and live administrator permissions."""
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
    from PyQt5.QtCore import QTimer
    from PyQt5.QtWidgets import QApplication, QDialog, QLineEdit, QMessageBox
    from ui.accounts_workspace import AccountsWorkspace, AccountDialog, PasswordDialog
    QT_AVAILABLE = True
except ModuleNotFoundError as exc:
    if not exc.name.startswith('PyQt5'):
        raise
    QT_AVAILABLE = False
from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager


@unittest.skipUnless(QT_AVAILABLE, 'Install PyQt5 to run UI checks')
class AccountsWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.temp.name) / 'accounts.db')
        self.db.bootstrap_admin('admin-password')
        self.manager = LoginManager(self.db)
        self.assertTrue(self.manager.login('admin_admin', 'admin-password'))
        self.workspace = AccountsWorkspace(self.db, self.manager)
        self.workspace.refresh()

    def tearDown(self):
        self.workspace.close()
        self.manager.logout()
        self.db.close()
        self.temp.cleanup()

    def select(self, login):
        for row in range(self.workspace.table.rowCount()):
            if self.workspace.table.item(row, 1).text() == login:
                self.workspace.table.selectRow(row)
                return
        self.fail(f'User {login} missing from table')

    def test_create_edit_reset_and_logout(self):
        dialogs = []

        def create(dialog):
            dialogs.append(dialog)
            self.assertEqual(dialog.password.echoMode(), QLineEdit.Password)
            self.assertEqual(dialog.repeat.echoMode(), QLineEdit.Password)
            dialog.login.setText('analyst')
            dialog.password.setText('initial-password')
            dialog.repeat.setText('initial-password')
            dialog.accept()
            return dialog.result()

        with patch.object(AccountDialog, 'exec_', create):
            self.workspace.create_user()
        self.assertEqual(dialogs[-1].password.text(), '')
        self.assertEqual(dialogs[-1].repeat.text(), '')
        user = self.db.fetch_one('SELECT id FROM users WHERE login=?', ('analyst',))
        self.assertIsNotNone(user)
        self.select('analyst')

        def edit(dialog):
            self.assertTrue(dialog.login.isReadOnly())
            self.assertIsNone(dialog.password)
            dialog.direction.setCurrentIndex(dialog.direction.findData(2))
            dialog.level.setCurrentIndex(dialog.level.findData(2))
            dialog.is_admin.setChecked(True)
            dialog.accept()
            return dialog.result()

        with patch.object(AccountDialog, 'exec_', edit):
            self.workspace.edit_user()
        updated = self.manager.get_user_by_id(user['id'])
        self.assertEqual((updated.direction_id, updated.secrecy_level_id, updated.is_admin), (2, 2, True))

        def reset(dialog):
            dialogs.append(dialog)
            self.assertEqual(dialog.password.echoMode(), QLineEdit.Password)
            dialog.password.setText('replacement-password')
            dialog.repeat.setText('replacement-password')
            dialog.accept()
            return dialog.result()

        with patch.object(PasswordDialog, 'exec_', reset):
            self.workspace.reset_password()
        self.assertEqual(dialogs[-1].password.text(), '')
        self.assertEqual(dialogs[-1].repeat.text(), '')
        other = LoginManager(self.db)
        self.assertFalse(other.login('analyst', 'initial-password'))
        self.assertTrue(other.login('analyst', 'replacement-password'))
        other.logout()
        self.manager.logout()
        self.workspace.validate_session()
        self.assertEqual(self.workspace.table.rowCount(), 0)
        self.assertFalse(self.workspace.create_button.isEnabled())
        self.assertFalse(self.workspace.reset_button.isEnabled())

    def test_non_admin_slots_cannot_read_or_write_accounts(self):
        self.assertTrue(self.manager.register_user('reader', 'reader-password', 1, 1))
        self.assertTrue(self.manager.login('reader', 'reader-password'))
        self.workspace.refresh()
        with patch.object(AccountDialog, 'exec_') as account_dialog, \
             patch.object(PasswordDialog, 'exec_') as password_dialog, \
             patch('ui.accounts_workspace.QMessageBox.question') as question:
            self.workspace.create_user()
            self.workspace.edit_user()
            self.workspace.reset_password()
            self.workspace.deactivate_user()
        account_dialog.assert_not_called()
        password_dialog.assert_not_called()
        question.assert_not_called()
        self.assertEqual(self.workspace.table.rowCount(), 0)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM users')[0], 2)

    def test_admin_revoked_while_dialog_open_blocks_submit_and_clears_password(self):
        dialogs = []

        def revoked(dialog):
            dialogs.append(dialog)
            dialog.login.setText('blocked-create')
            dialog.password.setText('unused-password')
            dialog.repeat.setText('unused-password')
            dialog.accept()
            self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
            return dialog.result()

        with patch.object(AccountDialog, 'exec_', revoked):
            self.workspace.create_user()
        self.assertIsNone(self.db.fetch_one('SELECT id FROM users WHERE login=?', ('blocked-create',)))
        self.assertEqual(self.workspace.table.rowCount(), 0)
        self.assertEqual(dialogs[0].password.text(), '')
        self.assertEqual(dialogs[0].repeat.text(), '')

    def test_last_admin_role_is_preserved(self):
        self.select('admin_admin')

        def demote(dialog):
            dialog.is_admin.setChecked(False)
            dialog.accept()
            return dialog.result()

        with patch.object(AccountDialog, 'exec_', demote):
            self.workspace.edit_user()
        self.assertTrue(self.manager.current_user.is_admin)
        self.assertIn('последнего администратора', self.workspace.status.text())
        self.assertFalse(self.workspace.deactivate_button.isEnabled())

    def test_deactivation_requires_confirmation_and_revokes_target_session(self):
        self.assertTrue(self.manager.register_user('reader', 'reader-password', 1, 1))
        other = LoginManager(self.db)
        self.assertTrue(other.login('reader', 'reader-password'))
        self.workspace.refresh()
        self.select('reader')
        with patch('ui.accounts_workspace.QMessageBox.question', return_value=QMessageBox.No):
            self.workspace.deactivate_user()
        self.assertIsNotNone(other.current_user)
        with patch('ui.accounts_workspace.QMessageBox.question', return_value=QMessageBox.Yes):
            self.workspace.deactivate_user()
        self.assertIsNone(other.current_user)
        self.assertEqual(self.workspace.table.rowCount(), 1)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE login=?', ('reader',))[0], 0)

    def test_cancel_clears_password_without_creating_account(self):
        dialogs = []

        def cancel(dialog):
            dialogs.append(dialog)
            dialog.login.setText('cancelled-user')
            dialog.password.setText('cancelled-password')
            dialog.repeat.setText('cancelled-password')
            dialog.reject()
            return dialog.result()

        with patch.object(AccountDialog, 'exec_', cancel):
            self.workspace.create_user()
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM users')[0], 1)
        self.assertEqual(dialogs[0].password.text(), '')
        self.assertEqual(dialogs[0].repeat.text(), '')

    def test_logout_closes_active_dialog_and_clears_password(self):
        def logout(dialog):
            dialog.login.setText('logout-user')
            dialog.password.setText('logout-password')
            dialog.repeat.setText('logout-password')
            self.manager.logout()
            self.workspace.clear_session()
            self.assertEqual(dialog.result(), QDialog.Rejected)
            self.assertEqual(dialog.password.text(), '')
            self.assertEqual(dialog.repeat.text(), '')
            return dialog.result()

        with patch.object(AccountDialog, 'exec_', logout):
            self.workspace.create_user()
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM users')[0], 1)
        self.assertIsNone(self.workspace._active_dialog)
        self.assertEqual(self.workspace.table.rowCount(), 0)

    def test_live_role_demotion_closes_visible_modal_and_scrubs_fields(self):
        original_exec = AccountDialog.exec_
        observations = {}

        def execute(dialog):
            dialog.login.setText('never-created')
            dialog.password.setText('draft-password')
            dialog.repeat.setText('draft-password')

            def revoke():
                observations['was_visible'] = dialog.isVisible()
                self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
                self.workspace.validate_session()
                observations['is_visible'] = dialog.isVisible()
                observations['login'] = dialog.login.text()
                observations['password'] = dialog.password.text()
                observations['direction'] = dialog.direction.currentData()
                observations['admin'] = dialog.is_admin.isChecked()
                observations['result'] = dialog.result()

            timer = QTimer(dialog)
            timer.setSingleShot(True)
            timer.timeout.connect(dialog.reject)
            timer.start(2000)
            QTimer.singleShot(0, revoke)
            return original_exec(dialog)

        with patch.object(AccountDialog, 'exec_', execute):
            self.workspace.create_user()
        self.assertEqual(observations, {
            'was_visible': True, 'is_visible': False, 'login': '', 'password': '',
            'direction': None, 'admin': False, 'result': QDialog.Rejected,
        })
        self.assertEqual(self.workspace.table.rowCount(), 0)
        self.assertEqual(self.db.fetch_one('SELECT count(*) FROM users')[0], 1)


if __name__ == '__main__':
    unittest.main()

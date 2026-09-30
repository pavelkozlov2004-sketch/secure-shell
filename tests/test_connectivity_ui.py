"""Connection status, reactivation and privacy checks through actual Qt widgets."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('VUAL_DATA_DIR', _TMP.name)

from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager
from auth.connectivity import ConnectivityMonitor
try:
    from PyQt5.QtWidgets import QApplication, QMessageBox
    from PyQt5.QtCore import Qt
    from PyQt5.QtTest import QTest
    from ui.connectivity_window import ConnectivityWindow
    from ui.login_window import LoginWindow
    QT_AVAILABLE = True
except ModuleNotFoundError as exc:
    if not exc.name.startswith('PyQt5'):
        raise
    QT_AVAILABLE = False


class FakeRemoteManager(LoginManager):
    is_remote = True
    server_url = 'https://server.local:8765'
    last_sync_at = 1000.0
    last_error = ''
    available = True

    def refresh_session(self):
        if not self.available:
            self.last_error = 'Нет ответа от сервера'
            self.logout()
            return False
        return True

    def _request(self, endpoint, data=None):
        if endpoint == '/api/connections':
            return {'users': []}
        raise AssertionError(f'Unexpected test request: {endpoint}')


@unittest.skipUnless(QT_AVAILABLE, 'Install PyQt5 to run UI checks')
class ConnectivityUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.db.bootstrap_admin('admin-password')
        self.manager = LoginManager(self.db)
        self.manager.login('admin_admin', 'admin-password')
        for login in ('online', 'offline', 'deactivated'):
            self.manager.register_user(login, 'worker-password', 1, 1)
        self.ids = {r['login']: r['id'] for r in self.db.fetch_all('SELECT id,login FROM users')}
        self.worker = LoginManager(self.db)
        self.worker.login('online', 'worker-password')
        self.now = 1000.0
        self.db.execute('UPDATE live_sessions SET last_seen_at=? WHERE user_id=?',
                        (self.now, self.ids['online']))
        self.db.execute('UPDATE users SET active=0,network_blocked=1 WHERE id=?',
                        (self.ids['deactivated'],))
        self.monitor = ConnectivityMonitor(self.manager, lambda: self.now)
        self.board = ConnectivityWindow(self.monitor)
        self.board.show()
        self.board.display(self.monitor.user_statuses())
        self.app.processEvents()

    def tearDown(self):
        self.board.close()
        self.app.processEvents()
        self.db.close()

    def row_index(self, login):
        for i in range(self.board.table.rowCount()):
            if self.board.table.item(i, 0).text() == login:
                return i
        self.fail(f'Missing user {login}')

    def test_all_states_are_visible_in_colour_and_text(self):
        self.assertEqual(self.board.table.rowCount(), 3)
        states = {'online': ('Работает', '#d8f0df'),
                  'offline': ('Нет подключения', '#e6e8eb'),
                  'deactivated': ('Пользователь деактивирован', '#f9dddd')}
        for login, (label, colour) in states.items():
            item = self.board.table.item(self.row_index(login), 1)
            self.assertEqual(item.text(), label)
            self.assertEqual(item.background().color().name(), colour)
        self.assertIn('работают: 1', self.board.summary.text())
        self.assertIn('нет подключения: 1', self.board.summary.text())
        self.assertIn('деактивированы: 1', self.board.summary.text())

    def test_selection_survives_refresh_and_buttons_match_action(self):
        self.assertFalse(self.board.unblock_button.isEnabled())
        for login, enabled in [('online', False), ('offline', False), ('deactivated', True)]:
            self.board.table.selectRow(self.row_index(login))
            self.assertEqual(self.board.unblock_button.isEnabled(), enabled)
        self.board.display(list(reversed(self.monitor.user_statuses())))
        self.assertEqual(self.board._selected_id(), self.ids['deactivated'])
        self.assertTrue(self.board.unblock_button.isEnabled())
        self.db.execute('UPDATE users SET network_blocked=1 WHERE id=?', (self.ids['offline'],))
        self.board.display(self.monitor.user_statuses())
        self.board.table.selectRow(self.row_index('offline'))
        self.assertTrue(self.board.unblock_button.isEnabled())

    def test_reactivation_confirmation_preserves_credentials_and_owner(self):
        uid = self.ids['deactivated']
        before = self.db.fetch_one('SELECT password_hash FROM users WHERE id=?', (uid,))[0]
        self.db.execute("INSERT INTO login_attempts(login,failures,locked_until) VALUES ('deactivated',3,9999999999)")
        self.board.table.selectRow(self.row_index('deactivated'))
        with patch('ui.connectivity_window.QMessageBox.question', return_value=QMessageBox.No):
            QTest.mouseClick(self.board.unblock_button, Qt.LeftButton)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?', (uid,))[0], 0)
        with patch('ui.connectivity_window.QMessageBox.question', return_value=QMessageBox.Yes):
            QTest.mouseClick(self.board.unblock_button, Qt.LeftButton)
        row = self.db.fetch_one('SELECT id,active,network_blocked,password_hash FROM users WHERE id=?', (uid,))
        self.assertEqual((row['id'], row['active'], row['network_blocked']), (uid, 1, 0))
        self.assertEqual(row['password_hash'], before)
        self.assertIsNone(self.db.fetch_one("SELECT * FROM login_attempts WHERE login='deactivated'"))
        self.assertTrue(LoginManager(self.db).login('deactivated', 'worker-password'))
        self.assertEqual(self.db.fetch_one("SELECT count(*) FROM audit_logs WHERE action='REACTIVATE_USER'")[0], 1)

    def test_local_monitor_uses_real_lan_signal_and_skips_legacy_challenge(self):
        self.db.execute('INSERT INTO lan_presence(session_id,address,client_name,last_heartbeat) VALUES (?,?,?,?)',
                        (self.worker._session_id, '192.168.1.15', 'Рабочее место', self.now))
        self.monitor.poll()
        self.assertIsNone(self.db.fetch_one('SELECT 1 FROM connectivity_challenges WHERE session_id=?',
                                           (self.worker._session_id,)))
        rows = {r['login']: r for r in self.monitor.user_statuses()}
        self.assertEqual(rows['online']['status_code'], 'online')
        self.assertEqual(rows['online']['address'], '192.168.1.15')
        self.assertEqual(rows['online']['client_name'], 'Рабочее место')
        self.now += 11
        # A different authenticated action may update DB presence but must not be a LAN heartbeat.
        self.db.execute('UPDATE live_sessions SET last_seen_at=? WHERE id=?',
                        (self.now, self.worker._session_id))
        rows = {r['login']: r for r in self.monitor.user_statuses()}
        self.assertEqual(rows['online']['status_code'], 'offline')
        self.assertEqual(rows['online']['last_seen'], 1000.0)
        self.now += 60
        self.assertEqual(self.monitor.poll(), [])

    def test_reactivation_cannot_recover_old_sessions(self):
        uid = self.ids['online']
        self.manager.delete_user(uid)
        self.assertTrue(self.monitor.unblock(uid))
        self.assertIsNone(self.worker.current_user)
        self.assertTrue(self.worker.login('online', 'worker-password'))

    def test_revoked_admin_cannot_restore_account(self):
        self.board.table.selectRow(self.row_index('deactivated'))
        self.db.execute('UPDATE users SET is_admin=0 WHERE id=?', (self.manager._user_id,))
        with patch('ui.connectivity_window.QMessageBox.question', return_value=QMessageBox.Yes):
            QTest.mouseClick(self.board.unblock_button, Qt.LeftButton)
        self.assertEqual(self.db.fetch_one('SELECT active FROM users WHERE id=?',
                                          (self.ids['deactivated'],))[0], 0)
        self.assertEqual(self.board.table.rowCount(), 0)
        self.assertFalse(self.board.isVisible())

    def test_login_board_refreshes_without_reopening_after_user_closes(self):
        window = LoginWindow(self.db)
        try:
            window.login_edit.setText('admin_admin')
            window.password_edit.setText('admin-password')
            window._login()
            window.connectivity_window.hide()
            window._next_board = 0
            window._refresh_session()
            self.assertFalse(window.connectivity_window.isVisible())
            window._show_connections()
            self.assertTrue(window.connectivity_window.isVisible())
            self.db.execute('UPDATE users SET active=0 WHERE id=?', (self.ids['offline'],))
            window._refresh_session()
            for i in range(window.connectivity_window.table.rowCount()):
                if window.connectivity_window.table.item(i, 0).text() == 'offline':
                    self.assertEqual(window.connectivity_window.table.item(i, 1).text(), 'Пользователь деактивирован')
                    break
            else:
                self.fail('Offline user missing from refreshed board')
        finally:
            window.close()


@unittest.skipUnless(QT_AVAILABLE, 'Install PyQt5 to run UI checks')
class RemoteLoginUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.manager = FakeRemoteManager(self.db)
        self.window = LoginWindow(self.db, manager=self.manager)
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()
        self.app.processEvents()
        self.db.close()

    def login(self):
        self.db.bootstrap_admin('admin-password')
        self.window.login_edit.setText('admin_admin')
        self.window.password_edit.setText('admin-password')
        self.window._login()
        self.assertIs(self.window.pages.currentWidget(), self.window.session_page)

    def test_empty_remote_client_has_no_local_admin_bootstrap(self):
        self.assertIs(self.window.pages.currentWidget(), self.window.login_page)
        self.window.setup_password.setText('local-password')
        self.window.setup_repeat.setText('local-password')
        self.window._setup()
        self.assertIsNone(self.db.fetch_one('SELECT * FROM users'))
        self.assertIs(self.window.pages.currentWidget(), self.window.login_page)

    def test_remote_session_disconnection_clears_all_views(self):
        self.login()
        self.window.report_table.show_example()
        self.window.old_password.setText('admin-password')
        self.window._show_connections()
        self.manager.available = False
        with patch('ui.login_window.QMessageBox.warning') as warning:
            self.window._refresh_session()
        warning.assert_not_called()
        self.assertIs(self.window.pages.currentWidget(), self.window.login_page)
        self.assertIsNone(self.manager.current_user)
        self.assertFalse(self.window.connectivity_window.isVisible())
        self.assertEqual(self.window.connectivity_window.table.rowCount(), 0)
        self.assertEqual(self.window.accounts_workspace.table.rowCount(), 0)
        self.assertEqual(self.window.old_password.text(), '')
        self.assertEqual(self.window.identity_label.text(), '')
        self.assertIn('Нет подключения', self.window.network_status.text())

    def test_remote_emergency_buttons_stay_disabled_and_settings_signal_is_available(self):
        events = []
        self.window.network_settings_requested.connect(lambda: events.append(True))
        QTest.mouseClick(self.window.network_settings_button, Qt.LeftButton)
        self.assertEqual(events, [True])
        self.login()
        self.assertFalse(self.window.prepare_button.isEnabled())
        self.assertFalse(self.window.compromise_button.isEnabled())
        self.assertIn('сервере', self.window.emergency_status.text())
        self.assertIn('server.local', self.window.network_status.text())

    def test_remote_role_revocation_clears_administrator_views(self):
        self.login()
        self.window._show_connections()
        self.db.execute('UPDATE users SET is_admin=0 WHERE id=1')
        self.window._refresh_session()
        self.assertFalse(self.window.connectivity_window.isVisible())
        self.assertEqual(self.window.accounts_workspace.table.rowCount(), 0)
        index = self.window.session_tabs.indexOf(self.window.accounts_workspace)
        self.assertFalse(self.window.session_tabs.isTabVisible(index))
        self.assertTrue(self.window.emergency_panel.isHidden())


if __name__ == '__main__':
    unittest.main()

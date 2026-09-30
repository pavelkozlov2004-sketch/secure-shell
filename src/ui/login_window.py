"""Окно входа, первоначальной настройки и управления текущим сеансом."""
import sqlite3
import time
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
    QStackedWidget, QHBoxLayout, QFrame, QFileDialog, QInputDialog, QMessageBox, QTabWidget,
)
from auth.login_manager import LoginManager
from auth.emergency import EmergencyManager
from config import APP_TITLE
from auth.connectivity import ConnectivityMonitor, BOARD_SECONDS
from ui.connectivity_window import ConnectivityWindow
from ui.file_workspace import FileWorkspace
from ui.report_table import ReportTable
from ui.database_workspace import DatabaseWorkspace
from ui.accounts_workspace import AccountsWorkspace


class LoginWindow(QWidget):
    def __init__(self, db_manager):
        super().__init__()
        self.db = db_manager
        self.manager = LoginManager(db_manager)
        self.emergency = EmergencyManager(self.manager)
        self.connectivity = ConnectivityMonitor(self.manager)
        self.connectivity_window = ConnectivityWindow(self.connectivity, self)
        self._next_board = 0
        self.setWindowTitle(APP_TITLE)
        self.resize(580, 700)
        self.setMinimumSize(460, 440)
        self.setStyleSheet('''
            QWidget { background: #f3f5f9; color: #17263b; font-size: 14px; }
            QLineEdit { background: white; border: 1px solid #b8c4d5;
                        border-radius: 6px; padding: 9px; }
            QLineEdit:focus { border: 2px solid #285cca; }
            QPushButton { background: #285cca; color: white; border: none;
                          border-radius: 6px; padding: 10px 16px; }
            QPushButton:disabled { background: #8b9bb6; }
            QLabel#heading { font-size: 25px; font-weight: bold; }
            QLabel#status { color: #9a2525; }
        ''')
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        heading = QLabel('Secure Shell')
        heading.setObjectName('heading')
        outer.addWidget(heading)
        subtitle = QLabel('Вход и управление сеансом')
        outer.addWidget(subtitle)
        self.pages = QStackedWidget()
        outer.addWidget(self.pages)
        self._build_login()
        self._build_setup()
        self._build_session()
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self._refresh_session)
        self.timer.start()
        if self.db.fetch_one('SELECT 1 FROM users LIMIT 1'):
            self.pages.setCurrentWidget(self.login_page)
            self.login_edit.setFocus()
        else:
            self.pages.setCurrentWidget(self.setup_page)
            self.setup_password.setFocus()

    @staticmethod
    def _password():
        field = QLineEdit()
        field.setEchoMode(QLineEdit.Password)
        field.setMaxLength(1024)
        return field

    @staticmethod
    def _status():
        label = QLabel('')
        label.setObjectName('status')
        label.setWordWrap(True)
        label.setTextFormat(Qt.PlainText)
        label.setAccessibleName('Состояние операции')
        return label

    def _build_login(self):
        self.login_page = QWidget()
        layout = QVBoxLayout(self.login_page)
        layout.setContentsMargins(0, 24, 0, 0)
        form = QFormLayout()
        self.login_edit = QLineEdit()
        self.login_edit.setMaxLength(200)
        self.login_edit.setPlaceholderText('Введите логин')
        self.password_edit = self._password()
        form.addRow('Логин', self.login_edit)
        form.addRow('Пароль', self.password_edit)
        layout.addLayout(form)
        self.login_status = self._status()
        layout.addWidget(self.login_status)
        self.login_button = QPushButton('Войти')
        self.login_button.clicked.connect(self._login)
        self.password_edit.returnPressed.connect(self._login)
        self.login_edit.returnPressed.connect(self.password_edit.setFocus)
        layout.addWidget(self.login_button)
        help_text = QLabel('После трёх неудачных попыток вход блокируется на пять минут.')
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        layout.addStretch()
        self.pages.addWidget(self.login_page)

    def _build_setup(self):
        self.setup_page = QWidget()
        layout = QVBoxLayout(self.setup_page)
        layout.setContentsMargins(0, 24, 0, 0)
        note = QLabel('Первый запуск\nЗадайте пароль администратора admin_admin.\nОт 8 до 1024 символов.')
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        self.setup_password = self._password()
        self.setup_repeat = self._password()
        form.addRow('Новый пароль', self.setup_password)
        form.addRow('Повтор пароля', self.setup_repeat)
        layout.addLayout(form)
        self.setup_status = self._status()
        layout.addWidget(self.setup_status)
        self.setup_button = QPushButton('Создать администратора')
        self.setup_button.clicked.connect(self._setup)
        self.setup_repeat.returnPressed.connect(self._setup)
        layout.addWidget(self.setup_button)
        layout.addStretch()
        self.pages.addWidget(self.setup_page)

    def _build_session(self):
        self.session_page = QWidget()
        page_layout = QVBoxLayout(self.session_page)
        self.session_tabs = QTabWidget()
        page_layout.addWidget(self.session_tabs)
        info_page = QWidget()
        layout = QVBoxLayout(info_page)
        layout.setContentsMargins(0, 20, 0, 0)
        self.identity_label = QLabel()
        self.identity_label.setTextFormat(Qt.PlainText)
        self.identity_label.setWordWrap(True)
        layout.addWidget(self.identity_label)
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        layout.addWidget(line)
        layout.addWidget(QLabel('Смена пароля'))
        form = QFormLayout()
        self.old_password = self._password()
        self.new_password = self._password()
        self.repeat_password = self._password()
        form.addRow('Текущий пароль', self.old_password)
        form.addRow('Новый пароль', self.new_password)
        form.addRow('Повтор пароля', self.repeat_password)
        layout.addLayout(form)
        self.session_status = self._status()
        layout.addWidget(self.session_status)
        buttons = QHBoxLayout()
        self.change_button = QPushButton('Изменить пароль')
        self.change_button.clicked.connect(self._change_password)
        self.logout_button = QPushButton('Выйти')
        self.logout_button.clicked.connect(self._logout)
        buttons.addWidget(self.change_button)
        buttons.addWidget(self.logout_button)
        layout.addLayout(buttons)
        self.emergency_panel = QWidget()
        emergency_layout = QVBoxLayout(self.emergency_panel)
        emergency_layout.setContentsMargins(0, 12, 0, 0)
        self.emergency_status = self._status()
        emergency_layout.addWidget(self.emergency_status)
        self.prepare_button = QPushButton('Подготовить резервные пароли…')
        self.prepare_button.clicked.connect(self._prepare_emergency)
        emergency_layout.addWidget(self.prepare_button)
        self.compromise_button = QPushButton('компрометация')
        self.compromise_button.setStyleSheet('background: #a32730; color: white; padding: 10px; border-radius: 6px;')
        self.compromise_button.clicked.connect(self._compromise)
        emergency_layout.addWidget(self.compromise_button)
        self.connections_button = QPushButton('Подключения пользователей…')
        self.connections_button.clicked.connect(self._show_connections)
        emergency_layout.addWidget(self.connections_button)
        self.connections_status = QLabel('Опрос: каждые 5 минут; ответ: 60 секунд. Табло: каждые 10 минут.')
        self.connections_status.setWordWrap(True)
        emergency_layout.addWidget(self.connections_status)
        self.emergency_panel.hide()
        layout.addWidget(self.emergency_panel)
        layout.addStretch()
        self.session_tabs.addTab(info_page, 'Сеанс')
        self.file_workspace = FileWorkspace(self.db, self.manager)
        self.session_tabs.addTab(self.file_workspace, 'Файлы и редактор')
        self.database_workspace = DatabaseWorkspace(self.db, self.manager)
        self.session_tabs.addTab(self.database_workspace, 'Библиотека')
        self.accounts_workspace = AccountsWorkspace(self.db, self.manager)
        self.session_tabs.addTab(self.accounts_workspace, 'Учётные записи')
        self.session_tabs.setTabVisible(self.session_tabs.indexOf(self.accounts_workspace), False)
        self.report_table = ReportTable(self.db, self.manager)
        self.session_tabs.addTab(self.report_table, 'Таблицы')
        self.file_workspace.open_table_callback = self._open_table
        self.database_workspace.stored_table_callback = self._open_stored_table
        self.pages.addWidget(self.session_page)

    def _open_table(self, path):
        if self.report_table.load_file(path):
            self.session_tabs.setCurrentWidget(self.report_table)

    def _open_stored_table(self, table_id):
        if self.report_table.load_stored(table_id):
            self.session_tabs.setCurrentWidget(self.report_table)

    def _clear_secrets(self):
        for field in (self.password_edit, self.setup_password, self.setup_repeat,
                      self.old_password, self.new_password, self.repeat_password):
            field.clear()


    def _login(self):
        if self.pages.currentWidget() is not self.login_page or not self.login_button.isEnabled():
            return
        login = self.login_edit.text().strip()
        if not login or not self.password_edit.text():
            self.login_status.setText('Введите логин и пароль.')
            return
        self.login_button.setEnabled(False)
        try:
            ok = self.manager.login(login, self.password_edit.text())
            self._clear_secrets()
            if ok:
                self.login_status.clear()
                self.session_status.clear()
                self.pages.setCurrentWidget(self.session_page)
                self.resize(1200, 800)
                self.file_workspace.refresh()
                self.database_workspace.refresh()
                self.accounts_workspace.refresh()
                self.report_table.show_example()
                self._refresh_session()
            else:
                self.login_status.setText('Вход не выполнен. Проверьте данные; при сетевой блокировке обратитесь к администратору; после трёх ошибок подождите пять минут.')
                self.password_edit.setFocus()
        except (sqlite3.Error, OSError):
            self._logout()
            self.login_status.setText('Не удалось обратиться к базе или журналу. Проверьте доступ к каталогу данных.')
        finally:
            self.login_button.setEnabled(True)

    def _setup(self):
        if self.pages.currentWidget() is not self.setup_page:
            return
        if self.setup_password.text() != self.setup_repeat.text():
            self.setup_status.setText('Пароли не совпадают.')
            return
        self.setup_button.setEnabled(False)
        try:
            self.db.bootstrap_admin(self.setup_password.text())
            self._clear_secrets()
            self.login_edit.setText('admin_admin')
            self.login_status.setText('Администратор создан. Введите выбранный пароль.')
            self.pages.setCurrentWidget(self.login_page)
            self.password_edit.setFocus()
        except ValueError as exc:
            self.setup_status.setText(str(exc))
            if self.db.fetch_one('SELECT 1 FROM users LIMIT 1'):
                self._clear_secrets()
                self.pages.setCurrentWidget(self.login_page)
                self.login_status.setText('Настройка уже выполнена. Войдите в систему.')
        except (sqlite3.Error, OSError):
            self.setup_status.setText('Не удалось сохранить настройки. Проверьте доступ к каталогу данных.')
        finally:
            self.setup_button.setEnabled(True)

    def _refresh_session(self):
        if self.pages.currentWidget() is not self.session_page:
            return
        try:
            user = self.manager.current_user
            if user is None:
                self._logout()
                self.login_status.setText('Сеанс завершён: учётная запись недоступна.')
                return
            self.file_workspace.validate_session()
            self.database_workspace.validate_session()
            self.accounts_workspace.validate_session()
            self.session_tabs.setTabVisible(
                self.session_tabs.indexOf(self.accounts_workspace), user.is_admin)
            self.report_table.validate_session()
            self.file_workspace.register_button.setVisible(user.is_admin)
            self.connectivity.respond()
            if user.is_admin:
                self.connectivity.poll()
                if time.monotonic() >= self._next_board:
                    self._show_connections(automatic=True)
            else:
                self.connectivity_window.hide()
                self.connectivity_window.table.setRowCount(0)
            self.emergency_panel.setVisible(user.is_admin)
            if user.is_admin:
                ready, message = self.emergency.status()
                self.emergency_status.setText(message)
                self.compromise_button.setEnabled(ready)
            else:
                self.compromise_button.setEnabled(False)
            direction = self.db.fetch_one('SELECT name FROM directions WHERE id=?', (user.direction_id,))
            level = self.db.fetch_one('SELECT name FROM secrecy_levels WHERE id=?', (user.secrecy_level_id,))
            self.identity_label.setText(
                f'Пользователь: {user.login}\nРоль: {"Администратор" if user.is_admin else "Пользователь"}'
                f'\nНаправление: {direction[0] if direction else "—"}'
                f'\nУровень доступа: {level[0] if level else "—"}')
        except (sqlite3.Error, OSError):
            self._logout()
            self.login_status.setText('Сеанс завершён: не удалось проверить права доступа.')

    def _change_password(self):
        try:
            user = self.manager.current_user
        except (sqlite3.Error, OSError):
            self._logout()
            self.login_status.setText("Не удалось проверить сеанс. Войдите повторно.")
            return
        if user is None:
            self._logout()
            return
        if self.new_password.text() != self.repeat_password.text():
            self.session_status.setText('Новые пароли не совпадают.')
            return
        self.change_button.setEnabled(False)
        try:
            ok = self.manager.change_password(user.id, self.old_password.text(), self.new_password.text())
            self._clear_secrets()
            self.session_status.setText('Пароль изменён.' if ok else 'Проверьте текущий пароль и длину нового: от 8 до 1024 символов.')
        except (sqlite3.Error, OSError):
            self._clear_secrets()
            self.session_status.setText('Не удалось завершить операцию. Проверьте базу и журнал.')
        finally:
            self.change_button.setEnabled(True)

    def _show_connections(self, checked=False, automatic=False):
        try:
            rows = self.connectivity.offline_users()
            self.connectivity_window.display(rows)
            self._next_board = time.monotonic() + BOARD_SECONDS
            if rows or not automatic:
                self.connectivity_window.show()
        except PermissionError:
            self.connectivity_window.hide()
        except (sqlite3.Error, OSError):
            self.connections_status.setText('Не удалось обновить подключения: проверьте доступ к базе.')

    def _logout(self):
        self.file_workspace.clear_session()
        self.database_workspace.clear_session()
        self.accounts_workspace.clear_session()
        self.session_tabs.setTabVisible(self.session_tabs.indexOf(self.accounts_workspace), False)
        self.report_table.clear_session()
        self.session_tabs.setCurrentIndex(0)
        self.connectivity_window.hide()
        self.connectivity_window.table.setRowCount(0)
        self._next_board = 0
        try:
            self.manager.logout()
        except (sqlite3.Error, OSError):
            pass  # Менеджер очищает сеанс до записи события выхода.
        self._clear_secrets()
        self.identity_label.clear()
        self.session_status.clear()
        self.login_status.clear()
        self.pages.setCurrentWidget(self.login_page)
        self.password_edit.setFocus()

    def _prepare_emergency(self):
        user = self.manager.current_user
        if not user or not user.is_admin:
            self._refresh_session()
            return
        phrase, ok = QInputDialog.getText(self, 'Резервные пароли',
            'Парольная фраза для шифрования файла (минимум 12 символов).\nСохраните её отдельно от файла:', QLineEdit.Password)
        if not ok:
            return
        repeated, ok = QInputDialog.getText(self, 'Резервные пароли', 'Повторите парольную фразу:', QLineEdit.Password)
        if not ok:
            return
        if phrase != repeated:
            QMessageBox.warning(self, 'Резервные пароли', 'Парольные фразы не совпадают.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Сохранить новый резервный файл',
                                             'SecureShell-recovery.json', 'Зашифрованный файл (*.json)')
        if not path:
            return
        self.prepare_button.setEnabled(False)
        try:
            self.emergency.prepare(path, phrase)
            QMessageBox.information(self, 'Резервные пароли сохранены',
                'Резервный файл создан. До применения команды проверьте его через «Резервные пароли.bat».\n'
                'При запросе укажите этот файл и выбранную парольную фразу.\n'
                'Набор одноразовый; новый набор заменяет ранее подготовленный.')
        except (ValueError, PermissionError, OSError, sqlite3.Error) as exc:
            QMessageBox.warning(self, 'Не удалось подготовить пароли', str(exc))
        finally:
            self.prepare_button.setEnabled(True)
            self._refresh_session()

    def _compromise(self):
        ready, message = self.emergency.status()
        if not ready:
            QMessageBox.warning(self, 'Компрометация', message)
            return
        choice = QMessageBox.question(self, 'Компрометация',
            'Сбросить пароли всех активных аккаунтов на подготовленные резервные пароли '
            'и завершить все сеансы, включая ваш?\n'
            'Убедитесь, что резервный файл и его парольная фраза доступны. '
            'Отчёт активности будет сохранён автоматически.',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if choice != QMessageBox.Yes:
            return
        self.compromise_button.setEnabled(False)
        try:
            result = self.emergency.activate()
        except (ValueError, PermissionError, OSError, sqlite3.Error) as exc:
            QMessageBox.warning(self, 'Команда не выполнена', str(exc))
            self._refresh_session()
            return
        self._logout()
        text = 'Все сеансы отозваны. Для входа используйте резервные пароли.'
        if result['report_path']:
            text += '\nОтчёт: ' + result['report_path']
        else:
            text += '\nОтчёт сохранён в БД (emergency_reports), ID: ' + result['incident_id']
            text += '\nНе удалось создать копию файла: ' + result['export_error']
        self.login_status.setText(text)
        QMessageBox.information(self, 'Команда выполнена', text)

    def closeEvent(self, event):
        self.timer.stop()
        self._logout()
        event.accept()

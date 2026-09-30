"""Управление учётными записями через проверяемые права администратора."""
import sqlite3

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QHeaderView, QDialog, QDialogButtonBox, QComboBox, QCheckBox, QMessageBox,
)


def _password_fields(form):
    fields = []
    for label in ('Новый пароль', 'Повтор пароля'):
        field = QLineEdit()
        field.setEchoMode(QLineEdit.Password)
        field.setMaxLength(1024)
        form.addRow(label, field)
        fields.append(field)
    return fields


class PasswordDialog(QDialog):
    """Ввод нового пароля без отображения сохранённых учётных данных."""

    def __init__(self, parent=None, title='Новый пароль'):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.layout = QVBoxLayout(self)
        self.form = QFormLayout()
        self.layout.addLayout(self.form)
        self.password, self.repeat = _password_fields(self.form)
        self._add_buttons()

    def _add_buttons(self):
        self.status = QLabel('Пароль должен содержать от 8 до 1024 символов.')
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        self.layout.addWidget(self.status)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Save).setText('Сохранить')
        self.buttons.button(QDialogButtonBox.Cancel).setText('Отмена')
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def accept(self):
        if self.password is not None:
            if not 8 <= len(self.password.text()) <= 1024:
                self.status.setText('Пароль должен содержать от 8 до 1024 символов.')
                return
            if self.password.text() != self.repeat.text():
                self.status.setText('Пароли не совпадают.')
                return
        super().accept()

    def values(self):
        return {'password': self.password.text()}

    def clear_passwords(self):
        for field in (self.password, self.repeat):
            if field is not None:
                field.clear()

    def clear_contents(self):
        self.clear_passwords()
        self.setWindowTitle('Новый пароль')


class AccountDialog(PasswordDialog):
    def __init__(self, db, user=None, parent=None):
        # Форма редактирования не получает пароль или его хеш из базы.
        QDialog.__init__(self, parent)
        self.setWindowTitle('Изменить учётную запись' if user else 'Создать учётную запись')
        self.layout = QVBoxLayout(self)
        self.form = QFormLayout()
        self.layout.addLayout(self.form)
        self.login = QLineEdit(user.login if user else '')
        self.login.setMaxLength(200)
        self.login.setReadOnly(user is not None)
        self.form.addRow('Логин', self.login)
        self.direction = QComboBox()
        self.level = QComboBox()
        for row in db.fetch_all('SELECT id,name FROM directions ORDER BY id'):
            self.direction.addItem(row['name'], row['id'])
        for row in db.fetch_all('SELECT id,name FROM secrecy_levels ORDER BY level_order,id'):
            self.level.addItem(row['name'], row['id'])
        self.form.addRow('Направление', self.direction)
        self.form.addRow('Уровень доступа', self.level)
        self.is_admin = QCheckBox('Права администратора')
        self.form.addRow(self.is_admin)
        if user:
            self.direction.setCurrentIndex(self.direction.findData(user.direction_id))
            self.level.setCurrentIndex(self.level.findData(user.secrecy_level_id))
            self.is_admin.setChecked(user.is_admin)
            self.password = self.repeat = None
        else:
            self.password, self.repeat = _password_fields(self.form)
        self._add_buttons()
        if user:
            self.status.setText('Пароль изменяется отдельно кнопкой «Сбросить пароль».')

    def accept(self):
        if not self.login.text().strip():
            self.status.setText('Введите логин.')
            return
        if self.direction.currentData() is None or self.level.currentData() is None:
            self.status.setText('Выберите направление и уровень доступа.')
            return
        super().accept()

    def values(self):
        result = {
            'login': self.login.text().strip(),
            'direction_id': self.direction.currentData(),
            'secrecy_level_id': self.level.currentData(),
            'is_admin': self.is_admin.isChecked(),
        }
        if self.password is not None:
            result['password'] = self.password.text()
        return result

    def clear_contents(self):
        super().clear_contents()
        self.login.clear()
        self.direction.setCurrentIndex(-1)
        self.level.setCurrentIndex(-1)
        self.is_admin.setChecked(False)
        self.setWindowTitle('Учётная запись')


class AccountsWorkspace(QWidget):
    def __init__(self, db, manager, parent=None):
        super().__init__(parent)
        self.db = db
        self.manager = manager
        self._active_dialog = None
        layout = QVBoxLayout(self)
        description = QLabel('Активные учётные записи. Доступ к управлению имеет только администратор. '
                             'Деактивация сохраняет документы пользователя и историю действий.')
        description.setWordWrap(True)
        layout.addWidget(description)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['ID', 'Логин', 'Направление', 'Уровень доступа', 'Роль'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        layout.addWidget(self.table)
        buttons = QHBoxLayout()
        self.create_button = QPushButton('Создать пользователя')
        self.edit_button = QPushButton('Изменить права')
        self.reset_button = QPushButton('Сбросить пароль')
        self.deactivate_button = QPushButton('Деактивировать')
        self.refresh_button = QPushButton('Обновить')
        for button, action in (
            (self.create_button, self.create_user), (self.edit_button, self.edit_user),
            (self.reset_button, self.reset_password), (self.deactivate_button, self.deactivate_user),
            (self.refresh_button, self.refresh),
        ):
            button.clicked.connect(action)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.status = QLabel('')
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        layout.addWidget(self.status)
        self.clear_session()

    def _current_admin(self):
        user = self.manager.current_user
        return user if user and user.is_admin else None

    def _ensure_admin(self):
        try:
            actor = self._current_admin()
        except (sqlite3.Error, OSError):
            self.clear_session()
            self.status.setText('Не удалось проверить права доступа. Войдите повторно.')
            return None
        if not actor:
            self.clear_session()
            self.status.setText('Управление учётными записями доступно только администратору.')
        return actor

    def _selected_id(self):
        selected = self.table.selectionModel().selectedRows()
        item = self.table.item(selected[0].row(), 0) if selected else None
        return item.data(Qt.UserRole) if item else None

    def _selection_changed(self):
        actor = self._ensure_admin()
        if not actor:
            return
        selected = self._selected_id()
        self.edit_button.setEnabled(selected is not None)
        self.reset_button.setEnabled(selected is not None)
        self.deactivate_button.setEnabled(selected is not None and selected != actor.id)

    def refresh(self):
        if not self._ensure_admin():
            return
        selected = self._selected_id()
        try:
            users = self.manager.get_all_users()
            directions = {r['id']: r['name'] for r in self.db.fetch_all('SELECT id,name FROM directions')}
            levels = {r['id']: r['name'] for r in self.db.fetch_all('SELECT id,name FROM secrecy_levels')}
            if not self._ensure_admin():
                return
            self.table.blockSignals(True)
            try:
                self.table.setRowCount(len(users))
                self.table.clearSelection()
                for index, user in enumerate(users):
                    values = (str(user.id), user.login, directions.get(user.direction_id, '—'),
                              levels.get(user.secrecy_level_id, '—'),
                              'Администратор' if user.is_admin else 'Пользователь')
                    for column, value in enumerate(values):
                        self.table.setItem(index, column, QTableWidgetItem(value))
                    self.table.item(index, 0).setData(Qt.UserRole, user.id)
                    if user.id == selected:
                        self.table.selectRow(index)
            finally:
                self.table.blockSignals(False)
            self.table.setEnabled(True)
            self.create_button.setEnabled(True)
            self.refresh_button.setEnabled(True)
            self._selection_changed()
            self.status.clear()
        except (sqlite3.Error, OSError):
            self.clear_session()
            self.status.setText('Не удалось загрузить учётные записи. Проверьте доступ к базе.')

    def validate_session(self):
        if self._ensure_admin() and not self.create_button.isEnabled():
            self.refresh()

    def clear_session(self):
        if self._active_dialog is not None:
            self._active_dialog.clear_contents()
            self._active_dialog.reject()
        self.table.blockSignals(True)
        try:
            self.table.clearContents()
            self.table.setRowCount(0)
        finally:
            self.table.blockSignals(False)
        self.table.setEnabled(False)
        for button in (self.create_button, self.edit_button, self.reset_button,
                       self.deactivate_button, self.refresh_button):
            button.setEnabled(False)
        self.status.clear()

    def _target(self):
        if not self._ensure_admin():
            return None
        user_id = self._selected_id()
        if user_id is None:
            self.status.setText('Выберите учётную запись.')
            return None
        target = self.manager.get_user_by_id(user_id)
        if target is None:
            self.refresh()
            self.status.setText('Учётная запись больше недоступна. Список обновлён.')
        return target

    def _dialog_values(self, dialog):
        self._active_dialog = dialog
        try:
            if dialog.exec_() == QDialog.Accepted and self._ensure_admin():
                return dialog.values()
            return None
        finally:
            dialog.clear_contents()
            self._active_dialog = None
            dialog.deleteLater()

    def _complete(self, ok, success, failure):
        self.refresh()
        if self._ensure_admin():
            self.status.setText(success if ok else failure)

    def _error(self):
        self.status.setText('Не удалось завершить операцию. Проверьте доступ к базе и журналу.')

    def create_user(self):
        if not self._ensure_admin():
            return
        try:
            values = self._dialog_values(AccountDialog(self.db, parent=self))
            if values is None:
                return
            ok = self.manager.register_user(**values)
            self._complete(ok, 'Учётная запись создана.',
                           'Не удалось создать пользователя. Проверьте логин, пароль и права доступа.')
        except (sqlite3.Error, OSError):
            self._error()

    def edit_user(self):
        try:
            target = self._target()
            if not target:
                return
            values = self._dialog_values(AccountDialog(self.db, target, self))
            if values is None:
                return
            values.pop('login')
            ok = self.manager.update_user(target.id, **values)
            self._complete(ok, 'Права пользователя изменены.',
                           'Изменение отклонено. Нельзя снять права последнего администратора.')
        except (sqlite3.Error, OSError):
            self._error()

    def reset_password(self):
        try:
            target = self._target()
            if not target:
                return
            values = self._dialog_values(PasswordDialog(self, f'Сброс пароля: {target.login}'))
            if values is None:
                return
            ok = self.manager.reset_password(target.id, values['password'])
            self._complete(ok, 'Пароль пользователя изменён.',
                           'Сброс пароля отклонён. Проверьте пароль и доступность учётной записи.')
        except (sqlite3.Error, OSError):
            self._error()

    def deactivate_user(self):
        try:
            target = self._target()
            if not target:
                return
            if QMessageBox.question(
                self, 'Деактивация пользователя',
                f'Деактивировать учётную запись «{target.login}» и завершить её сеансы?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            ) != QMessageBox.Yes or not self._ensure_admin():
                return
            ok = self.manager.delete_user(target.id)
            self._complete(ok, 'Учётная запись деактивирована.',
                           'Деактивация отклонена. Нельзя деактивировать свой аккаунт.')
        except (sqlite3.Error, OSError):
            self._error()

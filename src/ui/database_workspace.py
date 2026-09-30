"""Библиотека сохранённых таблиц и защищённых исходных документов."""
import json
import sqlite3
from pathlib import Path

from PyQt5.QtCore import Qt, QSignalBlocker
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QTabWidget, QListWidget,
    QListWidgetItem, QLineEdit, QPlainTextEdit, QPushButton, QLabel, QSplitter,
    QComboBox, QFileDialog, QMessageBox,
    QDialog, QDialogButtonBox,
)

from storage.document_storage import DocumentStorage, MAX_DOCUMENT_BYTES
from storage.report_format import MAX_TABLE_BYTES


STORAGE_ERRORS = (PermissionError, ValueError, LookupError, OSError, UnicodeError, sqlite3.Error)


class DatabaseWorkspace(QWidget):
    def __init__(self, db_manager, login_manager, parent=None):
        super().__init__(parent)
        self.storage = DocumentStorage(db_manager, login_manager)
        self.db = db_manager
        self.login = login_manager
        self.stored_table_callback = None
        self._identity = None
        self._document_id = None
        self._revision = None
        self._original_name = ''
        self._baseline_title = ''
        self._baseline_content = ''
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self._build_tables()
        self._build_documents()
        self.status = QLabel('')
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.clear_session()

    def _build_tables(self):
        self.tables_page = QWidget()
        layout = QVBoxLayout(self.tables_page)
        note = QLabel('Сохранённые таблицы доступны согласно направлению и уровню доступа вашей учётной записи.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.table_list = QListWidget()
        self.table_list.setAccessibleName('Сохранённые таблицы')
        layout.addWidget(self.table_list, 1)
        buttons = QHBoxLayout()
        self.open_table_button = QPushButton('Открыть таблицу')
        self.open_table_button.clicked.connect(self.open_table)
        self.refresh_button = QPushButton('Обновить список')
        self.refresh_button.clicked.connect(self.refresh)
        self.import_table_button = QPushButton('Импорт таблицы JSON…')
        self.import_table_button.clicked.connect(self.import_table)
        self.delete_table_button = QPushButton('Удалить таблицу…')
        self.delete_table_button.clicked.connect(self.delete_table)
        self.table_access_button = QPushButton('Права таблицы…')
        self.table_access_button.clicked.connect(self.change_table_access)
        for button in (self.open_table_button, self.refresh_button,
                       self.import_table_button, self.table_access_button, self.delete_table_button):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.table_list.itemDoubleClicked.connect(self.open_table)
        self.tabs.addTab(self.tables_page, 'Сохранённые таблицы')

    def _build_documents(self):
        self.documents_page = QWidget()
        layout = QVBoxLayout(self.documents_page)
        note = QLabel('Исходные документы доступны только администраторам. '
                      'Создайте документ или импортируйте текст UTF-8, затем сохраните его и конвертируйте в таблицу.')
        note.setWordWrap(True)
        layout.addWidget(note)
        split = QSplitter()
        self.document_list = QListWidget()
        self.document_list.setAccessibleName('Исходные документы')
        split.addWidget(self.document_list)
        editor_page = QWidget()
        editor_layout = QVBoxLayout(editor_page)
        editor_layout.setContentsMargins(8, 0, 0, 0)
        form = QFormLayout()
        self.document_title = QLineEdit()
        self.document_title.setMaxLength(500)
        form.addRow('Название', self.document_title)
        editor_layout.addLayout(form)
        self.document_info = QLabel('')
        self.document_info.setTextFormat(Qt.PlainText)
        editor_layout.addWidget(self.document_info)
        self.editor = QPlainTextEdit()
        self.editor.setAccessibleName('Текст исходного документа')
        self.editor.setPlaceholderText('CSV/TSV: 13 столбцов таблицы; также поддерживается JSON таблицы приложения.')
        editor_layout.addWidget(self.editor, 1)
        split.addWidget(editor_page)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)
        buttons = QHBoxLayout()
        self.new_document_button = QPushButton('Новый документ')
        self.new_document_button.clicked.connect(self.new_document)
        self.import_document_button = QPushButton('Импорт текста…')
        self.import_document_button.clicked.connect(self.import_document)
        self.save_document_button = QPushButton('Сохранить')
        self.save_document_button.clicked.connect(self.save_document)
        self.delete_document_button = QPushButton('Удалить…')
        self.delete_document_button.clicked.connect(self.delete_document)
        for button in (self.new_document_button, self.import_document_button,
                       self.save_document_button, self.delete_document_button):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        conversion = QHBoxLayout()
        conversion.addWidget(QLabel('Разделитель:'))
        self.delimiter = QComboBox()
        for name, value in (('Автоматически', 'auto'), ('Табуляция', '\t'),
                            ('Точка с запятой', ';'), ('Запятая', ',')):
            self.delimiter.addItem(name, value)
        conversion.addWidget(self.delimiter)
        self.convert_button = QPushButton('Сохранить и конвертировать')
        self.convert_button.clicked.connect(self.convert_document)
        conversion.addWidget(self.convert_button)
        conversion.addStretch()
        layout.addLayout(conversion)
        self.document_list.currentItemChanged.connect(self._select_document)

    def _error(self, title, error):
        self.status.setText(str(error))
        QMessageBox.warning(self, title, str(error))
        if isinstance(error, PermissionError):
            self.validate_session()

    def _is_dirty(self):
        return (self.editor.toPlainText() != self._baseline_content
                or self.document_title.text() != self._baseline_title)

    def _confirm_discard(self):
        if not self._is_dirty():
            return True
        return QMessageBox.question(
            self, 'Несохранённые изменения', 'Отменить несохранённые изменения исходного документа?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def _clear_document(self):
        self._document_id = None
        self._revision = None
        self._original_name = ''
        self._baseline_title = ''
        self._baseline_content = ''
        self.document_title.clear()
        self.document_info.clear()
        self.editor.clear()
        self.editor.document().setModified(False)

    def _display_document(self, document):
        self._document_id = document['id']
        self._revision = document['revision']
        self._original_name = document.get('original_name', '')
        self._baseline_title = document['title']
        self.document_title.setText(document['title'])
        self.editor.setPlainText(document['content'])
        self._baseline_content = self.editor.toPlainText()
        self.editor.document().setModified(False)
        self.document_info.setText(f'Версия {document["revision"]}'
                                  + (f' · {self._original_name}' if self._original_name else ''))

    def _apply_role(self, user):
        admin = bool(user and user.is_admin)
        self.import_table_button.setVisible(admin)
        self.delete_table_button.setVisible(admin)
        self.table_access_button.setVisible(admin)
        self.documents_page.setEnabled(admin)
        index = self.tabs.indexOf(self.documents_page)
        if admin and index < 0:
            self.tabs.addTab(self.documents_page, 'Исходные документы')
        elif not admin:
            if index >= 0:
                self.tabs.removeTab(index)
            self._clear_document()
            self.document_list.clear()

    def clear_session(self):
        self._identity = None
        self._clear_document()
        self.document_list.clear()
        self.table_list.clear()
        self._apply_role(None)
        self.status.clear()
        self.tabs.setCurrentIndex(0)

    @staticmethod
    def _selected_id(widget):
        item = widget.currentItem()
        return item.data(Qt.UserRole) if item is not None else None

    @staticmethod
    def _fill_list(widget, records, selected_id, *, documents=False):
        blocker = QSignalBlocker(widget)
        widget.clear()
        selected = None
        for record in records:
            suffix = f' · версия {record["revision"]}' if documents else ''
            if not documents and record.get('source_document_id') is not None:
                suffix = f' · из документа, версия {record["source_revision"]}'
            item = QListWidgetItem(record['title'] + suffix)
            item.setData(Qt.UserRole, record['id'])
            widget.addItem(item)
            if record['id'] == selected_id:
                selected = item
        if selected is not None:
            widget.setCurrentItem(selected)
        del blocker

    def refresh(self):
        try:
            user = self.login.current_user
            if user is None:
                self.clear_session()
                return False
            self._apply_role(user)
            tables = self.storage.list_tables()
            self._fill_list(self.table_list, tables, self._selected_id(self.table_list))
            if user.is_admin:
                documents = self.storage.list_documents()
                self._fill_list(self.document_list, documents, self._document_id, documents=True)
                if self._document_id is not None and not any(
                        row['id'] == self._document_id for row in documents):
                    self._clear_document()
            self._identity = (user.id, user.is_admin, user.direction_id, user.secrecy_level_id)
            self.status.setText(f'Доступных таблиц: {len(tables)}.')
            return True
        except STORAGE_ERRORS as exc:
            self.clear_session()
            self.status.setText('Не удалось обновить библиотеку: ' + str(exc))
            return False

    def validate_session(self):
        user = self.login.current_user
        if user is None:
            self.clear_session()
            return
        identity = (user.id, user.is_admin, user.direction_id, user.secrecy_level_id)
        if self._identity != identity:
            self.refresh()
        if self._document_id is not None:
            try:
                document = self.storage.get_document(self._document_id)
            except (PermissionError, LookupError):
                self._clear_document()
                self.refresh()
            else:
                if document['revision'] != self._revision:
                    if self._is_dirty():
                        self.status.setText('Документ изменён другим пользователем. '
                                            'Скопируйте свои изменения и откройте документ заново.')
                    else:
                        self._display_document(document)

    def _require_admin(self):
        user = self.login.current_user
        if user is None or not user.is_admin:
            self.validate_session()
            raise PermissionError('Для этой операции нужны права администратора.')

    def open_table(self, *_args):
        table_id = self._selected_id(self.table_list)
        if table_id is None:
            self.status.setText('Выберите сохранённую таблицу.')
            return
        if self.stored_table_callback is not None:
            self.stored_table_callback(table_id)

    def _select_document(self, current, previous):
        if current is None:
            return
        if not self._confirm_discard():
            blocker = QSignalBlocker(self.document_list)
            self.document_list.setCurrentItem(previous)
            del blocker
            return
        try:
            self._display_document(self.storage.get_document(current.data(Qt.UserRole)))
            self.status.clear()
        except STORAGE_ERRORS as exc:
            self._clear_document()
            self._error('Не удалось открыть документ', exc)

    def new_document(self):
        try:
            self._require_admin()
            if not self._confirm_discard():
                return
            blocker = QSignalBlocker(self.document_list)
            self.document_list.setCurrentItem(None)
            del blocker
            self._clear_document()
            self._baseline_title = 'Новый документ'
            self.document_title.setText(self._baseline_title)
            self.document_title.setFocus()
            self.status.setText('Введите текст и сохраните документ.')
        except STORAGE_ERRORS as exc:
            self._error('Не удалось создать документ', exc)

    @staticmethod
    def _read_utf8(path, limit):
        with open(path, 'rb') as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('Файл превышает допустимый размер.')
        return raw.decode('utf-8-sig')

    def import_document(self):
        try:
            self._require_admin()
            if not self._confirm_discard():
                return
            path, _ = QFileDialog.getOpenFileName(
                self, 'Импорт исходного документа UTF-8', '', 'Текстовые документы (*.txt *.csv *.tsv *.json)')
            if not path:
                return
            source = Path(path)
            if source.suffix.lower() not in ('.txt', '.csv', '.tsv', '.json'):
                raise ValueError('Выберите текстовый документ TXT, CSV, TSV или JSON.')
            content = self._read_utf8(path, MAX_DOCUMENT_BYTES)
            document = self.storage.create_document(source.stem, content, original_name=source.name)
            self._display_document(document)
            self.refresh()
            self.status.setText('Исходный документ импортирован. Выберите разделитель и выполните конвертирование.')
        except STORAGE_ERRORS as exc:
            self._error('Не удалось импортировать документ', exc)

    def save_document(self):
        try:
            self._require_admin()
            title = self.document_title.text().strip()
            content = self.editor.toPlainText()
            if self._document_id is None:
                document = self.storage.create_document(title, content, original_name=self._original_name)
            else:
                document = self.storage.update_document(
                    self._document_id, title, content, expected_revision=self._revision)
            self._display_document(document)
            self.refresh()
            self.status.setText('Исходный документ сохранён. Конвертирование создаст новую таблицу из этой версии.')
            return True
        except STORAGE_ERRORS as exc:
            self._error('Не удалось сохранить документ', exc)
            return False

    def convert_document(self):
        try:
            self._require_admin()
            if (self._document_id is None or self._is_dirty()) and not self.save_document():
                return
            self._display_document(self.storage.get_document(self._document_id))
            table = self.storage.convert_document(self._document_id, delimiter=self.delimiter.currentData())
            self.refresh()
            self.status.setText('Таблица сохранена. Исходный документ остаётся доступен только администраторам.')
            if self.stored_table_callback is not None:
                self.stored_table_callback(table['id'])
        except STORAGE_ERRORS as exc:
            self._error('Не удалось конвертировать документ', exc)

    def import_table(self):
        try:
            self._require_admin()
            path, _ = QFileDialog.getOpenFileName(self, 'Импорт готовой таблицы', '', 'Таблица приложения (*.json)')
            if not path:
                return
            report = json.loads(self._read_utf8(path, MAX_TABLE_BYTES))
            title = report.get('title', Path(path).stem) if isinstance(report, dict) else Path(path).stem
            table = self.storage.import_table(title, report)
            self.refresh()
            self.status.setText('Таблица импортирована и сохранена.')
            if self.stored_table_callback is not None:
                self.stored_table_callback(table['id'])
        except STORAGE_ERRORS as exc:
            self._error('Не удалось импортировать таблицу', exc)

    def delete_document(self):
        try:
            self._require_admin()
            if self._document_id is None:
                self.status.setText('Выберите сохранённый исходный документ.')
                return
            if QMessageBox.question(
                    self, 'Удаление документа',
                    'Удалить исходный документ? Если из него созданы таблицы, сначала удалите их.',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
            self.storage.delete_document(self._document_id)
            self._clear_document()
            self.refresh()
            self.status.setText('Исходный документ удалён.')
        except STORAGE_ERRORS as exc:
            self._error('Не удалось удалить документ', exc)

    def delete_table(self):
        try:
            self._require_admin()
            table_id = self._selected_id(self.table_list)
            if table_id is None:
                self.status.setText('Выберите таблицу для удаления.')
                return
            if QMessageBox.question(
                    self, 'Удаление таблицы', 'Удалить сохранённую таблицу?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
            self.storage.delete_table(table_id)
            self.refresh()
            self.status.setText('Таблица удалена.')
        except STORAGE_ERRORS as exc:
            self._error('Не удалось удалить таблицу', exc)

    def change_table_access(self):
        try:
            self._require_admin()
            table_id = self._selected_id(self.table_list)
            if table_id is None:
                self.status.setText('Выберите таблицу, для которой нужно изменить доступ.')
                return
            record = self.storage.get_table(table_id)
            directions = self.db.fetch_all('SELECT id, name FROM directions ORDER BY id')
            levels = self.db.fetch_all('SELECT id, name FROM secrecy_levels ORDER BY level_order')
            dialog = QDialog(self)
            dialog.setWindowTitle('Права таблицы')
            layout = QVBoxLayout(dialog)
            note = QLabel('Таблицу смогут открыть пользователи выбранного направления '
                          'с указанным или более высоким уровнем доступа. '
                          'Исходный документ останется доступен только администраторам.')
            note.setWordWrap(True)
            layout.addWidget(note)
            form = QFormLayout()
            direction = QComboBox()
            level = QComboBox()
            for row in directions:
                direction.addItem(row['name'], row['id'])
            for row in levels:
                level.addItem(row['name'], row['id'])
            direction.setCurrentIndex(direction.findData(record['direction_id']))
            level.setCurrentIndex(level.findData(record['secrecy_level_id']))
            form.addRow('Направление', direction)
            form.addRow('Уровень доступа', level)
            layout.addLayout(form)
            buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            buttons.button(QDialogButtonBox.Save).setText('Сохранить')
            buttons.button(QDialogButtonBox.Cancel).setText('Отмена')
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            if dialog.exec_() != QDialog.Accepted:
                return
            self.storage.set_table_access(table_id, direction.currentData(), level.currentData())
            self.refresh()
            self.status.setText('Права таблицы изменены.')
        except STORAGE_ERRORS as exc:
            self._error('Не удалось изменить доступ', exc)

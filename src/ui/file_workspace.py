"""File browser and UTF-8 editor backed exclusively by FileOperations."""
import os
import json
import sqlite3
from pathlib import Path

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QPlainTextEdit, QLabel, QPushButton, QInputDialog, QMessageBox, QFileDialog, QSizePolicy,
)

from file_manager.file_ops import FileOperations
from ui.report_table import EXAMPLE_REPORT

MAX_TEXT_BYTES = 2 * 1024 * 1024
_ITEM_PATH = Qt.UserRole
_ITEM_DIRECTORY = Qt.UserRole + 1


class FileWorkspace(QWidget):
    def __init__(self, db_manager, login_manager, parent=None):
        super().__init__(parent)
        self.ops = FileOperations(db_manager, login_manager)
        self._path = None
        self._original = None
        self.open_table_callback = None
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        self.refresh_button = QPushButton('Обновить каталоги')
        self.register_button = QPushButton('Зарегистрировать каталог…')
        self.folder_button = QPushButton('Новая папка')
        self.new_button = QPushButton('Новый текстовый файл')
        self.save_button = QPushButton('Сохранить')
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.register_button)
        buttons.addWidget(self.folder_button)
        layout.addLayout(buttons)
        table_buttons = QHBoxLayout()
        self.example_button = QPushButton('Создать образец таблицы')
        self.table_button = QPushButton('Показать как таблицу')
        table_buttons.addWidget(self.new_button)
        table_buttons.addWidget(self.example_button)
        table_buttons.addWidget(self.table_button)
        table_buttons.addWidget(self.save_button)
        layout.addLayout(table_buttons)
        splitter = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel('Доступные файлы и каталоги')
        self.tree.setMinimumWidth(230)
        splitter.addWidget(self.tree)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.filename = QLabel('Откройте текстовый файл двойным щелчком')
        self.filename.setTextFormat(Qt.PlainText)
        self.filename.setWordWrap(True)
        right_layout.addWidget(self.filename)
        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText('Текст в кодировке UTF-8')
        self.editor.setEnabled(False)
        right_layout.addWidget(self.editor)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        self.status = QLabel('')
        self.status.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.refresh_button.clicked.connect(self.refresh)
        self.register_button.clicked.connect(self.register_root)
        self.folder_button.clicked.connect(self.create_folder)
        self.new_button.clicked.connect(self.create_text)
        self.example_button.clicked.connect(self.create_table_example)
        self.table_button.clicked.connect(self.open_as_table)
        self.save_button.clicked.connect(self.save)
        self.tree.itemExpanded.connect(self._expand)
        self.tree.itemDoubleClicked.connect(self._activate)
        self.save_button.setEnabled(False)

    def clear_session(self):
        """Forget protected content immediately when the session ends."""
        self._path = None
        self._original = None
        self.editor.clear()
        self.editor.setEnabled(False)
        self.save_button.setEnabled(False)
        self.filename.setText('Откройте текстовый файл двойным щелчком')
        self.tree.clear()
        self.status.clear()
        self.register_button.hide()

    def validate_session(self):
        if self._path and not self.ops.permissions.can_access_file(
                self.ops.login.current_user, self._path):
            self.clear_session()

    def _message(self, title, exc):
        self.status.setText(str(exc))
        QMessageBox.warning(self, title, str(exc))

    def _item(self, path, directory, label=None):
        item = QTreeWidgetItem([label if label is not None else Path(path).name])
        item.setData(0, _ITEM_PATH, str(path))
        item.setData(0, _ITEM_DIRECTORY, directory)
        if directory:
            item.addChild(QTreeWidgetItem(['Загрузка…']))
        return item

    def refresh(self):
        self.tree.clear()
        try:
            user = self.ops.login.current_user
            self.register_button.setVisible(bool(user and user.is_admin))
            roots = self.ops.list_accessible_roots()
            for path in roots:
                self.tree.addTopLevelItem(self._item(path, True, path))
            self.status.setText('Зарегистрированных доступных каталогов нет.' if not roots else '')
        except (PermissionError, OSError, sqlite3.Error) as exc:
            self._message('Не удалось обновить каталоги', exc)

    def _expand(self, item):
        path = item.data(0, _ITEM_PATH)
        item.takeChildren()
        try:
            for name in sorted(self.ops.list_directory(path), key=str.casefold):
                child_path = os.path.join(path, name)
                try:
                    directory = self.ops.is_directory(child_path)
                except (PermissionError, OSError, sqlite3.Error):
                    continue
                item.addChild(self._item(child_path, directory, name))
        except (PermissionError, OSError, sqlite3.Error) as exc:
            self._message('Не удалось открыть каталог', exc)

    def _confirm_discard(self):
        if not self.editor.document().isModified():
            return True
        return QMessageBox.question(
            self, 'Несохранённые изменения', 'Отменить несохранённые изменения?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def _activate(self, item, column=0):
        if item.data(0, _ITEM_DIRECTORY):
            return
        self.open_file(item.data(0, _ITEM_PATH))

    def open_file(self, path, discard_confirmed=False):
        if self._path == path and self.editor.document().isModified():
            return
        if not discard_confirmed and not self._confirm_discard():
            return
        try:
            data = self.ops.read_bytes(path, max_bytes=MAX_TEXT_BYTES)
            text = data.decode('utf-8')
            if '\x00' in text:
                raise ValueError('Двоичный файл нельзя открыть в текстовом редакторе')
        except (PermissionError, OSError, ValueError, UnicodeError, sqlite3.Error) as exc:
            self._message('Не удалось открыть файл', exc)
            return
        self._path = path
        self._original = data
        self.editor.setPlainText(text)
        self.editor.document().setModified(False)
        self.editor.setEnabled(True)
        self.save_button.setEnabled(True)
        self.filename.setText(path)
        self.status.setText('Файл открыт.')

    def create_text(self):
        item = self.tree.currentItem()
        if item is None:
            self.status.setText('Выберите каталог для нового файла.')
            return
        directory = item.data(0, _ITEM_PATH)
        if not item.data(0, _ITEM_DIRECTORY):
            directory = str(Path(directory).parent)
        name = self._ask_name('Новый текстовый файл')
        if name is None:
            return
        if not self._confirm_discard():
            return
        path = os.path.join(directory, name)
        try:
            self.ops.create_text_file(path)
            self.refresh()
            self.open_file(path, discard_confirmed=True)
        except (PermissionError, OSError, ValueError, sqlite3.Error) as exc:
            self._message('Не удалось создать файл', exc)

    def _ask_name(self, title):
        name, ok = QInputDialog.getText(self, title, 'Имя:')
        if not ok:
            return None
        if not name or name in ('.', '..') or Path(name).name != name or '\\' in name or '/' in name:
            self.status.setText('Укажите имя без разделителей пути.')
            return None
        return name

    def create_folder(self):
        item = self.tree.currentItem()
        if item is None:
            self.status.setText('Выберите родительский каталог.')
            return
        parent = item.data(0, _ITEM_PATH)
        if not item.data(0, _ITEM_DIRECTORY):
            parent = str(Path(parent).parent)
        name = self._ask_name('Новая папка')
        if name is None:
            return
        try:
            self.ops.create_directory(os.path.join(parent, name))
            self.refresh()
            self.status.setText('Папка создана.')
        except (PermissionError, OSError, ValueError, sqlite3.Error) as exc:
            self._message('Не удалось создать папку', exc)

    def open_as_table(self):
        item = self.tree.currentItem()
        if item is None or item.data(0, _ITEM_DIRECTORY):
            self.status.setText('Выберите файл таблицы в проводнике.')
            return
        if self.open_table_callback is not None:
            self.open_table_callback(item.data(0, _ITEM_PATH))

    def create_table_example(self):
        item = self.tree.currentItem()
        if item is None:
            self.status.setText('Выберите каталог для образца таблицы.')
            return
        directory = item.data(0, _ITEM_PATH)
        if not item.data(0, _ITEM_DIRECTORY):
            directory = str(Path(directory).parent)
        path = os.path.join(directory, 'Пример таблицы.json')
        try:
            self.ops.create_text_file(path, json.dumps(EXAMPLE_REPORT, ensure_ascii=False, indent=2))
            self.refresh()
            self.status.setText('Образец создан.')
            if self.open_table_callback is not None:
                self.open_table_callback(path)
        except (PermissionError, OSError, ValueError, sqlite3.Error) as exc:
            self._message('Не удалось создать образец', exc)

    def register_root(self):
        user = self.ops.login.current_user
        if not user or not user.is_admin:
            return
        path = QFileDialog.getExistingDirectory(self, 'Зарегистрировать каталог')
        if not path:
            return
        try:
            directions = self.ops.db.fetch_all('SELECT id, name FROM directions ORDER BY id')
            levels = self.ops.db.fetch_all('SELECT id, name FROM secrecy_levels ORDER BY level_order')
            direction, ok = QInputDialog.getItem(self, 'Направление', 'Направление каталога:',
                                                  [row['name'] for row in directions], 0, False)
            if not ok:
                return
            level, ok = QInputDialog.getItem(self, 'Уровень', 'Уровень каталога:',
                                              [row['name'] for row in levels], 0, False)
            if not ok:
                return
            direction_id = next(row['id'] for row in directions if row['name'] == direction)
            level_id = next(row['id'] for row in levels if row['name'] == level)
            self.ops.register_directory(path, direction_id, level_id)
            self.refresh()
            self.status.setText('Каталог зарегистрирован.')
        except (PermissionError, OSError, ValueError, sqlite3.Error) as exc:
            self._message('Не удалось зарегистрировать каталог', exc)

    def save(self):
        if self._path is None:
            return
        try:
            # Warn when another process changed the opened file in the meantime.
            if self.ops.read_bytes(self._path, max_bytes=MAX_TEXT_BYTES) != self._original:
                raise ValueError('Файл изменён после открытия. Откройте его заново перед сохранением.')
            data = self.editor.toPlainText().encode('utf-8')
            if len(data) > MAX_TEXT_BYTES:
                raise ValueError('Текст превышает предел редактора (2 МиБ).')
            self.ops.write_bytes(self._path, data)
        except (PermissionError, OSError, ValueError, UnicodeError, sqlite3.Error) as exc:
            self._message('Не удалось сохранить файл', exc)
            return
        self._original = data
        self.editor.document().setModified(False)
        self.status.setText('Файл сохранён.')

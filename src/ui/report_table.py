"""Read-only, structured report tables opened through the authorized file service."""
import json
import sqlite3

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QMessageBox, QAbstractItemView,
)

from file_manager.file_ops import FileOperations
from storage.document_storage import DocumentStorage
from storage.report_format import (
    FORMAT, MAX_TABLE_BYTES, COLUMNS, MERGE_COLUMNS, EXAMPLE_REPORT, validate_report,
)


class ReportTable(QWidget):
    def __init__(self, db_manager, login_manager, parent=None):
        super().__init__(parent)
        self.ops = FileOperations(db_manager, login_manager)
        self.storage = DocumentStorage(db_manager, login_manager)
        self._path = None
        self._stored_id = None
        self._report = None
        self._zoom = 1.0
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.title = QLabel('Таблица')
        self.title.setTextFormat(Qt.PlainText)
        title_font = QFont()
        title_font.setPointSize(15)
        title_font.setBold(True)
        self.title.setFont(title_font)
        toolbar.addWidget(self.title, 1)
        self.minus_button = QPushButton('−')
        self.plus_button = QPushButton('+')
        self.minus_button.setFixedWidth(44)
        self.plus_button.setFixedWidth(44)
        toolbar.addWidget(self.minus_button)
        toolbar.addWidget(self.plus_button)
        layout.addLayout(toolbar)
        self.subtitle = QLabel('')
        self.subtitle.setTextFormat(Qt.PlainText)
        layout.addWidget(self.subtitle)
        self.table = QTableWidget()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setWordWrap(True)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().hide()
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setAlternatingRowColors(False)
        layout.addWidget(self.table, 1)
        self.status = QLabel('')
        self.status.setTextFormat(Qt.PlainText)
        layout.addWidget(self.status)
        self.minus_button.clicked.connect(lambda: self._change_zoom(-0.1))
        self.plus_button.clicked.connect(lambda: self._change_zoom(0.1))

    def _change_zoom(self, delta):
        self.validate_session()
        self._zoom = max(0.7, min(1.6, round(self._zoom + delta, 1)))
        if self._report is not None:
            self.render_report(self._report)

    def clear_session(self):
        self._path = None
        self._stored_id = None
        self._report = None
        self.title.setText('Таблица')
        self.subtitle.clear()
        self.table.clearSpans()
        self.table.clear()
        self.table.setRowCount(0)
        self.table.setColumnCount(0)
        self.status.clear()

    def validate_session(self):
        user = self.ops.login.current_user
        if user is None:
            self.clear_session()
            return
        if self._path and not self.ops.permissions.can_access_file(user, self._path):
            self.clear_session()
        elif self._stored_id is not None:
            try:
                self.storage.get_table(self._stored_id)
            except (PermissionError, LookupError, ValueError):
                self.clear_session()

    def show_example(self):
        self._path = None
        self._stored_id = None
        self.render_report(EXAMPLE_REPORT)
        self.status.setText('Образец. Для открытия файла выберите JSON в проводнике.')

    def load_file(self, path):
        try:
            raw = self.ops.read_bytes(path, max_bytes=MAX_TABLE_BYTES)
            value = validate_report(json.loads(raw.decode('utf-8')))
        except (PermissionError, OSError, UnicodeError, ValueError, sqlite3.Error) as exc:
            QMessageBox.warning(self, 'Не удалось открыть таблицу', str(exc))
            return False
        self.render_report(value)
        self._path = path
        self._stored_id = None
        self.status.setText(path)
        return True

    def load_stored(self, table_id):
        try:
            record = self.storage.get_table(table_id)
            value = validate_report(record['report'])
        except (PermissionError, LookupError, ValueError, sqlite3.Error, OSError) as exc:
            self.clear_session()
            QMessageBox.warning(self, 'Не удалось открыть таблицу', str(exc))
            return False
        self.render_report(value)
        self._path = None
        self._stored_id = record['id']
        source = record.get('source_document_id')
        self.status.setText('Сохранённая таблица'
                            + (f' · версия исходного документа: {record["source_revision"]}'
                               if source is not None else ''))
        return True

    def _cell(self, row, col, text, background, *, bold=False, align=Qt.AlignCenter):
        item = QTableWidgetItem(text)
        item.setFlags(Qt.ItemIsEnabled)
        item.setTextAlignment(align)
        item.setBackground(QColor(background))
        font = QFont('Arial', max(7, round(9 * self._zoom)))
        font.setBold(bold)
        item.setFont(font)
        self.table.setItem(row, col, item)

    def _band(self, row, text, color):
        self._cell(row, 0, text, color, bold=True)
        self.table.setSpan(row, 0, 1, len(COLUMNS))
        self.table.setRowHeight(row, round(29 * self._zoom))

    def render_report(self, value):
        value = validate_report(value)
        self._report = value
        self.title.setText(value['title'])
        self.subtitle.setText(value.get('subtitle', ''))
        count = 2 + sum(1 + bool(section.get('summary')) + sum(
            1 + len(group['rows']) for group in section['groups']) for section in value['sections'])
        count += bool(value.get('summary'))
        table = self.table
        table.setUpdatesEnabled(False)
        try:
            table.clearSpans()
            table.clear()
            table.setRowCount(count)
            table.setColumnCount(len(COLUMNS))
            for col, (_, width) in enumerate(COLUMNS):
                table.setColumnWidth(col, round(width * self._zoom))
            for col, (name, _) in enumerate(COLUMNS):
                if 5 <= col <= 8:
                    self._cell(1, col, name, '#eee9df', bold=True)
                else:
                    self._cell(0, col, name, '#eee9df', bold=True)
                    table.setSpan(0, col, 2, 1)
            self._cell(0, 5, 'Показатели', '#eee9df', bold=True)
            table.setSpan(0, 5, 1, 4)
            table.setRowHeight(0, round(32 * self._zoom))
            table.setRowHeight(1, round(30 * self._zoom))
            row = 2
            for section in value['sections']:
                self._band(row, section['title'], '#e7c6cc')
                row += 1
                for group in section['groups']:
                    self._band(row, group['title'], '#f3e5dc')
                    row += 1
                    start = row
                    for cells in group['rows']:
                        for col, cell in enumerate(cells):
                            self._cell(row, col, cell, '#dceaf5',
                                       align=Qt.AlignLeft | Qt.AlignVCenter if col in (2, 3, 12)
                                       else Qt.AlignCenter)
                        table.setRowHeight(row, round(52 * self._zoom))
                        row += 1
                    if row - start > 1:
                        for col in MERGE_COLUMNS:
                            first = group['rows'][0][col]
                            if first and all(cells[col] == first for cells in group['rows'][1:]):
                                table.setSpan(start, col, row - start, 1)
                if section.get('summary'):
                    self._band(row, section['summary'], '#e7c6cc')
                    row += 1
            if value.get('summary'):
                self._band(row, value['summary'], '#eee9df')
        finally:
            table.setUpdatesEnabled(True)

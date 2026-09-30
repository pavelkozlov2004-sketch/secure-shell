"""Administrator connection board with accessible, coloured account states."""
from datetime import datetime, timezone
import sqlite3
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QAbstractItemView, QMessageBox)


class ConnectivityWindow(QDialog):
    STATUS_COLOURS = {
        'online': ('#d8f0df', '#155b2b'),
        'offline': ('#e6e8eb', '#414750'),
        'deactivated': ('#f9dddd', '#942525'),
    }

    def __init__(self, monitor, parent=None):
        super().__init__(parent)
        self.monitor = monitor
        self._rows = {}
        self.setWindowTitle('Подключения пользователей — Вуаль')
        self.resize(1280, 560)
        layout = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.PlainText)
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            'Пользователь', 'Состояние', 'Адрес в сети', 'Компьютер',
            'Последний вход (UTC)', 'Последний сигнал (UTC)',
            'Последние файловые действия (UTC)',
        ])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setWordWrap(False)
        for index, width in enumerate((160, 245, 150, 150, 180, 180)):
            self.table.setColumnWidth(index, width)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        layout.addWidget(self.table)
        self.unblock_button = QPushButton('Разблокировать выбранного пользователя')
        self.unblock_button.setEnabled(False)
        self.unblock_button.clicked.connect(self.unblock_selected)
        layout.addWidget(self.unblock_button)

    @staticmethod
    def stamp(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if value is not None else '—'

    def _selected_id(self):
        selected = self.table.selectionModel().selectedRows()
        item = self.table.item(selected[0].row(), 0) if selected else None
        return item.data(Qt.UserRole) if item else None

    def _selection_changed(self):
        row = self._rows.get(self._selected_id())
        self.unblock_button.setEnabled(bool(row and (
            row['status_code'] == 'deactivated' or
            (row['status_code'] == 'offline' and row.get('network_blocked')))))

    def clear_session(self):
        self.hide()
        self._rows = {}
        self.table.clearContents()
        self.table.setRowCount(0)
        self.summary.clear()
        self.unblock_button.setEnabled(False)

    def display(self, rows):
        selected = self._selected_id()
        self._rows = {row['id']: row for row in rows}
        counts = {code: sum(row['status_code'] == code for row in rows)
                  for code in self.STATUS_COLOURS}
        self.summary.setText(
            f'Зелёный — работают: {counts["online"]}; '
            f'серый — нет подключения: {counts["offline"]}; '
            f'красный — деактивированы: {counts["deactivated"]}. '
            f'Обновлено: {datetime.now(timezone.utc):%H:%M:%S} UTC. '
            'Показаны до 5 последних файловых действий каждого пользователя.')
        self.table.blockSignals(True)
        try:
            self.table.setRowCount(len(rows))
            self.table.clearSelection()
            self.table.setCurrentItem(None)
            for i, row in enumerate(rows):
                files = '\n'.join(
                    f'{f["timestamp"]} | {f["action"]} | {f.get("details") or "—"}'
                    for f in row.get('files', []))
                values = [row['login'], row['status'], row.get('address') or '—',
                          row.get('client_name') or '—', self.stamp(row.get('last_login')),
                          self.stamp(row.get('last_seen')), files or 'Нет записей']
                background, foreground = self.STATUS_COLOURS[row['status_code']]
                for j, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setToolTip(str(value))
                    item.setBackground(QColor(background))
                    item.setForeground(QColor(foreground))
                    if j == 0:
                        item.setData(Qt.UserRole, row['id'])
                    self.table.setItem(i, j, item)
                if row['id'] == selected:
                    self.table.selectRow(i)
        finally:
            self.table.blockSignals(False)
        self.table.resizeRowsToContents()
        self._selection_changed()

    def unblock_selected(self):
        row = self._rows.get(self._selected_id())
        if row is None or not self.unblock_button.isEnabled():
            return
        if row['status_code'] == 'deactivated':
            if QMessageBox.question(
                self, 'Разблокировка пользователя',
                f'Активировать учётную запись «{row["login"]}»? '
                'Пользователь сможет войти с прежним паролем.',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            ) != QMessageBox.Yes:
                return
        self.unblock_button.setEnabled(False)
        try:
            ok = self.monitor.unblock(row['id'])
            self.display(self.monitor.user_statuses())
            self.summary.setText(self.summary.text() + (
                '\nУчётная запись разблокирована. Для работы требуется новый вход.' if ok else
                '\nРазблокировка отклонена: права или состояние аккаунта изменились.'))
        except PermissionError:
            self.clear_session()
        except OSError:
            self.clear_session()
            parent = self.parent()
            if parent is not None and hasattr(parent, '_refresh_session'):
                parent._refresh_session()
        except sqlite3.Error:
            self.summary.setText('Не удалось обратиться к базе. Разблокирование не подтверждено.')
            self._selection_changed()

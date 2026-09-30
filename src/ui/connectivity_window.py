"""Scrollable administrator board; does not block client heartbeat timers."""
from datetime import datetime, timezone
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QAbstractItemView)


class ConnectivityWindow(QDialog):
    def __init__(self, monitor, parent=None):
        super().__init__(parent)
        self.monitor = monitor
        self.setWindowTitle('Подключения пользователей')
        self.resize(1180, 560)
        layout = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['Пользователь', 'Состояние', 'Последний вход (UTC)',
                                             'Последний сигнал (UTC)', 'Последние файловые действия (UTC)'])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setWordWrap(False)
        self.table.setColumnWidth(0, 180)
        self.table.setColumnWidth(1, 220)
        self.table.setColumnWidth(2, 180)
        self.table.setColumnWidth(3, 180)
        layout.addWidget(self.table)
        self.unblock_button = QPushButton('Разблокировать выбранного пользователя')
        self.unblock_button.clicked.connect(self.unblock_selected)
        layout.addWidget(self.unblock_button)

    @staticmethod
    def stamp(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if value is not None else '—'

    def display(self, rows):
        self.table.setRowCount(len(rows))
        self.summary.setText(f'Нет подключения: {len(rows)}. Обновлено: {datetime.now(timezone.utc):%H:%M:%S} UTC. '
                             'Показаны до 5 последних файловых действий внутри приложения для каждого пользователя.')
        for i, row in enumerate(rows):
            files = '\n'.join(f'{f["timestamp"]} | {f["action"]} | {f["details"] or "—"}' for f in row['files'])
            values = [row['login'], row['status'], self.stamp(row['last_login']),
                      self.stamp(row['last_seen']), files or 'Нет записей']
            for j, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if j == 0:
                    item.setData(Qt.UserRole, row['id'])
                self.table.setItem(i, j, item)
        self.table.resizeRowsToContents()

    def unblock_selected(self):
        item = self.table.item(self.table.currentRow(), 0)
        if item is None:
            return
        try:
            ok = self.monitor.unblock(item.data(Qt.UserRole))
            self.display(self.monitor.offline_users())
            if not ok:
                self.summary.setText('Аккаунт не имеет сетевой блокировки или деактивирован.')
        except PermissionError:
            self.hide()
        except Exception:
            self.summary.setText('Не удалось обратиться к базе. Разблокирование не подтверждено.')

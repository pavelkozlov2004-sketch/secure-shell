"""Настройка доверенного сервера учётных записей локальной сети."""
import socket

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QHBoxLayout, QLabel, QCheckBox,
    QLineEdit, QPushButton, QFileDialog, QDialogButtonBox,
)
from PyQt5.QtCore import Qt

from network.settings import save_settings


class NetworkSettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Вуаль — подключение к локальной сети')
        self.resize(620, 340)
        layout = QVBoxLayout(self)
        note = QLabel('Укажите адрес компьютера с сервером «Вуаль» и выберите его '
                      'открытый сертификат. Переключение завершит текущий сеанс '
                      'и откроет новое окно входа.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.enabled = QCheckBox('Использовать сервер учётных записей в локальной сети')
        self.enabled.setChecked(bool(settings.get('enabled', False)))
        layout.addWidget(self.enabled)
        form = QFormLayout()
        self.server_url = QLineEdit(settings.get('server_url', ''))
        self.server_url.setPlaceholderText('https://192.168.1.10:8765')
        self.server_url.setMaxLength(2048)
        form.addRow('Адрес сервера', self.server_url)
        cert_row = QHBoxLayout()
        self.ca_file = QLineEdit(settings.get('ca_file', ''))
        self.ca_file.setMaxLength(4096)
        cert_row.addWidget(self.ca_file, 1)
        self.browse = QPushButton('Выбрать…')
        cert_row.addWidget(self.browse)
        form.addRow('Сертификат сервера', cert_row)
        self.client_name = QLineEdit(settings.get('client_name') or socket.gethostname())
        self.client_name.setMaxLength(120)
        form.addRow('Имя этого компьютера', self.client_name)
        layout.addLayout(form)
        self.status = QLabel('')
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Save).setText('Сохранить')
        buttons.button(QDialogButtonBox.Cancel).setText('Отмена')
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.browse.clicked.connect(self._choose_certificate)
        self.enabled.toggled.connect(self._update_fields)
        self._update_fields()
        self.saved_settings = None

    def _update_fields(self):
        enabled = self.enabled.isChecked()
        for widget in (self.server_url, self.ca_file, self.browse, self.client_name):
            widget.setEnabled(enabled)

    def _choose_certificate(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 'Открытый сертификат сервера', '', 'Сертификаты (*.pem *.crt *.cer);;Все файлы (*)')
        if path:
            self.ca_file.setText(path)

    def accept(self):
        settings = {
            'enabled': self.enabled.isChecked(),
            'server_url': self.server_url.text().strip(),
            'ca_file': self.ca_file.text().strip(),
            'client_name': self.client_name.text().strip(),
        }
        try:
            self.saved_settings = save_settings(settings)
        except (ValueError, OSError) as exc:
            self.status.setText(str(exc))
            return
        super().accept()

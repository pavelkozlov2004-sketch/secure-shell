"""Client connection setup preserves isolation and invalid settings stay unsaved."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('VUAL_DATA_DIR', _TMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from PyQt5.QtWidgets import QApplication, QDialog
from main import client_database_path
from network.settings import DEFAULT_SETTINGS, load_settings, save_settings
from network.tls import generate_server_certificate
from ui.network_settings import NetworkSettingsDialog


class NetworkSettingsUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_client_cache_is_distinct_for_each_server_and_local_mode(self):
        local = dict(DEFAULT_SETTINGS)
        self.assertIsNone(client_database_path(local))
        first = dict(local, enabled=True, server_url='https://192.168.1.10:8765')
        second = dict(first, server_url='https://192.168.1.11:8765')
        self.assertNotEqual(client_database_path(first), client_database_path(second))
        self.assertEqual(client_database_path(first), client_database_path(dict(
            first, server_url=first['server_url'] + '/')))
        self.assertEqual(client_database_path(first).name, 'users.db')
        self.assertEqual(client_database_path(first).parent.parent.name, 'clients')

    def test_dialog_saves_valid_server_and_certificate_without_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            certificate = root / 'server.crt'
            generate_server_certificate(certificate, root / 'server.key', ['127.0.0.1'])
            dialog = NetworkSettingsDialog(dict(DEFAULT_SETTINGS))
            try:
                dialog.enabled.setChecked(True)
                dialog.server_url.setText('https://127.0.0.1:8765')
                dialog.ca_file.setText(str(certificate))
                dialog.client_name.setText('Тестовый клиент')
                with patch('ui.network_settings.save_settings',
                           side_effect=lambda values: save_settings(values, root)):
                    dialog.accept()
                self.assertEqual(dialog.result(), QDialog.Accepted)
                saved = load_settings(root)
                self.assertEqual(set(saved), {'enabled', 'server_url', 'ca_file', 'client_name'})
                self.assertEqual(saved['client_name'], 'Тестовый клиент')
                self.assertTrue(saved['enabled'])
            finally:
                dialog.close()

    def test_invalid_certificate_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            certificate = root / 'invalid.crt'
            certificate.write_text('This is not a certificate', encoding='utf-8')
            dialog = NetworkSettingsDialog(dict(DEFAULT_SETTINGS))
            try:
                dialog.enabled.setChecked(True)
                dialog.server_url.setText('https://127.0.0.1:8765')
                dialog.ca_file.setText(str(certificate))
                with patch('ui.network_settings.save_settings',
                           side_effect=lambda values: save_settings(values, root)):
                    dialog.accept()
                self.assertEqual(dialog.result(), QDialog.Rejected)
                self.assertIsNone(dialog.saved_settings)
                self.assertTrue(dialog.status.text())
                self.assertFalse((root / 'lan-settings.json').exists())
            finally:
                dialog.close()


if __name__ == '__main__':
    unittest.main()

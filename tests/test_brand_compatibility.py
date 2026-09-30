"""Existing accounts, report JSON and encrypted recovery files survive renaming."""
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest

_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault('VUAL_DATA_DIR', _TMP.name)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from auth.emergency import (LEGACY_RECOVERY_FORMAT, RECOVERY_FORMAT,
                            decrypt_vault, encrypt_vault)
from config import (LEGACY_DATA_DIR_ENV, LEGACY_DATA_DIRECTORY,
                    LEGACY_DATABASE_FILENAME, resolve_data_dir)
from storage.report_format import EXAMPLE_REPORT, FORMAT, LEGACY_FORMAT, validate_report


class DataDirectoryCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_environment_overrides_legacy_environment(self):
        env = {'VUAL_DATA_DIR': str(self.root / 'new'),
               LEGACY_DATA_DIR_ENV: str(self.root / 'old')}
        self.assertEqual(resolve_data_dir(env, self.root), self.root / 'new')
        del env['VUAL_DATA_DIR']
        self.assertEqual(resolve_data_dir(env, self.root), self.root / 'old')

    def test_fresh_install_uses_vual_directory(self):
        legacy = self.root / LEGACY_DATA_DIRECTORY
        legacy.mkdir()
        (legacy / 'audit.log').write_text('log without accounts')
        self.assertEqual(resolve_data_dir({}, self.root), self.root / '.vual')

    def test_existing_users_and_legacy_database_are_preserved(self):
        legacy = self.root / LEGACY_DATA_DIRECTORY
        legacy.mkdir()
        for filename in ('users.db', LEGACY_DATABASE_FILENAME):
            with self.subTest(filename=filename):
                account_path = legacy / filename
                account_path.write_bytes(b'Existing account data')
                self.assertEqual(resolve_data_dir({}, self.root), legacy)
                self.assertEqual(account_path.read_bytes(), b'Existing account data')
                account_path.unlink()

    def test_existing_vual_database_has_priority_over_legacy_database(self):
        current, legacy = self.root / '.vual', self.root / LEGACY_DATA_DIRECTORY
        current.mkdir()
        legacy.mkdir()
        (current / 'users.db').touch()
        (legacy / 'users.db').touch()
        self.assertEqual(resolve_data_dir({}, self.root), current)


class TableCompatibilityTests(unittest.TestCase):
    def test_new_and_previous_report_formats_are_accepted_without_data_loss(self):
        for format_name in (FORMAT, LEGACY_FORMAT):
            with self.subTest(format_name=format_name):
                report = copy.deepcopy(EXAMPLE_REPORT)
                report['format'] = format_name
                before = json.dumps(report, ensure_ascii=False)
                validate_report(report)
                self.assertEqual(json.dumps(report, ensure_ascii=False), before)

    def test_unknown_report_format_is_rejected(self):
        report = copy.deepcopy(EXAMPLE_REPORT)
        report['format'] = 'unrelated-table-v1'
        with self.assertRaises(ValueError):
            validate_report(report)


class RecoveryCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'recovery.json'
        self.phrase = 'long independent recovery phrase'
        self.data = {'accounts': [{'login': 'admin_admin', 'password': 'secret'}]}

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_recovery_file_roundtrip(self):
        self.path.write_bytes(encrypt_vault(self.data, self.phrase))
        self.assertEqual(json.loads(self.path.read_bytes())['format'], RECOVERY_FORMAT)
        self.assertEqual(decrypt_vault(self.path, self.phrase), self.data)

    def test_previous_recovery_file_uses_previous_authenticated_format(self):
        # Construct the old envelope independently from encrypt_vault.
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(self.phrase.encode())
        cipher = AESGCM(key).encrypt(nonce, json.dumps(self.data).encode(),
                                     LEGACY_RECOVERY_FORMAT.encode('ascii'))
        envelope = {'format': LEGACY_RECOVERY_FORMAT,
                    'salt': base64.b64encode(salt).decode(),
                    'nonce': base64.b64encode(nonce).decode(),
                    'ciphertext': base64.b64encode(cipher).decode()}
        self.path.write_text(json.dumps(envelope), encoding='utf-8')
        self.assertEqual(decrypt_vault(self.path, self.phrase), self.data)
        # Changing only the format must not bypass AES-GCM authentication.
        envelope['format'] = RECOVERY_FORMAT
        self.path.write_text(json.dumps(envelope), encoding='utf-8')
        with self.assertRaises(ValueError):
            decrypt_vault(self.path, self.phrase)


if __name__ == '__main__':
    unittest.main()

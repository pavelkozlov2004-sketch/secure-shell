"""Настройки сервера без паролей и сохранённых токенов сеанса."""
import json
import os
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from config import DATA_DIR

SETTINGS_FILENAME = 'lan-settings.json'
SETTINGS_KEYS = frozenset(('enabled', 'server_url', 'ca_file', 'client_name'))
DEFAULT_SETTINGS = dict(enabled=False, server_url='', ca_file='', client_name='')


def validate_server_url(value):
    """Разрешается только корень HTTPS-сервера с явным именем или IP."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError('Укажите адрес HTTPS-сервера.')
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError('Адрес сервера содержит недопустимые символы.')
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError('Некорректный адрес или порт сервера.') from None
    if (parts.scheme.lower() != 'https' or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or parts.path not in ('', '/')
            or '?' in value or '#' in value
            or any(char in parts.hostname for char in ('%', '\\', '/', '@'))
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError('Нужен адрес вида https://имя-сервера:порт без логина, пути и параметров.')
    # urlsplit принимает обратный слеш и некоторые скобки внутри netloc.
    if '\\' in parts.netloc:
        raise ValueError('Некорректное имя сервера.')
    return value.rstrip('/')


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) - SETTINGS_KEYS:
        raise ValueError('Некорректный формат сетевых настроек.')
    result = dict(DEFAULT_SETTINGS, **settings)
    if type(result['enabled']) is not bool:
        raise ValueError('Некорректный режим подключения.')
    for field in ('server_url', 'ca_file', 'client_name'):
        if not isinstance(result[field], str):
            raise ValueError('Поля сетевых настроек должны содержать текст.')
    if len(result['client_name']) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in result['client_name']):
        raise ValueError('Имя компьютера должно содержать до 128 символов.')
    if result['server_url']:
        result['server_url'] = validate_server_url(result['server_url'])
    if result['ca_file']:
        result['ca_file'] = str(Path(result['ca_file']).expanduser().resolve())
    if result['enabled']:
        if not result['server_url']:
            raise ValueError('Укажите адрес HTTPS-сервера.')
        if not result['ca_file'] or not Path(result['ca_file']).is_file():
            raise ValueError('Выберите файл сертификата сервера для проверки подключения.')
        try:
            trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            trust.load_verify_locations(cafile=result['ca_file'])
        except (ssl.SSLError, OSError):
            raise ValueError('Не удалось прочитать сертификат сервера. Выберите корректный файл PEM.') from None
    return result


def load_settings(data_dir=None):
    path = Path(DATA_DIR if data_dir is None else data_dir) / SETTINGS_FILENAME
    try:
        with path.open(encoding='utf-8') as stream:
            settings = json.load(stream)
    except FileNotFoundError:
        return dict(DEFAULT_SETTINGS)
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError('Не удалось прочитать сетевые настройки.') from None
    return validate_settings(settings)


def save_settings(settings, data_dir=None):
    """Атомарная запись только разрешённых полей с правами владельца."""
    result = validate_settings(settings)
    directory = Path(DATA_DIR if data_dir is None else data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.lan-settings-', suffix='.json', dir=directory)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        destination = directory / SETTINGS_FILENAME
        os.replace(temporary, destination)
        if os.name == 'posix':
            os.chmod(destination, 0o600)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return result

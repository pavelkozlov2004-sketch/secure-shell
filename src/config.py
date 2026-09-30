"""Конфигурация приложения"""

import os
from pathlib import Path
from enum import Enum

# Пути
BASE_DIR = Path(__file__).parent.parent

# Совместимость с настройками и каталогом данных предыдущих выпусков.
LEGACY_DATA_DIR_ENV = "SECURE_SHELL_DATA_DIR"
LEGACY_DATA_DIRECTORY = ".secure-shell"
LEGACY_DATABASE_FILENAME = "secure_shell.db"


def resolve_data_dir(environ=None, home=None):
    """Сохранять существующие аккаунты при смене названия приложения."""
    environ = os.environ if environ is None else environ
    configured = environ.get("VUAL_DATA_DIR") or environ.get(LEGACY_DATA_DIR_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    home = Path.home() if home is None else Path(home)
    current = home / ".vual"
    legacy = home / LEGACY_DATA_DIRECTORY
    database_names = ("users.db", LEGACY_DATABASE_FILENAME)
    if not any((current / name).is_file() for name in database_names):
        if any((legacy / name).is_file() for name in database_names):
            return legacy.resolve()
    return current.resolve()


DATA_DIR = resolve_data_dir()
RESOURCES_DIR = BASE_DIR / "resources"
LOGS_DIR = DATA_DIR / "logs"

# Создание директорий если их нет
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# База данных
DB_PATH = DATA_DIR / "users.db"
TABLES_DB_PATH = DATA_DIR / "tables.db"
DOCUMENTS_DB_PATH = DATA_DIR / "documents.db"
LEGACY_DB_PATH = DATA_DIR / LEGACY_DATABASE_FILENAME

# Логирование
AUDIT_LOG_PATH = DATA_DIR / "audit.log"
APP_LOG_PATH = LOGS_DIR / "app.log"

# Интерфейс
APP_TITLE = "Вуаль — Защищённая оболочка"
WINDOW_WIDTH = 1200
WINDOW_HEIGHT = 800
DEFAULT_THEME = "light"  # light или dark

# Направления деятельности
class Direction(Enum):
    NORTH = (1, "Север")
    WEST = (2, "Запад")
    SOUTH = (3, "Юг")
    
    def __init__(self, id, display_name):
        self.id = id
        self.display_name = display_name

# Уровни секретности
class SecrecyLevel(Enum):
    UNCLASSIFIED = (1, "Несекретно", 1)
    OFFICIAL_USE = (2, "Для служебного пользования", 2)
    SECRET = (3, "Секретно", 3)
    TOP_SECRET = (4, "Совершенно секретно", 4)
    
    def __init__(self, id, display_name, level_order):
        self.id = id
        self.display_name = display_name
        self.level_order = level_order

# Учётные данные администратора по умолчанию
DEFAULT_ADMIN = {
    "login": "admin_admin",
    "password": None,  # Задаётся при первоначальной настройке
    "direction": Direction.NORTH,
    "secrecy_level": SecrecyLevel.TOP_SECRET,
}

# Параметры приложения
MAX_LOGIN_ATTEMPTS = 3
LOCK_TIMEOUT = 300  # 5 минут

# Форматы файлов
TEXT_FORMATS = [".txt", ".rtf", ".docx"]
SPREADSHEET_FORMATS = [".csv", ".xlsx"]

# Размеры окон
LOGIN_WINDOW_WIDTH = 400
LOGIN_WINDOW_HEIGHT = 300
ADMIN_PANEL_WIDTH = 800
ADMIN_PANEL_HEIGHT = 600

# Стили
QSS_LIGHT = RESOURCES_DIR / "styles" / "light.qss"
QSS_DARK = RESOURCES_DIR / "styles" / "dark.qss"

# Иконки
ICONS_DIR = RESOURCES_DIR / "icons"

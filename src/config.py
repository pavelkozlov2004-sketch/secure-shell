"""Конфигурация приложения"""

import os
from pathlib import Path
from enum import Enum

# Пути
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
RESOURCES_DIR = BASE_DIR / "resources"
LOGS_DIR = DATA_DIR / "logs"

# Создание директорий если их нет
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# База данных
DB_PATH = DATA_DIR / "secure_shell.db"

# Логирование
AUDIT_LOG_PATH = DATA_DIR / "audit.log"
APP_LOG_PATH = LOGS_DIR / "app.log"

# Интерфейс
APP_TITLE = "Secure Shell - Защищённая оболочка"
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
    "password": "12345678",
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

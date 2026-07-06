"""Главная точка входа приложения"""

import sys
from pathlib import Path

# Добавляем src в path
sys.path.insert(0, str(Path(__file__).parent))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from database.db_manager import DatabaseManager
from ui.login_window import LoginWindow
from config import APP_TITLE, DEFAULT_THEME


def main():
    """Главная функция приложения"""
    
    # Инициализация БД
    db_manager = DatabaseManager()
    
    # Создание приложения PyQt5
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setApplicationVersion("1.0.0")
    
    # Установка стиля
    app.setStyle('Fusion')
    
    # Создание и показ окна входа
    login_window = LoginWindow(db_manager)
    login_window.show()
    
    # Запуск цикла событий
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

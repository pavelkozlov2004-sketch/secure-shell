"""Главное окно приложения"""

from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QLabel
from PyQt5.QtCore import Qt

from config import APP_TITLE, WINDOW_WIDTH, WINDOW_HEIGHT
from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager


class MainWindow(QMainWindow):
    """Главное окно приложения"""
    
    def __init__(self, db_manager: DatabaseManager, login_manager: LoginManager):
        super().__init__()
        self.db_manager = db_manager
        self.login_manager = login_manager
        self.current_user = login_manager.get_current_user()
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализирует интерфейс главного окна"""
        self.setWindowTitle(f"{APP_TITLE} - {self.current_user.login}")
        self.setGeometry(100, 100, WINDOW_WIDTH, WINDOW_HEIGHT)
        
        # Центральный виджет
        central_widget = QWidget()
        layout = QVBoxLayout()
        
        # Временный текст
        label = QLabel(f"Добро пожаловать, {self.current_user.login}!")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
    
    def closeEvent(self, event):
        """Обработчик закрытия окна"""
        self.login_manager.logout()
        event.accept()

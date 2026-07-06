"""Окно входа в систему"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QCheckBox
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QPixmap, QIcon

from database.db_manager import DatabaseManager
from auth.login_manager import LoginManager
from config import LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT, APP_TITLE
from ui.main_window import MainWindow


class LoginWindow(QDialog):
    """Окно авторизации пользователя"""
    
    def __init__(self, db_manager: DatabaseManager):
        super().__init__()
        self.db_manager = db_manager
        self.login_manager = LoginManager(db_manager)
        self.main_window = None
        self.init_ui()
    
    def init_ui(self):
        """Инициализирует интерфейс окна"""
        self.setWindowTitle(APP_TITLE)
        self.setFixedSize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 12px;
            }
            QPushButton {
                padding: 8px 20px;
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #005fa3;
            }
            QLabel {
                font-size: 12px;
                color: #333;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        # Заголовок
        title = QLabel("Вход в систему")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Логин
        login_label = QLabel("Логин:")
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("Иванов_ИИ")
        layout.addWidget(login_label)
        layout.addWidget(self.login_input)
        
        # Пароль
        password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("12345678")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(password_label)
        layout.addWidget(self.password_input)
        
        # Запомнить
        self.remember_checkbox = QCheckBox("Запомнить логин")
        layout.addWidget(self.remember_checkbox)
        
        layout.addSpacing(20)
        
        # Кнопки
        button_layout = QHBoxLayout()
        
        login_button = QPushButton("Вход")
        login_button.clicked.connect(self.on_login)
        button_layout.addWidget(login_button)
        
        exit_button = QPushButton("Выход")
        exit_button.setStyleSheet("""
            QPushButton {
                background-color: #999;
            }
            QPushButton:hover {
                background-color: #777;
            }
        """)
        exit_button.clicked.connect(self.on_exit)
        button_layout.addWidget(exit_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
        
        # Фокус на поле логина
        self.login_input.setFocus()
        
        # Центрируем окно на экране
        self.center_window()
    
    def center_window(self):
        """Центрирует окно на экране"""
        geometry = self.frameGeometry()
        screen = self.screen().geometry()
        geometry.moveCenter(screen.center())
        self.move(geometry.topLeft())
    
    def on_login(self):
        """Обработчик кнопки входа"""
        login = self.login_input.text().strip()
        password = self.password_input.text()
        
        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, заполните все поля")
            return
        
        if self.login_manager.login(login, password):
            # Вход успешен
            self.main_window = MainWindow(self.db_manager, self.login_manager)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.critical(self, "Ошибка входа", "Неверный логин или пароль")
            self.password_input.clear()
            self.password_input.setFocus()
    
    def on_exit(self):
        """Обработчик кнопки выхода"""
        self.close()
    
    def keyPressEvent(self, event):
        """Обработчик нажатия клавиши"""
        if event.key() == Qt.Key_Return:
            self.on_login()
        else:
            super().keyPressEvent(event)

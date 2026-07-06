"""Меню Пуск с доступными приложениями"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QPushButton, QLabel, QMenu
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from auth.login_manager import User
from access_control.permissions import PermissionManager


class StartMenu(QWidget):
    """Меню Пуск с доступными приложениями"""
    
    app_selected = pyqtSignal(str)  # Сигнал при выборе приложения
    
    def __init__(self, current_user: User, db_manager, parent=None):
        super().__init__(parent)
        self.current_user = current_user
        self.db_manager = db_manager
        self.permission_manager = PermissionManager(db_manager)
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализирует интерфейс меню Пуск"""
        self.setWindowTitle("Меню Пуск")
        self.setGeometry(0, 0, 250, 500)
        
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: white;
                border: none;
                border-bottom: 1px solid #e0e0e0;
                padding: 10px;
                text-align: left;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QLabel {
                padding: 8px;
                font-weight: bold;
                background-color: #e0e0e0;
                border-bottom: 1px solid #d0d0d0;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Заголовок
        header = QLabel("Приложения")
        header.setFont(QFont("Arial", 10, QFont.Bold))
        layout.addWidget(header)
        
        # Прокручиваемая область
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        apps_container = QWidget()
        apps_layout = QVBoxLayout(apps_container)
        apps_layout.setContentsMargins(0, 0, 0, 0)
        apps_layout.setSpacing(0)
        
        # Категория: Офисные приложения
        office_label = QLabel("📄 Офисные приложения")
        office_label.setFont(QFont("Arial", 9, QFont.Bold))
        office_label.setStyleSheet("background-color: #f5f5f5; padding: 5px;")
        apps_layout.addWidget(office_label)
        
        # Текстовый редактор
        text_editor_btn = QPushButton("📝 Текстовый редактор")
        text_editor_btn.clicked.connect(lambda: self.app_selected.emit("text_editor"))
        apps_layout.addWidget(text_editor_btn)
        
        # Табличный редактор
        spreadsheet_btn = QPushButton("📊 Табличный редактор")
        spreadsheet_btn.clicked.connect(lambda: self.app_selected.emit("spreadsheet"))
        apps_layout.addWidget(spreadsheet_btn)
        
        # Категория: Системные приложения
        system_label = QLabel("⚙️ Системные приложения")
        system_label.setFont(QFont("Arial", 9, QFont.Bold))
        system_label.setStyleSheet("background-color: #f5f5f5; padding: 5px;")
        apps_layout.addWidget(system_label)
        
        # Проводник
        explorer_btn = QPushButton("📁 Проводник")
        explorer_btn.clicked.connect(lambda: self.app_selected.emit("explorer"))
        apps_layout.addWidget(explorer_btn)
        
        # Категория: Параметры
        settings_label = QLabel("🔧 Параметры")
        settings_label.setFont(QFont("Arial", 9, QFont.Bold))
        settings_label.setStyleSheet("background-color: #f5f5f5; padding: 5px;")
        apps_layout.addWidget(settings_label)
        
        # Параметры
        settings_btn = QPushButton("⚙️ Параметры")
        settings_btn.clicked.connect(lambda: self.app_selected.emit("settings"))
        apps_layout.addWidget(settings_btn)
        
        # Смена пароля
        change_password_btn = QPushButton("🔐 Сменить пароль")
        change_password_btn.clicked.connect(lambda: self.app_selected.emit("change_password"))
        apps_layout.addWidget(change_password_btn)
        
        apps_layout.addStretch()
        scroll_area.setWidget(apps_container)
        layout.addWidget(scroll_area)
        
        self.setLayout(layout)
    
    def get_available_apps(self) -> list:
        """Возвращает список доступных приложений для текущего пользователя"""
        apps = [
            {'name': 'Текстовый редактор', 'id': 'text_editor', 'icon': '📝'},
            {'name': 'Табличный редактор', 'id': 'spreadsheet', 'icon': '📊'},
            {'name': 'Проводник', 'id': 'explorer', 'icon': '📁'},
            {'name': 'Параметры', 'id': 'settings', 'icon': '⚙️'},
            {'name': 'Сменить пароль', 'id': 'change_password', 'icon': '🔐'},
        ]
        
        # Фильтруем приложения по правам пользователя (если нужно)
        # Пока все приложения доступны всем
        return apps
    
    def closeEvent(self, event):
        """Закрытие меню"""
        super().closeEvent(event)

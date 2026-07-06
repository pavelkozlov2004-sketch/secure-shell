"""Виджет рабочего стола с иконками"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QMenu, QMessageBox
from PyQt5.QtCore import Qt, QPoint, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPixmap, QIcon
from PyQt5.QtWidgets import QFrame

from auth.login_manager import User


class DesktopIcon(QFrame):
    """Иконка на рабочем столе"""
    
    double_clicked = pyqtSignal(str)  # Сигнал при двойном клике
    
    def __init__(self, name: str, icon_path: str = None, parent=None):
        super().__init__(parent)
        self.name = name
        self.icon_path = icon_path
        
        self.setStyleSheet("""
            QFrame {
                background-color: transparent;
                border: none;
                border-radius: 4px;
            }
            QFrame:hover {
                background-color: rgba(0, 0, 0, 0.1);
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # Иконка
        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setFixedSize(64, 64)
        
        # Устанавливаем иконку (пока просто текст вместо иконки)
        if icon_path:
            try:
                pixmap = QPixmap(icon_path).scaledToWidth(64, Qt.SmoothTransformation)
                self.icon_label.setPixmap(pixmap)
            except:
                # Если иконка не найдена, используем текст
                self.icon_label.setText("📁")
                self.icon_label.setFont(QFont("Arial", 32))
        else:
            # Иконки по типам
            if "Документы" in name:
                self.icon_label.setText("📄")
            elif "Загрузки" in name:
                self.icon_label.setText("⬇️")
            elif "Корзина" in name:
                self.icon_label.setText("🗑️")
            else:
                self.icon_label.setText("📁")
            self.icon_label.setFont(QFont("Arial", 32))
        
        layout.addWidget(self.icon_label, alignment=Qt.AlignCenter)
        
        # Название
        self.name_label = QLabel(name)
        self.name_label.setAlignment(Qt.AlignCenter)
        font = QFont()
        font.setPointSize(9)
        self.name_label.setFont(font)
        self.name_label.setWordWrap(True)
        self.name_label.setFixedWidth(80)
        layout.addWidget(self.name_label, alignment=Qt.AlignCenter)
        
        self.setLayout(layout)
        self.setFixedSize(100, 120)
    
    def mouseDoubleClickEvent(self, event):
        """Двойной клик по иконке"""
        self.double_clicked.emit(self.name)
        super().mouseDoubleClickEvent(event)
    
    def contextMenuEvent(self, event):
        """Контекстное меню"""
        menu = QMenu(self)
        open_action = menu.addAction("Открыть")
        properties_action = menu.addAction("Свойства")
        
        action = menu.exec_(self.mapToGlobal(event.pos()))
        
        if action == open_action:
            self.double_clicked.emit(self.name)


class Desktop(QWidget):
    """Рабочий стол с иконками"""
    
    open_file = pyqtSignal(str)  # Сигнал для открытия папки/приложения
    
    def __init__(self, current_user: User, parent=None):
        super().__init__(parent)
        self.current_user = current_user
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализирует интерфейс рабочего стола"""
        # Фон
        self.setStyleSheet("""
            QWidget {
                background-color: #0078d4;
                background-image: url('');
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        
        # Создаём иконки рабочего стола
        self.icons = {}
        
        # Иконка: Мой компьютер
        my_computer_icon = DesktopIcon("Мой компьютер", parent=self)
        my_computer_icon.double_clicked.connect(lambda: self.open_file.emit("my_computer"))
        layout.addWidget(my_computer_icon)
        self.icons["my_computer"] = my_computer_icon
        
        # Иконка: Документы
        documents_icon = DesktopIcon("Документы", parent=self)
        documents_icon.double_clicked.connect(lambda: self.open_file.emit("documents"))
        layout.addWidget(documents_icon)
        self.icons["documents"] = documents_icon
        
        # Иконка: Загрузки
        downloads_icon = DesktopIcon("Загрузки", parent=self)
        downloads_icon.double_clicked.connect(lambda: self.open_file.emit("downloads"))
        layout.addWidget(downloads_icon)
        self.icons["downloads"] = downloads_icon
        
        # Иконка: Корзина
        trash_icon = DesktopIcon("Корзина", parent=self)
        trash_icon.double_clicked.connect(lambda: self.open_file.emit("trash"))
        layout.addWidget(trash_icon)
        self.icons["trash"] = trash_icon
        
        layout.addStretch()
        
        self.setLayout(layout)
    
    def contextMenuEvent(self, event):
        """Контекстное меню рабочего стола"""
        menu = QMenu(self)
        
        create_folder = menu.addAction("Создать папку")
        menu.addSeparator()
        refresh = menu.addAction("Обновить")
        
        action = menu.exec_(self.mapToGlobal(event.pos()))
        
        if action == create_folder:
            pass  # Обработаем позже
        elif action == refresh:
            pass  # Обновим содержимое

"""Панель задач с кнопкой Пуск, часами и системным треем"""

from PyQt5.QtWidgets import QWidget, QHBoxLayout, QPushButton, QLabel, QMenu
from PyQt5.QtCore import Qt, QTimer, QTime, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import QSize

from auth.login_manager import User


class Taskbar(QWidget):
    """Панель задач (taskbar)"""
    
    start_menu_clicked = pyqtSignal()  # Сигнал при клике на Пуск
    logout_clicked = pyqtSignal()      # Сигнал при выходе
    
    def __init__(self, current_user: User, parent=None):
        super().__init__(parent)
        self.current_user = current_user
        self.open_windows = {}  # Словарь открытых окон {имя: окно}
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализирует интерфейс панели задач"""
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
                border-top: 1px solid #ddd;
            }
            QPushButton {
                background-color: #f0f0f0;
                border: 1px solid #ddd;
                border-radius: 2px;
                padding: 4px 10px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
        """)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Кнопка "Пуск"
        self.start_button = QPushButton("⊞ Пуск")
        self.start_button.setFixedSize(60, 32)
        self.start_button.setFont(QFont("Arial", 10, QFont.Bold))
        self.start_button.clicked.connect(self.on_start_clicked)
        layout.addWidget(self.start_button)
        
        # Разделитель
        layout.addSpacing(10)
        
        # Область для активных окон (будет заполняться динамически)
        self.windows_container = QWidget()
        self.windows_layout = QHBoxLayout(self.windows_container)
        self.windows_layout.setContentsMargins(0, 0, 0, 0)
        self.windows_layout.setSpacing(2)
        layout.addWidget(self.windows_container)
        
        # Растягиваем свободное место
        layout.addStretch()
        
        # Системный трей (условно)
        self.tray_widget = QWidget()
        tray_layout = QHBoxLayout(self.tray_widget)
        tray_layout.setContentsMargins(0, 0, 0, 0)
        tray_layout.setSpacing(5)
        
        # Часы
        self.clock_label = QLabel()
        self.clock_label.setFont(QFont("Arial", 10))
        self.clock_label.setFixedWidth(60)
        self.update_clock()
        
        # Таймер для обновления часов
        self.clock_timer = QTimer()
        self.clock_timer.timeout.connect(self.update_clock)
        self.clock_timer.start(1000)  # Обновляем каждую секунду
        
        tray_layout.addWidget(self.clock_label)
        
        # Кнопка выхода
        self.exit_button = QPushButton("Выход")
        self.exit_button.setFixedWidth(70)
        self.exit_button.clicked.connect(self.on_exit_clicked)
        tray_layout.addWidget(self.exit_button)
        
        layout.addWidget(self.tray_widget)
        
        self.setLayout(layout)
        self.setFixedHeight(40)
    
    def update_clock(self):
        """Обновляет время на часах"""
        current_time = QTime.currentTime()
        self.clock_label.setText(current_time.toString("HH:mm"))
    
    def on_start_clicked(self):
        """Обработчик клика на кнопку Пуск"""
        self.start_menu_clicked.emit()
    
    def on_exit_clicked(self):
        """Обработчик клика на кнопку выхода"""
        self.logout_clicked.emit()
    
    def add_window_button(self, window_name: str, window_widget):
        """Добавляет кнопку активного окна в панель задач"""
        if window_name not in self.open_windows:
            # Создаём кнопку для окна
            button = QPushButton(window_name[:15])  # Ограничиваем длину названия
            button.setFixedHeight(32)
            button.setFixedWidth(120)
            button.setToolTip(window_name)
            
            # Сохраняем ссылку на окно
            self.open_windows[window_name] = {
                'widget': window_widget,
                'button': button
            }
            
            # При клике на кнопку активируем окно
            button.clicked.connect(lambda: self.activate_window(window_name))
            
            # Добавляем кнопку в панель
            self.windows_layout.insertWidget(
                self.windows_layout.count() - 1,
                button
            )
    
    def remove_window_button(self, window_name: str):
        """Удаляет кнопку закрытого окна из панели задач"""
        if window_name in self.open_windows:
            button = self.open_windows[window_name]['button']
            button.setParent(None)
            button.deleteLater()
            del self.open_windows[window_name]
    
    def activate_window(self, window_name: str):
        """Активирует окно (показывает его поверх остальных)"""
        if window_name in self.open_windows:
            window = self.open_windows[window_name]['widget']
            window.showNormal()
            window.raise_()
            window.setFocus()
    
    def get_open_windows(self) -> dict:
        """Возвращает словарь открытых окон"""
        return self.open_windows
    
    def clear_windows(self):
        """Очищает все кнопки активных окон"""
        for window_name in list(self.open_windows.keys()):
            self.remove_window_button(window_name)
    
    def closeEvent(self, event):
        """Остановить таймер при закрытии"""
        self.clock_timer.stop()
        super().closeEvent(event)

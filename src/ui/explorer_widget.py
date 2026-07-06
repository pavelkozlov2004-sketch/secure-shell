"""Проводник (файловый менеджер) с фильтрацией по правам доступа"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
                             QListWidget, QListWidgetItem, QLabel, QPushButton, QMessageBox,
                             QInputDialog, QMenu, QFileDialog, QHeaderView, QSplitter)
from PyQt5.QtCore import Qt, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QIcon
import os
from pathlib import Path

from database.db_manager import DatabaseManager
from auth.login_manager import User
from access_control.permissions import PermissionManager
from file_manager.file_ops import FileOperations
from logging.audit_logger import AuditLogger


class FileExplorer(QWidget):
    """Проводник с поддержкой фильтрации по правам доступа"""
    
    file_opened = pyqtSignal(str)  # Сигнал при открытии файла
    file_selected = pyqtSignal(str)  # Сигнал при выборе файла
    
    def __init__(self, current_user: User, db_manager: DatabaseManager, parent=None):
        super().__init__(parent)
        self.current_user = current_user
        self.db_manager = db_manager
        self.permission_manager = PermissionManager(db_manager)
        self.audit_logger = AuditLogger(db_manager)
        self.current_path = str(Path.home())
        
        self.init_ui()
        self.load_directory(self.current_path)
    
    def init_ui(self):
        """Инициализирует интерфейс проводника"""
        self.setStyleSheet("""
            QWidget {
                background-color: white;
            }
            QTreeWidget, QListWidget {
                border: 1px solid #ddd;
                background-color: white;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #005fa3;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Панель адреса
        address_layout = QHBoxLayout()
        address_layout.setContentsMargins(0, 0, 0, 0)
        address_layout.setSpacing(5)
        
        address_label = QLabel("Адрес:")
        self.address_bar = QLabel(self.current_path)
        self.address_bar.setStyleSheet("background-color: #f5f5f5; padding: 5px; border: 1px solid #ddd; border-radius: 3px;")
        
        address_layout.addWidget(address_label)
        address_layout.addWidget(self.address_bar, 1)
        
        back_button = QPushButton("←")
        back_button.setFixedWidth(40)
        back_button.clicked.connect(self.go_back)
        address_layout.addWidget(back_button)
        
        forward_button = QPushButton("→")
        forward_button.setFixedWidth(40)
        forward_button.clicked.connect(self.go_forward)
        address_layout.addWidget(forward_button)
        
        refresh_button = QPushButton("🔄")
        refresh_button.setFixedWidth(40)
        refresh_button.clicked.connect(self.refresh)
        address_layout.addWidget(refresh_button)
        
        layout.addLayout(address_layout)
        
        # Разделитель между папками и файлами
        splitter = QSplitter(Qt.Horizontal)
        
        # Дерево папок
        self.folder_tree = QTreeWidget()
        self.folder_tree.setHeaderLabels(["Папки"])
        self.folder_tree.setMaximumWidth(250)
        self.folder_tree.itemClicked.connect(self.on_folder_selected)
        self.folder_tree.setStyleSheet("""
            QTreeWidget {
                outline: none;
            }
            QTreeWidget::item {
                padding: 3px;
            }
            QTreeWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
        """)
        splitter.addWidget(self.folder_tree)
        
        # Список файлов
        files_container = QWidget()
        files_layout = QVBoxLayout(files_container)
        files_layout.setContentsMargins(0, 0, 0, 0)
        files_layout.setSpacing(5)
        
        files_label = QLabel("Файлы")
        files_label.setFont(QFont("Arial", 10, QFont.Bold))
        files_layout.addWidget(files_label)
        
        self.file_list = QListWidget()
        self.file_list.itemDoubleClicked.connect(self.on_file_double_clicked)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.on_file_context_menu)
        files_layout.addWidget(self.file_list)
        
        splitter.addWidget(files_container)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        layout.addWidget(splitter)
        
        # Панель инструментов
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(5)
        
        new_folder_btn = QPushButton("📁 Новая папка")
        new_folder_btn.clicked.connect(self.create_new_folder)
        toolbar_layout.addWidget(new_folder_btn)
        
        delete_btn = QPushButton("🗑️ Удалить")
        delete_btn.clicked.connect(self.delete_selected)
        toolbar_layout.addWidget(delete_btn)
        
        properties_btn = QPushButton("ℹ️ Свойства")
        properties_btn.clicked.connect(self.show_properties)
        toolbar_layout.addWidget(properties_btn)
        
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        self.setLayout(layout)
    
    def load_directory(self, path: str):
        """Загружает содержимое директории"""
        if not os.path.isdir(path):
            QMessageBox.warning(self, "Ошибка", f"Папка не существует: {path}")
            return
        
        self.current_path = path
        self.address_bar.setText(path)
        
        # Загружаем файлы
        self.file_list.clear()
        try:
            items = FileOperations.list_directory(path)
            
            for item in sorted(items):
                item_path = os.path.join(path, item)
                
                # Проверяем права доступа
                if not self.permission_manager.can_access_file(self.current_user, item_path):
                    continue
                
                # Отображаем элемент
                if os.path.isdir(item_path):
                    display_name = f"📁 {item}"
                else:
                    display_name = f"📄 {item}"
                
                list_item = QListWidgetItem(display_name)
                list_item.setData(Qt.UserRole, item_path)
                self.file_list.addItem(list_item)
        
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при чтении папки: {str(e)}")
        
        # Загружаем папки в дерево
        self.load_folder_tree(path)
    
    def load_folder_tree(self, root_path: str):
        """Загружает структуру папок в дерево"""
        self.folder_tree.clear()
        
        try:
            root_item = self.create_tree_item(root_path)
            self.folder_tree.addTopLevelItem(root_item)
            root_item.setExpanded(True)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при загрузке дерева: {str(e)}")
    
    def create_tree_item(self, path: str, parent=None) -> QTreeWidgetItem:
        """Создаёт элемент дерева для папки"""
        folder_name = os.path.basename(path) or path
        item = QTreeWidgetItem([f"📁 {folder_name}"])
        item.setData(Qt.UserRole, 0, path)
        
        # Загружаем подпапки
        try:
            sub_items = FileOperations.list_directory(path)
            for sub_item in sorted(sub_items):
                sub_path = os.path.join(path, sub_item)
                
                # Проверяем права и являемся ли это папкой
                if (os.path.isdir(sub_path) and 
                    self.permission_manager.can_access_file(self.current_user, sub_path)):
                    
                    sub_tree_item = self.create_tree_item(sub_path)
                    item.addChild(sub_tree_item)
        except:
            pass
        
        return item
    
    def on_folder_selected(self, item: QTreeWidgetItem, column: int):
        """Обработчик выбора папки в дереве"""
        path = item.data(Qt.UserRole, 0)
        if path:
            self.load_directory(path)
    
    def on_file_double_clicked(self, item: QListWidgetItem):
        """Обработчик двойного клика по файлу"""
        path = item.data(Qt.UserRole)
        
        if os.path.isdir(path):
            self.load_directory(path)
        else:
            self.file_opened.emit(path)
            self.audit_logger.log_file_open(self.current_user.id, path)
    
    def on_file_context_menu(self, position):
        """Контекстное меню для файлов"""
        item = self.file_list.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        open_action = menu.addAction("Открыть")
        menu.addSeparator()
        delete_action = menu.addAction("Удалить")
        properties_action = menu.addAction("Свойства")
        
        action = menu.exec_(self.file_list.mapToGlobal(position))
        
        if action == open_action:
            self.on_file_double_clicked(item)
        elif action == delete_action:
            self.delete_file(item.data(Qt.UserRole))
        elif action == properties_action:
            self.show_file_properties(item.data(Qt.UserRole))
    
    def create_new_folder(self):
        """Создаёт новую папку"""
        folder_name, ok = QInputDialog.getText(self, "Новая папка", "Введите имя папки:")
        
        if ok and folder_name:
            new_path = os.path.join(self.current_path, folder_name)
            
            if FileOperations.create_directory(new_path):
                self.audit_logger.log_file_create(self.current_user.id, new_path)
                self.load_directory(self.current_path)
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось создать папку")
    
    def delete_selected(self):
        """Удаляет выбранный файл"""
        item = self.file_list.currentItem()
        if item:
            path = item.data(Qt.UserRole)
            self.delete_file(path)
    
    def delete_file(self, path: str):
        """Удаляет файл"""
        if QMessageBox.question(self, "Подтверждение", 
                               f"Вы уверены, что хотите удалить?\n{path}") == QMessageBox.Yes:
            
            if FileOperations.delete_file(path):
                self.audit_logger.log_file_delete(self.current_user.id, path)
                self.load_directory(self.current_path)
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось удалить файл")
    
    def show_properties(self):
        """Показывает свойства выбранного файла"""
        item = self.file_list.currentItem()
        if item:
            self.show_file_properties(item.data(Qt.UserRole))
    
    def show_file_properties(self, path: str):
        """Показывает окно со свойствами файла"""
        if not os.path.exists(path):
            QMessageBox.warning(self, "Ошибка", "Файл не на��ден")
            return
        
        file_name = os.path.basename(path)
        file_size = FileOperations.get_file_size(path)
        is_dir = FileOperations.is_directory(path)
        
        info = f"Имя: {file_name}\n"
        info += f"Путь: {path}\n"
        info += f"Тип: {'Папка' if is_dir else 'Файл'}\n"
        
        if not is_dir:
            info += f"Размер: {self.format_size(file_size)} ({file_size} байт)\n"
        
        QMessageBox.information(self, "Свойства", info)
    
    def refresh(self):
        """Обновляет содержимое"""
        self.load_directory(self.current_path)
    
    def go_back(self):
        """Переходит на уровень выше"""
        parent_path = os.path.dirname(self.current_path)
        if parent_path and parent_path != self.current_path:
            self.load_directory(parent_path)
    
    def go_forward(self):
        """Заглушка для кнопки вперёд"""
        pass
    
    @staticmethod
    def format_size(size: int) -> str:
        """Форматирует размер файла в читаемый вид"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

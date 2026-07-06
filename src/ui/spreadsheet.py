"""Табличный редактор с поддержкой CSV и базовых операций"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QFileDialog, QMessageBox, QSpinBox, QLabel, QHeaderView)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
import csv
import os

from database.db_manager import DatabaseManager
from auth.login_manager import User
from access_control.permissions import PermissionManager
from logging.audit_logger import AuditLogger


class SpreadsheetEditor(QWidget):
    """Табличный редактор"""
    
    content_changed = pyqtSignal()
    
    def __init__(self, current_user: User, db_manager: DatabaseManager, parent=None):
        super().__init__(parent)
        self.current_user = current_user
        self.db_manager = db_manager
        self.permission_manager = PermissionManager(db_manager)
        self.audit_logger = AuditLogger(db_manager)
        
        self.current_file = None
        self.is_modified = False
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализирует интерфейс редактора таблиц"""
        self.setWindowTitle("Табличный редактор")
        self.setGeometry(100, 100, 1000, 600)
        
        self.setStyleSheet("""
            QWidget {
                background-color: white;
            }
            QTableWidget {
                border: 1px solid #ddd;
                background-color: white;
                gridline-color: #ddd;
            }
            QTableWidget::item {
                padding: 4px;
                border: 1px solid #ddd;
            }
            QTableWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #005fa3;
            }
            QSpinBox {
                border: 1px solid #ddd;
                padding: 4px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Панель инструментов
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(5)
        
        # Управление строками и столбцами
        rows_label = QLabel("Строк:")
        self.rows_spinbox = QSpinBox()
        self.rows_spinbox.setMinimum(1)
        self.rows_spinbox.setMaximum(1000)
        self.rows_spinbox.setValue(10)
        self.rows_spinbox.setMaximumWidth(60)
        self.rows_spinbox.valueChanged.connect(self.on_rows_changed)
        toolbar_layout.addWidget(rows_label)
        toolbar_layout.addWidget(self.rows_spinbox)
        
        cols_label = QLabel("Столбцов:")
        self.cols_spinbox = QSpinBox()
        self.cols_spinbox.setMinimum(1)
        self.cols_spinbox.setMaximum(100)
        self.cols_spinbox.setValue(5)
        self.cols_spinbox.setMaximumWidth(60)
        self.cols_spinbox.valueChanged.connect(self.on_cols_changed)
        toolbar_layout.addWidget(cols_label)
        toolbar_layout.addWidget(self.cols_spinbox)
        
        toolbar_layout.addSpacing(20)
        
        # Кнопки операций
        insert_row_btn = QPushButton("➕ Строка")
        insert_row_btn.clicked.connect(self.insert_row)
        toolbar_layout.addWidget(insert_row_btn)
        
        insert_col_btn = QPushButton("➕ Столбец")
        insert_col_btn.clicked.connect(self.insert_column)
        toolbar_layout.addWidget(insert_col_btn)
        
        delete_row_btn = QPushButton("➖ Строка")
        delete_row_btn.clicked.connect(self.delete_row)
        toolbar_layout.addWidget(delete_row_btn)
        
        delete_col_btn = QPushButton("➖ Столбец")
        delete_col_btn.clicked.connect(self.delete_column)
        toolbar_layout.addWidget(delete_col_btn)
        
        toolbar_layout.addSpacing(20)
        
        sort_btn = QPushButton("🔤 Сортировать")
        sort_btn.clicked.connect(self.sort_data)
        toolbar_layout.addWidget(sort_btn)
        
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        # Таблица
        self.table = QTableWidget()
        self.table.setRowCount(10)
        self.table.setColumnCount(5)
        self.table.itemChanged.connect(self.on_cell_changed)
        
        # Установим заголовки
        for i in range(5):
            self.table.setHorizontalHeaderItem(i, QTableWidgetItem(f"Столбец {i+1}"))
        
        # Установим высоту строк
        self.table.verticalHeader().setDefaultSectionSize(25)
        
        layout.addWidget(self.table)
        
        # Панель кнопок
        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(0, 0, 0, 0)
        buttons_layout.setSpacing(5)
        
        new_btn = QPushButton("📄 Новый")
        new_btn.clicked.connect(self.new_file)
        buttons_layout.addWidget(new_btn)
        
        open_btn = QPushButton("📂 Открыть")
        open_btn.clicked.connect(self.open_file)
        buttons_layout.addWidget(open_btn)
        
        save_btn = QPushButton("💾 Сохранить")
        save_btn.clicked.connect(self.save_file)
        buttons_layout.addWidget(save_btn)
        
        save_as_btn = QPushButton("💾 Сохранить как...")
        save_as_btn.clicked.connect(self.save_as)
        buttons_layout.addWidget(save_as_btn)
        
        export_csv_btn = QPushButton("📥 Экспорт CSV")
        export_csv_btn.clicked.connect(self.export_csv)
        buttons_layout.addWidget(export_csv_btn)
        
        buttons_layout.addStretch()
        
        close_btn = QPushButton("✕ Закрыть")
        close_btn.clicked.connect(self.close)
        buttons_layout.addWidget(close_btn)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def on_cell_changed(self, item):
        """Обработчик изменения ячейки"""
        self.is_modified = True
        self.content_changed.emit()
    
    def on_rows_changed(self, value):
        """Изменяет количество строк"""
        current_rows = self.table.rowCount()
        if value > current_rows:
            self.table.insertRow(current_rows)
        elif value < current_rows:
            self.table.removeRow(current_rows - 1)
    
    def on_cols_changed(self, value):
        """Изменяет количество столбцов"""
        current_cols = self.table.columnCount()
        if value > current_cols:
            for i in range(value - current_cols):
                self.table.insertColumn(current_cols + i)
                self.table.setHorizontalHeaderItem(current_cols + i, 
                                                   QTableWidgetItem(f"Столбец {current_cols + i + 1}"))
        elif value < current_cols:
            for i in range(current_cols - value):
                self.table.removeColumn(current_cols - 1)
    
    def insert_row(self):
        """Вставляет новую строку"""
        self.table.insertRow(self.table.rowCount())
        self.is_modified = True
    
    def insert_column(self):
        """Вставляет новый столбец"""
        col_count = self.table.columnCount()
        self.table.insertColumn(col_count)
        self.table.setHorizontalHeaderItem(col_count, 
                                          QTableWidgetItem(f"Столбец {col_count + 1}"))
        self.is_modified = True
    
    def delete_row(self):
        """Удаляет выбранную строку"""
        current_row = self.table.currentRow()
        if current_row >= 0:
            self.table.removeRow(current_row)
            self.is_modified = True
    
    def delete_column(self):
        """Удаляет выбранный столбец"""
        current_col = self.table.currentColumn()
        if current_col >= 0:
            self.table.removeColumn(current_col)
            self.is_modified = True
    
    def sort_data(self):
        """Сортирует данные по первому столбцу"""
        self.table.sortItems(0, Qt.AscendingOrder)
        self.is_modified = True
    
    def new_file(self):
        """Создаёт новую таблицу"""
        if self.is_modified:
            reply = QMessageBox.question(self, "Новая таблица",
                                        "Сохранить изменения?",
                                        QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if reply == QMessageBox.Yes:
                self.save_file()
            elif reply == QMessageBox.Cancel:
                return
        
        self.table.setRowCount(10)
        self.table.setColumnCount(5)
        for i in range(5):
            self.table.setHorizontalHeaderItem(i, QTableWidgetItem(f"Столбец {i+1}"))
        
        self.current_file = None
        self.is_modified = False
        self.setWindowTitle("Табличный редактор")
    
    def open_file(self):
        """Открывает CSV файл"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Открыть файл", "",
                                                   "CSV файлы (*.csv);;Все файлы (*)")
        
        if file_path:
            if not self.permission_manager.can_access_file(self.current_user, file_path):
                QMessageBox.critical(self, "Ошибка", "У вас нет доступа к этому файлу")
                self.audit_logger.log_access_denied(self.current_user.id, file_path)
                return
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    rows = list(reader)
                
                if rows:
                    max_cols = max(len(row) for row in rows)
                    self.table.setRowCount(len(rows))
                    self.table.setColumnCount(max_cols)
                    
                    for i, row in enumerate(rows):
                        for j, cell in enumerate(row):
                            self.table.setItem(i, j, QTableWidgetItem(cell))
                
                self.current_file = file_path
                self.is_modified = False
                self.setWindowTitle(f"Табличный редактор - {os.path.basename(file_path)}")
                
                self.audit_logger.log_file_open(self.current_user.id, file_path)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось открыть файл: {str(e)}")
    
    def save_file(self):
        """Сохраняет текущий файл"""
        if not self.current_file:
            self.save_as()
            return
        
        if not self.permission_manager.can_write_file(self.current_user, self.current_file):
            QMessageBox.critical(self, "Ошибка", "У вас нет прав на запись в этот файл")
            self.audit_logger.log_access_denied(self.current_user.id, self.current_file)
            return
        
        try:
            with open(self.current_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                for row in range(self.table.rowCount()):
                    row_data = []
                    for col in range(self.table.columnCount()):
                        item = self.table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
            
            self.is_modified = False
            self.audit_logger.log_file_save(self.current_user.id, self.current_file)
            QMessageBox.information(self, "Успех", "Файл сохранён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл: {str(e)}")
    
    def save_as(self):
        """Сохраняет файл с новым именем"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", "",
                                                   "CSV файлы (*.csv);;Все файлы (*)")
        
        if file_path:
            if not self.permission_manager.can_write_file(self.current_user, file_path):
                QMessageBox.critical(self, "Ошибка", "У вас нет прав на запись в эту директорию")
                self.audit_logger.log_access_denied(self.current_user.id, file_path)
                return
            
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    for row in range(self.table.rowCount()):
                        row_data = []
                        for col in range(self.table.columnCount()):
                            item = self.table.item(row, col)
                            row_data.append(item.text() if item else "")
                        writer.writerow(row_data)
                
                self.current_file = file_path
                self.is_modified = False
                self.setWindowTitle(f"Табличный редактор - {os.path.basename(file_path)}")
                
                self.audit_logger.log_file_save(self.current_user.id, file_path)
                QMessageBox.information(self, "Успех", "Файл сохранён")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл: {str(e)}")
    
    def export_csv(self):
        """Экспортирует таблицу в CSV"""
        self.save_as()
    
    def closeEvent(self, event):
        """Обработчик закрытия редактора"""
        if self.is_modified:
            reply = QMessageBox.question(self, "Закрыть",
                                        "Сохранить изменения?",
                                        QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if reply == QMessageBox.Yes:
                self.save_file()
                event.accept()
            elif reply == QMessageBox.Cancel:
                event.ignore()
            else:
                event.accept()
        else:
            event.accept()

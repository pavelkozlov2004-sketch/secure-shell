"""Текстовый редактор с поддержкой основных форматов"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
                             QComboBox, QSpinBox, QColorDialog, QFileDialog, QMessageBox,
                             QToolBar, QLabel, QFontComboBox)
from PyQt5.QtCore import Qt, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QTextCursor, QColor
from PyQt5.QtPrintSupport import QPrinter, QPrintDialog
import os

from database.db_manager import DatabaseManager
from auth.login_manager import User
from access_control.permissions import PermissionManager
from logging.audit_logger import AuditLogger


class TextEditor(QWidget):
    """Текстовый редактор с форматированием"""
    
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
        """Инициализирует интерфейс редактора"""
        self.setWindowTitle("Текстовый редактор")
        self.setGeometry(100, 100, 800, 600)
        
        self.setStyleSheet("""
            QWidget {
                background-color: white;
            }
            QTextEdit {
                border: 1px solid #ddd;
                background-color: white;
                font-size: 11px;
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
            QComboBox, QSpinBox, QFontComboBox {
                border: 1px solid #ddd;
                padding: 4px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Панель инструментов форматирования
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(5)
        
        # Шрифт
        font_label = QLabel("Шрифт:")
        self.font_combo = QFontComboBox()
        self.font_combo.currentFontChanged.connect(self.on_font_changed)
        toolbar_layout.addWidget(font_label)
        toolbar_layout.addWidget(self.font_combo)
        
        # Размер шрифта
        size_label = QLabel("Размер:")
        self.size_spinbox = QSpinBox()
        self.size_spinbox.setMinimum(8)
        self.size_spinbox.setMaximum(72)
        self.size_spinbox.setValue(11)
        self.size_spinbox.setMaximumWidth(60)
        self.size_spinbox.valueChanged.connect(self.on_font_size_changed)
        toolbar_layout.addWidget(size_label)
        toolbar_layout.addWidget(self.size_spinbox)
        
        toolbar_layout.addSpacing(20)
        
        # Жирный
        bold_btn = QPushButton("B")
        bold_btn.setCheckable(True)
        bold_btn.setMaximumWidth(35)
        bold_btn.clicked.connect(self.toggle_bold)
        toolbar_layout.addWidget(bold_btn)
        self.bold_btn = bold_btn
        
        # Курсив
        italic_btn = QPushButton("I")
        italic_btn.setCheckable(True)
        italic_btn.setMaximumWidth(35)
        italic_btn.clicked.connect(self.toggle_italic)
        toolbar_layout.addWidget(italic_btn)
        self.italic_btn = italic_btn
        
        # Подчёркивание
        underline_btn = QPushButton("U")
        underline_btn.setCheckable(True)
        underline_btn.setMaximumWidth(35)
        underline_btn.clicked.connect(self.toggle_underline)
        toolbar_layout.addWidget(underline_btn)
        self.underline_btn = underline_btn
        
        toolbar_layout.addSpacing(20)
        
        # Выравнивание
        align_left_btn = QPushButton("◀ Влево")
        align_left_btn.setMaximumWidth(80)
        align_left_btn.clicked.connect(lambda: self.text_edit.setAlignment(Qt.AlignLeft))
        toolbar_layout.addWidget(align_left_btn)
        
        align_center_btn = QPushButton("◆ По центру")
        align_center_btn.setMaximumWidth(80)
        align_center_btn.clicked.connect(lambda: self.text_edit.setAlignment(Qt.AlignCenter))
        toolbar_layout.addWidget(align_center_btn)
        
        align_right_btn = QPushButton("Вправо ▶")
        align_right_btn.setMaximumWidth(80)
        align_right_btn.clicked.connect(lambda: self.text_edit.setAlignment(Qt.AlignRight))
        toolbar_layout.addWidget(align_right_btn)
        
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        # Основной текстовый редактор
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Arial", 11))
        self.text_edit.textChanged.connect(self.on_text_changed)
        layout.addWidget(self.text_edit)
        
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
        
        buttons_layout.addStretch()
        
        close_btn = QPushButton("✕ Закрыть")
        close_btn.clicked.connect(self.close)
        buttons_layout.addWidget(close_btn)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def on_text_changed(self):
        """Обработчик изменения текста"""
        self.is_modified = True
        self.content_changed.emit()
    
    def on_font_changed(self, font):
        """Изменяет шрифт выделенного текста"""
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection():
            format = cursor.charFormat()
            format.setFont(font)
            cursor.setCharFormat(format)
        else:
            self.text_edit.setCurrentFont(font)
    
    def on_font_size_changed(self, size):
        """Изменяет размер шрифта выделенного текста"""
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection():
            format = cursor.charFormat()
            format.setFontPointSize(size)
            cursor.setCharFormat(format)
    
    def toggle_bold(self):
        """Переключает жирный текст"""
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection():
            format = cursor.charFormat()
            format.setFontWeight(700 if not self.bold_btn.isChecked() else 400)
            cursor.setCharFormat(format)
    
    def toggle_italic(self):
        """Переключает курсив"""
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection():
            format = cursor.charFormat()
            format.setFontItalic(self.italic_btn.isChecked())
            cursor.setCharFormat(format)
    
    def toggle_underline(self):
        """Переключает подчёркивание"""
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection():
            format = cursor.charFormat()
            format.setFontUnderline(self.underline_btn.isChecked())
            cursor.setCharFormat(format)
    
    def new_file(self):
        """Создаёт новый файл"""
        if self.is_modified:
            reply = QMessageBox.question(self, "Новый файл",
                                        "Сохранить изменения?",
                                        QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if reply == QMessageBox.Yes:
                self.save_file()
            elif reply == QMessageBox.Cancel:
                return
        
        self.text_edit.clear()
        self.current_file = None
        self.is_modified = False
        self.setWindowTitle("Текстовый редактор")
    
    def open_file(self):
        """Открывает файл"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Открыть файл", "",
                                                   "Текстовые файлы (*.txt);;Все файлы (*)")
        
        if file_path:
            if not self.permission_manager.can_access_file(self.current_user, file_path):
                QMessageBox.critical(self, "Ошибка", "У вас нет доступа к этому файлу")
                self.audit_logger.log_access_denied(self.current_user.id, file_path)
                return
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.text_edit.setPlainText(content)
                self.current_file = file_path
                self.is_modified = False
                self.setWindowTitle(f"Текстовый редактор - {os.path.basename(file_path)}")
                
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
            with open(self.current_file, 'w', encoding='utf-8') as f:
                f.write(self.text_edit.toPlainText())
            
            self.is_modified = False
            self.audit_logger.log_file_save(self.current_user.id, self.current_file)
            QMessageBox.information(self, "Успех", "Файл сохранён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл: {str(e)}")
    
    def save_as(self):
        """Сохраняет файл с новым именем"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", "",
                                                   "Текстовые файлы (*.txt);;Все файлы (*)")
        
        if file_path:
            if not self.permission_manager.can_write_file(self.current_user, file_path):
                QMessageBox.critical(self, "Ошибка", "У вас нет прав на запись в эту директорию")
                self.audit_logger.log_access_denied(self.current_user.id, file_path)
                return
            
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.text_edit.toPlainText())
                
                self.current_file = file_path
                self.is_modified = False
                self.setWindowTitle(f"Текстовый редактор - {os.path.basename(file_path)}")
                
                self.audit_logger.log_file_save(self.current_user.id, file_path)
                QMessageBox.information(self, "Успех", "Файл сохранён")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл: {str(e)}")
    
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

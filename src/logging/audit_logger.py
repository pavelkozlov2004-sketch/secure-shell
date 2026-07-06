"""Логирование действий пользователей для аудита"""

import logging
from datetime import datetime
from pathlib import Path

from config import AUDIT_LOG_PATH, APP_LOG_PATH


class AuditLogger:
    """Логирует действия пользователей в БД и файл"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.file_logger = self._setup_file_logger()
    
    @staticmethod
    def _setup_file_logger():
        """Настраивает логирование в файл"""
        logger = logging.getLogger('audit')
        logger.setLevel(logging.INFO)
        
        # Файловый обработчик
        handler = logging.FileHandler(AUDIT_LOG_PATH, encoding='utf-8')
        handler.setLevel(logging.INFO)
        
        # Формат логов
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def log_action(self, user_id: int, action: str, details: str = None):
        """Логирует действие пользователя"""
        try:
            self.db.execute(
                '''INSERT INTO audit_logs (user_id, action, details)
                   VALUES (?, ?, ?)''',
                (user_id, action, details)
            )
        except Exception as e:
            self.file_logger.error(f"Ошибка при логировании: {e}")
        
        # Также логируем в файл
        self.file_logger.info(f"User={user_id}, Action={action}, Details={details}")
    
    def log_login(self, user_id: int):
        """Логирует вход пользователя"""
        self.log_action(user_id, 'LOGIN', 'Пользователь вошёл в систему')
    
    def log_logout(self, user_id: int):
        """Логирует выход пользователя"""
        self.log_action(user_id, 'LOGOUT', 'Пользователь вышел из системы')
    
    def log_file_open(self, user_id: int, file_path: str):
        """Логирует открытие файла"""
        self.log_action(user_id, 'FILE_OPEN', f'Открыт файл: {file_path}')
    
    def log_file_save(self, user_id: int, file_path: str):
        """Логирует сохранение файла"""
        self.log_action(user_id, 'FILE_SAVE', f'Сохранён файл: {file_path}')
    
    def log_file_create(self, user_id: int, file_path: str):
        """Логирует создание файла"""
        self.log_action(user_id, 'FILE_CREATE', f'Создан файл: {file_path}')
    
    def log_file_delete(self, user_id: int, file_path: str):
        """Логирует удаление файла"""
        self.log_action(user_id, 'FILE_DELETE', f'Удалён файл: {file_path}')
    
    def log_access_denied(self, user_id: int, resource: str):
        """Логирует отказ в доступе"""
        self.log_action(user_id, 'ACCESS_DENIED', f'Отказано в доступе к: {resource}')

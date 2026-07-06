"""Операции с файлами"""

import os
from pathlib import Path


class FileOperations:
    """Класс для выполнения операций с файлами"""
    
    @staticmethod
    def file_exists(file_path: str) -> bool:
        """Проверяет, существует ли файл"""
        return os.path.exists(file_path)
    
    @staticmethod
    def is_directory(path: str) -> bool:
        """Проверяет, является ли путь директорией"""
        return os.path.isdir(path)
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Возвращает размер файла в байтах"""
        return os.path.getsize(file_path)
    
    @staticmethod
    def get_modification_time(file_path: str) -> float:
        """Возвращает время последнего изменения файла"""
        return os.path.getmtime(file_path)
    
    @staticmethod
    def create_directory(path: str) -> bool:
        """Создаёт директорию"""
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def delete_file(file_path: str) -> bool:
        """Удаляет файл"""
        try:
            os.remove(file_path)
            return True
        except Exception:
            return False
    
    @staticmethod
    def rename_file(old_path: str, new_path: str) -> bool:
        """Переименовывает файл"""
        try:
            os.rename(old_path, new_path)
            return True
        except Exception:
            return False
    
    @staticmethod
    def list_directory(path: str) -> list:
        """Получает список файлов в директории"""
        try:
            return os.listdir(path)
        except Exception:
            return []

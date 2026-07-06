"""Проверка прав доступа к ресурсам"""

from typing import List, Optional

from database.db_manager import DatabaseManager
from auth.login_manager import User


class PermissionManager:
    """Менеджер для проверки прав доступа"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def can_access_file(self, user: User, file_path: str) -> bool:
        """Проверяет, может ли пользователь получить доступ к файлу
        
        Args:
            user: объект пользователя
            file_path: путь к файлу
            
        Returns:
            True если есть доступ, иначе False
        """
        file_meta = self._get_file_metadata(file_path)
        
        if not file_meta:
            # Если метаданные не найдены, отказываем в доступе
            return False
        
        # Проверка по направлению
        if user.direction_id != file_meta['direction_id']:
            return False
        
        # Проверка по уровню секретности
        # Пользователь может видеть файлы своего уровня и ниже
        if user.secrecy_level_id < file_meta['secrecy_level_id']:
            return False
        
        return True
    
    def can_write_file(self, user: User, file_path: str) -> bool:
        """Проверяет, может ли пользователь писать в файл"""
        return self.can_access_file(user, file_path)
    
    def can_delete_file(self, user: User, file_path: str) -> bool:
        """Проверяет, может ли пользователь удалить файл"""
        return self.can_access_file(user, file_path)
    
    def filter_files(self, user: User, file_paths: List[str]) -> List[str]:
        """Фильтрует список файлов по правам пользователя
        
        Args:
            user: объект пользователя
            file_paths: список путей к файлам
            
        Returns:
            Отфильтрованный список файлов
        """
        return [f for f in file_paths if self.can_access_file(user, f)]
    
    def _get_file_metadata(self, file_path: str) -> Optional[dict]:
        """Получает метаданные файла из БД"""
        meta = self.db.fetch_one(
            'SELECT direction_id, secrecy_level_id FROM files_metadata WHERE path = ?',
            (file_path,)
        )
        if meta:
            return {
                'direction_id': meta[0],
                'secrecy_level_id': meta[1]
            }
        return None

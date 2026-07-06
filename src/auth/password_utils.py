"""Утилиты для работы с паролями"""

import hashlib
import secrets
from typing import Tuple


class PasswordUtils:
    """Утилиты для хеширования и проверки паролей"""
    
    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """Хеширует пароль с солью SHA-256
        
        Args:
            password: исходный пароль
            
        Returns:
            Кортеж (хеш, соль)
        """
        salt = secrets.token_hex(16)  # 32-символьная соль
        hash_obj = hashlib.sha256((password + salt).encode('utf-8'))
        return hash_obj.hexdigest(), salt
    
    @staticmethod
    def verify_password(password: str, hash_value: str, salt: str) -> bool:
        """Проверяет пароль против хеша
        
        Args:
            password: пароль для проверки
            hash_value: сохранённый хеш
            salt: сохранённая соль
            
        Returns:
            True если пароль верный, иначе False
        """
        hash_obj = hashlib.sha256((password + salt).encode('utf-8'))
        return hash_obj.hexdigest() == hash_value
    
    @staticmethod
    def is_valid_password(password: str) -> bool:
        """Проверяет, соответствует ли пароль требованиям
        
        Args:
            password: пароль для проверки
            
        Returns:
            True если пароль валидный
        """
        # Минимум 8 символов
        if len(password) < 8:
            return False
        return True

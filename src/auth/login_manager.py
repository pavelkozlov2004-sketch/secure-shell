"""Менеджер авторизации и управления пользователями"""

import sqlite3
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from database.db_manager import DatabaseManager
from auth.password_utils import PasswordUtils
from logging.audit_logger import AuditLogger


@dataclass
class User:
    """Класс для представления пользователя"""
    id: int
    login: str
    direction_id: int
    secrecy_level_id: int
    is_admin: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразует пользователя в словарь"""
        return {
            'id': self.id,
            'login': self.login,
            'direction_id': self.direction_id,
            'secrecy_level_id': self.secrecy_level_id,
            'is_admin': self.is_admin
        }


class LoginManager:
    """Менеджер для авторизации и управления пользователями"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.current_user: Optional[User] = None
        self.audit_logger = AuditLogger(db_manager)
    
    def register_user(self, login: str, password: str, direction_id: int,
                     secrecy_level_id: int, is_admin: bool = False) -> bool:
        """Регистрирует нового пользователя
        
        Args:
            login: логин пользователя
            password: пароль
            direction_id: ID направления
            secrecy_level_id: ID уровня секретности
            is_admin: администратор ли
            
        Returns:
            True если пользователь создан, иначе False
        """
        try:
            if not PasswordUtils.is_valid_password(password):
                return False
            
            password_hash, salt = PasswordUtils.hash_password(password)
            stored_hash = f"{password_hash}${salt}"
            
            self.db.execute(
                '''INSERT INTO users 
                   (login, password_hash, direction_id, secrecy_level_id, is_admin)
                   VALUES (?, ?, ?, ?, ?)''',
                (login, stored_hash, direction_id, secrecy_level_id, int(is_admin))
            )
            return True
            
        except sqlite3.IntegrityError:
            # Пользователь с таким логином уже существует
            return False
    
    def login(self, login: str, password: str) -> bool:
        """Авторизует пользователя
        
        Args:
            login: логин
            password: пароль
            
        Returns:
            True если авторизация успешна, иначе False
        """
        user_row = self.db.fetch_one(
            '''SELECT id, login, password_hash, direction_id, secrecy_level_id, is_admin
               FROM users WHERE login = ?''',
            (login,)
        )
        
        if not user_row:
            return False
        
        user_id, username, stored_hash, direction_id, level_id, is_admin = user_row
        
        try:
            hash_value, salt = stored_hash.split('$')
        except ValueError:
            return False
        
        if PasswordUtils.verify_password(password, hash_value, salt):
            self.current_user = User(
                id=user_id,
                login=username,
                direction_id=direction_id,
                secrecy_level_id=level_id,
                is_admin=bool(is_admin)
            )
            self.audit_logger.log_login(user_id)
            return True
        
        return False
    
    def logout(self):
        """Завершает текущий сеанс"""
        if self.current_user:
            self.audit_logger.log_logout(self.current_user.id)
            self.current_user = None
    
    def get_current_user(self) -> Optional[User]:
        """Возвращает текущего авторизованного пользователя"""
        return self.current_user
    
    def is_logged_in(self) -> bool:
        """Проверяет, авторизован ли пользователь"""
        return self.current_user is not None
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """Меняет пароль пользователя
        
        Args:
            user_id: ID пользователя
            old_password: старый пароль
            new_password: новый пароль
            
        Returns:
            True если пароль изменён, иначе False
        """
        user_row = self.db.fetch_one(
            'SELECT login, password_hash FROM users WHERE id = ?',
            (user_id,)
        )
        
        if not user_row:
            return False
        
        login, stored_hash = user_row
        
        try:
            hash_value, salt = stored_hash.split('$')
        except ValueError:
            return False
        
        # Проверяем старый пароль
        if not PasswordUtils.verify_password(old_password, hash_value, salt):
            return False
        
        # Проверяем новый пароль
        if not PasswordUtils.is_valid_password(new_password):
            return False
        
        # Хешируем новый пароль
        new_hash, new_salt = PasswordUtils.hash_password(new_password)
        new_stored_hash = f"{new_hash}${new_salt}"
        
        self.db.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_stored_hash, user_id)
        )
        
        self.audit_logger.log_action(user_id, 'CHANGE_PASSWORD', 'Пользователь изменил пароль')
        return True
    
    def reset_password(self, user_id: int, new_password: str) -> bool:
        """Сбрасывает пароль пользователя (для администратора)
        
        Args:
            user_id: ID пользователя
            new_password: новый пароль
            
        Returns:
            True если пароль сброшен
        """
        if not self.current_user or not self.current_user.is_admin:
            return False
        
        if not PasswordUtils.is_valid_password(new_password):
            return False
        
        new_hash, new_salt = PasswordUtils.hash_password(new_password)
        new_stored_hash = f"{new_hash}${new_salt}"
        
        self.db.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_stored_hash, user_id)
        )
        
        self.audit_logger.log_action(
            self.current_user.id,
            'RESET_PASSWORD',
            f'Администратор сбросил пароль пользователю ID={user_id}'
        )
        return True
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Получает пользователя по ID"""
        user_row = self.db.fetch_one(
            'SELECT id, login, direction_id, secrecy_level_id, is_admin FROM users WHERE id = ?',
            (user_id,)
        )
        
        if user_row:
            return User(
                id=user_row[0],
                login=user_row[1],
                direction_id=user_row[2],
                secrecy_level_id=user_row[3],
                is_admin=bool(user_row[4])
            )
        return None
    
    def get_all_users(self) -> List[User]:
        """Получает список всех пользователей (для администратора)"""
        if not self.current_user or not self.current_user.is_admin:
            return []
        
        users_rows = self.db.fetch_all(
            'SELECT id, login, direction_id, secrecy_level_id, is_admin FROM users'
        )
        
        return [
            User(
                id=row[0],
                login=row[1],
                direction_id=row[2],
                secrecy_level_id=row[3],
                is_admin=bool(row[4])
            )
            for row in users_rows
        ]
    
    def delete_user(self, user_id: int) -> bool:
        """Удаляет пользователя (для администратора)"""
        if not self.current_user or not self.current_user.is_admin:
            return False
        
        if user_id == self.current_user.id:
            # Нельзя удалить себя
            return False
        
        self.db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        self.audit_logger.log_action(
            self.current_user.id,
            'DELETE_USER',
            f'Администратор удалил пользователя ID={user_id}'
        )
        return True
    
    def update_user(self, user_id: int, direction_id: int = None,
                   secrecy_level_id: int = None, is_admin: bool = None) -> bool:
        """Обновляет параметры пользователя (для администратора)"""
        if not self.current_user or not self.current_user.is_admin:
            return False
        
        updates = []
        params = []
        
        if direction_id is not None:
            updates.append('direction_id = ?')
            params.append(direction_id)
        
        if secrecy_level_id is not None:
            updates.append('secrecy_level_id = ?')
            params.append(secrecy_level_id)
        
        if is_admin is not None:
            updates.append('is_admin = ?')
            params.append(int(is_admin))
        
        if not updates:
            return False
        
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        
        self.db.execute(query, tuple(params))
        self.audit_logger.log_action(
            self.current_user.id,
            'UPDATE_USER',
            f'Администратор обновил пользователя ID={user_id}'
        )
        return True

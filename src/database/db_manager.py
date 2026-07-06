"""Менеджер базы данных SQLite"""

import sqlite3
import os
from pathlib import Path
from contextlib import contextmanager
from typing import List, Tuple, Optional, Any, Dict

from config import DB_PATH, DEFAULT_ADMIN, Direction, SecrecyLevel


class DatabaseManager:
    """Менеджер для работы с БД SQLite"""
    
    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self.connection = None
        self.init_db()
    
    def init_db(self):
        """Инициализирует БД и создаёт таблицы"""
        is_new_db = not os.path.exists(self.db_path)
        
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        
        if is_new_db:
            self._create_tables()
            self._populate_defaults()
    
    def _create_tables(self):
        """Создаёт таблицы из schema.sql"""
        schema_path = Path(__file__).parent / 'schema.sql'
        
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()
        
        cursor = self.connection.cursor()
        cursor.executescript(sql_script)
        self.connection.commit()
    
    def _populate_defaults(self):
        """Заполняет справочные данные и создаёт администратора"""
        cursor = self.connection.cursor()
        
        # Направления
        for direction in Direction:
            cursor.execute(
                'INSERT INTO directions (id, name) VALUES (?, ?)',
                (direction.id, direction.display_name)
            )
        
        # Уровни секретности
        for level in SecrecyLevel:
            cursor.execute(
                'INSERT INTO secrecy_levels (id, name, level_order) VALUES (?, ?, ?)',
                (level.id, level.display_name, level.level_order)
            )
        
        # Администратор по умолчанию
        from auth.password_utils import PasswordUtils
        
        admin_login = DEFAULT_ADMIN["login"]
        admin_password = DEFAULT_ADMIN["password"]
        admin_direction = DEFAULT_ADMIN["direction"].id
        admin_level = DEFAULT_ADMIN["secrecy_level"].id
        
        password_hash, salt = PasswordUtils.hash_password(admin_password)
        stored_hash = f"{password_hash}${salt}"
        
        cursor.execute(
            '''INSERT INTO users 
               (login, password_hash, direction_id, secrecy_level_id, is_admin) 
               VALUES (?, ?, ?, ?, ?)''',
            (admin_login, stored_hash, admin_direction, admin_level, 1)
        )
        
        self.connection.commit()
    
    @contextmanager
    def get_cursor(self):
        """Контекстный менеджер для работы с курсором"""
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            raise e
    
    def execute(self, query: str, params: tuple = None) -> sqlite3.Cursor:
        """Выполняет SQL-запрос (INSERT, UPDATE, DELETE)"""
        with self.get_cursor() as cursor:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor
    
    def fetch_one(self, query: str, params: tuple = None) -> Optional[sqlite3.Row]:
        """Возвращает одну строку результата запроса"""
        cursor = self.connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.fetchone()
    
    def fetch_all(self, query: str, params: tuple = None) -> List[sqlite3.Row]:
        """Возвращает все строки результата запроса"""
        cursor = self.connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.fetchall()
    
    def fetch_dict(self, query: str, params: tuple = None) -> Dict[str, Any]:
        """Возвращает одну строку как словарь"""
        row = self.fetch_one(query, params)
        if row:
            return dict(row)
        return None
    
    def fetch_all_dict(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """Возвращает все строки как список словарей"""
        rows = self.fetch_all(query, params)
        return [dict(row) for row in rows]
    
    def close(self):
        """Закрывает соединение с БД"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __del__(self):
        """Деструктор: закрывает БД"""
        self.close()

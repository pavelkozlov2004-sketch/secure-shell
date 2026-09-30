"""Три связанные SQLite-базы с миграцией и общими транзакциями."""
import os
import sqlite3
import tempfile
from pathlib import Path
from contextlib import closing, contextmanager
from config import (DB_PATH, TABLES_DB_PATH, DOCUMENTS_DB_PATH, LEGACY_DB_PATH,
                    DEFAULT_ADMIN, Direction, SecrecyLevel)


class DatabaseManager:
    def __init__(self, db_path=None):
        self.connection = None
        self.db_path = str(DB_PATH if db_path is None else db_path)
        self._migrate_legacy = db_path is None
        if self.db_path == ':memory:':
            self.tables_db_path = self.documents_db_path = ':memory:'
        else:
            directory = Path(self.db_path).parent
            self.tables_db_path = str(directory / TABLES_DB_PATH.name)
            self.documents_db_path = str(directory / DOCUMENTS_DB_PATH.name)
            paths = {Path(p).resolve() for p in
                     (self.db_path, self.tables_db_path, self.documents_db_path)}
            if len(paths) != 3:
                raise ValueError('Для учётных данных, таблиц и документов нужны разные файлы БД')
        self.init_db()

    def init_db(self):
        if self.db_path != ':memory:':
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._copy_legacy_database()
            for path in (self.db_path, self.tables_db_path, self.documents_db_path):
                self._prepare_private_file(path)
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute('PRAGMA foreign_keys = ON')
            # INSERT OR REPLACE также должен запускать ограничения удаления.
            self.connection.execute('PRAGMA recursive_triggers = ON')
            self.connection.execute('PRAGMA busy_timeout = 5000')
            self.connection.execute('ATTACH DATABASE ? AS tables_store', (self.tables_db_path,))
            self.connection.execute('ATTACH DATABASE ? AS documents_store', (self.documents_db_path,))
            # DELETE/FULL позволяет SQLite атомарно фиксировать изменения во всех
            # трёх файлах через super-journal, в отличие от режима WAL.
            for schema in ('main', 'tables_store', 'documents_store'):
                mode = self.connection.execute(f'PRAGMA {schema}.journal_mode = DELETE').fetchone()[0]
                if self.db_path != ':memory:' and mode.lower() != 'delete':
                    raise RuntimeError('Не удалось включить атомарные транзакции между базами')
                self.connection.execute(f'PRAGMA {schema}.synchronous = FULL')
            self._load_sql('schema.sql')
            with self.connection:
                columns = {r['name'] for r in self.connection.execute('PRAGMA table_info(users)')}
                if 'active' not in columns:
                    self.connection.execute('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1')
                if 'network_blocked' not in columns:
                    self.connection.execute('ALTER TABLE users ADD COLUMN network_blocked INTEGER NOT NULL DEFAULT 0')
                audit_columns = {r['name'] for r in self.connection.execute('PRAGMA table_info(audit_logs)')}
                for name in ('session_id', 'executable_path', 'transfer_source', 'transfer_destination'):
                    if name not in audit_columns:
                        self.connection.execute(f'ALTER TABLE audit_logs ADD COLUMN {name} TEXT')
                for d in Direction:
                    self.connection.execute('INSERT OR IGNORE INTO directions(id,name) VALUES (?,?)', (d.id, d.display_name))
                for level in SecrecyLevel:
                    self.connection.execute('INSERT OR IGNORE INTO secrecy_levels(id,name,level_order) VALUES (?,?,?)',
                                            (level.id, level.display_name, level.level_order))
            self._load_sql('storage_schema.sql')
            self._load_sql('storage_links.sql')
            self._check_database_links()
        except Exception:
            self.close()
            raise

    def _load_sql(self, name):
        self.connection.executescript(Path(__file__).with_name(name).read_text(encoding='utf-8'))

    def _copy_legacy_database(self):
        """Копируем старую БД через backup, включая зафиксированные данные из WAL."""
        destination = Path(self.db_path)
        legacy = destination.parent / LEGACY_DB_PATH.name
        if not self._migrate_legacy or destination.exists() or not legacy.is_file():
            return
        fd, temporary = tempfile.mkstemp(prefix='.users-migration-', suffix='.db', dir=destination.parent)
        os.close(fd)
        try:
            with closing(sqlite3.connect(legacy.resolve().as_uri() + '?mode=ro', uri=True)) as source:
                with closing(sqlite3.connect(temporary)) as target:
                    source.backup(target)
            # Публикация готовой копии не перезаписывает БД другого экземпляра.
            try:
                os.link(temporary, destination)
            except FileExistsError:
                pass
        finally:
            Path(temporary).unlink(missing_ok=True)

    @staticmethod
    def _prepare_private_file(path):
        """На POSIX файлы с данными доступны только владельцу процесса."""
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        if os.name == 'posix':
            os.chmod(path, 0o600)

    def _check_database_links(self):
        for schema in ('main', 'tables_store', 'documents_store'):
            if self.connection.execute(f'PRAGMA {schema}.foreign_key_check').fetchone():
                raise RuntimeError('Нарушены связи в существующей БД. Восстановите связи на копии базы перед запуском.')
        invalid_document = self.connection.execute('''
            SELECT 1 FROM documents_store.documents AS d
            LEFT JOIN main.users AS u ON u.id = d.owner_id
            WHERE u.id IS NULL LIMIT 1
        ''').fetchone()
        invalid_table = self.connection.execute('''
            SELECT 1 FROM tables_store.converted_tables AS t
            LEFT JOIN main.users AS u ON u.id = t.owner_id
            LEFT JOIN main.directions AS d ON d.id = t.direction_id
            LEFT JOIN main.secrecy_levels AS s ON s.id = t.secrecy_level_id
            LEFT JOIN documents_store.documents AS source ON source.id = t.source_document_id
            WHERE u.id IS NULL OR d.id IS NULL OR s.id IS NULL
               OR (t.source_document_id IS NULL AND t.source_revision IS NOT NULL)
               OR (t.source_document_id IS NOT NULL
                   AND (source.id IS NULL OR t.source_revision IS NULL
                        OR t.source_revision < 1 OR t.source_revision > source.revision))
            LIMIT 1
        ''').fetchone()
        if invalid_document or invalid_table:
            raise RuntimeError('Нарушены связи в существующей БД. Восстановите связи на копии базы перед запуском.')

    def bootstrap_admin(self, password, login=None):
        """Однократная локальная настройка пустой БД. Не вызывать из публичного UI."""
        from auth.password_utils import PasswordUtils
        if not PasswordUtils.is_valid_password(password):
            raise ValueError('Пароль должен содержать от 8 до 1024 символов')
        login = login or DEFAULT_ADMIN['login']
        if not login.strip():
            raise ValueError('Пустой логин')
        digest, salt = PasswordUtils.hash_password(password)
        with self.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            if cursor.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise ValueError('Первоначальная настройка уже выполнена')
            cursor.execute('INSERT INTO users(login,password_hash,direction_id,secrecy_level_id,is_admin) VALUES (?,?,?,?,1)',
                           (login, f'{digest}${salt}', DEFAULT_ADMIN['direction'].id, DEFAULT_ADMIN['secrecy_level'].id))

    @contextmanager
    def get_cursor(self):
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def execute(self, query, params=None):
        # Возвращаем открытый курсор для совместимости с lastrowid/rowcount.
        try:
            cursor = self.connection.execute(query, () if params is None else params)
            self.connection.commit()
            return cursor
        except Exception:
            self.connection.rollback()
            raise

    def fetch_one(self, query, params=None):
        cursor = self.connection.execute(query, () if params is None else params)
        try:
            return cursor.fetchone()
        finally:
            cursor.close()

    def fetch_all(self, query, params=None):
        cursor = self.connection.execute(query, () if params is None else params)
        try:
            return cursor.fetchall()
        finally:
            cursor.close()

    def fetch_dict(self, query, params=None):
        row = self.fetch_one(query, params)
        return dict(row) if row is not None else None

    def fetch_all_dict(self, query, params=None):
        return [dict(r) for r in self.fetch_all(query, params)]

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __del__(self):
        self.close()

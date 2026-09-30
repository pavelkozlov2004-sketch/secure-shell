"""Три связанные SQLite-базы с миграцией и общими транзакциями."""
import os
import sqlite3
import tempfile
import time
import uuid
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
                sync_columns = {r['name'] for r in self.connection.execute('PRAGMA table_info(lan_sync_state)')}
                if 'server_id' not in sync_columns:
                    self.connection.execute('ALTER TABLE lan_sync_state ADD COLUMN server_id TEXT')
                self.connection.execute('INSERT OR IGNORE INTO server_identity(id,server_id) VALUES (1,?)',
                                        (str(uuid.uuid4()),))
                audit_columns = {r['name'] for r in self.connection.execute('PRAGMA table_info(audit_logs)')}
                for name in ('session_id', 'executable_path', 'transfer_source', 'transfer_destination'):
                    if name not in audit_columns:
                        self.connection.execute(f'ALTER TABLE audit_logs ADD COLUMN {name} TEXT')
                for d in Direction:
                    self.connection.execute('INSERT OR IGNORE INTO directions(id,name) VALUES (?,?)', (d.id, d.display_name))
                for level in SecrecyLevel:
                    self.connection.execute('INSERT OR IGNORE INTO secrecy_levels(id,name,level_order) VALUES (?,?,?)',
                                            (level.id, level.display_name, level.level_order))
                self._install_account_revision_triggers()
            self._load_sql('storage_schema.sql')
            self._load_sql('storage_links.sql')
            self._check_database_links()
        except Exception:
            self.close()
            raise

    def _load_sql(self, name):
        self.connection.executescript(Path(__file__).with_name(name).read_text(encoding='utf-8'))

    def _install_account_revision_triggers(self):
        """Перехватывать все изменения, включая аварийный сброс и блокировку."""
        for event in ('INSERT', 'DELETE'):
            self.connection.execute(f'''
                CREATE TRIGGER IF NOT EXISTS users_account_revision_{event.lower()}
                AFTER {event} ON users BEGIN
                    UPDATE account_sync_state SET revision=revision+1 WHERE id=1;
                END
            ''')
        fields = ('id', 'login', 'password_hash', 'direction_id', 'secrecy_level_id',
                  'is_admin', 'active', 'network_blocked')
        changed = ' OR '.join(f'NEW.{field} IS NOT OLD.{field}' for field in fields)
        self.connection.execute(f'''
            CREATE TRIGGER IF NOT EXISTS users_account_revision_update
            AFTER UPDATE ON users WHEN {changed} BEGIN
                UPDATE account_sync_state SET revision=revision+1 WHERE id=1;
            END
        ''')

    def account_revision(self):
        """Номер последнего зафиксированного изменения учётных данных."""
        return self.fetch_one('SELECT revision FROM account_sync_state WHERE id=1')[0]

    def server_identity(self):
        """Постоянный ID сервера позволяет распознать замену его базы данных."""
        return self.fetch_one('SELECT server_id FROM server_identity WHERE id=1')[0]

    @staticmethod
    def _validate_account_snapshot(snapshot):
        """Разобрать весь сетевой ответ до начала записи в локальную базу."""
        if not isinstance(snapshot, dict):
            raise ValueError('Некорректный снимок учётных записей')
        allowed = {'revision', 'changed', 'users', 'directions', 'secrecy_levels', 'server_id'}
        if set(snapshot) - allowed or not {'revision', 'changed', 'server_id'} <= set(snapshot):
            raise ValueError('Некорректные поля снимка учётных записей')
        server_id = snapshot['server_id']
        try:
            if not isinstance(server_id, str) or str(uuid.UUID(server_id)) != server_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError('Некорректный идентификатор сервера') from None
        revision = snapshot['revision']
        if type(revision) is not int or not 0 <= revision <= 2**63 - 1:
            raise ValueError('Некорректная ревизия снимка')
        if type(snapshot['changed']) is not bool:
            raise ValueError('Некорректный признак изменения снимка')
        if not snapshot['changed']:
            if any(key in snapshot and snapshot[key] != []
                   for key in ('users', 'directions', 'secrecy_levels')):
                raise ValueError('Неизменённый снимок не должен содержать записи')
            return server_id, revision, None

        def integer(value, *, positive=True):
            lower = 1 if positive else 0
            if type(value) is not int or not lower <= value <= 2**63 - 1:
                raise ValueError('Некорректное число в снимке')
            return value

        def text(value, *, timestamp=False):
            if timestamp and value is None:
                return value
            if (not isinstance(value, str) or not value.strip()
                    or len(value) > (128 if timestamp else 4096) or '\x00' in value):
                raise ValueError('Некорректный текст в снимке')
            return value

        def flag(value):
            if type(value) not in (bool, int) or value not in (0, 1):
                raise ValueError('Некорректный статус учётной записи')
            return int(value)

        expected = {
            'directions': {'id', 'name'},
            'secrecy_levels': {'id', 'name', 'level_order'},
            'users': {'id', 'login', 'direction_id', 'secrecy_level_id',
                      'is_admin', 'active', 'network_blocked', 'created_at', 'updated_at'},
        }
        records = {}
        for key, fields in expected.items():
            source = snapshot.get(key)
            if not isinstance(source, list) or len(source) > 100000:
                raise ValueError('Некорректный список записей в снимке')
            items, ids, names = [], set(), set()
            for source_item in source:
                if not isinstance(source_item, dict) or set(source_item) != fields:
                    raise ValueError('Некорректные поля записи в снимке')
                item = {'id': integer(source_item['id'])}
                name_key = 'login' if key == 'users' else 'name'
                item[name_key] = text(source_item[name_key])
                if item['id'] in ids or item[name_key] in names:
                    raise ValueError('Повторяющиеся записи в снимке')
                ids.add(item['id'])
                names.add(item[name_key])
                if key == 'secrecy_levels':
                    item['level_order'] = integer(source_item['level_order'], positive=False)
                elif key == 'users':
                    for field in ('direction_id', 'secrecy_level_id'):
                        item[field] = integer(source_item[field])
                    for field in ('is_admin', 'active', 'network_blocked'):
                        item[field] = flag(source_item[field])
                    for field in ('created_at', 'updated_at'):
                        item[field] = text(source_item[field], timestamp=True)
                items.append(item)
            records[key] = items
        directions = {item['id'] for item in records['directions']}
        levels = {item['id'] for item in records['secrecy_levels']}
        if any(user['direction_id'] not in directions or user['secrecy_level_id'] not in levels
               for user in records['users']):
            raise ValueError('Снимок содержит неизвестные направления или уровни доступа')
        return server_id, revision, records

    def apply_account_snapshot(self, snapshot):
        """Атомарно обновить локальную копию без передачи хешей паролей.

        Отсутствующие владельцы остаются в базе деактивированными, чтобы связи
        с ранее сохранёнными документами и таблицами продолжали работать.
        """
        server_id, revision, records = self._validate_account_snapshot(snapshot)
        if records is None:
            source = self.fetch_one('SELECT server_id FROM lan_sync_state WHERE id=1')[0]
            if source is not None and source != server_id:
                raise ValueError('Идентификатор сервера изменился. Нужна отдельная копия базы для нового сервера.')
            return False
        remote_hash = '!remote-authentication-only!'
        now = time.time()
        with self.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            source = cursor.execute('SELECT server_id,revision FROM lan_sync_state WHERE id=1').fetchone()
            if source['server_id'] is not None and source['server_id'] != server_id:
                raise ValueError('Идентификатор сервера изменился. Нужна отдельная копия базы для нового сервера.')
            if revision <= source['revision']:
                return False

            # Временные имена позволяют обменять имена между существующими ID,
            # не удаляя строки с владельцами и классификацией файлов.
            for table, name_key in (('directions', 'name'), ('secrecy_levels', 'name'), ('users', 'login')):
                existing = {row['id']: row[name_key] for row in cursor.execute(
                    f'SELECT id,{name_key} FROM {table}').fetchall()}
                desired = {item['id']: item[name_key] for item in records[table]}
                for ident, name in desired.items():
                    if ident in existing and existing[ident] != name:
                        cursor.execute(f'UPDATE {table} SET {name_key}=? WHERE id=?',
                                       (f'!lan-sync-{uuid.uuid4().hex}-{ident}', ident))
                if table == 'users':
                    incoming_names = set(desired.values())
                    for ident, name in existing.items():
                        if ident not in desired and name in incoming_names:
                            cursor.execute('UPDATE users SET login=? WHERE id=?',
                                           (f'!lan-retired-{uuid.uuid4().hex}-{ident}', ident))

            cursor.executemany('INSERT INTO directions(id,name) VALUES (:id,:name) '
                               'ON CONFLICT(id) DO UPDATE SET name=excluded.name', records['directions'])
            cursor.executemany('INSERT INTO secrecy_levels(id,name,level_order) '
                               'VALUES (:id,:name,:level_order) ON CONFLICT(id) DO UPDATE SET '
                               'name=excluded.name,level_order=excluded.level_order', records['secrecy_levels'])
            users = [dict(item, password_hash=remote_hash) for item in records['users']]
            cursor.executemany('''
                INSERT INTO users(id,login,password_hash,direction_id,secrecy_level_id,
                                  is_admin,active,network_blocked,created_at,updated_at)
                VALUES (:id,:login,:password_hash,:direction_id,:secrecy_level_id,
                        :is_admin,:active,:network_blocked,:created_at,:updated_at)
                ON CONFLICT(id) DO UPDATE SET login=excluded.login,
                    password_hash=excluded.password_hash,direction_id=excluded.direction_id,
                    secrecy_level_id=excluded.secrecy_level_id,is_admin=excluded.is_admin,
                    active=excluded.active,network_blocked=excluded.network_blocked,
                    created_at=excluded.created_at,updated_at=excluded.updated_at
            ''', users)
            incoming_ids = {item['id'] for item in users}
            missing_ids = [(row['id'],) for row in cursor.execute('SELECT id FROM users').fetchall()
                           if row['id'] not in incoming_ids]
            cursor.executemany('UPDATE users SET active=0,password_hash=?,updated_at=CURRENT_TIMESTAMP '
                               'WHERE id=?', [(remote_hash, ident[0]) for ident in missing_ids])
            cursor.execute("UPDATE live_sessions SET ended_at=?,end_reason='remote_account_revoked' "
                           'WHERE ended_at IS NULL AND user_id IN '
                           '(SELECT id FROM users WHERE active=0 OR network_blocked=1)', (now,))
            cursor.execute('DELETE FROM user_sessions WHERE user_id IN '
                           '(SELECT id FROM users WHERE active=0 OR network_blocked=1)')
            cursor.execute('UPDATE lan_sync_state SET revision=?,server_id=? WHERE id=1', (revision, server_id))
        return True

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

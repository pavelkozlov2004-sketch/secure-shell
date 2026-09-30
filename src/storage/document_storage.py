"""Application storage with live session authorization and source provenance.

All three SQLite databases share one connection. Authorization, changes, source
links, and the audit event therefore commit together in one transaction.
"""
import csv
import io
import json
from contextlib import contextmanager

from storage.report_format import COLUMNS, FORMAT, MAX_TABLE_BYTES, validate_report


MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
_DOCUMENT_META = 'id,title,original_name,owner_id,revision,created_at,updated_at'
_TABLE_META = ('id,title,owner_id,direction_id,secrecy_level_id,source_document_id,'
               'source_revision,created_at,updated_at')


def _positive_id(value, label='Идентификатор'):
    if type(value) is not int or not 1 <= value <= 9223372036854775807:
        raise ValueError(f'{label} должен быть положительным целым числом')
    return value


def _text(value, label, *, nonempty=False):
    if not isinstance(value, str) or len(value) > 500:
        raise ValueError(f'{label}: ожидается строка длиной до 500 символов')
    if nonempty and not value.strip():
        raise ValueError(f'{label} не может быть пустым')
    try:
        value.encode('utf-8')
    except UnicodeError as exc:
        raise ValueError(f'{label}: недопустимый текст UTF-8') from exc
    if '\x00' in value:
        raise ValueError(f'{label}: недопустимый нулевой символ')
    return value.strip() if nonempty else value


def _content(value):
    if not isinstance(value, str):
        raise ValueError('Документ должен содержать текст UTF-8')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError as exc:
        raise ValueError('Документ должен содержать корректный текст UTF-8') from exc
    if size > MAX_DOCUMENT_BYTES:
        raise ValueError('Размер документа превышает 2 МиБ')
    if '\x00' in value:
        raise ValueError('Документ содержит нулевые символы; ожидается обычный текст')
    return value


def _encoded_report(report):
    validate_report(report)
    try:
        encoded = json.dumps(report, ensure_ascii=False, allow_nan=False,
                             separators=(',', ':'))
        size = len(encoded.encode('utf-8'))
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError('Таблица должна содержать корректные данные JSON / UTF-8') from exc
    if size > MAX_TABLE_BYTES:
        raise ValueError('Размер таблицы превышает 1 МиБ')
    return encoded


def _parse_rows(content, delimiter):
    try:
        # Empty physical lines are harmless; quoted multiline cells stay intact.
        rows = [row for row in csv.reader(io.StringIO(content, newline=''),
                                         delimiter=delimiter, strict=True) if row]
    except csv.Error as exc:
        raise ValueError('Некорректная структура CSV/TSV') from exc
    if not rows or any(len(row) != len(COLUMNS) for row in rows):
        raise ValueError(f'Каждая строка должна содержать {len(COLUMNS)} ячеек')
    if rows[0] == [name for name, _ in COLUMNS]:
        rows = rows[1:]
    if not rows:
        raise ValueError('Документ содержит только заголовок; добавьте строки данных')
    return rows


def convert_text(content, title, delimiter='auto'):
    """Convert only the documented JSON or delimited 13-column text format."""
    content = _content(content).lstrip('\ufeff')
    title = _text(title, 'Название', nonempty=True)
    if delimiter not in ('auto', ',', ';', '\t'):
        raise ValueError('Выберите разделитель: автоматически, запятая, точка с запятой или табуляция')
    if not content.strip():
        raise ValueError('Пустой документ нельзя преобразовать в таблицу')
    if content.lstrip().startswith(('{', '[')):
        try:
            report = json.loads(content)
        except (ValueError, RecursionError) as exc:
            raise ValueError('Некорректный JSON таблицы') from exc
        _encoded_report(report)
        return report
    if delimiter == 'auto':
        candidates = []
        for candidate in (',', ';', '\t'):
            try:
                rows = _parse_rows(content, candidate)
            except ValueError:
                continue
            candidates.append(rows)
        if not candidates:
            raise ValueError('Не удалось распознать таблицу: используйте JSON vual-table-v1 '
                             'или CSV/TSV с 13 ячейками в каждой строке')
        if len(candidates) > 1:
            raise ValueError('Неоднозначный разделитель; выберите его явно')
        rows = candidates[0]
    else:
        rows = _parse_rows(content, delimiter)
    groups = [dict(title=f'Строки {start + 1}–{min(start + 100, len(rows))}',
                   rows=rows[start:start + 100]) for start in range(0, len(rows), 100)]
    report = {
        'format': FORMAT, 'title': title, 'subtitle': '',
        'sections': [{'title': 'Данные документа', 'groups': groups}],
    }
    _encoded_report(report)
    return report


class DocumentStorage:
    def __init__(self, db_manager, login_manager):
        self.db = db_manager
        self.login = login_manager

    @contextmanager
    def _authorized(self, *, admin=False):
        # current_user checks live session state and updates its heartbeat. Do it
        # before BEGIN because that existing API commits its heartbeat update.
        user = self.login.current_user
        session_id = self.login._session_id
        if user is None or session_id is None:
            raise PermissionError('Для доступа к базе данных необходимо войти в систему')
        with self.db.get_cursor() as cursor:
            cursor.execute('BEGIN IMMEDIATE')
            actor = cursor.execute(
                'SELECT u.id,u.direction_id,u.secrecy_level_id,u.is_admin,l.level_order '
                'FROM main.users u JOIN main.live_sessions s ON s.user_id=u.id '
                'JOIN main.secrecy_levels l ON l.id=u.secrecy_level_id '
                'WHERE u.id=? AND s.id=? AND s.ended_at IS NULL '
                'AND u.active=1 AND u.network_blocked=0',
                (user.id, session_id)).fetchone()
            if actor is None:
                raise PermissionError('Сеанс завершён или учётная запись заблокирована')
            if getattr(self.login, 'is_remote', False) and (
                    actor['direction_id'] != user.direction_id
                    or actor['secrecy_level_id'] != user.secrecy_level_id
                    or bool(actor['is_admin']) != user.is_admin):
                raise PermissionError('Локальные права не соответствуют серверным. Обновите подключение.')
            if admin and not actor['is_admin']:
                raise PermissionError('Доступ к исходным документам и изменению таблиц разрешён только администратору')
            yield cursor, actor, session_id

    @staticmethod
    def _audit(cursor, actor, session_id, action, details):
        # Only stable IDs/revisions enter the audit. No title, content or cells.
        cursor.execute('INSERT INTO main.audit_logs(user_id,action,details,session_id) '
                       'VALUES (?,?,?,?)', (actor['id'], action, details, session_id))

    @staticmethod
    def _document(cursor, document_id):
        row = cursor.execute('SELECT * FROM documents_store.documents WHERE id=?',
                             (document_id,)).fetchone()
        if row is None:
            raise LookupError('Исходный документ не найден')
        return dict(row)

    @staticmethod
    def _table(cursor, table_id, actor):
        row = cursor.execute(
            'SELECT t.*,l.level_order AS table_level_order '
            'FROM tables_store.converted_tables t '
            'JOIN main.secrecy_levels l ON l.id=t.secrecy_level_id WHERE t.id=?',
            (table_id,)).fetchone()
        if row is None:
            raise LookupError('Таблица не найдена')
        if not actor['is_admin'] and (row['direction_id'] != actor['direction_id'] or
                                     row['table_level_order'] > actor['level_order']):
            raise PermissionError('Недостаточно прав для просмотра таблицы')
        result = dict(row)
        result.pop('table_level_order')
        encoded = result.pop('report_json')
        if len(encoded.encode('utf-8')) > MAX_TABLE_BYTES:
            raise ValueError('Размер таблицы превышает 1 МиБ')
        try:
            result['report'] = validate_report(json.loads(encoded))
        except (ValueError, TypeError, RecursionError) as exc:
            raise ValueError('В базе сохранена таблица неподдерживаемого формата') from exc
        return result

    def list_documents(self):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            rows = cursor.execute('SELECT ' + _DOCUMENT_META +
                                  ' FROM documents_store.documents ORDER BY updated_at DESC,id DESC').fetchall()
            self._audit(cursor, actor, session_id, 'DOCUMENT_LIST', f'count={len(rows)}')
            return [dict(row) for row in rows]

    def get_document(self, document_id):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            document = self._document(cursor, _positive_id(document_id))
            self._audit(cursor, actor, session_id, 'DOCUMENT_OPEN', f'document_id={document_id}')
            return document

    def create_document(self, title, content, original_name=''):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            cursor.execute(
                'INSERT INTO documents_store.documents(title,content,original_name,owner_id) '
                'VALUES (?,?,?,?)',
                (_text(title, 'Название', nonempty=True), _content(content),
                 _text(original_name, 'Исходное имя файла'), actor['id']))
            document_id = cursor.lastrowid
            self._audit(cursor, actor, session_id, 'DOCUMENT_CREATE', f'document_id={document_id};revision=1')
            return self._document(cursor, document_id)

    def update_document(self, document_id, title, content, expected_revision):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            document_id = _positive_id(document_id)
            expected_revision = _positive_id(expected_revision, 'Редакция')
            self._document(cursor, document_id)
            cursor.execute(
                'UPDATE documents_store.documents SET title=?,content=?,revision=revision+1,'
                'updated_at=CURRENT_TIMESTAMP WHERE id=? AND revision=?',
                (_text(title, 'Название', nonempty=True), _content(content), document_id, expected_revision))
            if cursor.rowcount != 1:
                raise ValueError('Документ уже изменён другим сеансом; обновите список и откройте его заново')
            self._audit(cursor, actor, session_id, 'DOCUMENT_UPDATE',
                        f'document_id={document_id};revision={expected_revision + 1}')
            return self._document(cursor, document_id)

    def delete_document(self, document_id):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            document_id = _positive_id(document_id)
            self._document(cursor, document_id)
            if cursor.execute('SELECT 1 FROM tables_store.converted_tables WHERE source_document_id=? LIMIT 1',
                              (document_id,)).fetchone():
                raise ValueError('Документ связан с сохранёнными таблицами; сначала удалите эти таблицы')
            cursor.execute('DELETE FROM documents_store.documents WHERE id=?', (document_id,))
            self._audit(cursor, actor, session_id, 'DOCUMENT_DELETE', f'document_id={document_id}')
            return True

    def list_tables(self):
        with self._authorized() as (cursor, actor, session_id):
            query = 'SELECT ' + ','.join('t.' + column for column in _TABLE_META.split(','))
            query += (' FROM tables_store.converted_tables t '
                      'JOIN main.secrecy_levels l ON l.id=t.secrecy_level_id')
            params = ()
            if not actor['is_admin']:
                query += ' WHERE t.direction_id=? AND l.level_order<=?'
                params = (actor['direction_id'], actor['level_order'])
            rows = cursor.execute(query + ' ORDER BY t.updated_at DESC,t.id DESC', params).fetchall()
            return [dict(row) for row in rows]

    def get_table(self, table_id):
        with self._authorized() as (cursor, actor, session_id):
            table = self._table(cursor, _positive_id(table_id), actor)
            self._audit(cursor, actor, session_id, 'TABLE_OPEN', f'table_id={table_id}')
            return table

    @staticmethod
    def _access_labels(cursor, actor, direction_id, secrecy_level_id):
        direction_id = actor['direction_id'] if direction_id is None else _positive_id(direction_id)
        secrecy_level_id = actor['secrecy_level_id'] if secrecy_level_id is None else _positive_id(secrecy_level_id)
        if not cursor.execute('SELECT 1 FROM main.directions WHERE id=?', (direction_id,)).fetchone():
            raise ValueError('Указано неизвестное направление таблицы')
        if not cursor.execute('SELECT 1 FROM main.secrecy_levels WHERE id=?', (secrecy_level_id,)).fetchone():
            raise ValueError('Указан неизвестный уровень секретности таблицы')
        return direction_id, secrecy_level_id

    def _insert_table(self, cursor, actor, session_id, title, report, source=None,
                      direction_id=None, secrecy_level_id=None):
        encoded = _encoded_report(report)
        direction_id, secrecy_level_id = self._access_labels(cursor, actor, direction_id, secrecy_level_id)
        cursor.execute(
            'INSERT INTO tables_store.converted_tables(title,report_json,owner_id,direction_id,'
            'secrecy_level_id,source_document_id,source_revision) VALUES (?,?,?,?,?,?,?)',
            (_text(title, 'Название', nonempty=True), encoded, actor['id'], direction_id,
             secrecy_level_id, source['id'] if source else None,
             source['revision'] if source else None))
        table_id = cursor.lastrowid
        details = f'table_id={table_id};direction_id={direction_id};secrecy_level_id={secrecy_level_id}'
        if source:
            details += f';source_document_id={source["id"]};source_revision={source["revision"]}'
        self._audit(cursor, actor, session_id, 'TABLE_CONVERT' if source else 'TABLE_IMPORT', details)
        return self._table(cursor, table_id, actor)

    def import_table(self, title, report, source_document_id=None, *,
                     direction_id=None, secrecy_level_id=None):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            source = (self._document(cursor, _positive_id(source_document_id))
                      if source_document_id is not None else None)
            return self._insert_table(cursor, actor, session_id, title, report, source,
                                      direction_id, secrecy_level_id)

    def convert_document(self, document_id, delimiter='auto', *,
                         direction_id=None, secrecy_level_id=None):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            source = self._document(cursor, _positive_id(document_id))
            report = convert_text(source['content'], source['title'], delimiter)
            return self._insert_table(cursor, actor, session_id, source['title'], report, source,
                                      direction_id, secrecy_level_id)

    def set_table_access(self, table_id, direction_id, secrecy_level_id):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            table_id = _positive_id(table_id)
            self._table(cursor, table_id, actor)
            direction_id, secrecy_level_id = self._access_labels(cursor, actor, direction_id, secrecy_level_id)
            cursor.execute('UPDATE tables_store.converted_tables SET direction_id=?,secrecy_level_id=?,'
                           'updated_at=CURRENT_TIMESTAMP WHERE id=?',
                           (direction_id, secrecy_level_id, table_id))
            self._audit(cursor, actor, session_id, 'TABLE_ACCESS_UPDATE',
                        f'table_id={table_id};direction_id={direction_id};secrecy_level_id={secrecy_level_id}')
            return self._table(cursor, table_id, actor)

    def delete_table(self, table_id):
        with self._authorized(admin=True) as (cursor, actor, session_id):
            table_id = _positive_id(table_id)
            self._table(cursor, table_id, actor)
            cursor.execute('DELETE FROM tables_store.converted_tables WHERE id=?', (table_id,))
            self._audit(cursor, actor, session_id, 'TABLE_DELETE', f'table_id={table_id}')
            return True

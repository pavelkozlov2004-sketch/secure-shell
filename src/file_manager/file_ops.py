"""Файловые операции через авторизованную сессию и метаданные.

API: FileOperations(db_manager, login_manager). Старые статические вызовы
больше не поддерживаются. Каталоги с содержимым не удаляются и не переименовываются.
"""
import os
import stat
import uuid
from pathlib import Path
from access_control.permissions import PermissionManager, canonical_path


class FileOperations:
    def __init__(self, db_manager, login_manager):
        self.db = db_manager
        self.login = login_manager
        self.permissions = PermissionManager(db_manager)
        self.audit = login_manager.audit_logger

    def _require(self, path):
        path = canonical_path(path)
        user = self.login.current_user
        if not self.permissions.can_access_file(user, path):
            self.audit.log_access_denied(user.id if user else None, path)
            raise PermissionError('Недостаточно прав на ресурс')
        return path, user

    def _require_write(self, path):
        path = canonical_path(path)
        user = self.login.current_user
        if not self.permissions.can_write_file(user, path):
            self.audit.log_access_denied(user.id if user else None, path)
            raise PermissionError('Недостаточно прав на изменение ресурса')
        return path, user

    @staticmethod
    def _regular_file_mode(path):
        mode = os.lstat(path).st_mode
        if not stat.S_ISREG(mode):
            raise IsADirectoryError('Операция поддерживает только обычные файлы')
        return stat.S_IMODE(mode)

    @staticmethod
    def _write_new_file(path, data, mode=0o600):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
        fd = None
        created = False
        try:
            fd = os.open(path, flags, mode)
            created = True
            with os.fdopen(fd, 'wb') as stream:
                fd = None
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # os.open применяет umask. Для замены существующего файла возвращаем
            # его исходные биты режима; для нового файла mode=0600 остаётся закрытым.
            os.chmod(path, mode)
        except Exception:
            if fd is not None:
                os.close(fd)
            if created:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            raise

    def read_bytes(self, file_path, max_bytes=None):
        """Прочитать обычный файл после проверки прав и записать FILE_OPEN в аудит."""
        path, user = self._require(file_path)
        self._regular_file_mode(path)
        if max_bytes is not None and max_bytes < 0:
            raise ValueError('max_bytes не может быть отрицательным')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            with os.fdopen(fd, 'rb') as stream:
                fd = -1
                data = stream.read() if max_bytes is None else stream.read(max_bytes + 1)
        finally:
            if fd != -1:
                os.close(fd)
        if max_bytes is not None and len(data) > max_bytes:
            raise ValueError(f'Файл превышает допустимый размер {max_bytes} байт')
        self.audit.log_file_open(user.id, path)
        return data

    def read_text(self, file_path, encoding='utf-8', errors='strict', max_bytes=None):
        return self.read_bytes(file_path, max_bytes=max_bytes).decode(encoding, errors)

    def create_file(self, file_path, data=b''):
        """Создать новый файл с метками родителя. Существующие файлы не перезаписываются."""
        try:
            data = bytes(data)
        except (TypeError, ValueError) as exc:
            raise TypeError('data должен быть bytes-подобным объектом') from exc
        path = canonical_path(file_path)
        parent, user = self._require(Path(path).parent)
        meta = self.permissions._get_file_metadata(parent)
        if not meta or not meta['is_directory']:
            raise NotADirectoryError(parent)
        if self.permissions._get_file_metadata(path) is not None:
            raise FileExistsError(path)
        created = False
        try:
            self._write_new_file(path, data)
            created = True
            with self.db.get_cursor() as c:
                c.execute('INSERT INTO files_metadata(path,direction_id,secrecy_level_id,owner_id,is_directory) VALUES (?,?,?,?,0)',
                          (path, meta['direction_id'], meta['secrecy_level_id'], user.id))
        except Exception:
            if created:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            raise
        self.audit.log_file_create(user.id, path)
        return True

    def create_text_file(self, file_path, text='', encoding='utf-8', errors='strict'):
        if not isinstance(text, str):
            raise TypeError('text должен быть строкой')
        return self.create_file(file_path, text.encode(encoding, errors))

    def write_bytes(self, file_path, data):
        """Атомарно заменить содержимое существующего обычного файла."""
        try:
            data = bytes(data)
        except (TypeError, ValueError) as exc:
            raise TypeError('data должен быть bytes-подобным объектом') from exc
        path, user = self._require_write(file_path)
        mode = self._regular_file_mode(path)
        temp = str(Path(path).with_name('.pending-save-' + uuid.uuid4().hex))
        created = False
        try:
            self._write_new_file(temp, data, mode=mode)
            created = True
            os.replace(temp, path)
            created = False
        except Exception:
            if created:
                try:
                    os.unlink(temp)
                except FileNotFoundError:
                    pass
            raise
        self.audit.log_file_save(user.id, path)
        return True

    def write_text(self, file_path, text, encoding='utf-8', errors='strict'):
        if not isinstance(text, str):
            raise TypeError('text должен быть строкой')
        return self.write_bytes(file_path, text.encode(encoding, errors))

    def register_directory(self, path, direction_id, secrecy_level_id):
        """Администратор регистрирует существующий корневой каталог в БД."""
        actor = self.login.current_user
        if not actor or not actor.is_admin:
            raise PermissionError('Требуются права администратора')
        path = canonical_path(path)
        if not Path(path).is_dir():
            raise NotADirectoryError(path)
        self.db.execute('INSERT INTO files_metadata(path,direction_id,secrecy_level_id,owner_id,is_directory) VALUES (?,?,?,?,1)',
                        (path, direction_id, secrecy_level_id, actor.id))
        self.audit.log_action(actor.id, 'REGISTER_DIRECTORY', path)
        return True

    def file_exists(self, file_path):
        path, _ = self._require(file_path)
        return os.path.exists(path)

    def is_directory(self, path):
        path, _ = self._require(path)
        return os.path.isdir(path)

    def get_file_size(self, file_path):
        path, _ = self._require(file_path)
        return os.path.getsize(path)

    def get_modification_time(self, file_path):
        path, _ = self._require(file_path)
        return os.path.getmtime(path)

    def create_directory(self, path):
        path = canonical_path(path)
        parent, user = self._require(Path(path).parent)
        meta = self.permissions._get_file_metadata(parent)
        if not meta['is_directory']:
            raise NotADirectoryError(parent)
        created = False
        try:
            with self.db.get_cursor() as c:
                c.execute('INSERT INTO files_metadata(path,direction_id,secrecy_level_id,owner_id,is_directory) VALUES (?,?,?,?,1)',
                          (path, meta['direction_id'], meta['secrecy_level_id'], user.id))
                os.mkdir(path)
                created = True
        except Exception:
            if created:
                os.rmdir(path)
            raise
        self.audit.log_file_create(user.id, path)
        return True

    def delete_file(self, file_path):
        path, user = self._require(file_path)
        if not Path(path).is_file():
            raise IsADirectoryError('delete_file поддерживает только обычные файлы')
        # Сначала временно перемещаем файл: при ошибке SQL возвращаем его на место.
        staged = str(Path(path).with_name('.pending-delete-' + uuid.uuid4().hex))
        moved = False
        try:
            with self.db.get_cursor() as c:
                c.execute('DELETE FROM files_metadata WHERE path=?', (path,))
                if c.rowcount != 1:
                    raise FileNotFoundError('Метаданные исчезли во время операции')
                os.rename(path, staged)
                moved = True
        except Exception:
            if moved:
                os.rename(staged, path)
            raise
        try:
            os.remove(staged)
        except OSError:
            self.audit.log_action(user.id, 'DELETE_CLEANUP_REQUIRED', staged)
            raise OSError('Метаданные удалены; временный файл требует очистки: ' + staged)
        self.audit.log_file_delete(user.id, path)
        return True

    def rename_file(self, old_path, new_path):
        old, user = self._require(old_path)
        new = canonical_path(new_path)
        parent, _ = self._require(Path(new).parent)
        if not Path(old).is_file():
            raise IsADirectoryError('Переименование каталогов не поддерживается')
        source = self.permissions._get_file_metadata(old)
        destination = self.permissions._get_file_metadata(parent)
        if not destination['is_directory']:
            raise NotADirectoryError(parent)
        if (source['direction_id'], source['secrecy_level_id']) != (destination['direction_id'], destination['secrecy_level_id']):
            raise PermissionError('Перемещение между различными метками доступа запрещено')
        moved = False
        try:
            with self.db.get_cursor() as c:
                c.execute('UPDATE files_metadata SET path=?,updated_at=CURRENT_TIMESTAMP WHERE path=?', (new, old))
                if c.rowcount != 1:
                    raise FileNotFoundError(old)
                # link не перезаписывает существующий файл, в отличие от rename на POSIX.
                # Между разными файловыми системами операция явно отклоняется.
                os.link(old, new)
                try:
                    os.unlink(old)
                except Exception:
                    os.unlink(new)
                    raise
                moved = True
        except Exception:
            if moved:
                os.link(new, old)
                os.unlink(new)
            raise
        self.audit.log_action(user.id, 'FILE_RENAME', f'{old} -> {new}', transfer_source=old, transfer_destination=new)
        return True

    def list_directory(self, path):
        path, user = self._require(path)
        if not self.permissions._get_file_metadata(path)['is_directory'] or not os.path.isdir(path):
            raise NotADirectoryError(path)
        result = []
        for name in os.listdir(path):
            child = os.path.join(path, name)
            if self.permissions.can_access_file(user, child):
                result.append(name)
        self.audit.log_action(user.id, 'LIST_DIRECTORY', path)
        return result

    def list_accessible_roots(self):
        """Return registered directories visible to the session, without exposing other paths."""
        user = self.login.current_user
        if user is None:
            raise PermissionError('Требуется действующий сеанс')
        rows = self.db.fetch_all('SELECT path FROM files_metadata WHERE is_directory=1 ORDER BY path')
        visible = set()
        for row in rows:
            path = row['path']
            if self.permissions.can_access_file(user, path):
                try:
                    if canonical_path(path) == path and os.path.isdir(path):
                        visible.add(path)
                except (OSError, ValueError, PermissionError):
                    continue
        return sorted(path for path in visible if not any(
            parent in visible for parent in map(str, Path(path).parents)))

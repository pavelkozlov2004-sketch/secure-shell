"""Проверка текущих прав и порядка уровней из справочника БД."""
import os
from pathlib import Path


def canonical_path(path):
    path = Path(os.path.abspath(os.fspath(path)))
    # Не позволяем заменить разрешённый путь ссылкой на другой объект.
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise PermissionError('Символические ссылки и junction не поддерживаются')
    return os.path.normcase(str(path))


class PermissionManager:
    def __init__(self, db_manager):
        self.db = db_manager

    def _get_file_metadata(self, file_path):
        return self.db.fetch_dict('SELECT * FROM files_metadata WHERE path=?', (canonical_path(file_path),))

    def can_access_file(self, user, file_path):
        if user is None:
            return False
        try:
            path = canonical_path(file_path)
        except (OSError, ValueError, PermissionError):
            return False
        row = self.db.fetch_one('''SELECT u.direction_id AS ud, f.direction_id AS fd,
                   ul.level_order AS ulevel, fl.level_order AS flevel
            FROM users u JOIN secrecy_levels ul ON ul.id=u.secrecy_level_id
            JOIN files_metadata f ON f.path=?
            JOIN secrecy_levels fl ON fl.id=f.secrecy_level_id
            WHERE u.id=? AND u.active=1''', (path, user.id))
        return bool(row and row['ud'] == row['fd'] and row['ulevel'] >= row['flevel'])

    def can_write_file(self, user, file_path):
        return self.can_access_file(user, file_path)

    def can_delete_file(self, user, file_path):
        return self.can_access_file(user, file_path)

    def filter_files(self, user, file_paths):
        return [p for p in file_paths if self.can_access_file(user, p)]

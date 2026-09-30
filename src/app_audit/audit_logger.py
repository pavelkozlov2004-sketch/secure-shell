"""Аудит без конфликта со стандартным logging и дублирования обработчиков."""
import logging
from pathlib import Path
from config import AUDIT_LOG_PATH


class AuditLogger:
    def __init__(self, db_manager):
        self.db = db_manager
        self.session_id = None
        self.file_logger = self._setup_file_logger()

    @staticmethod
    def _setup_file_logger():
        path = Path(AUDIT_LOG_PATH).resolve()
        logger = logging.getLogger('vual.audit.' + str(path))
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(path, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
        return logger

    def log_action(self, user_id, action, details=None, *, executable_path=None, transfer_source=None, transfer_destination=None):
        # Анонимные события пишутся в файл: старая схема audit_logs требует user_id.
        # События авторизованных пользователей сохраняются также в БД.
        clean = str(details or '').replace('\n', '\\n').replace('\r', '\\r')
        if user_id is not None:
            try:
                self.db.execute('INSERT INTO audit_logs(user_id,action,details,session_id,executable_path,transfer_source,transfer_destination) VALUES (?,?,?,?,?,?,?)',
                                (user_id, action, clean, self.session_id, executable_path, transfer_source, transfer_destination))
            except Exception:
                self.file_logger.exception('Не удалось записать аудит в БД')
        self.file_logger.info('User=%s Action=%s Details=%s', user_id, action, clean)

    def log_login(self, user_id): self.log_action(user_id, 'LOGIN')
    def log_logout(self, user_id): self.log_action(user_id, 'LOGOUT')
    def log_file_open(self, user_id, path): self.log_action(user_id, 'FILE_OPEN', path)
    def log_file_save(self, user_id, path): self.log_action(user_id, 'FILE_SAVE', path)
    def log_file_create(self, user_id, path): self.log_action(user_id, 'FILE_CREATE', path)
    def log_file_delete(self, user_id, path): self.log_action(user_id, 'FILE_DELETE', path)
    def log_access_denied(self, user_id, path): self.log_action(user_id, 'ACCESS_DENIED', path)

    def log_execution(self, user_id, executable_path):
        """Вызывать после успешного запуска через доверенный сервис приложения."""
        self.log_action(user_id, 'EXECUTE_FILE', executable_path, executable_path=executable_path)

    def log_transfer(self, user_id, source, destination):
        """Вызывать после успешной передачи через доверенный сервис приложения."""
        self.log_action(user_id, 'TRANSFER_FILE', f'{source} -> {destination}',
                        transfer_source=source, transfer_destination=destination)

"""Запуск приложения с графической настройкой первого администратора."""
import sys
import hashlib
import json
from config import APP_TITLE, DATA_DIR


def client_database_path(settings):
    """Отдельный каталог кэша для каждого сервера сохраняет локальные данные."""
    if not settings.get('enabled'):
        return None
    endpoint = settings['server_url'].rstrip('/')
    name = hashlib.sha256(endpoint.encode('utf-8')).hexdigest()[:16]
    return DATA_DIR / 'clients' / name / 'users.db'


def main():
    from PyQt5.QtWidgets import QApplication, QMessageBox
    from database.db_manager import DatabaseManager
    from ui.login_window import LoginWindow
    from network.settings import load_settings, DEFAULT_SETTINGS, SETTINGS_FILENAME
    from network.manager import create_login_manager
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setApplicationVersion('1.7.0')
    app.setStyle('Fusion')
    if '--recover' in sys.argv:
        from ui.recovery_window import show_recovery
        show_recovery()
        return 0
    db = None
    try:
        try:
            settings = load_settings()
        except (ValueError, OSError) as exc:
            from PyQt5.QtWidgets import QDialog
            from ui.network_settings import NetworkSettingsDialog
            raw = dict(DEFAULT_SETTINGS)
            try:
                saved = json.loads((DATA_DIR / SETTINGS_FILENAME).read_text(encoding='utf-8'))
                if isinstance(saved, dict):
                    for field in raw:
                        expected = bool if field == 'enabled' else str
                        if type(saved.get(field)) is expected:
                            raw[field] = saved[field]
            except (OSError, ValueError, UnicodeError):
                pass
            repair = NetworkSettingsDialog(raw)
            repair.status.setText('Исправьте настройки подключения: ' + str(exc))
            if repair.exec_() != QDialog.Accepted:
                return 1
            settings = repair.saved_settings
        db = DatabaseManager(client_database_path(settings))
        if '--setup-admin' in sys.argv:
            if settings.get('enabled'):
                raise ValueError('Первый администратор создаётся на компьютере сервера. '
                                 'На клиенте войдите с серверной учётной записью.')
            from auth.initial_admin import create_initial_admin
            message = create_initial_admin(db)
            QMessageBox.information(None, 'Настройка администратора', message)
            return 0
        active = {'db': db, 'window': None}

        def open_window(database, selected_settings):
            manager = create_login_manager(database, selected_settings)
            window = LoginWindow(database, manager=manager)
            window.network_settings_requested.connect(change_settings)
            active.update(db=database, window=window)
            window.show()

        def change_settings():
            from PyQt5.QtWidgets import QDialog
            from ui.network_settings import NetworkSettingsDialog
            current = active['window']
            if current.pages.currentWidget() is current.session_page:
                if not current.file_workspace._confirm_discard():
                    return
                if not current.database_workspace._confirm_discard():
                    return
            dialog = NetworkSettingsDialog(settings, current)
            if dialog.exec_() != QDialog.Accepted:
                return
            next_db = None
            try:
                next_db = DatabaseManager(client_database_path(dialog.saved_settings))
                # Создать новое окно до закрытия прежнего, чтобы Qt продолжил работу.
                old_db = active['db']
                open_window(next_db, dialog.saved_settings)
                settings.update(dialog.saved_settings)
                current.close()
                current.deleteLater()
                old_db.close()
            except Exception as exc:
                if next_db is not None and next_db is not active['db']:
                    next_db.close()
                QMessageBox.warning(current, 'Не удалось сменить подключение', str(exc))

        open_window(db, settings)
        return app.exec_()
    except Exception as exc:
        QMessageBox.critical(None, 'Ошибка запуска', f'Не удалось запустить приложение:\n{exc}')
        return 1
    finally:
        if 'active' in locals():
            active['db'].close()
        elif db is not None:
            db.close()


if __name__ == '__main__':
    raise SystemExit(main())

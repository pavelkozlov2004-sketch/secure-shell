"""Запуск приложения с графической настройкой первого администратора."""
import sys
from config import APP_TITLE


def main():
    from PyQt5.QtWidgets import QApplication, QMessageBox
    from database.db_manager import DatabaseManager
    from ui.login_window import LoginWindow
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setApplicationVersion('1.6.0')
    app.setStyle('Fusion')
    if '--recover' in sys.argv:
        from ui.recovery_window import show_recovery
        show_recovery()
        return 0
    db = None
    try:
        db = DatabaseManager()
        if '--setup-admin' in sys.argv:
            from auth.initial_admin import create_initial_admin
            message = create_initial_admin(db)
            QMessageBox.information(None, 'Настройка администратора', message)
            return 0
        window = LoginWindow(db)
        window.show()
        return app.exec_()
    except Exception as exc:
        QMessageBox.critical(None, 'Ошибка запуска', f'Не удалось запустить приложение:\n{exc}')
        return 1
    finally:
        if db is not None:
            db.close()


if __name__ == '__main__':
    raise SystemExit(main())

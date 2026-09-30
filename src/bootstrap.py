"""Локальная первоначальная настройка: python src/bootstrap.py."""
from getpass import getpass
from database.db_manager import DatabaseManager


def main():
    db = DatabaseManager()
    try:
        if db.fetch_one('SELECT 1 FROM users LIMIT 1'):
            print('База уже настроена. Повторное создание администратора запрещено.')
            return 1
        password = getpass('Новый пароль администратора (минимум 8 символов): ')
        if password != getpass('Повторите пароль: '):
            print('Пароли не совпадают.')
            return 1
        db.bootstrap_admin(password)
        print('Администратор admin_admin создан.')
        return 0
    except ValueError as exc:
        print(exc)
        return 1
    finally:
        db.close()


if __name__ == '__main__':
    raise SystemExit(main())

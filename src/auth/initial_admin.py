"""Explicit local setup of the account requested by the project owner."""
from auth.password_utils import PasswordUtils


def create_initial_admin(db):
    existing = db.fetch_one('SELECT password_hash,is_admin,active,network_blocked FROM users WHERE login=?',
                            ('admin_admin',))
    if existing:
        digest, salt = existing['password_hash'].split('$')
        if (existing['is_admin'] and existing['active'] and not existing['network_blocked']
                and PasswordUtils.verify_password('12345678', digest, salt)):
            return 'Аккаунт admin_admin уже готов к входу с указанным паролем.'
        raise ValueError('Аккаунт admin_admin уже существует с другими параметрами. '
                         'Его пароль и блокировка не изменены. Используйте действующего администратора для настройки.')
    # Bootstrap is atomic and refuses databases that already contain users.
    db.bootstrap_admin('12345678', login='admin_admin')
    return 'Создан администратор admin_admin. Пароль: 12345678.'

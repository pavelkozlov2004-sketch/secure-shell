"""Запуск центрального сервера Вуали: python src/server_main.py --help."""
import argparse
from getpass import getpass
from pathlib import Path

from config import DATA_DIR, DB_PATH
from database.db_manager import DatabaseManager
from network.server import create_server
from network.tls import certificate_fingerprint, generate_server_certificate


def main(argv=None):
    parser = argparse.ArgumentParser(description='Центральный HTTPS-сервер учётных записей Вуали')
    parser.add_argument('--host', default='127.0.0.1', help='Адрес прослушивания; для сети явно задайте 0.0.0.0')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--db', type=Path, default=DB_PATH, help='Серверный файл users.db')
    parser.add_argument('--cert', type=Path, default=DATA_DIR / 'network' / 'server.crt')
    parser.add_argument('--key', type=Path, default=DATA_DIR / 'network' / 'server.key')
    parser.add_argument('--init-tls', action='store_true', help='Создать новую пару сертификат/ключ перед запуском')
    parser.add_argument('--server-name', action='append', default=[], help='IP или DNS-имя сервера в сети; можно повторять')
    parser.add_argument('--bootstrap-admin', action='store_true', help='Создать администратора в пустой базе с вводом пароля')
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error('Порт должен находиться в диапазоне 0–65535')
    try:
        if args.init_tls:
            generate_server_certificate(args.cert, args.key, args.server_name)
        if not args.cert.is_file() or not args.key.is_file():
            parser.error('Сначала создайте TLS-сертификат с --init-tls и --server-name IP_СЕРВЕРА')
        db = DatabaseManager(args.db)
        try:
            if args.bootstrap_admin:
                if db.fetch_one('SELECT 1 FROM users LIMIT 1'):
                    raise ValueError('База уже содержит пользователей; первоначальная настройка запрещена')
                password = getpass('Новый пароль администратора (минимум 8 символов): ')
                if password != getpass('Повторите пароль: '):
                    raise ValueError('Пароли не совпадают')
                db.bootstrap_admin(password)
            if not db.fetch_one('SELECT 1 FROM users WHERE active=1 AND network_blocked=0 AND is_admin=1 LIMIT 1'):
                raise ValueError('В базе нет действующего администратора. Используйте --bootstrap-admin для пустой базы')
        finally:
            db.close()
        server = create_server(args.db, args.host, args.port, certfile=args.cert, keyfile=args.key)
        print(f'Вуаль: HTTPS-сервер {args.host}:{server.server_address[1]}')
        print(f'База учётных записей: {args.db.resolve()}')
        print(f'Сертификат для клиентов: {args.cert.resolve()}')
        print(f'SHA-256 сертификата: {certificate_fingerprint(args.cert)}')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('Сервер остановлен.')
        finally:
            server.server_close()
        return 0
    except (ValueError, FileExistsError, OSError) as exc:
        print('Не удалось запустить сервер:', exc)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

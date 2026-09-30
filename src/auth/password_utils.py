"""Пароли PBKDF2; старые SHA-256 поддерживаются для миграции при входе."""
import hashlib
import hmac
import secrets


class PasswordUtils:
    ITERATIONS = 600_000

    @staticmethod
    def hash_password(password):
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(),
                                     PasswordUtils.ITERATIONS).hex()
        return f'pbkdf2_sha256:{PasswordUtils.ITERATIONS}:{digest}', salt

    @staticmethod
    def verify_password(password, hash_value, salt):
        try:
            if hash_value.startswith('pbkdf2_sha256:'):
                _, rounds, expected = hash_value.split(':')
                rounds = int(rounds)
                if not 100_000 <= rounds <= 2_000_000:
                    return False
                actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), rounds).hex()
            else:
                expected = hash_value
                actual = hashlib.sha256((password + salt).encode()).hexdigest()
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def is_valid_password(password):
        return isinstance(password, str) and 8 <= len(password) <= 1024

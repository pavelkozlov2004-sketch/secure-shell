"""HTTPS JSON-транспорт с проверкой сертификата выбранного LAN-сервера."""
import json
import ssl
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler, HTTPRedirectHandler

from network.settings import validate_server_url

REQUEST_TIMEOUT = 3.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class NetworkError(OSError):
    pass


class AuthenticationError(PermissionError):
    pass


class AuthorizationError(PermissionError):
    pass


class RequestError(ValueError):
    pass


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        # Нельзя отправлять пароль или Bearer другому узлу через перенаправление.
        return None


class NetworkClient:
    def __init__(self, server_url, ca_file, *, opener=None):
        self.server_url = validate_server_url(server_url)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=ca_file)
        self.ssl_context = context
        # LAN-адрес не передаётся HTTP-прокси, настроенному для доступа в интернет.
        self._opener = opener or build_opener(
            ProxyHandler({}), HTTPSHandler(context=context), _NoRedirects())

    def request(self, endpoint, data=None, *, session_id=None):
        if not isinstance(endpoint, str) or not endpoint.startswith('/api/') or any(
                char in endpoint for char in ('?', '#', '\\', '\r', '\n')):
            raise ValueError('Некорректный запрос к серверу.')
        headers = {'Content-Type': 'application/json; charset=utf-8', 'Accept': 'application/json'}
        if session_id is not None:
            if (not isinstance(session_id, str) or not session_id or len(session_id) > 512
                    or any(ord(c) < 33 or ord(c) > 126 for c in session_id)):
                raise ValueError('Некорректный идентификатор сеанса.')
            headers['Authorization'] = 'Bearer ' + session_id
        payload = json.dumps({} if data is None else data, ensure_ascii=False).encode('utf-8')
        request = Request(self.server_url + endpoint, data=payload, headers=headers, method='POST')
        try:
            with self._opener.open(request, timeout=REQUEST_TIMEOUT) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            status = exc.code
            exc.close()
            if status == 401:
                raise AuthenticationError('Сеанс на сервере завершён или учётная запись недоступна.') from None
            if status == 403:
                raise AuthorizationError('На сервере недостаточно прав для этой операции.') from None
            if status in (400, 404, 409, 413):
                raise RequestError('Сервер отклонил запрос. Проверьте данные операции.') from None
            raise NetworkError('Сервер недоступен или вернул ошибку.') from None
        except (URLError, OSError, TimeoutError, HTTPException):
            raise NetworkError('Нет защищённого подключения к серверу. Проверьте сеть и сертификат.') from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise NetworkError('Ответ сервера превышает допустимый размер.')
        try:
            result = json.loads(raw.decode('utf-8'))
        except (UnicodeError, ValueError, RecursionError):
            raise NetworkError('Сервер вернул некорректный ответ.') from None
        if not isinstance(result, dict):
            raise NetworkError('Сервер вернул некорректный ответ.')
        return result

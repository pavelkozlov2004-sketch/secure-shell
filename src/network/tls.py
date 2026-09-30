"""Локальный сертификат сервера; клиент доверяет его явной копии."""
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_server_certificate(certfile, keyfile, server_names=()):
    """Создать новую пару, не заменяя существующий сертификат или ключ."""
    certfile, keyfile = Path(certfile), Path(keyfile)
    if certfile.resolve() == keyfile.resolve():
        raise ValueError('Сертификат и ключ должны находиться в разных файлах')
    if certfile.exists() or keyfile.exists():
        raise FileExistsError('Сертификат или ключ уже существует')
    names = list(dict.fromkeys(['localhost', '127.0.0.1', *server_names]))
    alternatives = []
    for name in names:
        if not isinstance(name, str) or not name or len(name) > 253 or '*' in name:
            raise ValueError('Некорректное имя сервера')
        try:
            alternatives.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            # IDNA и явные имена позволяют стандартной проверке TLS сопоставить адрес.
            alternatives.append(x509.DNSName(name.encode('idna').decode('ascii')))
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Vual LAN server')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256()))
    cert_data = certificate.public_bytes(serialization.Encoding.PEM)
    key_data = private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    certfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for path, data, permissions in ((keyfile, key_data, 0o600), (certfile, cert_data, 0o644)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, permissions)
            created.append(path)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return certificate_fingerprint(certfile)


def certificate_fingerprint(certfile):
    certificate = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
    digest = certificate.fingerprint(hashes.SHA256()).hex().upper()
    return ':'.join(digest[index:index + 2] for index in range(0, len(digest), 2))


def server_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certfile), str(keyfile))
    return context


def client_context(certfile):
    """Без незащищённого обхода ошибок сертификата или проверки имени."""
    context = ssl.create_default_context(cafile=str(certfile))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context

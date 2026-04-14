# node_setup/ssl_generate.py
# ==============================================================================
# Функции генерации SSL-сертификатов: self-signed, mkcert, Let's Encrypt, manual.
# ==============================================================================

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend

from node_setup.ssl_result import SSLResult, _local_ips
from node_setup.ssl_install import install_ca_to_trust_store
from node_setup.ssl_utils import _get_mkcert_ca_path

logger = logging.getLogger(__name__)


def generate_self_signed(
        cert_dir: Path,
        hostname: str = "",
        org_name: str = "Vortex Node",
        days: int = 825,
        install_ca: bool = True,
        admin_password: str = "",
) -> SSLResult:
    """
    Генерирует самоподписанный корневой CA и сертификат сервера.
    - Создаёт CA на 10 лет.
    - Создаёт сертификат сервера с SAN, включающим все локальные IP и localhost.
    - Сохраняет файлы: vortex-ca.crt, vortex.crt, vortex.key.
    - Если install_ca=True, пытается установить CA в системное хранилище.
    Возвращает SSLResult с путями к файлам и информацией о доверии.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    backend = default_backend()
    hostname = hostname or socket.gethostname()
    now = datetime.datetime.now(datetime.timezone.utc)

    # --- Генерация корневого CA ---
    ca_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=backend
    )
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{org_name} CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_name} Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 лет
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256(), backend)
    )

    # --- Генерация сертификата сервера ---
    srv_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=backend
    )
    # Список SAN: localhost, hostname, hostname.local, все IP
    san_list: list = [
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.DNSName(hostname + ".local"),
    ]
    for ip_str in _local_ips():
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass

    srv_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256(), backend)
    )

    # Запись файлов
    ca_path = cert_dir / "vortex-ca.crt"
    cert_path = cert_dir / "vortex.crt"
    key_path = cert_dir / "vortex.key"

    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(srv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

    try:
        os.chmod(key_path, 0o600)  # защищаем ключ
    except Exception:
        pass

    logger.info(f"SSL: сгенерированы сертификаты в {cert_dir}")
    trusted = False
    if install_ca:
        trusted = install_ca_to_trust_store(ca_path, password=admin_password or None)

    return SSLResult(
        ok=True,
        cert=str(cert_path),
        key=str(key_path),
        ca=str(ca_path),
        message=f"Сертификат создан для: {hostname} + {len(_local_ips())} IP-адресов",
        trusted=trusted,
    )


def generate_with_mkcert(cert_dir: Path, hostname: str = "") -> SSLResult:
    """
    Генерирует сертификат с помощью утилиты mkcert.
    mkcert создаёт локально доверенные сертификаты (CA устанавливается однократно).
    Возвращает SSLResult с путями к файлам и флагом trusted=True (если успешно).
    """
    mkcert_bin = shutil.which("mkcert")
    if not mkcert_bin:
        return SSLResult(ok=False, cert="", key="", ca="",
                         message="mkcert не найден. Установите: https://github.com/FiloSottile/mkcert",
                         trusted=False)
    cert_dir.mkdir(parents=True, exist_ok=True)
    hostname = hostname or socket.gethostname()
    cert_path = cert_dir / "vortex.crt"
    key_path = cert_dir / "vortex.key"
    ips = _local_ips()

    domains = [hostname, "localhost", "127.0.0.1"] + ips

    # Устанавливаем CA mkcert (если ещё не установлен)
    subprocess.run([mkcert_bin, "-install"], capture_output=True)

    result = subprocess.run(
        [mkcert_bin,
         "-cert-file", str(cert_path),
         "-key-file",  str(key_path),
         *domains],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return SSLResult(ok=False, cert="", key="", ca="",
                         message=f"mkcert ошибка: {result.stderr}",
                         trusted=False)

    ca_path = _get_mkcert_ca_path()
    return SSLResult(
        ok=True, cert=str(cert_path), key=str(key_path), ca=ca_path or "",
        message=f"mkcert: сертификат создан для {len(domains)} хостов/IP",
        trusted=True,
    )


def generate_letsencrypt(
        cert_dir: Path,
        domain: str,
        email: str,
        port: int = 80,
        staging: bool = False,
) -> SSLResult:
    """
    Получает сертификат Let's Encrypt через certbot.
    Требует, чтобы порт 80 был открыт и домен указывал на этот сервер.
    При staging=True использует тестовый сервер (невалидные сертификаты, но без лимитов).
    """
    certbot_bin = shutil.which("certbot") or shutil.which("certbot3")
    if not certbot_bin:
        return SSLResult(ok=False, cert="", key="", ca="",
                         message="certbot не найден. Установите: https://certbot.eff.org/",
                         trusted=False)

    cert_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        certbot_bin, "certonly",
        "--standalone",
        "--non-interactive",
        "--agree-tos",
        f"--email={email}",
        f"--domain={domain}",
        f"--http-01-port={port}",
        f"--config-dir={cert_dir / 'certbot'}",
        f"--work-dir={cert_dir / 'certbot' / 'work'}",
        f"--logs-dir={cert_dir / 'certbot' / 'logs'}",
    ]
    if staging:
        cmd.append("--staging")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return SSLResult(ok=False, cert="", key="", ca="",
                         message=f"certbot ошибка: {result.stderr[:400]}",
                         trusted=False)

    live_dir = cert_dir / "certbot" / "live" / domain
    cert_path = live_dir / "fullchain.pem"
    key_path = live_dir / "privkey.pem"

    if not cert_path.exists() or not key_path.exists():
        return SSLResult(ok=False, cert="", key="", ca="",
                         message=f"certbot: файлы не найдены в {live_dir}",
                         trusted=False)

    # Копируем в стандартные имена vortex.crt / vortex.key
    import shutil as sh
    sh.copy2(cert_path, cert_dir / "vortex.crt")
    sh.copy2(key_path, cert_dir / "vortex.key")

    return SSLResult(
        ok=True,
        cert=str(cert_dir / "vortex.crt"),
        key=str(cert_dir / "vortex.key"),
        ca="",
        message=f"Let's Encrypt: сертификат для {domain} получен",
        trusted=True,
    )


def use_manual_cert(cert_src: str, key_src: str, cert_dir: Path) -> SSLResult:
    """
    Копирует предоставленные пользователем файлы сертификата в рабочую директорию.
    Используется для ручной загрузки существующих сертификатов.
    """
    import shutil as sh
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "vortex.crt"
    key_path = cert_dir / "vortex.key"
    try:
        sh.copy2(cert_src, cert_path)
        sh.copy2(key_src, key_path)
        os.chmod(key_path, 0o600)
        return SSLResult(ok=True, cert=str(cert_path), key=str(key_path), ca="",
                         message="Сертификат скопирован", trusted=True)
    except Exception as e:
        return SSLResult(ok=False, cert="", key="", ca="",
                         message=f"Ошибка копирования: {e}", trusted=False)

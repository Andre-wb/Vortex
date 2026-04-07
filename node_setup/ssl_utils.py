# node_setup/ssl_utils.py
# ==============================================================================
# Утилиты: проверка срока сертификата, определение доступных методов, путь CA mkcert.
# ==============================================================================

from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path


def check_cert_expiry(cert_path: Path) -> dict:
    """
    Проверяет срок действия сертификата.
    Возвращает словарь с полями:
      valid: bool
      expires_at: ISO дата
      days_left: int
      subject: строка subject
      error: если произошла ошибка
    """
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
            cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        delta = exp - now
        return {
            "valid": delta.days > 0,
            "expires_at": exp.isoformat(),
            "days_left": max(0, delta.days),
            "subject": cert.subject.rfc4514_string(),
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def detect_available_methods() -> dict[str, bool]:
    """
    Определяет, какие методы генерации сертификатов доступны на данной системе.
    Возвращает словарь {имя_метода: bool}.
    """
    return {
        "self_signed": True,  # всегда доступен (чистый Python)
        "mkcert": bool(shutil.which("mkcert")),
        "letsencrypt": bool(shutil.which("certbot") or shutil.which("certbot3")),
        "manual": True,       # всегда доступен (загрузка своих файлов)
    }


def _get_mkcert_ca_path() -> str:
    """Возвращает путь к CA-сертификату mkcert, если он существует."""
    mkcert_bin = shutil.which("mkcert")
    if not mkcert_bin:
        return ""
    r = subprocess.run([mkcert_bin, "-CAROOT"], capture_output=True, text=True)
    if r.returncode == 0:
        ca_dir = Path(r.stdout.strip())
        for name in ("rootCA.pem", "rootCA.crt"):
            p = ca_dir / name
            if p.exists():
                return str(p)
    return ""

# node_setup/ssl_install.py
# ==============================================================================
# Установка CA-сертификата в системное хранилище доверия.
#
# Пароль администратора приходит из wizard web UI.
# Без пароля установка пропускается (возвращаем False).
#   macOS  — sudo -S + security add-trusted-cert
#   Linux  — sudo -S + cp + update-ca-certificates
#   Windows — certutil (UAC автоматически, пароль не нужен)
# ==============================================================================

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from node_setup.ssl_result import _get_system

logger = logging.getLogger(__name__)


def install_ca_to_trust_store(ca_path: Path, password: Optional[str] = None) -> bool:
    """
    Устанавливает CA-сертификат в системное хранилище доверия.
    password — пароль администратора из wizard UI (обязателен для macOS/Linux).
    Возвращает True, если установка прошла успешно.
    """
    system = _get_system()
    try:
        if system == "windows":
            return _install_ca_windows(ca_path)
        if not password:
            logger.info("CA install skipped — no admin password provided")
            return False
        if system == "macos":
            return _install_ca_macos(ca_path, password)
        elif system == "debian":
            return _install_ca_debian(ca_path, password)
        elif system in ("rhel", "arch", "linux"):
            return _install_ca_linux_generic(ca_path, password)
    except Exception as e:
        logger.warning("Не удалось установить CA: %s", e)
    return False


# ══════════════════════════════════════════════════════════════════════════════
# sudo -S helper
# ══════════════════════════════════════════════════════════════════════════════

def _sudo_run(cmd: list[str], password: str) -> subprocess.CompletedProcess:
    """Запускает команду через sudo -S (пароль через stdin)."""
    return subprocess.run(
        ["sudo", "-S"] + cmd,
        input=password + "\n",
        capture_output=True, text=True,
        timeout=30,
    )


# ══════════════════════════════════════════════════════════════════════════════
# macOS
# ══════════════════════════════════════════════════════════════════════════════

def _install_ca_macos(ca_path: Path, password: str) -> bool:
    """Установка CA на macOS через security add-trusted-cert."""
    result = _sudo_run(
        ["security", "add-trusted-cert",
         "-d", "-r", "trustRoot",
         "-k", "/Library/Keychains/System.keychain",
         str(ca_path)],
        password,
    )
    if result.returncode != 0:
        logger.warning("macOS CA install failed: %s", result.stderr.strip())
    return result.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# Windows
# ══════════════════════════════════════════════════════════════════════════════

def _install_ca_windows(ca_path: Path) -> bool:
    """Установка CA на Windows через certutil (UAC prompt автоматически)."""
    flags = {}
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        flags["creationflags"] = subprocess.CREATE_NO_WINDOW
    result = subprocess.run(
        ["certutil", "-addstore", "-f", "ROOT", str(ca_path)],
        capture_output=True, text=True,
        **flags,
    )
    return result.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# Debian/Ubuntu
# ══════════════════════════════════════════════════════════════════════════════

def _install_ca_debian(ca_path: Path, password: str) -> bool:
    """Установка CA на Debian/Ubuntu."""
    dest = f"/usr/local/share/ca-certificates/{ca_path.name}"
    r1 = _sudo_run(["cp", str(ca_path), dest], password)
    if r1.returncode != 0:
        return False
    r2 = _sudo_run(["update-ca-certificates"], password)
    return r2.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# Generic Linux (RHEL, Arch, etc.)
# ══════════════════════════════════════════════════════════════════════════════

def _install_ca_linux_generic(ca_path: Path, password: str) -> bool:
    """Попытка установки CA на других Linux-системах."""
    for dest_dir, update_cmd in [
        ("/etc/pki/ca-trust/source/anchors",  ["update-ca-trust", "extract"]),
        ("/etc/ca-certificates/trust-source",  ["trust", "extract-compat"]),
        ("/usr/local/share/ca-certificates",   ["update-ca-certificates"]),
    ]:
        if Path(dest_dir).exists():
            r1 = _sudo_run(["cp", str(ca_path), dest_dir], password)
            if r1.returncode != 0:
                return False
            r2 = _sudo_run(update_cmd, password)
            return r2.returncode == 0
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Manual instructions (fallback)
# ══════════════════════════════════════════════════════════════════════════════

def get_ca_install_instructions(ca_path: Path) -> str:
    """
    Возвращает текстовую инструкцию для ручной установки CA,
    если автоматическая установка не удалась или не была запрошена.
    """
    system = _get_system()
    p = str(ca_path.resolve())
    instructions = {
        "macos":   f"sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {p}",
        "windows": f"certutil -addstore -f ROOT {p}  (от имени администратора)",
        "debian":  f"sudo cp {p} /usr/local/share/ca-certificates/ && sudo update-ca-certificates",
        "rhel":    f"sudo cp {p} /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust extract",
        "arch":    f"sudo trust anchor {p}",
        "linux":   f"sudo cp {p} /usr/local/share/ca-certificates/ && sudo update-ca-certificates",
    }
    return instructions.get(system, instructions["linux"])

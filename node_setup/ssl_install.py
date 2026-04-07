# node_setup/ssl_install.py
# ==============================================================================
# Установка CA-сертификата в системное хранилище доверия.
# ==============================================================================

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from node_setup.ssl_result import _get_system

logger = logging.getLogger(__name__)


def install_ca_to_trust_store(ca_path: Path) -> bool:
    """
    Устанавливает CA-сертификат в системное хранилище доверия.
    В зависимости от ОС вызывает соответствующую команду с sudo.
    Возвращает True, если установка прошла успешно.
    """
    system = _get_system()
    try:
        if system == "macos":
            return _install_ca_macos(ca_path)
        elif system == "windows":
            return _install_ca_windows(ca_path)
        elif system == "debian":
            return _install_ca_debian(ca_path)
        elif system in ("rhel", "arch", "linux"):
            return _install_ca_linux_generic(ca_path)
    except Exception as e:
        logger.warning(f"Не удалось установить CA: {e}")
    return False


def _install_ca_macos(ca_path: Path) -> bool:
    """Установка CA на macOS через security add-trusted-cert."""
    result = subprocess.run(
        ["sudo", "security", "add-trusted-cert",
         "-d", "-r", "trustRoot",
         "-k", "/Library/Keychains/System.keychain",
         str(ca_path)],
        capture_output=True, text=True
    )
    return result.returncode == 0


def _install_ca_windows(ca_path: Path) -> bool:
    """Установка CA на Windows через certutil."""
    flags = {}
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        flags["creationflags"] = subprocess.CREATE_NO_WINDOW
    result = subprocess.run(
        ["certutil", "-addstore", "-f", "ROOT", str(ca_path)],
        capture_output=True, text=True,
        **flags
    )
    return result.returncode == 0


def _install_ca_debian(ca_path: Path) -> bool:
    """Установка CA на Debian/Ubuntu: копирование в /usr/local/share/ca-certificates и update-ca-certificates."""
    dest = Path("/usr/local/share/ca-certificates") / ca_path.name
    subprocess.run(["sudo", "cp", str(ca_path), str(dest)], check=True)
    result = subprocess.run(["sudo", "update-ca-certificates"], capture_output=True, text=True)
    return result.returncode == 0


def _install_ca_linux_generic(ca_path: Path) -> bool:
    """
    Попытка установки CA на других Linux-системах.
    Перебирает возможные каталоги и команды обновления.
    """
    for dest_dir, update_cmd in [
        ("/etc/pki/ca-trust/source/anchors",    ["sudo", "update-ca-trust", "extract"]),
        ("/etc/ca-certificates/trust-source",   ["sudo", "trust", "extract-compat"]),
        ("/usr/local/share/ca-certificates",    ["sudo", "update-ca-certificates"]),
    ]:
        if Path(dest_dir).exists():
            subprocess.run(["sudo", "cp", str(ca_path), dest_dir], check=True)
            result = subprocess.run(update_cmd, capture_output=True, text=True)
            return result.returncode == 0
    return False


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

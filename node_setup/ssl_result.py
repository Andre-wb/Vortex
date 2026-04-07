# node_setup/ssl_result.py
# ==============================================================================
# SSLResult namedtuple и вспомогательные функции определения окружения.
# ==============================================================================

from __future__ import annotations

import platform
import socket
from pathlib import Path
from typing import NamedTuple


class SSLResult(NamedTuple):
    """
    Результат операции с SSL-сертификатом.
    ok: успешно ли выполнено
    cert: путь к файлу сертификата
    key: путь к файлу приватного ключа
    ca: путь к файлу CA (если есть)
    message: текстовое сообщение для пользователя
    trusted: доверяет ли система этому сертификату (CA установлен)
    """
    ok: bool
    cert: str
    key: str
    ca: str
    message: str
    trusted: bool


def _local_ips() -> list[str]:
    """
    Собирает все локальные IP-адреса (IPv4 и IPv6) этой машины.
    Использует несколько методов:
      - 127.0.0.1, ::1 всегда присутствуют
      - socket.gethostbyname(hostname)
      - netifaces (если установлен) для получения всех интерфейсов
      - сокетное подключение к внешним адресам для определения основного IP
    Возвращает отсортированный список уникальных IP-адресов.
    """
    ips = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for family in (netifaces.AF_INET, netifaces.AF_INET6):
                for addr in addrs.get(family, []):
                    ips.add(addr["addr"].split("%")[0])  # удаляем scope_id для IPv6
    except ImportError:
        # fallback: пробуем подключиться к известным адресам
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for target in ("192.168.1.1", "10.0.0.1", "8.8.8.8"):
                try:
                    s.connect((target, 80))
                    ips.add(s.getsockname()[0])
                    break
                except Exception:
                    pass
            s.close()
        except Exception:
            pass
    return sorted(ips)


def _get_system() -> str:
    """
    Определяет тип операционной системы для выбора правильных команд установки CA.
    Возвращает:
      'windows', 'macos', 'debian', 'rhel', 'arch', 'linux'
    """
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "macos"
    # Проверка наличия специфичных файлов для дистрибутивов Linux
    if Path("/etc/debian_version").exists():
        return "debian"
    if Path("/etc/redhat-release").exists() or Path("/etc/fedora-release").exists():
        return "rhel"
    if Path("/etc/arch-release").exists():
        return "arch"
    return "linux"

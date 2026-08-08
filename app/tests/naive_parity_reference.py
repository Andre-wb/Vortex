"""Независимая Python-реализация правил NaiveProxy.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная реализация двух форматов, против которых сверяется
`vortex-transport`.

Caddyfile. Каждое значение, приходящее из конфигурации, попадает в файл ровно
одним токеном. Основная защита — список разрешённых байт, а не экранирование:
значение с пробелом, переводом строки, кавычкой, обратной косой, апострофом,
обратной кавычкой, фигурной скобкой или решёткой отвергается целиком, и
Caddyfile не собирается вовсе. Кавычки вокруг токена — второй рубеж, а не
первый: на экранирование внутри кавычек и на то, разворачивает ли Caddy
подстановки `{...}` внутри них, полагаться нельзя.

    имя, пароль    ASCII 0x21..0x7E минус `" \\ ' ` { } #`, 1..255 байт
    probe-домен    имя хоста: буквы, цифры, `-`, `.`, не длиннее 253
    почта ACME     те же байты, ровно одна `@`, домен — имя хоста, ≤254
    backend        scheme://host[:port], scheme = http|https, без пути,
                   запроса, фрагмента и userinfo
    порт           только десятичные цифры, 1..65535

URL прокси. `https://имя:пароль@хост:порт`, где имя и пароль
percent-кодируются: всё, кроме `A-Za-z0-9-._~`, уезжает как `%XX` в верхнем
регистре. IPv6-адрес сервера пишется в квадратных скобках.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

MAX_CREDENTIAL_LEN = 255
MAX_HOST_LEN = 253
MAX_EMAIL_LEN = 254
MAX_PORT_DIGITS = 5

REFUSED_BYTES = "\"\\'`{}#"

DEFAULT_PORT = 443
DEFAULT_UPSTREAM = "http://127.0.0.1:8000"
DEFAULT_ACME_EMAIL = "admin@example.com"
DEFAULT_LISTEN = "socks://127.0.0.1:1080"

SCHEMES = ("http", "https")

UNRESERVED = "-._~"

CADDY_TEMPLATE = """\
{{
    order forward_proxy before file_server
    servers {{
        protocols h1 h2
    }}
}}

:{port} {{
    tls {email} {{
        protocols tls1.2 tls1.3
        curves x25519 secp256r1 secp384r1
    }}

    forward_proxy {{
        basic_auth {username} {password}
        hide_ip
        hide_via
        probe_resistance {probe_domain}
    }}

    reverse_proxy {upstream} {{
        header_up Host {{host}}
        header_up X-Real-IP {{remote_host}}
    }}

    file_server {{
        root /var/www/html
    }}
}}
"""


def acceptable(symbol: str) -> bool:
    return 0x21 <= ord(symbol) <= 0x7E and symbol not in REFUSED_BYTES


def credential(value: str) -> Optional[str]:
    if not value or len(value.encode("utf-8", "surrogatepass")) > MAX_CREDENTIAL_LEN:
        return None
    if not all(acceptable(symbol) for symbol in value):
        return None
    return value


def plausible_host(value: str) -> Optional[str]:
    encoded = value.encode("utf-8", "surrogatepass")
    if not encoded or len(encoded) > MAX_HOST_LEN:
        return None
    if not all(symbol.isascii() and (symbol.isalnum() or symbol in "-.") for symbol in value):
        return None
    return value


def acme_email(value: str) -> Optional[str]:
    if not value or len(value.encode("utf-8", "surrogatepass")) > MAX_EMAIL_LEN:
        return None
    if not all(acceptable(symbol) for symbol in value):
        return None
    local, separator, domain = value.partition("@")
    if not separator or not local or "@" in domain:
        return None
    if plausible_host(domain) is None:
        return None
    return value


def port_number(value: str) -> Optional[int]:
    if not value or len(value) > MAX_PORT_DIGITS:
        return None
    if not all(symbol in "0123456789" for symbol in value):
        return None
    number = int(value)
    return number if 1 <= number <= 65535 else None


def host(value: str) -> Optional[str]:
    """Хост в том виде, в каком он пишется в URL: IPv6 — в скобках."""
    if "%" in value:
        return None
    if value.startswith("[") and value.endswith("]"):
        try:
            return f"[{ipaddress.IPv6Address(value[1:-1])}]"
        except ipaddress.AddressValueError:
            return None
    try:
        return f"[{ipaddress.IPv6Address(value)}]"
    except ipaddress.AddressValueError:
        pass
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass
    return plausible_host(value)


def upstream(value: str) -> Optional[str]:
    scheme, separator, authority = value.partition("://")
    if not separator or scheme.lower() not in SCHEMES:
        return None
    if any(symbol in authority for symbol in "/?#@"):
        return None
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return None
        name = host(authority[: closing + 1])
        tail = authority[closing + 1 :]
        if name is None:
            return None
        if not tail:
            return f"{scheme.lower()}://{name}"
        if not tail.startswith(":"):
            return None
        number = port_number(tail[1:])
        return None if number is None else f"{scheme.lower()}://{name}:{number}"
    name, separator, tail = authority.rpartition(":")
    if not separator:
        name = host(authority)
        return None if name is None else f"{scheme.lower()}://{name}"
    resolved = host(name)
    number = port_number(tail)
    if resolved is None or number is None:
        return None
    return f"{scheme.lower()}://{resolved}:{number}"


def quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def percent_encode(value: str) -> str:
    encoded = []
    for byte in value.encode("utf-8", "surrogatepass"):
        symbol = chr(byte)
        if symbol.isascii() and (symbol.isalnum() or symbol in UNRESERVED):
            encoded.append(symbol)
        else:
            encoded.append(f"%{byte:02X}")
    return "".join(encoded)


def caddyfile(
    port: int,
    email: str,
    username: str,
    password: str,
    probe_domain: str,
    backend_url: str,
) -> Optional[str]:
    if port == 0:
        return None
    checked_email = acme_email(email or DEFAULT_ACME_EMAIL)
    checked_username = credential(username)
    checked_password = credential(password)
    checked_domain = plausible_host(probe_domain)
    checked_upstream = upstream(backend_url or DEFAULT_UPSTREAM)
    if None in (checked_email, checked_username, checked_password, checked_domain, checked_upstream):
        return None
    return CADDY_TEMPLATE.format(
        port=port,
        email=quoted(checked_email),
        username=quoted(checked_username),
        password=quoted(checked_password),
        probe_domain=quoted(checked_domain),
        upstream=quoted(checked_upstream),
    )


def proxy_url(server_host: str, port: int, username: str, password: str) -> Optional[str]:
    if port == 0:
        return None
    name = host(server_host)
    if name is None or credential(username) is None or credential(password) is None:
        return None
    return f"https://{percent_encode(username)}:{percent_encode(password)}@{name}:{port}"


def client_config(server_host: str, port: int, username: str, password: str) -> Optional[dict]:
    url = proxy_url(server_host, port, username, password)
    if url is None:
        return None
    return {"listen": DEFAULT_LISTEN, "proxy": url, "log": "", "padding": True}


def _caddyfile_case(args: dict) -> dict:
    return {
        "caddyfile": caddyfile(
            args["port"],
            args["email"],
            args["username"],
            args["password"],
            args["probe_domain"],
            args["backend_url"],
        )
    }


def _proxy_url_case(args: dict) -> dict:
    return {"url": proxy_url(args["server_host"], args["port"], args["username"], args["password"])}


def _client_config_case(args: dict) -> dict:
    return {"config": client_config(args["server_host"], args["port"], args["username"], args["password"])}


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list


def _site(**overrides) -> dict:
    case = {
        "port": 443,
        "email": "admin@example.com",
        "username": "a3f9c2b1",
        "password": "xK-_9Zq",
        "probe_domain": "www.bing.com",
        "backend_url": "http://127.0.0.1:8000",
    }
    case.update(overrides)
    return case


def _client(**overrides) -> dict:
    case = {
        "server_host": "proxy.example.com",
        "port": 443,
        "username": "a3f9c2b1",
        "password": "xK-_9Zq",
    }
    case.update(overrides)
    return case


FUNCTIONS: list[ParityFunction] = [
    ParityFunction(
        name="caddyfile",
        python=_caddyfile_case,
        cases=[
            _site(),
            _site(port=8443),
            _site(email="", backend_url=""),
            _site(email="ops+acme@vortex.test"),
            _site(probe_domain="archive.org"),
            _site(backend_url="https://backend.internal"),
            _site(backend_url="http://[::1]:9000"),
            _site(backend_url="HTTP://127.0.0.1:08000"),
            _site(username="A" * 255),
            _site(password="p!$%&()*+,;=<>?@[]^|~"),
            _site(port=0),
            _site(username=""),
            _site(password=""),
            _site(probe_domain=""),
            _site(username="a3f9 c2b1"),
            _site(password='s3cret}\n    respond "pwned"\n{'),
            _site(password="s3cret{env.HOME}"),
            _site(password='s3"cret'),
            _site(password="s3\\cret"),
            _site(password="s3'cret"),
            _site(password="s3`cret"),
            _site(password="s3#cret"),
            _site(password="пароль"),
            _site(password="A" * 256),
            _site(email="admin@example.com\n    respond"),
            _site(email="admin"),
            _site(email="a@b@c.com"),
            _site(probe_domain="www.bing.com\n    respond"),
            _site(probe_domain="гугл.рф"),
            _site(backend_url="127.0.0.1:8000"),
            _site(backend_url="http://127.0.0.1:8000/api"),
            _site(backend_url="http://user:pass@127.0.0.1:8000"),
            _site(backend_url="http://127.0.0.1:+8000"),
            _site(backend_url="http://127.0.0.1:0"),
            _site(backend_url="unix//run/app.sock"),
        ],
    ),
    ParityFunction(
        name="proxy_url",
        python=_proxy_url_case,
        cases=[
            _client(),
            _client(port=8443),
            _client(server_host="127.0.0.1"),
            _client(server_host="2001:db8::1"),
            _client(server_host="[2001:db8::1]"),
            _client(password="p@ss/evil.test"),
            _client(password="a:b"),
            _client(password="100%"),
            _client(username="u ser"),
            _client(password="p!$&()*+,;=~._-"),
            _client(server_host=""),
            _client(server_host="proxy.example.com/path"),
            _client(server_host="user@proxy.example.com"),
            _client(server_host="[127.0.0.1]"),
            _client(port=0),
            _client(username=""),
            _client(password=""),
            _client(password="пароль"),
        ],
    ),
    ParityFunction(
        name="client_config",
        python=_client_config_case,
        cases=[
            _client(),
            _client(port=8443),
            _client(server_host="2001:db8::1"),
            _client(password="p@ss/evil.test"),
            _client(server_host=""),
            _client(password="пароль"),
        ],
    ),
]

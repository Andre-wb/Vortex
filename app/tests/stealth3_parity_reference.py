"""Независимая Python-реализация форматов и правил шага 3.10.

Пишется по описанию формата, а не переносом кода из `vortex-transport`, —
иначе сверка проверяла бы, что копия совпадает с оригиналом, а не что две
реализации сошлись. Используется только в тестах и генераторе векторов.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import zlib

# --- порядок заголовков Chrome ---

CHROME_ORDER = [
    ":method",
    ":authority",
    ":scheme",
    ":path",
    "host",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "content-type",
    "content-length",
    "origin",
]


def arrange_headers(fields: list[tuple[str, str]]) -> list[tuple[str, str]]:
    collapsed: list[tuple[str, str]] = []
    for name, value in fields:
        for index, (held, _) in enumerate(collapsed):
            if held.lower() == name.lower():
                collapsed[index] = (name, value)
                break
        else:
            collapsed.append((name, value))

    known = [f for f in collapsed if f[0].lower() in CHROME_ORDER]
    rest = [f for f in collapsed if f[0].lower() not in CHROME_ORDER]
    known.sort(key=lambda field: CHROME_ORDER.index(field[0].lower()))
    return known + rest


# --- генератор резервных доменов ---

CONSONANTS = "bcdfghjklmnpqrstvwxyz"
VOWELS = "aeiou"
TLDS = [".com", ".net", ".org", ".info", ".xyz", ".online", ".site"]


def dga_domains(seed: str, day: str, count: int) -> list[str]:
    out = []
    for index in range(count):
        digest = hmac.new(seed.encode(), f"{day}:{index}".encode(), hashlib.sha256).digest()
        length = 6 + digest[0] % 7
        name = "".join(
            (CONSONANTS[digest[(i + 1) % len(digest)] % len(CONSONANTS)])
            if i % 2 == 0
            else (VOWELS[digest[(i + 1) % len(digest)] % len(VOWELS)])
            for i in range(length)
        )
        out.append(name + TLDS[digest[-1] % len(TLDS)])
    return out


# --- gzip-конверт ---

GZIP_HEADER = bytes([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF])
MAX_STORED_BLOCK = 65535


def entropy_wrap(payload: bytes) -> bytes:
    out = bytearray(GZIP_HEADER)
    chunks = [payload[i : i + MAX_STORED_BLOCK] for i in range(0, len(payload), MAX_STORED_BLOCK)] or [b""]
    for index, chunk in enumerate(chunks):
        out.append(0x01 if index == len(chunks) - 1 else 0x00)
        out += len(chunk).to_bytes(2, "little")
        out += (len(chunk) ^ 0xFFFF).to_bytes(2, "little")
        out += chunk
    out += (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little")
    out += (len(payload) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


def entropy_unwrap(envelope: bytes) -> bytes | None:
    if len(envelope) < len(GZIP_HEADER) + 8 or envelope[:2] != GZIP_HEADER[:2]:
        return None
    body = envelope[len(GZIP_HEADER) : len(envelope) - 8]
    payload = bytearray()
    at = 0
    while True:
        if at + 5 > len(body):
            return None
        marker = body[at]
        if marker & 0x06:
            return None
        length = int.from_bytes(body[at + 1 : at + 3], "little")
        checked = int.from_bytes(body[at + 3 : at + 5], "little")
        if checked != (length ^ 0xFFFF):
            return None
        start, end = at + 5, at + 5 + length
        if end > len(body):
            return None
        payload += body[start:end]
        at = end
        if marker & 0x01:
            break
    if at != len(body):
        return None
    trailer = envelope[len(envelope) - 8 :]
    if int.from_bytes(trailer[4:8], "little") != len(payload):
        return None
    if int.from_bytes(trailer[0:4], "little") != (zlib.crc32(bytes(payload)) & 0xFFFFFFFF):
        return None
    return bytes(payload)


# --- base32 и туннель DoH ---

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
MAX_LABEL = 63
MAX_NAME = 255


def base32_encode(raw: bytes) -> str:
    bits = "".join(f"{byte:08b}" for byte in raw)
    out = ""
    for at in range(0, len(bits), 5):
        piece = bits[at : at + 5]
        if len(piece) < 5:
            piece = piece.ljust(5, "0")
        out += ALPHABET[int(piece, 2)]
    return out


def base32_decode(text: str) -> bytes | None:
    bits = ""
    for symbol in text.lower():
        if symbol not in ALPHABET:
            return None
        bits += f"{ALPHABET.index(symbol):05b}"
    return bytes(int(bits[at : at + 8], 2) for at in range(0, len(bits) - 7, 8))


def wire_length(name: str) -> int:
    return sum(1 + len(label) for label in name.rstrip(".").split(".")) + 1


def doh_payload_size(suffix: str) -> int | None:
    suffix = suffix.strip(".")
    if not suffix:
        return None
    free = MAX_NAME - wire_length(suffix)
    best = 0
    for raw in range(1, free + 1):
        encoded = -(-(raw * 8) // 5)
        if encoded + -(-encoded // MAX_LABEL) <= free:
            best = raw
    return None if best <= 6 else best - 6


def doh_encode(suffix: str, data: bytes, message: int) -> list[str] | None:
    room = doh_payload_size(suffix)
    if room is None:
        return None
    suffix = suffix.strip(".")
    pieces = [data[i : i + room] for i in range(0, len(data), room)] or [b""]
    if len(pieces) > 0xFFFF:
        return None
    names = []
    for index, piece in enumerate(pieces):
        raw = message.to_bytes(2, "big") + len(pieces).to_bytes(2, "big") + index.to_bytes(2, "big") + piece
        encoded = base32_encode(raw)
        labels = [encoded[i : i + MAX_LABEL] for i in range(0, len(encoded), MAX_LABEL)]
        names.append(".".join([*labels, suffix]))
    return names


def doh_decode(suffix: str, fqdn: str) -> tuple[int, int, int, bytes] | None:
    suffix = suffix.strip(".")
    bare = fqdn.rstrip(".")
    if not bare.endswith("." + suffix):
        return None
    head = bare[: -(len(suffix) + 1)]
    if not head:
        return None
    raw = base32_decode(head.replace(".", ""))
    if raw is None or len(raw) < 6:
        return None
    message = int.from_bytes(raw[0:2], "big")
    total = int.from_bytes(raw[2:4], "big")
    index = int.from_bytes(raw[4:6], "big")
    if total == 0 or index >= total:
        return None
    return message, total, index, raw[6:]


# --- формат провода DNS ---


def dns_query(host: str, kind: int = 1) -> bytes | None:
    out = bytearray(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for label in host.rstrip(".").split("."):
        if not label or len(label) > MAX_LABEL or not label.isascii():
            return None
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    if len(out) - 12 > MAX_NAME:
        return None
    out += kind.to_bytes(2, "big") + b"\x00\x01"
    return bytes(out)


def _skip_name(wire: bytes, at: int) -> int | None:
    while True:
        if at >= len(wire):
            return None
        length = wire[at]
        if length == 0:
            return at + 1
        if length & 0xC0 == 0xC0:
            return at + 2 if at + 2 <= len(wire) else None
        if length > MAX_LABEL:
            return None
        at += 1 + length
        if at > len(wire):
            return None


def dns_addresses(wire: bytes) -> list[str]:
    if len(wire) < 12:
        return []
    questions = int.from_bytes(wire[4:6], "big")
    answers = int.from_bytes(wire[6:8], "big")
    at = 12
    for _ in range(questions):
        skipped = _skip_name(wire, at)
        if skipped is None or skipped + 4 > len(wire):
            return []
        at = skipped + 4
    found = []
    for _ in range(answers):
        skipped = _skip_name(wire, at)
        if skipped is None or skipped + 10 > len(wire):
            return []
        at = skipped
        kind = int.from_bytes(wire[at : at + 2], "big")
        klass = int.from_bytes(wire[at + 2 : at + 4], "big")
        length = int.from_bytes(wire[at + 8 : at + 10], "big")
        data = at + 10
        if data + length > len(wire):
            return []
        if kind == 1 and klass == 1 and length == 4:
            found.append(".".join(str(b) for b in wire[data : data + 4]))
        at = data + length
    return found


# --- вердикт детектора зондов ---

SUSPECTED = ["109.124.0.0/16", "149.154.0.0/16", "185.228.0.0/16"]
NOT_A_CENSOR = ["149.154.160.0/20", "149.154.164.0/22", "185.228.168.0/24", "185.228.169.0/24"]
ALWAYS_SENT = [
    "accept",
    "accept-language",
    "accept-encoding",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-dest",
]
TOOL_NAMES = ["curl", "wget", "python", "go-http", "java/", "scanner", "nikto", "sqlmap", "nmap", "masscan"]
MACHINE_ROUTES = ["/health", "/api/bmp/", "/api/federation/", "/api/peers/", "/api/global/"]


def _address(peer: str):
    value = peer.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    value = value.split("%")[0]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


LOCAL_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "0.0.0.0/32",
    "255.255.255.255/32",
    "::1/128",
    "::/128",
    "fc00::/7",
    "fe80::/10",
]


def _is_local(address) -> bool:
    """Сети перечислены явно, а не через `address.is_private`.

    В Python этот признак верен и для документационных диапазонов
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), которые локальной сетью
    не являются; `Ipv4Addr::is_private` в Rust покрывает только RFC 1918.
    Расхождение поймано паритетным прогоном шага 3.10.
    """
    return any(address in ipaddress.ip_network(net) for net in LOCAL_NETWORKS)


def _is_exempt(path: str) -> bool:
    return any(path.startswith(route) if route.endswith("/") else path == route for route in MACHINE_ROUTES)


def probe_signals(peer: str, method: str, path: str, headers: dict[str, str]) -> list[str]:
    """Сигналы без учёта повтора — повтор требует состояния и вектором не морозится."""
    address = _address(peer)
    if address is not None and _is_local(address):
        return []
    if _is_exempt(path):
        return []

    lowered = {name.lower(): value for name, value in headers.items()}
    signals = []

    if address is not None and not any(address in ipaddress.ip_network(net) for net in NOT_A_CENSOR):
        for net in SUSPECTED:
            if address in ipaddress.ip_network(net):
                signals.append(f"censor_net:{net}")
                break

    missing = sum(1 for name in ALWAYS_SENT if name not in lowered)
    if missing >= 4:
        signals.append(f"missing_headers:{missing}")

    agent = lowered.get("user-agent", "")
    if not agent:
        signals.append("no_user_agent")
    elif len(agent) < 20:
        signals.append("short_ua")
    elif any(tool in agent.lower() for tool in TOOL_NAMES):
        signals.append(f"bot_ua:{agent[:30]}")

    if "cookie" not in lowered and path != "/":
        signals.append("no_cookies")

    accept = lowered.get("accept", "")
    expected = "javascript" if path.endswith(".js") else ("text/css" if path.endswith(".css") else None)
    if expected is not None and expected not in accept and "/*" not in accept:
        signals.append("accept_mismatch")

    return signals


def probe_verdict(peer: str, method: str, path: str, headers: dict[str, str]) -> dict:
    signals = probe_signals(peer, method, path, headers)
    return {"is_probe": len(signals) >= 2, "signals": signals}

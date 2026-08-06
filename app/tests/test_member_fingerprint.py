"""ADR-008 G6/F6: отпечаток account-Ed участника + QR — cross-impl оракул (Python)
к static/js/fingerprint.js:computeFingerprint / computeEmojiFingerprint /
fingerprintQRPayload. Отпечаток и QR чисто клиентские (сервер не участвует);
Python здесь — референс сериализации, пиннящий тот же hex, что и JS-тест
(static/js/__tests__/member-fingerprint.test.js).

Сериализация ЗАФИКСИРОВАНА (§4.7): sort LOWERCASE hex-строк пары, разделитель ':',
SHA-256, UPPERCASE hex группами по 4. QR-payload: "VORTEX-FP:" + hex без пробелов.
"""

import hashlib

_EMOJI = [
    "🐶",
    "🐱",
    "🐭",
    "🐹",
    "🐰",
    "🦊",
    "🐻",
    "🐼",
    "🐨",
    "🐯",
    "🦁",
    "🐸",
    "🐵",
    "🐔",
    "🐧",
    "🐦",
    "🦅",
    "🦉",
    "🐺",
    "🐗",
    "🐴",
    "🦄",
    "🐝",
    "🐛",
    "🦋",
    "🐌",
    "🐞",
    "🐙",
    "🦑",
    "🐠",
    "🐳",
    "🐋",
    "🌵",
    "🌲",
    "🌻",
    "🌹",
    "🍄",
    "🍀",
    "🍁",
    "🌸",
    "🍎",
    "🍊",
    "🍋",
    "🍇",
    "🍉",
    "🍓",
    "🥝",
    "🍒",
    "🌍",
    "🌙",
    "⭐",
    "🔥",
    "💧",
    "❄️",
    "⚡",
    "🌈",
    "💎",
    "🔑",
    "🎵",
    "🎯",
    "🚀",
    "⚓",
    "🏔️",
    "🎲",
]


def _raw(a, b):
    s = sorted([a.lower(), b.lower()])
    return hashlib.sha256((s[0] + ":" + s[1]).encode()).digest()


def fingerprint_blocks(a, b):
    hexs = _raw(a, b).hex().upper()
    return " ".join(hexs[i : i + 4] for i in range(0, len(hexs), 4))


def emoji_fingerprint(a, b):
    d = _raw(a, b)
    return [_EMOJI[d[i] % 64] for i in range(6)]


def qr_payload(a, b):
    return "VORTEX-FP:" + _raw(a, b).hex().upper()


_EDA = "aa" * 32
_EDB = "bb" * 32
_BLOCKS = "6173 CF9D 3267 E6B9 2610 2C8B 1498 1265 8D05 D834 916F D23F 7451 C48C 8881 47AB"
_QR = "VORTEX-FP:6173CF9D3267E6B926102C8B149812658D05D834916FD23F7451C48C888147AB"
_EMOJIS = ["🌲", "🔥", "🐦", "🐠", "⭐", "🌸"]


def test_fingerprint_matches_cross_impl_vector():
    # Тот же hex, что пинит JS-тест → JS↔Python сходятся.
    assert fingerprint_blocks(_EDA, _EDB) == _BLOCKS


def test_emoji_matches_cross_impl_vector():
    assert emoji_fingerprint(_EDA, _EDB) == _EMOJIS


def test_qr_payload_matches_cross_impl_vector():
    assert qr_payload(_EDA, _EDB) == _QR


def test_fingerprint_symmetric():
    # sort пары → обе стороны видят один отпечаток (иначе QR-скан никогда не совпал бы).
    assert fingerprint_blocks(_EDA, _EDB) == fingerprint_blocks(_EDB, _EDA)


def test_substitution_breaks_match():
    # Подмена Ea одного участника → отпечаток расходится → скан не подтверждает.
    assert fingerprint_blocks(_EDA, _EDB) != fingerprint_blocks(_EDA, "cc" * 32)

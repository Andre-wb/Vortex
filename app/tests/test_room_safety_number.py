"""ADR-008 G5: room safety number — cross-impl оракул (Python) к
static/js/fingerprint.js:computeRoomSafetyNumber. room_sn чисто клиентский
(сервер не участвует); Python здесь — референс сериализации, пиннящий тот же
hashHex, что и JS-тест (static/js/__tests__/room-safety-number.test.js).

Сериализация ЗАФИКСИРОВАНА (ADR-008 §4.7): sort LOWERCASE hex-строк (НЕ raw-байты),
домен "vortex-room-sn:v1", разделитель ":".
"""

import hashlib


def room_safety_number(room_id, eds_hex):
    sorted_eds = sorted(e.lower() for e in eds_hex if e)
    inp = f"vortex-room-sn:v1:{room_id}:" + ":".join(sorted_eds)
    return hashlib.sha256(inp.encode()).hexdigest()


_EDS = ["ff" * 32, "aa" * 32, "0f" * 32]
_HASHHEX = "14820ad9c2507332d385f6e164b448e28b1b89b96e90ea0ebecb95efac10475a"


def test_room_sn_matches_cross_impl_vector():
    # Тот же hashHex, что пинит JS-тест → JS↔Python сходятся.
    assert room_safety_number(42, _EDS) == _HASHHEX


def test_room_sn_sort_and_case_independent():
    # Порядок/регистр входа не влияют → все участники видят один код.
    assert room_safety_number(42, ["0f" * 32, "AA" * 32, "FF" * 32]) == _HASHHEX


def test_room_sn_detects_key_change():
    base = room_safety_number(42, _EDS)
    changed = room_safety_number(42, ["ff" * 32, "aa" * 32, "be" * 32])
    assert changed != base


def test_room_sn_binds_room_id():
    assert room_safety_number(42, _EDS) != room_safety_number(43, _EDS)

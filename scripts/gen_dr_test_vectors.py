#!/usr/bin/env python3
"""Генератор кросс-языковых тест-векторов для Double Ratchet.

Прогоняет референс-реализацию app/security/double_ratchet.py на детерминированных
ключах/нонсах и пишет app/tests/vectors/dr_vectors.json. Повторный запуск даёт
байт-в-байт идентичный файл — это проверяется тестом и позволяет ревьюить диффы.

Векторы предназначены для:
  - пиннинга Python-референса (app/tests/test_double_ratchet.py, класс TestVectors);
  - будущей JS-реализации: JS обязан расшифровать все транскрипты
    и сойтись по KDF/X3DH/Header байт-в-байт.

ВНИМАНИЕ: файл векторов содержит приватные ключи — это тестовые данные,
использовать их вне тестов нельзя.

Запуск (из корня репозитория):
    python scripts/gen_dr_test_vectors.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import secrets as _secrets_mod
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(ROOT, "app", "tests", "vectors", "dr_vectors.json")

# Загружаем модуль напрямую по пути, минуя пакет app.* (его __init__ тянет
# конфигурацию приложения, которая скрипту не нужна).
_spec = importlib.util.spec_from_file_location(
    "double_ratchet", os.path.join(ROOT, "app", "security", "double_ratchet.py")
)
dr = importlib.util.module_from_spec(_spec)
sys.modules["double_ratchet"] = dr  # нужен dataclass'ам модуля при исполнении
_spec.loader.exec_module(dr)


def _det_bytes(label: str, n: int = 32) -> bytes:
    """Детерминированные псевдослучайные байты из метки."""
    return hashlib.sha256(f"vortex-dr-vectors:{label}".encode()).digest()[:n]


def _det_priv(label: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_det_bytes(label))


def _det_bytes_xof(label: str, n: int) -> bytes:
    """Детерминированные псевдослучайные байты произвольной длины (SHAKE-256).

    _det_bytes ограничен 32 байтами (SHA-256); KEM-поля PQXDH больше
    (pqpk 1184, ct 1088) — для них нужен XOF.
    """
    return hashlib.shake_256(f"vortex-dr-vectors:{label}".encode()).digest(n)


class _DetSource:
    """Детерминированная замена источников случайности референса.

    Подменяет dr._generate_x25519_pair (эфемерные/ratchet-ключи) и
    secrets.token_bytes (нонсы AES-GCM в dr._encrypt_aes_gcm), чтобы
    транскрипты были воспроизводимы байт-в-байт.
    """

    def __init__(self):
        self.key_ctr = 0
        self.nonce_ctr = 0

    def next_priv(self) -> X25519PrivateKey:
        priv = _det_priv(f"gen-key:{self.key_ctr}")
        self.key_ctr += 1
        return priv

    def next_nonce(self, n: int = 12) -> bytes:
        out = _det_bytes(f"nonce:{self.nonce_ctr}", n)
        self.nonce_ctr += 1
        return out


def _pub_hex(priv: X25519PrivateKey) -> str:
    return priv.public_key().public_bytes_raw().hex()


def gen_kdf_vectors() -> dict:
    kdf_ck = []
    for i in range(4):
        ck = _det_bytes(f"kdf-ck-input:{i}")
        new_ck, mk = dr.kdf_ck(ck)
        kdf_ck.append({"ck": ck.hex(), "new_ck": new_ck.hex(), "mk": mk.hex()})

    kdf_rk = []
    for i in range(4):
        rk = _det_bytes(f"kdf-rk-input:{i}")
        dh_out = _det_bytes(f"kdf-rk-dh:{i}")
        new_rk, new_ck = dr.kdf_rk(rk, dh_out)
        kdf_rk.append({
            "rk": rk.hex(), "dh_out": dh_out.hex(),
            "new_rk": new_rk.hex(), "new_ck": new_ck.hex(),
        })
    return {"kdf_ck": kdf_ck, "kdf_rk": kdf_rk}


def gen_header_vectors() -> list:
    vectors = []
    for i, (pn, n) in enumerate([(0, 0), (3, 7), (0xFFFFFFFF, 0xFFFFFFFF)]):
        h = dr.Header(dh_public=_det_bytes(f"header-pub:{i}"), prev_count=pn, msg_number=n)
        vectors.append({
            "dh_public": h.dh_public.hex(),
            "prev_count": h.prev_count,
            "msg_number": h.msg_number,
            "serialized": h.serialize().hex(),
        })
    return vectors


def gen_spk_vector() -> dict:
    seed = _det_bytes("ed25519-identity")
    identity = Ed25519PrivateKey.from_private_bytes(seed)
    spk_priv = _det_priv("spk-for-signature")
    spk_pub = spk_priv.public_key().public_bytes_raw()
    sig = dr.sign_spk(identity, spk_pub)
    return {
        "ed25519_seed": seed.hex(),
        "ed25519_pub": identity.public_key().public_bytes_raw().hex(),
        "spk_pub": spk_pub.hex(),
        "signature": sig.hex(),
    }


def gen_device_cert_vector() -> dict:
    """Authorization-cert устройства: аккаунтный Ed25519 подписывает
    (client_device_id ‖ device_x3dh_pub ‖ device_sign_pub) = 80 байт.
    Раскладка зеркалит certMessage() из static/js/dr/device-identity.js —
    вектор пиннит JS↔Python byte-parity перед включением проверки cert'а (M3)."""
    seed = _det_bytes("device-cert-account-ed")
    account = Ed25519PrivateKey.from_private_bytes(seed)
    client_device_id = _det_bytes("device-cert-cid", 16)        # 16 байт = 32 hex
    x3dh_pub = _det_priv("device-cert-x3dh").public_key().public_bytes_raw()
    sign_pub = Ed25519PrivateKey.from_private_bytes(
        _det_bytes("device-cert-sign")).public_key().public_bytes_raw()
    cert_message = client_device_id + x3dh_pub + sign_pub       # cid(16)‖x3dh(32)‖sign(32)
    cert_sig = account.sign(cert_message)
    return {
        "account_ed_seed": seed.hex(),
        "account_ed_pub": account.public_key().public_bytes_raw().hex(),
        "client_device_id": client_device_id.hex(),
        "device_x3dh_pub": x3dh_pub.hex(),
        "device_sign_pub": sign_pub.hex(),
        "cert_message": cert_message.hex(),
        "cert_sig": cert_sig.hex(),
    }


def gen_x3dh_vectors(det: _DetSource) -> dict:
    alice_ik = _det_priv("alice-ik")
    bob_ik = _det_priv("bob-ik")
    bob_spk = _det_priv("bob-spk")
    bob_opk = _det_priv("bob-opk")

    result = {
        "alice": {"ik_priv": dr._priv_to_bytes(alice_ik).hex(), "ik_pub": _pub_hex(alice_ik)},
        "bob": {
            "ik_priv": dr._priv_to_bytes(bob_ik).hex(), "ik_pub": _pub_hex(bob_ik),
            "spk_priv": dr._priv_to_bytes(bob_spk).hex(), "spk_pub": _pub_hex(bob_spk),
            "opk_priv": dr._priv_to_bytes(bob_opk).hex(), "opk_pub": _pub_hex(bob_opk),
        },
    }

    for name, opk_pub, opk_priv in [
        ("with_opk", bob_opk.public_key(), bob_opk),
        ("without_opk", None, None),
    ]:
        shared, ek = dr.x3dh_initiate(
            alice_ik, bob_ik.public_key(), bob_spk.public_key(), opk_pub
        )
        shared_bob = dr.x3dh_respond(
            bob_ik, bob_spk, opk_priv, alice_ik.public_key(), ek.public_key()
        )
        assert shared == shared_bob, f"X3DH mismatch ({name})"
        result[name] = {
            "ek_priv": dr._priv_to_bytes(ek).hex(),
            "ek_pub": _pub_hex(ek),
            "shared_secret": shared.hex(),
        }
    return result


def gen_x3dh_pq_vectors(det: _DetSource) -> dict:
    """PQXDH-вектор: классический X3DH-handshake + фиксированные KEM-части.

    pqpk/ct/ss — НЕ реальный ML-KEM (liboqs Kyber768 ≠ FIPS ML-KEM-768; KEM
    считает клиент на JS). Референс пиннит только byte-parity KDF-конкатенации
    km ‖ pqpk ‖ ct ‖ ss под info="vortex-pqxdh". Собственные метки ключей —
    независимы от классического x3dh-вектора.
    """
    alice_ik = _det_priv("pqxdh-alice-ik")
    bob_ik = _det_priv("pqxdh-bob-ik")
    bob_spk = _det_priv("pqxdh-bob-spk")
    bob_opk = _det_priv("pqxdh-bob-opk")

    pqpk_pub = _det_bytes_xof("pqxdh-bob-pqpk-pub", 1184)   # ML-KEM-768 pub
    kem_ct = _det_bytes_xof("pqxdh-kem-ciphertext", 1088)   # ML-KEM-768 ciphertext
    kem_ss = _det_bytes_xof("pqxdh-kem-shared", 32)         # KEM shared secret

    result = {
        "pqpk_pub": pqpk_pub.hex(),
        "kem_ciphertext": kem_ct.hex(),
        "kem_shared": kem_ss.hex(),
        "alice": {"ik_priv": dr._priv_to_bytes(alice_ik).hex(), "ik_pub": _pub_hex(alice_ik)},
        "bob": {
            "ik_priv": dr._priv_to_bytes(bob_ik).hex(), "ik_pub": _pub_hex(bob_ik),
            "spk_priv": dr._priv_to_bytes(bob_spk).hex(), "spk_pub": _pub_hex(bob_spk),
            "opk_priv": dr._priv_to_bytes(bob_opk).hex(), "opk_pub": _pub_hex(bob_opk),
        },
    }

    for name, opk_pub, opk_priv in [
        ("with_opk", bob_opk.public_key(), bob_opk),
        ("without_opk", None, None),
    ]:
        shared, ek = dr.x3dh_initiate_pq(
            alice_ik, bob_ik.public_key(), bob_spk.public_key(), opk_pub,
            pqpk_pub, kem_ct, kem_ss,
        )
        shared_bob = dr.x3dh_respond_pq(
            bob_ik, bob_spk, opk_priv, alice_ik.public_key(), ek.public_key(),
            pqpk_pub, kem_ct, kem_ss,
        )
        assert shared == shared_bob, f"PQXDH mismatch ({name})"
        result[name] = {
            "ek_priv": dr._priv_to_bytes(ek).hex(),
            "ek_pub": _pub_hex(ek),
            "shared_secret": shared.hex(),
        }
    return result


def gen_transcript(det: _DetSource, x3dh: dict) -> dict:
    """Полный двусторонний транскрипт с out-of-order доставкой и DH-шагами.

    Сценарий:
      a0..a2  alice → bob   (bob получает в порядке a0, a2, a1 — skipped keys)
      b0..b1  bob → alice   (первый DH-шаг bob)
      a3      alice → bob   (DH-шаг alice, prev_count=4)

    Чекпойнты состояний сериализуются так, чтобы каждый сегмент расшифровки
    можно было воспроизвести независимо (в т.ч. из JS): внутри сегмента
    получатель не зависит от ключей, сгенерированных им же после чекпойнта.
    """
    shared = bytes.fromhex(x3dh["with_opk"]["shared_secret"])
    bob_spk = X25519PrivateKey.from_private_bytes(bytes.fromhex(x3dh["bob"]["spk_priv"]))

    bob = dr.ratchet_init_bob(shared, bob_spk)
    alice = dr.ratchet_init_alice(shared, bob_spk.public_key())

    def _ser(state):
        """serialize_state + производный dh_sending_pub.

        Web Crypto не импортирует X25519 private как raw — только JWK, которому
        нужен публичный ключ (поле x). Публичный ключ dh_sending и так неявно
        присутствует (заголовки сообщений, X3DH) — добавляем его как удобство,
        чтобы JS мог собрать {d,x} JWK и восстановить состояние. Секрета не
        раскрывает; Python deserialize_state лишнее поле игнорирует.
        """
        d = dr.serialize_state(state)
        d["dh_sending_pub"] = (
            X25519PrivateKey.from_private_bytes(bytes.fromhex(d["dh_sending"]))
            .public_key().public_bytes_raw().hex()
        )
        return d

    checkpoints = {
        "alice_initial": _ser(alice),
        "bob_initial": _ser(bob),
    }

    messages = []

    def _send(state, actor, msg_id, text):
        header, ct = dr.ratchet_encrypt(state, text.encode("utf-8"))
        messages.append({
            "id": msg_id,
            "from": actor,
            "plaintext_utf8": text,
            "header": {
                "dh_public": header.dh_public.hex(),
                "prev_count": header.prev_count,
                "msg_number": header.msg_number,
            },
            "header_serialized": header.serialize().hex(),
            "ciphertext": ct.hex(),
        })

    _send(alice, "alice", "a0", "Привет, Боб!")
    _send(alice, "alice", "a1", "Второе сообщение")
    _send(alice, "alice", "a2", "Придёт раньше первого")
    _send(alice, "alice", "a3_same_chain", "Хвост первой цепочки")
    checkpoints["alice_before_b_replies"] = _ser(alice)

    def _recv(state, msg_id):
        m = next(m for m in messages if m["id"] == msg_id)
        header = dr.Header(
            dh_public=bytes.fromhex(m["header"]["dh_public"]),
            prev_count=m["header"]["prev_count"],
            msg_number=m["header"]["msg_number"],
        )
        plain = dr.ratchet_decrypt(state, header, bytes.fromhex(m["ciphertext"]))
        assert plain.decode("utf-8") == m["plaintext_utf8"], f"transcript self-check failed: {msg_id}"

    # Сегмент 1: bob, out-of-order (a1 приходит после a2 — из skipped keys)
    bob_delivery = ["a0", "a2", "a1", "a3_same_chain"]
    for mid in bob_delivery:
        _recv(bob, mid)

    _send(bob, "bob", "b0", "Привет, Алиса!")
    _send(bob, "bob", "b1", "Ответ во второй цепочке")
    checkpoints["bob_before_a_second_chain"] = _ser(bob)

    # Сегмент 2: alice получает ответы (её первый DH-шаг)
    alice_delivery = ["b0", "b1"]
    for mid in alice_delivery:
        _recv(alice, mid)

    _send(alice, "alice", "a4_new_chain", "Новая цепочка после DH-шага")

    # Сегмент 3: bob получает сообщение новой цепочки (его второй DH-шаг)
    _recv(bob, "a4_new_chain")

    checkpoints["alice_final"] = _ser(alice)
    checkpoints["bob_final"] = _ser(bob)

    return {
        "shared_secret": shared.hex(),
        "messages": messages,
        "segments": [
            {"receiver": "bob", "state_checkpoint": "bob_initial", "delivery_order": bob_delivery},
            {"receiver": "alice", "state_checkpoint": "alice_before_b_replies", "delivery_order": alice_delivery},
            {"receiver": "bob", "state_checkpoint": "bob_before_a_second_chain", "delivery_order": ["a4_new_chain"]},
        ],
        "checkpoints": checkpoints,
    }


def main() -> None:
    det = _DetSource()
    dr._generate_x25519_pair = det.next_priv
    _secrets_mod.token_bytes = det.next_nonce  # используется в dr._encrypt_aes_gcm

    kdf = gen_kdf_vectors()
    x3dh = gen_x3dh_vectors(det)
    # transcript ДО pqxdh — pqxdh потребляет det-ключи после, чтобы не сдвигать
    # ratchet-ключи транскрипта (нулевой churn существующих векторов).
    transcript = gen_transcript(det, x3dh)
    x3dh_pq = gen_x3dh_pq_vectors(det)
    vectors = {
        "meta": {
            "description": (
                "Cross-language Double Ratchet test vectors generated from the "
                "reference implementation app/security/double_ratchet.py. "
                "Deterministic: re-running the generator must reproduce this file "
                "byte-for-byte. Contains private keys BY DESIGN — test data only."
            ),
            "generator": "scripts/gen_dr_test_vectors.py",
            "hkdf_info_ratchet": dr._HKDF_INFO_RATCHET.decode(),
            "hkdf_info_x3dh": dr._HKDF_INFO_X3DH.decode(),
            "hkdf_info_pqxdh": dr._HKDF_INFO_PQXDH.decode(),
            "max_skip": dr.MAX_SKIP,
        },
        "kdf_ck": kdf["kdf_ck"],
        "kdf_rk": kdf["kdf_rk"],
        "header": gen_header_vectors(),
        "spk_signature": gen_spk_vector(),
        "device_cert": gen_device_cert_vector(),
        "x3dh": x3dh,
        "x3dh_pq": x3dh_pq,
        "transcript": transcript,
    }

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()

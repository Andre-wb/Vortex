"""Тесты референс-реализации Double Ratchet (app/security/double_ratchet.py).

модуль пока не используется в проде — эти тесты пиннят его как спецификацию
для будущей клиентской (JS) реализации и валидируют кросс-языковые векторы
app/tests/vectors/dr_vectors.json (генератор: scripts/gen_dr_test_vectors.py).
"""

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from app.security import double_ratchet as dr

VECTORS_PATH = Path(__file__).parent / "vectors" / "dr_vectors.json"


def _priv(hex_str: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def _pub(hex_str: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def _make_session():
    """Свежая пара состояний (alice, bob) после X3DH."""
    alice_ik = X25519PrivateKey.generate()
    bob_ik = X25519PrivateKey.generate()
    bob_spk = X25519PrivateKey.generate()

    shared, ek = dr.x3dh_initiate(alice_ik, bob_ik.public_key(), bob_spk.public_key())
    shared_bob = dr.x3dh_respond(bob_ik, bob_spk, None, alice_ik.public_key(), ek.public_key())
    assert shared == shared_bob

    alice = dr.ratchet_init_alice(shared, bob_spk.public_key())
    bob = dr.ratchet_init_bob(shared, bob_spk)
    return alice, bob


class TestSignedPreKey:
    def test_sign_and_verify(self):
        identity = Ed25519PrivateKey.generate()
        spk_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
        sig = dr.sign_spk(identity, spk_pub)
        assert dr.verify_spk_signature(identity.public_key(), spk_pub, sig)

    def test_tampered_spk_fails(self):
        identity = Ed25519PrivateKey.generate()
        spk_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
        sig = dr.sign_spk(identity, spk_pub)
        tampered = bytes([spk_pub[0] ^ 0x01]) + spk_pub[1:]
        assert not dr.verify_spk_signature(identity.public_key(), tampered, sig)

    def test_wrong_identity_fails(self):
        identity = Ed25519PrivateKey.generate()
        other = Ed25519PrivateKey.generate()
        spk_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
        sig = dr.sign_spk(identity, spk_pub)
        assert not dr.verify_spk_signature(other.public_key(), spk_pub, sig)


class TestX3DH:
    def test_shared_secret_agreement_with_opk(self):
        alice_ik = X25519PrivateKey.generate()
        bob_ik = X25519PrivateKey.generate()
        bob_spk = X25519PrivateKey.generate()
        bob_opk = X25519PrivateKey.generate()

        shared_a, ek = dr.x3dh_initiate(alice_ik, bob_ik.public_key(), bob_spk.public_key(), bob_opk.public_key())
        shared_b = dr.x3dh_respond(bob_ik, bob_spk, bob_opk, alice_ik.public_key(), ek.public_key())
        assert shared_a == shared_b
        assert len(shared_a) == 32

    def test_opk_changes_secret(self):
        """Один и тот же обмен с OPK и без даёт разные секреты."""
        alice_ik = X25519PrivateKey.generate()
        bob_ik = X25519PrivateKey.generate()
        bob_spk = X25519PrivateKey.generate()
        bob_opk = X25519PrivateKey.generate()

        # Разные эфемерные ключи генерируются внутри, поэтому сравниваем
        # через респондера с одним и тем же ek.
        shared_with, ek = dr.x3dh_initiate(alice_ik, bob_ik.public_key(), bob_spk.public_key(), bob_opk.public_key())
        shared_without = dr.x3dh_respond(bob_ik, bob_spk, None, alice_ik.public_key(), ek.public_key())
        assert shared_with != shared_without


class TestKDF:
    def test_kdf_ck_deterministic_and_separated(self):
        ck = b"\x11" * 32
        new_ck1, mk1 = dr.kdf_ck(ck)
        new_ck2, mk2 = dr.kdf_ck(ck)
        assert new_ck1 == new_ck2 and mk1 == mk2
        assert new_ck1 != mk1  # message key и chain key разделены доменом
        assert len(new_ck1) == 32 and len(mk1) == 32

    def test_kdf_rk_advances_root(self):
        rk = b"\x22" * 32
        dh_out = b"\x33" * 32
        new_rk, ck = dr.kdf_rk(rk, dh_out)
        assert new_rk != rk
        assert new_rk != ck
        assert len(new_rk) == 32 and len(ck) == 32


class TestHeader:
    def test_serialize_roundtrip(self):
        h = dr.Header(dh_public=b"\x42" * 32, prev_count=7, msg_number=13)
        data = h.serialize()
        assert len(data) == 40
        restored = dr.Header.deserialize(data)
        assert restored == h

    def test_deserialize_wrong_length_raises(self):
        with pytest.raises(ValueError):
            dr.Header.deserialize(b"\x00" * 39)


class TestRatchetConversation:
    def test_basic_roundtrip(self):
        alice, bob = _make_session()
        header, ct = dr.ratchet_encrypt(alice, "Привет, Боб!".encode())
        assert dr.ratchet_decrypt(bob, header, ct).decode() == "Привет, Боб!"

    def test_ping_pong_with_dh_steps(self):
        """Несколько раундов в обе стороны; ratchet-ключ и root меняются."""
        alice, bob = _make_session()
        seen_ratchet_pubs = set()
        roots = set()

        for i in range(3):
            h, ct = dr.ratchet_encrypt(alice, f"a{i}".encode())
            assert dr.ratchet_decrypt(bob, h, ct) == f"a{i}".encode()
            seen_ratchet_pubs.add(h.dh_public)
            roots.add(bob.root_key)

            h, ct = dr.ratchet_encrypt(bob, f"b{i}".encode())
            assert dr.ratchet_decrypt(alice, h, ct) == f"b{i}".encode()
            seen_ratchet_pubs.add(h.dh_public)
            roots.add(alice.root_key)

        # Каждый разворот направления — DH-шаг: новые ratchet-ключи и root'ы
        assert len(seen_ratchet_pubs) == 6
        assert len(roots) == 6

    def test_out_of_order_via_skipped_keys(self):
        alice, bob = _make_session()
        msgs = [dr.ratchet_encrypt(alice, f"m{i}".encode()) for i in range(3)]

        # m2 приходит первым — ключи m0, m1 кэшируются
        h2, ct2 = msgs[2]
        assert dr.ratchet_decrypt(bob, h2, ct2) == b"m2"
        assert len(bob.skipped_keys) == 2

        h0, ct0 = msgs[0]
        h1, ct1 = msgs[1]
        assert dr.ratchet_decrypt(bob, h0, ct0) == b"m0"
        assert dr.ratchet_decrypt(bob, h1, ct1) == b"m1"
        assert len(bob.skipped_keys) == 0

    def test_max_skip_overflow(self):
        alice, bob = _make_session()
        h, ct = dr.ratchet_encrypt(alice, b"first")
        dr.ratchet_decrypt(bob, h, ct)

        fake = dr.Header(
            dh_public=h.dh_public,
            prev_count=h.prev_count,
            msg_number=bob.recv_count + dr.MAX_SKIP + 1,
        )
        with pytest.raises(OverflowError):
            dr.ratchet_decrypt(bob, fake, b"\x00" * 28)

    def test_replay_rejected(self):
        """Повторная расшифровка того же сообщения невозможна (ключ удалён)."""
        alice, bob = _make_session()
        h, ct = dr.ratchet_encrypt(alice, b"once")
        assert dr.ratchet_decrypt(bob, h, ct) == b"once"
        with pytest.raises(InvalidTag):
            dr.ratchet_decrypt(bob, h, ct)

    def test_tampered_ciphertext_rejected(self):
        alice, bob = _make_session()
        h, ct = dr.ratchet_encrypt(alice, b"secret")
        tampered = ct[:-1] + bytes([ct[-1] ^ 0x01])
        with pytest.raises(InvalidTag):
            dr.ratchet_decrypt(bob, h, tampered)

    def test_tampered_header_rejected(self):
        """Header — AAD: подмена счётчика ломает аутентификацию."""
        alice, bob = _make_session()
        h, ct = dr.ratchet_encrypt(alice, b"secret")
        forged = dr.Header(dh_public=h.dh_public, prev_count=h.prev_count + 1, msg_number=h.msg_number)
        with pytest.raises(InvalidTag):
            dr.ratchet_decrypt(bob, forged, ct)


class TestBreakInRecovery:
    """Post-compromise security: снапшот состояния перестаёт читать переписку
    после того, как скомпрометированная сторона сделала DH-шаг с новой
    случайностью. Ровно то свойство, которого нет у прод-схемы v1
    (static/js/crypto.js: цепочка выводима из постоянного roomKey)."""

    def test_snapshot_loses_access_after_dh_step(self):
        alice, bob = _make_session()

        # a0: alice → bob
        h, ct = dr.ratchet_encrypt(alice, b"a0")
        dr.ratchet_decrypt(bob, h, ct)

        # Атакующий снимает полное состояние bob (serialize → deep copy)
        stolen = dr.deserialize_state(dr.serialize_state(bob))

        # Переписка продолжается: bob отвечает (его ratchet-ключ пока тот же,
        # что в снапшоте), alice делает DH-шаг и шлёт a1
        h, ct = dr.ratchet_encrypt(bob, b"b0")
        dr.ratchet_decrypt(alice, h, ct)
        h_a1, ct_a1 = dr.ratchet_encrypt(alice, b"a1")

        # До восстановления снапшот ещё читает (новой случайности у bob не было)
        assert dr.ratchet_decrypt(stolen, h_a1, ct_a1) == b"a1"
        dr.ratchet_decrypt(bob, h_a1, ct_a1)

        # Recovery: bob делает DH-шаг (новый случайный ratchet-ключ), alice
        # ратчетится на него и шлёт a2
        h, ct = dr.ratchet_encrypt(bob, b"b1")
        dr.ratchet_decrypt(alice, h, ct)
        h_a2, ct_a2 = dr.ratchet_encrypt(alice, b"a2")

        # Настоящий bob читает, снапшот — уже нет
        assert dr.ratchet_decrypt(bob, h_a2, ct_a2) == b"a2"
        with pytest.raises(InvalidTag):
            dr.ratchet_decrypt(stolen, h_a2, ct_a2)


class TestStateSerialization:
    def test_roundtrip_mid_conversation_with_skipped_keys(self):
        alice, bob = _make_session()
        msgs = [dr.ratchet_encrypt(alice, f"m{i}".encode()) for i in range(3)]

        h2, ct2 = msgs[2]
        dr.ratchet_decrypt(bob, h2, ct2)  # m0, m1 → skipped_keys

        restored = dr.deserialize_state(dr.serialize_state(bob))
        assert dr.serialize_state(restored) == dr.serialize_state(bob)

        h0, ct0 = msgs[0]
        h1, ct1 = msgs[1]
        assert dr.ratchet_decrypt(restored, h0, ct0) == b"m0"
        assert dr.ratchet_decrypt(restored, h1, ct1) == b"m1"

    def test_restored_state_continues_conversation(self):
        alice, bob = _make_session()
        h, ct = dr.ratchet_encrypt(alice, b"before")
        dr.ratchet_decrypt(bob, h, ct)

        bob2 = dr.deserialize_state(dr.serialize_state(bob))
        h, ct = dr.ratchet_encrypt(bob2, b"reply")
        assert dr.ratchet_decrypt(alice, h, ct) == b"reply"


class TestVectors:
    """Валидация кросс-языковых векторов: Python-референс обязан
    воспроизводить их. Позже добавится зеркальная проверка из JS."""

    @pytest.fixture(scope="class")
    def vectors(self):
        assert VECTORS_PATH.exists(), f"{VECTORS_PATH} отсутствует — сгенерируй: python scripts/gen_dr_test_vectors.py"
        return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    def test_kdf_ck_vectors(self, vectors):
        for v in vectors["kdf_ck"]:
            new_ck, mk = dr.kdf_ck(bytes.fromhex(v["ck"]))
            assert new_ck.hex() == v["new_ck"]
            assert mk.hex() == v["mk"]

    def test_kdf_rk_vectors(self, vectors):
        for v in vectors["kdf_rk"]:
            new_rk, new_ck = dr.kdf_rk(bytes.fromhex(v["rk"]), bytes.fromhex(v["dh_out"]))
            assert new_rk.hex() == v["new_rk"]
            assert new_ck.hex() == v["new_ck"]

    def test_header_vectors(self, vectors):
        for v in vectors["header"]:
            h = dr.Header(
                dh_public=bytes.fromhex(v["dh_public"]),
                prev_count=v["prev_count"],
                msg_number=v["msg_number"],
            )
            assert h.serialize().hex() == v["serialized"]
            assert dr.Header.deserialize(bytes.fromhex(v["serialized"])) == h

    def test_spk_signature_vector(self, vectors):
        v = vectors["spk_signature"]
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["ed25519_pub"]))
        assert dr.verify_spk_signature(pub, bytes.fromhex(v["spk_pub"]), bytes.fromhex(v["signature"]))

    def test_device_cert_vector(self, vectors):
        """Byte-parity cert'а: раскладка cert-сообщения (cid‖x3dh‖sign) и подпись
        аккаунтного Ed25519 должны сойтись — то же самое проверяет JS (verifyDeviceCert)."""
        v = vectors["device_cert"]
        cid = bytes.fromhex(v["client_device_id"])
        x3dh = bytes.fromhex(v["device_x3dh_pub"])
        sign = bytes.fromhex(v["device_sign_pub"])
        # Раскладка cert-сообщения: client_device_id(16) ‖ x3dh(32) ‖ sign(32) = 80
        assert len(cid) == 16 and len(x3dh) == 32 and len(sign) == 32
        cert_message = cid + x3dh + sign
        assert cert_message.hex() == v["cert_message"]
        # Подпись аккаунтного Ed25519 над cert-сообщением
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["account_ed_pub"]))
        pub.verify(bytes.fromhex(v["cert_sig"]), cert_message)  # не бросает → валидна

    def test_x3dh_vectors(self, vectors):
        x = vectors["x3dh"]
        bob_ik = _priv(x["bob"]["ik_priv"])
        bob_spk = _priv(x["bob"]["spk_priv"])
        alice_ik_pub = _pub(x["alice"]["ik_pub"])

        for name, opk in [("with_opk", _priv(x["bob"]["opk_priv"])), ("without_opk", None)]:
            shared = dr.x3dh_respond(bob_ik, bob_spk, opk, alice_ik_pub, _pub(x[name]["ek_pub"]))
            assert shared.hex() == x[name]["shared_secret"], name

    def test_x3dh_pq_vectors(self, vectors):
        """PQXDH byte-parity: respond_pq воспроизводит shared_secret из вектора
        (KEM-части фиксированы — тот же km‖pqpk‖ct‖ss обязан дать JS)."""
        x = vectors["x3dh_pq"]
        bob_ik = _priv(x["bob"]["ik_priv"])
        bob_spk = _priv(x["bob"]["spk_priv"])
        alice_ik_pub = _pub(x["alice"]["ik_pub"])
        pqpk = bytes.fromhex(x["pqpk_pub"])
        ct = bytes.fromhex(x["kem_ciphertext"])
        ss = bytes.fromhex(x["kem_shared"])

        for name, opk in [("with_opk", _priv(x["bob"]["opk_priv"])), ("without_opk", None)]:
            shared = dr.x3dh_respond_pq(
                bob_ik,
                bob_spk,
                opk,
                alice_ik_pub,
                _pub(x[name]["ek_pub"]),
                pqpk,
                ct,
                ss,
            )
            assert shared.hex() == x[name]["shared_secret"], name

    def test_x3dh_pq_domain_separation(self, vectors):
        """PQXDH info домен-сепарирует: та же km-часть под классическим X3DH
        (без KEM) даёт другой ключ — треки не коллизят."""
        x = vectors["x3dh_pq"]
        bob_ik = _priv(x["bob"]["ik_priv"])
        bob_spk = _priv(x["bob"]["spk_priv"])
        alice_ik_pub = _pub(x["alice"]["ik_pub"])
        classical = dr.x3dh_respond(bob_ik, bob_spk, None, alice_ik_pub, _pub(x["without_opk"]["ek_pub"]))
        assert classical.hex() != x["without_opk"]["shared_secret"]

    def test_transcript_segments_decrypt(self, vectors):
        """Каждый сегмент транскрипта расшифровывается из своего чекпойнта.

        Покрывает: out-of-order (skipped keys), оба DH-шага и восстановление
        состояния из сериализованного вида — тот же протокол воспроизведения,
        который будет использовать JS-реализация.
        """
        t = vectors["transcript"]
        by_id = {m["id"]: m for m in t["messages"]}

        for segment in t["segments"]:
            state = dr.deserialize_state(t["checkpoints"][segment["state_checkpoint"]])
            for msg_id in segment["delivery_order"]:
                m = by_id[msg_id]
                header = dr.Header.deserialize(bytes.fromhex(m["header_serialized"]))
                plain = dr.ratchet_decrypt(state, header, bytes.fromhex(m["ciphertext"]))
                assert plain.decode("utf-8") == m["plaintext_utf8"], msg_id

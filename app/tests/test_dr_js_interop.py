"""Interop-тест JS→Python для Double Ratchet.

Запускает node-продюсер (scripts/dr_js_producer.mjs), где JS-Alice шифрует
сообщение клиентской реализацией (static/js/dr/*), и расшифровывает его
Python-референсом (app/security/double_ratchet.py). Дополняет обратное
направление (Python→JS проверяется в static/js/__tests__/dr-ratchet.test.js),
закрывая DoD «в обе стороны».

Пропускается, если node недоступен.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.security import double_ratchet as dr

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "scripts" / "dr_js_producer.mjs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node недоступен")


@pytest.fixture(scope="module")
def js_message():
    proc = subprocess.run(
        ["node", str(PRODUCER)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=60,
    )
    assert proc.returncode == 0, f"node producer failed: {proc.stderr}"
    return json.loads(proc.stdout)


def _bob_from(js):
    shared = bytes.fromhex(js["shared_hex"])
    bob_spk = X25519PrivateKey.from_private_bytes(bytes.fromhex(js["bob_spk_priv_hex"]))
    return dr.ratchet_init_bob(shared, bob_spk)


def _header(js):
    return dr.Header(
        dh_public=bytes.fromhex(js["header"]["dh_public"]),
        prev_count=js["header"]["prev_count"],
        msg_number=js["header"]["msg_number"],
    )


def test_python_decrypts_js_ciphertext(js_message):
    """Python-Bob расшифровывает сообщение, зашифрованное JS-Alice."""
    bob = _bob_from(js_message)
    plain = dr.ratchet_decrypt(bob, _header(js_message), bytes.fromhex(js_message["ciphertext_hex"]))
    assert plain.decode("utf-8") == js_message["plaintext"]


def test_tampered_js_ciphertext_rejected(js_message):
    """Порча JS-шифртекста ломает аутентификацию на Python-стороне."""
    bob = _bob_from(js_message)
    ct = bytearray.fromhex(js_message["ciphertext_hex"])
    ct[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        dr.ratchet_decrypt(bob, _header(js_message), bytes(ct))

// scripts/dr_js_producer.mjs
// Продюсер для interop-теста JS→Python (ADR-001, батч 5): JS-Alice шифрует
// сообщение, печатает всё, что нужно Python-Bob для расшифровки. Запускается
// из app/tests/test_dr_js_interop.py. Требует Node ≥20 (globalThis.crypto).

import { generateX25519, exportX25519PrivHex, toHex } from '../static/js/dr/primitives.js';
import { ratchetInitAlice, ratchetInitBob, ratchetEncrypt } from '../static/js/dr/ratchet.js';

const PLAINTEXT = 'JS→Python interop ✓ Тест';

const bobSpk = await generateX25519();
const shared = globalThis.crypto.getRandomValues(new Uint8Array(32));

const alice = await ratchetInitAlice(shared, bobSpk.pubHex);
// bob создаётся только чтобы подтвердить симметрию; Python восстановит своё.
ratchetInitBob(shared, bobSpk.priv, bobSpk.pubHex);

const msg = await ratchetEncrypt(alice, new TextEncoder().encode(PLAINTEXT));

process.stdout.write(JSON.stringify({
    shared_hex: toHex(shared),
    bob_spk_priv_hex: await exportX25519PrivHex(bobSpk.priv),
    bob_spk_pub_hex: bobSpk.pubHex,
    header: {
        dh_public: msg.header.dhPublicHex,
        prev_count: msg.header.prevCount,
        msg_number: msg.header.msgNumber,
    },
    ciphertext_hex: toHex(msg.ciphertext),
    plaintext: PLAINTEXT,
}));

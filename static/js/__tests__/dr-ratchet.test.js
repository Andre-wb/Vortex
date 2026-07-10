/**
 * dr-ratchet.test.js
 * Паритет JS Double Ratchet с Python-референсом (ADR-001, батч 5).
 * Векторы: app/tests/vectors/dr_vectors.json (сгенерированы double_ratchet.py).
 * Проверяет KDF, X3DH, Header, полный транскрипт (out-of-order + DH-шаги),
 * сериализацию и JS-внутренние round-trip'ы.
 */

const fs = require('fs');
const path = require('path');

const P = require('../dr/primitives.js');
const { x3dhInitiate, x3dhRespond } = require('../dr/x3dh.js');
const R = require('../dr/ratchet.js');

const vectors = JSON.parse(fs.readFileSync(
    path.resolve(__dirname, '../../../app/tests/vectors/dr_vectors.json'), 'utf8'
));

const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);

// Примитивы KDF/Header — прямая сверка байтов

describe('KDF parity', () => {
    test('kdf_ck совпадает с векторами (сырой HMAC 0x01/0x02)', async () => {
        for (const v of vectors.kdf_ck) {
            const { newCk, mk } = await P.kdfCk(P.fromHex(v.ck));
            expect(P.toHex(newCk)).toBe(v.new_ck);
            expect(P.toHex(mk)).toBe(v.mk);
        }
    });

    test('kdf_rk совпадает с векторами (HKDF salt=rk, ikm=dh_out, 64 байта)', async () => {
        for (const v of vectors.kdf_rk) {
            const { rootKey, chainKey } = await P.kdfRk(P.fromHex(v.rk), P.fromHex(v.dh_out));
            expect(P.toHex(rootKey)).toBe(v.new_rk);
            expect(P.toHex(chainKey)).toBe(v.new_ck);
        }
    });
});

describe('Header parity', () => {
    test('serializeHeader даёт те же 40 байт', () => {
        for (const v of vectors.header) {
            const bytes = P.serializeHeader({
                dhPublicHex: v.dh_public, prevCount: v.prev_count, msgNumber: v.msg_number,
            });
            expect(P.toHex(bytes)).toBe(v.serialized);
        }
    });
});

// X3DH — сверка shared secret

describe('X3DH parity', () => {
    test('respond воспроизводит shared_secret из вектора (with_opk и without_opk)', async () => {
        const x = vectors.x3dh;
        const bobIk = await P.importX25519Priv(x.bob.ik_priv, x.bob.ik_pub);
        const bobSpk = await P.importX25519Priv(x.bob.spk_priv, x.bob.spk_pub);
        const bobOpk = await P.importX25519Priv(x.bob.opk_priv, x.bob.opk_pub);

        const withOpk = await x3dhRespond(bobIk, bobSpk, bobOpk, x.alice.ik_pub, x.with_opk.ek_pub);
        expect(P.toHex(withOpk)).toBe(x.with_opk.shared_secret);

        const withoutOpk = await x3dhRespond(bobIk, bobSpk, null, x.alice.ik_pub, x.without_opk.ek_pub);
        expect(P.toHex(withoutOpk)).toBe(x.without_opk.shared_secret);
    });

    test('JS initiate ↔ JS respond согласуются (live round-trip)', async () => {
        const bobIk = await P.generateX25519();
        const bobSpk = await P.generateX25519();
        const bobOpk = await P.generateX25519();
        const aliceIk = await P.generateX25519();

        const { sharedSecret, ekPubHex } = await x3dhInitiate(
            aliceIk.priv, bobIk.pubHex, bobSpk.pubHex, bobOpk.pubHex,
        );
        const bobShared = await x3dhRespond(
            bobIk.priv, bobSpk.priv, bobOpk.priv, aliceIk.pubHex, ekPubHex,
        );
        expect(P.toHex(bobShared)).toBe(P.toHex(sharedSecret));
    });
});

// Транскрипт: JS расшифровывает шифртексты, созданные Python

describe('Transcript parity (JS decrypts Python ciphertexts)', () => {
    const t = vectors.transcript;
    const byId = Object.fromEntries(t.messages.map(m => [m.id, m]));

    test('каждый сегмент расшифровывается из своего чекпойнта', async () => {
        for (const segment of t.segments) {
            const state = await R.deserializeState(t.checkpoints[segment.state_checkpoint]);
            for (const msgId of segment.delivery_order) {
                const m = byId[msgId];
                const header = {
                    dhPublicHex: m.header.dh_public,
                    prevCount: m.header.prev_count,
                    msgNumber: m.header.msg_number,
                };
                const plain = await R.ratchetDecrypt(state, header, P.fromHex(m.ciphertext));
                expect(dec(plain)).toBe(m.plaintext_utf8);
            }
        }
    });
});

// JS ↔ JS полный диалог (encrypt+decrypt+DH-шаги+out-of-order)

describe('JS ratchet round-trip', () => {
    async function makeSession() {
        const bobSpk = await P.generateX25519();
        const shared = globalThis.crypto.getRandomValues(new Uint8Array(32));
        const alice = await R.ratchetInitAlice(shared, bobSpk.pubHex);
        const bob = R.ratchetInitBob(shared, bobSpk.priv, bobSpk.pubHex);
        return { alice, bob };
    }

    test('базовый обмен в обе стороны с DH-шагами', async () => {
        const { alice, bob } = await makeSession();
        for (let i = 0; i < 3; i++) {
            const a = await R.ratchetEncrypt(alice, enc(`a${i}`));
            expect(dec(await R.ratchetDecrypt(bob, a.header, a.ciphertext))).toBe(`a${i}`);
            const b = await R.ratchetEncrypt(bob, enc(`b${i}`));
            expect(dec(await R.ratchetDecrypt(alice, b.header, b.ciphertext))).toBe(`b${i}`);
        }
    });

    test('out-of-order доставка через skipped keys', async () => {
        const { alice, bob } = await makeSession();
        const msgs = [];
        for (let i = 0; i < 3; i++) msgs.push(await R.ratchetEncrypt(alice, enc(`m${i}`)));
        // m2 приходит первым
        expect(dec(await R.ratchetDecrypt(bob, msgs[2].header, msgs[2].ciphertext))).toBe('m2');
        expect(bob.skipped.size).toBe(2);
        expect(dec(await R.ratchetDecrypt(bob, msgs[0].header, msgs[0].ciphertext))).toBe('m0');
        expect(dec(await R.ratchetDecrypt(bob, msgs[1].header, msgs[1].ciphertext))).toBe('m1');
        expect(bob.skipped.size).toBe(0);
    });

    test('повреждённый шифртекст отвергается (InvalidTag)', async () => {
        const { alice, bob } = await makeSession();
        const a = await R.ratchetEncrypt(alice, enc('secret'));
        a.ciphertext[a.ciphertext.length - 1] ^= 0x01;
        await expect(R.ratchetDecrypt(bob, a.header, a.ciphertext)).rejects.toThrow();
    });

    test('превышение MAX_SKIP бросает', async () => {
        const { alice, bob } = await makeSession();
        const a = await R.ratchetEncrypt(alice, enc('first'));
        await R.ratchetDecrypt(bob, a.header, a.ciphertext);
        const forged = { dhPublicHex: a.header.dhPublicHex, prevCount: a.header.prevCount, msgNumber: bob.recvCount + R.MAX_SKIP + 1 };
        await expect(R.ratchetDecrypt(bob, forged, new Uint8Array(28))).rejects.toThrow();
    });
});

// Сериализация состояния

describe('State serialization', () => {
    test('JS serialize → deserialize сохраняет способность расшифровывать', async () => {
        const bobSpk = await P.generateX25519();
        const shared = globalThis.crypto.getRandomValues(new Uint8Array(32));
        const alice = await R.ratchetInitAlice(shared, bobSpk.pubHex);
        const bob = R.ratchetInitBob(shared, bobSpk.priv, bobSpk.pubHex);

        const a = await R.ratchetEncrypt(alice, enc('before reload'));
        // "перезапуск контекста" bob: сериализуем и восстанавливаем
        const restored = await R.deserializeState(await R.serializeState(bob));
        expect(dec(await R.ratchetDecrypt(restored, a.header, a.ciphertext))).toBe('before reload');
    });

    test('JS serialize даёт dh_sending (raw hex) — совместимо с Python-форматом', async () => {
        const bobSpk = await P.generateX25519();
        const shared = globalThis.crypto.getRandomValues(new Uint8Array(32));
        const alice = await R.ratchetInitAlice(shared, bobSpk.pubHex);
        const s = await R.serializeState(alice);
        expect(s.dh_sending).toMatch(/^[0-9a-f]{64}$/);       // raw 32 байта (как Python)
        expect(s.dh_sending_pub).toMatch(/^[0-9a-f]{64}$/);   // доп. поле для JS
    });
});

/**
 * crypto-hybrid.test.js
 * K3: гибридная обёртка X25519 + ML-KEM-768 (ADR-004). Round-trip между
 * РАЗДЕЛЬНЫМИ сторонами (отправитель знает только pub получателя; получатель —
 * только свой priv — same-instance ничего не доказывает). Классический fallback
 * (нет Kyber-pub → X25519-only). Неверный Kyber-priv → AEAD-провал.
 */

const { hybridEciesEncrypt, hybridEciesDecrypt } = require('../crypto.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

/** Получатель: X25519 пара (pub hex + priv JWK) + Kyber пара. */
async function makeRecipient() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const x25519PubHex = toHex(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
    const x25519PrivJwk = JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey));
    const kyber = mlkemKeygen();
    return { x25519PubHex, x25519PrivJwk, kyberPubHex: kyber.publicKeyHex, kyberPrivHex: kyber.secretKeyHex };
}

const DATA = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);   // «комнатный ключ»

test('гибрид round-trip: отправитель→конверт, ДРУГАЯ сторона расшифровывает', async () => {
    const rx = await makeRecipient();
    // Отправитель: только ПУБЛИЧНЫЕ ключи получателя
    const env = await hybridEciesEncrypt(DATA, rx.x25519PubHex, rx.kyberPubHex);
    expect(env.hybrid).toBe(true);
    expect(env.kyber_ciphertext).toMatch(/^[0-9a-f]{2176}$/);           // ML-KEM ct = 1088 байт
    expect(env.x25519_ephemeral_pub).toMatch(/^[0-9a-f]{64}$/);        // X25519 32 байта

    // Получатель: только СВОИ приватные
    const out = await hybridEciesDecrypt(env, rx.x25519PrivJwk, rx.kyberPrivHex);
    expect(Array.from(out)).toEqual(Array.from(DATA));
});

test('классический fallback: нет Kyber-pub → X25519-only конверт (без v)', async () => {
    const rx = await makeRecipient();
    const env = await hybridEciesEncrypt(DATA, rx.x25519PubHex, null);
    expect(env.hybrid).toBeUndefined();
    expect(env.kyber_ciphertext).toBeUndefined();
    // Расшифровка через ту же гибрид-функцию (роутинг по конверту) без Kyber-priv
    const out = await hybridEciesDecrypt(env, rx.x25519PrivJwk, null);
    expect(Array.from(out)).toEqual(Array.from(DATA));
});

test('неверный Kyber-priv → расшифровка падает (kyber_shared другой, AEAD InvalidTag)', async () => {
    const rx = await makeRecipient();
    const env = await hybridEciesEncrypt(DATA, rx.x25519PubHex, rx.kyberPubHex);
    const eve = mlkemKeygen();   // чужой Kyber-приватный
    await expect(hybridEciesDecrypt(env, rx.x25519PrivJwk, eve.secretKeyHex)).rejects.toBeTruthy();
});

test('неверный X25519-priv → расшифровка падает', async () => {
    const rx = await makeRecipient();
    const env = await hybridEciesEncrypt(DATA, rx.x25519PubHex, rx.kyberPubHex);
    const other = await makeRecipient();   // чужой X25519-приватный
    await expect(hybridEciesDecrypt(env, other.x25519PrivJwk, rx.kyberPrivHex)).rejects.toBeTruthy();
});

test('гибрид-конверт без Kyber-priv на приёме → явная ошибка', async () => {
    const rx = await makeRecipient();
    const env = await hybridEciesEncrypt(DATA, rx.x25519PubHex, rx.kyberPubHex);
    await expect(hybridEciesDecrypt(env, rx.x25519PrivJwk, null)).rejects.toThrow(/Kyber private/);
});

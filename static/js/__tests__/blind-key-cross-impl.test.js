/**
 * blind-key-cross-impl.test.js
 * Кросс-реализационный пин (корень бага): Python-сервер шифрует blind-key через
 * ecies_encrypt_for_client → браузер расшифровывает через decryptRoomKeyEnvelope
 * (ровно то, что делает zk-crypto.js:92). Доказывает ЭМПИРИЧЕСКИ, что client-диалект
 * совпадает МЕЖДУ рантаймами: Python HKDF salt=None == WebCrypto salt=Uint8Array(0).
 * Раньше сервер слал node-диалект (salt=sorted) → InvalidTag → фича тихо мертва.
 *
 * Вектор сгенерирован app/security/key_exchange.py:ecies_encrypt_for_client с
 * ДЕТЕРМИНИРОВАННЫМ recipient priv = байты 00 01 .. 1f (тестовые данные).
 */

const { decryptRoomKeyEnvelope } = require('../crypto.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

// ── Вектор из Python (ecies_encrypt_for_client, recipient priv = 00..1f) ──
const RECIPIENT_JWK = JSON.stringify({
    kty: 'OKP', crv: 'X25519',
    d: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    x: 'j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8',
});
const EPHEMERAL_PUB = 'a823d92040abd1a5de3b3b3821ea2f3ffe89170b0ba2d2ea64b2acf5dbe6632b';
const CIPHERTEXT = 'ffa2e79bff4b5fc6d06848130c31e13195abf47895280ec7b7805db7a7fb710bd81e5ec330492145ae842e4eeb1247bb88647f97a262a26be2b8a2a4';
const PLAINTEXT_HEX = '5a4b2d424c494e442d4b45592d63726f73732d696d706c2d766563746f722121';

beforeEach(() => {
    window.AppState = { user: {} };   // classical-конверт Kyber не требует
});

test('Python ecies_encrypt_for_client → JS decryptRoomKeyEnvelope (salt=None == WebCrypto пусто)', async () => {
    const env = { ephemeral_pub: EPHEMERAL_PUB, ciphertext: CIPHERTEXT };
    const decrypted = await decryptRoomKeyEnvelope(env, RECIPIENT_JWK);
    expect(toHex(decrypted)).toBe(PLAINTEXT_HEX);
});

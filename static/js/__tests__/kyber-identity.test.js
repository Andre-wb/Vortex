/**
 * kyber-identity.test.js
 * K2: аккаунтная ML-KEM-768 идентичность — client keygen, load-only (не форкается),
 * `_enc`-персистенция через logout, подпись pub аккаунтным Ed25519.
 * Зеркалит дисциплину аккаунтного Ed25519 (0-bis).
 */

const {
    loadKyberIdentity, loadOrCreateKyberIdentity, signKyberPub,
} = require('../dr/kyber-identity.js');
const { mlkemGetPublic } = require('../dr/mlkem.js');
const { saveKyberEnc, restoreKyberEnc } = require('../dr/identity-persist.js');
const { loadOrCreateEd25519Identity } = require('../dr/prekeys.js');

const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function verifyEd25519(pubHex, msgBytes, sigHex) {
    const key = await globalThis.crypto.subtle.importKey('raw', fromHex(pubHex), { name: 'Ed25519' }, false, ['verify']);
    return globalThis.crypto.subtle.verify('Ed25519', key, fromHex(sigHex), msgBytes);
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState = { user: { user_id: 7 } };
});

test('load-only: без ключа возвращает null (НЕ генерирует)', () => {
    expect(loadKyberIdentity(7)).toBeNull();
    expect(localStorage.getItem('vortex_kyber_priv_7')).toBeNull();
});

test('loadOrCreate генерирует пару; pub выводится из приватного', () => {
    const id = loadOrCreateKyberIdentity(7);
    expect(id.privHex).toMatch(/^[0-9a-f]{4800}$/);   // 2400 байт
    expect(id.pubHex).toMatch(/^[0-9a-f]{2368}$/);    // 1184 байта
    expect(mlkemGetPublic(id.privHex)).toBe(id.pubHex);
    expect(localStorage.getItem('vortex_kyber_priv_7')).toBe(id.privHex);
});

test('повторный load возвращает ту же идентичность (не форкается)', () => {
    const a = loadOrCreateKyberIdentity(7);
    const b = loadKyberIdentity(7);
    expect(b.privHex).toBe(a.privHex);
    expect(b.pubHex).toBe(a.pubHex);
});

test('разные аккаунты — разные идентичности', () => {
    window.AppState.user.user_id = 1;
    const a = loadOrCreateKyberIdentity(1);
    window.AppState.user.user_id = 2;
    const b = loadOrCreateKyberIdentity(2);
    expect(b.privHex).not.toBe(a.privHex);
});

test('_enc переживает logout, не форкается; restore даёт тот же приватный', async () => {
    const id = loadOrCreateKyberIdentity(7);
    await saveKyberEnc(7, 'Str0ng_pw!');

    // Симулируем logout: чистим плейнтекст, `_enc` остаётся
    localStorage.removeItem('vortex_kyber_priv_7');
    sessionStorage.removeItem('vortex_kyber_priv_7');
    expect(loadKyberIdentity(7)).toBeNull();   // load-only: НЕ форкается на новую

    // На логине restore по паролю возвращает ТОТ ЖЕ приватный
    expect(await restoreKyberEnc(7, 'Str0ng_pw!')).toBe(true);
    expect(loadKyberIdentity(7).privHex).toBe(id.privHex);
});

test('_enc restore с неверным паролем — провал, без порчи', async () => {
    loadOrCreateKyberIdentity(7);
    await saveKyberEnc(7, 'right_pw');
    localStorage.removeItem('vortex_kyber_priv_7');
    sessionStorage.removeItem('vortex_kyber_priv_7');
    expect(await restoreKyberEnc(7, 'wrong_pw')).toBe(false);
    expect(loadKyberIdentity(7)).toBeNull();
});

test('signKyberPub: подпись проверяется аккаунтным Ed25519', async () => {
    const kyber = loadOrCreateKyberIdentity(7);
    const ed = await loadOrCreateEd25519Identity();   // аккаунтный Ed25519
    const sig = await signKyberPub(kyber.pubHex, ed.privJwk);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(await verifyEd25519(ed.pubHex, fromHex(kyber.pubHex), sig)).toBe(true);
    // порча pub → подпись не сходится
    const badPub = kyber.pubHex.slice(0, -2) + (kyber.pubHex.endsWith('00') ? '01' : '00');
    expect(await verifyEd25519(ed.pubHex, fromHex(badPub), sig)).toBe(false);
});

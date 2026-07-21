/**
 * key-login-proof-cross-impl.test.js
 * Кросс-реализационный пин /api/authentication/login-key: клиентский
 * _computeKeyLoginProof (auth.js) ОБЯЗАН совпасть с серверным
 * HMAC(derive_x25519_session_key(server_priv, client_pub), challenge) (key_login.py:90-97).
 *
 * Вектор сгенерирован из РЕАЛЬНОГО серверного derive_x25519_session_key+HMAC
 * (client priv = 00..1f, server priv = 20..3f). Раньше клиент HMAC'ил СЫРОЙ DH
 * (без HKDF-шага) → proof не сходился → /login-key был тихо мёртв (не тестировался
 * кросс-реализационно). login salt=sorted — КОРРЕКТНЫЙ mutual-handshake диалект.
 */

const { _computeKeyLoginProof } = require('../auth.js');

const CLIENT_JWK = JSON.stringify({
    kty: 'OKP', crv: 'X25519',
    d: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    x: 'j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8',
});
const SERVER_PUB = '358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254';
const CHALLENGE = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const EXPECTED = 'a919ce4b6cea1f96c41912a1d5f40f6a258a77df609f3f356e30ec82be5c980d';

test('_computeKeyLoginProof совпадает с серверным derive+HMAC (кросс-рантайм)', async () => {
    expect(await _computeKeyLoginProof(CLIENT_JWK, SERVER_PUB, CHALLENGE)).toBe(EXPECTED);
});

test('регрессия: СЫРОЙ DH (старый баг, без HKDF) даёт ДРУГОЙ proof', async () => {
    // Воспроизводим прежнюю клиентскую логику: HMAC над сырым X25519 DH.
    const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));
    const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
    const priv = await crypto.subtle.importKey('jwk', JSON.parse(CLIENT_JWK), { name: 'X25519' }, false, ['deriveBits']);
    const serverPub = await crypto.subtle.importKey('raw', fromHex(SERVER_PUB), { name: 'X25519' }, false, []);
    const rawDH = await crypto.subtle.deriveBits({ name: 'X25519', public: serverPub }, priv, 256);
    const hmacKey = await crypto.subtle.importKey('raw', rawDH, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const rawProof = toHex(await crypto.subtle.sign('HMAC', hmacKey, fromHex(CHALLENGE)));
    expect(rawProof).not.toBe(EXPECTED);   // именно это расхождение делало /login-key мёртвым
});

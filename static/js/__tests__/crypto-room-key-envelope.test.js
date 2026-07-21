/**
 * crypto-room-key-envelope.test.js
 * K4b: приём комнатного ключа — decryptRoomKeyEnvelope понимает ОБЕ формы конверта
 * (классику и гибрид) всегда-вкл, подхватывая аккаунтный Kyber-priv текущего
 * пользователя для гибрид-конверта. Классику разворачивает без Kyber/AppState.
 */

const { decryptRoomKeyEnvelope, hybridEciesEncrypt, eciesEncrypt } = require('../crypto.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

async function makeX25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubHex = toHex(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
    const privJwk = JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey));
    return { pubHex, privJwk };
}

const DATA = new Uint8Array(32).map((_, i) => (i * 5 + 1) & 0xff);   // «комнатный ключ»

afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState.user = {};
});

test('классический конверт → расшифровка без Kyber и без AppState', async () => {
    const x = await makeX25519();
    const env = await eciesEncrypt(DATA, x.pubHex);        // {ephemeral_pub, ciphertext}
    const out = await decryptRoomKeyEnvelope(env, x.privJwk);
    expect(Array.from(out)).toEqual(Array.from(DATA));
});

test('гибрид → берёт Kyber-priv текущего пользователя из его слота', async () => {
    const uid = 42;
    const kyber = mlkemKeygen();
    window.AppState.user = { user_id: uid };
    localStorage.setItem(`vortex_kyber_priv_${uid}`, kyber.secretKeyHex);

    const x = await makeX25519();
    const env = await hybridEciesEncrypt(DATA, x.pubHex, kyber.publicKeyHex);
    expect(env.hybrid).toBe(true);
    const out = await decryptRoomKeyEnvelope(env, x.privJwk);
    expect(Array.from(out)).toEqual(Array.from(DATA));
});

test('гибрид без локальной Kyber-идентичности → явная ошибка (устройство без vault)', async () => {
    window.AppState.user = { user_id: 999 };               // слота нет
    const kyber = mlkemKeygen();
    const x = await makeX25519();
    const env = await hybridEciesEncrypt(DATA, x.pubHex, kyber.publicKeyHex);
    await expect(decryptRoomKeyEnvelope(env, x.privJwk)).rejects.toThrow(/Kyber identity/);
});

test('гибрид с чужим Kyber-priv в слоте → AEAD-провал (kyber_shared другой)', async () => {
    const uid = 7;
    const mine = mlkemKeygen();       // для этого зашифровано
    const other = mlkemKeygen();      // а в слоте лежит чужой
    window.AppState.user = { user_id: uid };
    localStorage.setItem(`vortex_kyber_priv_${uid}`, other.secretKeyHex);

    const x = await makeX25519();
    const env = await hybridEciesEncrypt(DATA, x.pubHex, mine.publicKeyHex);
    await expect(decryptRoomKeyEnvelope(env, x.privJwk)).rejects.toBeTruthy();
});

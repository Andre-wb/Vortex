/**
 * story-hybrid.test.js
 * K4e: wrapStoryKeyForContacts гибридно оборачивает при наличии verified kyber_pub
 * контакта; unwrapStoryKey разворачивает обе формы через decryptRoomKeyEnvelope
 * (подхватывая аккаунтный Kyber-priv получателя). crypto.js остаётся чистым —
 * capability/подпись резолвит stories.js (здесь передаём kyber_pub напрямую).
 */

const { wrapStoryKeyForContacts, unwrapStoryKey } = require('../crypto.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

async function makeX25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubHex = toHex(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
    const privJwk = JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey));
    return { pubHex, privJwk };
}

const STORY_KEY = new Uint8Array(32).map((_, i) => (i * 9 + 2) & 0xff);

afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState.user = {};
});

test('гибрид: контакт с verified kyber_pub → гибрид-конверт, разворот своим Kyber-priv', async () => {
    const uid = 51;
    const x = await makeX25519();
    const kyber = mlkemKeygen();
    // Получатель: аккаунтный Kyber-priv в его слоте + AppState.user
    window.AppState.user = { user_id: uid };
    localStorage.setItem(`vortex_kyber_priv_${uid}`, kyber.secretKeyHex);

    const [env] = await wrapStoryKeyForContacts(STORY_KEY, [
        { user_id: uid, pub_key: x.pubHex, kyber_pub: kyber.publicKeyHex },
    ]);
    expect(env.user_id).toBe(uid);
    expect(env.hybrid).toBe(true);
    expect(env.kyber_ciphertext).toMatch(/^[0-9a-f]{2176}$/);

    const out = await unwrapStoryKey(env, x.privJwk);
    expect(Array.from(out)).toEqual(Array.from(STORY_KEY));
});

test('классика: контакт без kyber_pub → классический конверт, разворот без Kyber', async () => {
    const x = await makeX25519();
    const [env] = await wrapStoryKeyForContacts(STORY_KEY, [
        { user_id: 7, pub_key: x.pubHex, kyber_pub: null },
    ]);
    expect(env.hybrid).toBeUndefined();
    expect(env.ephemeral_pub).toMatch(/^[0-9a-f]{64}$/);

    const out = await unwrapStoryKey(env, x.privJwk);
    expect(Array.from(out)).toEqual(Array.from(STORY_KEY));
});

test('гибрид-конверт получателя без локального Kyber-priv → явная ошибка', async () => {
    const uid = 99;
    const x = await makeX25519();
    const kyber = mlkemKeygen();
    window.AppState.user = { user_id: uid };   // слота Kyber нет
    const [env] = await wrapStoryKeyForContacts(STORY_KEY, [
        { user_id: uid, pub_key: x.pubHex, kyber_pub: kyber.publicKeyHex },
    ]);
    await expect(unwrapStoryKey(env, x.privJwk)).rejects.toThrow(/Kyber identity/);
});

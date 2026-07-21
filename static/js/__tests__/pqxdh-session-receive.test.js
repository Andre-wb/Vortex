/**
 * pqxdh-session-receive.test.js (P4)
 * Приём PQXDH-конверта (0x03) в decryptV2 — всегда-вкл, дормантно.
 *
 * P5 (отправка) ещё нет, поэтому Alice строит 0x03-конверт вручную
 * (x3dhInitiatePq + ratchet + encodeV2). Проверяется: Bob находит PQSPK-priv по
 * pqspk_id, декапсулирует, выводит собственный PQPK-pub из sk, x3dhRespondPq →
 * тот же root key → расшифровка. Деградация при отсутствии PQSPK-priv.
 */

const P = require('../dr/primitives.js');
const { encodeV2, decodeV2 } = require('../dr/v2-envelope.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');
const { decryptV2, dmSessionId, SessionError, importX25519PrivJwk } = require('../dr/session.js');
const { storePrekeyPrivates, storePqspkPrivate } = require('../dr/prekey-store.js');
const { certMessage } = require('../dr/device-identity.js');
const { x3dhInitiatePq } = require('../dr/x3dh.js');
const { ratchetInitAlice, ratchetEncrypt } = require('../dr/ratchet.js');
const { mlkemKeygen, mlkemGetPublic } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const ALICE_DEV = 'a1'.repeat(16);
const BOB_DEV = 'b2'.repeat(16);

async function genX25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const raw = await globalThis.crypto.subtle.exportKey('raw', pair.publicKey);
    const privJwk = JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey));
    return { pubHex: P.toHex(raw), privJwk, priv: pair.privateKey };
}

async function genEd25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const raw = await globalThis.crypto.subtle.exportKey('raw', pair.publicKey);
    return { pubHex: toHex(raw), priv: pair.privateKey };
}

async function edSign(priv, msgBytes) {
    return toHex(await globalThis.crypto.subtle.sign('Ed25519', priv, msgBytes));
}

/** Bob с PQSPK: SPK/OPK/PQSPK-приваты в сторе; bundle несёт device_kyber_pub. */
async function setupBobPq({ withOpk = true, storePqspk = true } = {}) {
    const x3dh = await genX25519();
    const spk = await genX25519();
    const opk = withOpk ? await genX25519() : null;
    const pqspk = mlkemKeygen();
    window.AppState = { user: { user_id: 2 } };
    storePrekeyPrivates({ id: 1, jwk: spk.privJwk }, opk ? [{ id: 100, jwk: opk.privJwk }] : []);
    if (storePqspk) storePqspkPrivate(1, pqspk.secretKeyHex);
    const bundle = {
        device_x3dh_pub: x3dh.pubHex,
        signed_prekey: spk.pubHex, signed_prekey_id: 1,
        one_time_prekey: opk ? opk.pubHex : null, one_time_prekey_id: opk ? 100 : null,
        device_kyber_pub: pqspk.publicKeyHex, device_kyber_id: 1,
    };
    return { x3dh, spk, opk, pqspk, bundle };
}

/** Alice строит PQXDH-конверт (0x03) вручную — как это сделает P5. */
async function makePqEnvelope(bob, plaintext) {
    const aliceX3dh = await genX25519();
    const aliceSign = await genEd25519();
    const aliceAccount = await genEd25519();
    const certSig = await edSign(aliceAccount.priv, certMessage(ALICE_DEV, aliceX3dh.pubHex, aliceSign.pubHex));

    const { sharedSecret, ekPubHex, ctHex } = await x3dhInitiatePq(
        aliceX3dh.priv, bob.bundle.device_x3dh_pub, bob.bundle.signed_prekey,
        bob.bundle.one_time_prekey, bob.bundle.device_kyber_pub);
    const state = await ratchetInitAlice(sharedSecret, bob.bundle.signed_prekey);
    const { header, ciphertext } = await ratchetEncrypt(state, new TextEncoder().encode(plaintext));
    const prelude = {
        ikPubHex: aliceX3dh.pubHex, ekPubHex,
        spkId: bob.bundle.signed_prekey_id,
        opkId: bob.bundle.one_time_prekey_id ?? null,
        clientDeviceId: ALICE_DEV, deviceSignPub: aliceSign.pubHex, deviceCertSig: certSig,
        pqspkId: bob.bundle.device_kyber_id, pqopkId: null, kyberCtHex: ctHex,
    };
    return { env: encodeV2({ prelude, header, aead: ciphertext }), accountEdPub: aliceAccount.pubHex };
}

async function bobRecvCtx(bob, trustedSenderAccountEd) {
    return { myDeviceX3dhPriv: await importX25519PrivJwk(bob.x3dh.privJwk), trustedSenderAccountEd };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
});

describe('PQXDH приём 0x03 (P4)', () => {
    test('полный round-trip с OPK: Bob декапсулирует и расшифровывает', async () => {
        const bob = await setupBobPq({ withOpk: true });
        const { env, accountEdPub } = await makePqEnvelope(bob, 'PQ привет!');
        expect(decodeV2(env).isPrekey).toBe(true);
        expect(env.slice(0, 2)).toBe('03');   // PQXDH-конверт

        const bobStore = createSessionStore(memoryBackend());
        const plain = await decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, accountEdPub), env);
        expect(plain).toBe('PQ привет!');
    });

    test('полный round-trip без OPK', async () => {
        const bob = await setupBobPq({ withOpk: false });
        const { env, accountEdPub } = await makePqEnvelope(bob, 'no opk PQ');
        const bobStore = createSessionStore(memoryBackend());
        const plain = await decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, accountEdPub), env);
        expect(plain).toBe('no opk PQ');
    });

    test('нет локального PQSPK-priv → SessionError no_pqspk_privates (деградация, не краш)', async () => {
        // Bob имеет SPK, но НЕ PQSPK (rollout-skew / очищенный стор). Null-lookup ДО decaps.
        const bob = await setupBobPq({ withOpk: true, storePqspk: false });
        const { env, accountEdPub } = await makePqEnvelope(bob, 'no pqspk');
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, accountEdPub), env))
            .rejects.toMatchObject({ code: 'no_pqspk_privates' });
    });

    test('byte-identity: mlkemGetPublic(sk) == опубликованный keygen-pub (иначе невидимый downgrade)', () => {
        // Bob связывает root key своим PQPK-pub = getPublic(sk); он ОБЯЗАН совпадать
        // с опубликованным (к которому Alice инкапсулировала), иначе KDF-binding
        // разойдётся → InvalidTag → тихий fallback. Полный round-trip выше уже
        // использует getPublic(sk) на приёме — здесь явная сверка байтов.
        const kp = mlkemKeygen();
        expect(mlkemGetPublic(kp.secretKeyHex)).toBe(kp.publicKeyHex);
    });
});

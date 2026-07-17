/**
 * dr-v2-session.test.js
 * Device-rooted парные v2-сессии (M3.2c): расширенная прелюда с device-cert
 * инициатора, X3DH по device-ключам, аутентичность инициатора через
 * verifyDeviceCert против ПРИПИНЕННОГО аккаунтного Ed25519 отправителя (вместо
 * старого account-X25519 TOFU), forward secrecy, graceful degradation.
 */

const P = require('../dr/primitives.js');
const { encodeV2, decodeV2 } = require('../dr/v2-envelope.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');
const { encryptV2, decryptV2, dmSessionId, SessionError, importX25519PrivJwk } = require('../dr/session.js');
const { storePrekeyPrivates, getOpkPrivate } = require('../dr/prekey-store.js');
const { createHistoryStore, decryptWithCache } = require('../dr/history-store.js');
const { certMessage } = require('../dr/device-identity.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

const ALICE_DEV = 'a1'.repeat(16);   // client_device_id инициатора (16 байт)
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

/** Инициатор (Alice): device x3dh + device signing + аккаунтный Ed25519 + cert над тройкой. */
async function makeSender(clientDeviceId, { badAccountForCert = null } = {}) {
    const x3dh = await genX25519();
    const sign = await genEd25519();
    const account = await genEd25519();
    // cert подписывает аккаунтный Ed25519 (либо чужой — для негативного теста)
    const signer = badAccountForCert || account;
    const certSig = await edSign(signer.priv, certMessage(clientDeviceId, x3dh.pubHex, sign.pubHex));
    return {
        clientDeviceId, x3dh, accountEdPub: account.pubHex,
        cert: { clientDeviceId, deviceSignPub: sign.pubHex, deviceCertSig: certSig },
        ctx: (getPeerBundle) => ({
            myDeviceX3dhPriv: x3dh.priv,
            myDeviceX3dhPubHex: x3dh.pubHex,
            myCert: { clientDeviceId, deviceSignPub: sign.pubHex, deviceCertSig: certSig },
            getPeerBundle,
        }),
    };
}

/** Адресат (Bob): device x3dh (IK_B) + SPK + OPK. Приватные SPK/OPK в prekey-store. */
async function setupBob({ withOpk = true } = {}) {
    const x3dh = await genX25519();
    const spk = await genX25519();
    const opk = withOpk ? await genX25519() : null;
    window.AppState = { user: { user_id: 2 } };
    storePrekeyPrivates({ id: 1, jwk: spk.privJwk }, opk ? [{ id: 100, jwk: opk.privJwk }] : []);
    const bundle = {
        device_x3dh_pub: x3dh.pubHex,
        signed_prekey: spk.pubHex,
        signed_prekey_id: 1,
        one_time_prekey: opk ? opk.pubHex : null,
        one_time_prekey_id: opk ? 100 : null,
    };
    return { x3dh, spk, opk, bundle };
}

async function bobRecvCtx(bob, trustedSenderAccountEd) {
    return { myDeviceX3dhPriv: await importX25519PrivJwk(bob.x3dh.privJwk), trustedSenderAccountEd };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
});

describe('v2 envelope encode/decode (device-cert прелюда)', () => {
    const prelude = (opkId) => ({
        ikPubHex: 'aa'.repeat(32), ekPubHex: 'bb'.repeat(32), spkId: 1, opkId,
        clientDeviceId: ALICE_DEV, deviceSignPub: 'cc'.repeat(32), deviceCertSig: 'dd'.repeat(64),
    });

    test('prekey-конверт round-trip (с cert-полями)', () => {
        const header = { dhPublicHex: '11'.repeat(32), prevCount: 4, msgNumber: 7 };
        const dec = decodeV2(encodeV2({ prelude: prelude(100), header, aead: new Uint8Array([1, 2, 3, 4]) }));
        expect(dec.isPrekey).toBe(true);
        expect(dec.prelude).toEqual(prelude(100));
        expect(dec.header).toEqual(header);
        expect(Array.from(dec.aead)).toEqual([1, 2, 3, 4]);
    });

    test('normal-конверт round-trip (без прелюды)', () => {
        const header = { dhPublicHex: 'dd'.repeat(32), prevCount: 0, msgNumber: 0 };
        const dec = decodeV2(encodeV2({ prelude: null, header, aead: new Uint8Array([9]) }));
        expect(dec.isPrekey).toBe(false);
        expect(dec.prelude).toBeNull();
    });

    test('prekey без OPK кодируется/декодируется', () => {
        const header = { dhPublicHex: '11'.repeat(32), prevCount: 0, msgNumber: 0 };
        const dec = decodeV2(encodeV2({ prelude: prelude(null), header, aead: new Uint8Array([0]) }));
        expect(dec.prelude.opkId).toBeNull();
        expect(dec.prelude.clientDeviceId).toBe(ALICE_DEV);
    });

    test('encodeV2 требует cert-поля в prekey-прелюде', () => {
        const header = { dhPublicHex: '11'.repeat(32), prevCount: 0, msgNumber: 0 };
        const noCert = { ikPubHex: 'aa'.repeat(32), ekPubHex: 'bb'.repeat(32), spkId: 1, opkId: null };
        expect(() => encodeV2({ prelude: noCert, header, aead: new Uint8Array([0]) })).toThrow();
    });
});

describe('device-rooted session round-trip (X3DH + cert)', () => {
    test('Alice устанавливает сессию, Bob проверяет cert и расшифровывает (с OPK)', async () => {
        const bob = await setupBob({ withOpk: true });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());

        const env = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'Привет из v2!');
        expect(decodeV2(env).isPrekey).toBe(true);
        expect(decodeV2(env).prelude.clientDeviceId).toBe(ALICE_DEV);   // cert инициатора в прелюде

        const bobStore = createSessionStore(memoryBackend());
        const plain = await decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, alice.accountEdPub), env);
        expect(plain).toBe('Привет из v2!');
    });

    test('последующие сообщения — normal, диалог продолжается', async () => {
        const bob = await setupBob({ withOpk: true });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());
        const bobStore = createSessionStore(memoryBackend());
        const recv = await bobRecvCtx(bob, alice.accountEdPub);
        const aliceSid = dmSessionId(42, BOB_DEV), bobSid = dmSessionId(42, ALICE_DEV);

        const e0 = await encryptV2(aliceStore, aliceSid, alice.ctx(async () => bob.bundle), 'm0');
        expect(await decryptV2(bobStore, bobSid, recv, e0)).toBe('m0');

        const e1 = await encryptV2(aliceStore, aliceSid, alice.ctx(async () => bob.bundle), 'm1');
        expect(decodeV2(e1).isPrekey).toBe(false);   // normal
        expect(await decryptV2(bobStore, bobSid, recv, e1)).toBe('m1');
    });

    test('сессия без OPK (пул исчерпан) работает', async () => {
        const bob = await setupBob({ withOpk: false });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());
        const env = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'no opk');
        const bobStore = createSessionStore(memoryBackend());
        expect(await decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, alice.accountEdPub), env)).toBe('no opk');
    });
});

describe('аутентичность инициатора (cert против припиненного account Ed25519)', () => {
    test('cert подписан ЧУЖИМ аккаунтным Ed25519 → cert_invalid', async () => {
        const bob = await setupBob({ withOpk: true });
        const attacker = await genEd25519();
        // cert подписан ключом атакующего, а Bob запинил НАСТОЯЩИЙ аккаунтный Ed25519 Alice
        const alice = await makeSender(ALICE_DEV, { badAccountForCert: attacker });
        const aliceStore = createSessionStore(memoryBackend());
        const env = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'spoof');

        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(42, ALICE_DEV),
            await bobRecvCtx(bob, alice.accountEdPub), env))   // пин ≠ ключ, подписавший cert
            .rejects.toMatchObject({ code: 'cert_invalid' });
    });

    test('нет припиненного account Ed25519 → no_sender_pin', async () => {
        const bob = await setupBob({ withOpk: true });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());
        const env = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'hi');
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(42, ALICE_DEV),
            { myDeviceX3dhPriv: await importX25519PrivJwk(bob.x3dh.privJwk), trustedSenderAccountEd: null }, env))
            .rejects.toMatchObject({ code: 'no_sender_pin' });
    });

    test('использованный OPK удаляется после установления (forward secrecy)', async () => {
        const bob = await setupBob({ withOpk: true });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());
        const env = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'burn opk');
        expect(getOpkPrivate(100)).not.toBeNull();
        const bobStore = createSessionStore(memoryBackend());
        await decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, alice.accountEdPub), env);
        expect(getOpkPrivate(100)).toBeNull();
    });
});

describe('история v2 после «перезагрузки» (кэш плейнтекста)', () => {
    test('израсходованный ключ читается из кэша, транспортная расшифровка не вызывается', async () => {
        const bob = await setupBob({ withOpk: true });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());
        const bobSess = createSessionStore(memoryBackend());
        const recv = await bobRecvCtx(bob, alice.accountEdPub);
        const hist = createHistoryStore(memoryBackend());
        const bobSid = dmSessionId(42, ALICE_DEV);

        const env0 = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'история m0');

        const thunk = jest.fn(() => decryptV2(bobSess, bobSid, recv, env0));
        expect(await decryptWithCache(hist, 42, 1, thunk)).toBe('история m0');
        expect(thunk).toHaveBeenCalledTimes(1);

        await expect(decryptV2(bobSess, bobSid, recv, env0)).rejects.toThrow(SessionError);

        const thunk2 = jest.fn(() => decryptV2(bobSess, bobSid, recv, env0));
        expect(await decryptWithCache(hist, 42, 1, thunk2)).toBe('история m0');
        expect(thunk2).not.toHaveBeenCalled();
    });
});

describe('graceful degradation', () => {
    test('нет приватных prekey → SessionError no_prekey_privates', async () => {
        const bob = await setupBob({ withOpk: true });
        const alice = await makeSender(ALICE_DEV);
        const aliceStore = createSessionStore(memoryBackend());
        const env = await encryptV2(aliceStore, dmSessionId(42, BOB_DEV), alice.ctx(async () => bob.bundle), 'hi');

        localStorage.removeItem('vortex_dr_prekeys_2');
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(42, ALICE_DEV), await bobRecvCtx(bob, alice.accountEdPub), env))
            .rejects.toMatchObject({ code: 'no_prekey_privates' });
    });

    test('normal-конверт без установленной сессии → no_session', async () => {
        window.AppState = { user: { user_id: 2 } };
        const bob = await setupBob({ withOpk: true });
        const header = { dhPublicHex: 'ab'.repeat(32), prevCount: 0, msgNumber: 0 };
        const normalEnv = encodeV2({ prelude: null, header, aead: new Uint8Array(28) });
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(9, ALICE_DEV), await bobRecvCtx(bob, 'cc'.repeat(32)), normalEnv))
            .rejects.toMatchObject({ code: 'no_session' });
    });

    test('битый конверт → bad_envelope', async () => {
        window.AppState = { user: { user_id: 2 } };
        const bob = await setupBob({ withOpk: true });
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(9, ALICE_DEV), await bobRecvCtx(bob, 'cc'.repeat(32)), 'zz'))
            .rejects.toThrow(SessionError);
    });
});

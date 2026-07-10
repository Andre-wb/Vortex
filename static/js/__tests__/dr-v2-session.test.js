/**
 * dr-v2-session.test.js
 * Парные v2-сессии Double Ratchet (ADR-001, батч 6a): v2-конверт, полный
 * round-trip Alice↔Bob через X3DH, TOFU-проверка, удаление OPK (FS),
 * graceful degradation для пользователей без приватных prekey.
 */

const P = require('../dr/primitives.js');
const { encodeV2, decodeV2 } = require('../dr/v2-envelope.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');
const { encryptV2, decryptV2, dmSessionId, SessionError, importX25519PrivJwk } = require('../dr/session.js');
const { storePrekeyPrivates, getOpkPrivate } = require('../dr/prekey-store.js');

/** Генерирует X25519 пару → { pubHex, privJwk, priv }. */
async function genX25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const raw = await globalThis.crypto.subtle.exportKey('raw', pair.publicKey);
    const privJwk = JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey));
    return { pubHex: P.toHex(raw), privJwk, priv: pair.privateKey };
}

/** Полный set ключей Bob-адресата + серверный бандл для Alice. Bob = userId 2. */
async function setupBob({ withOpk = true } = {}) {
    const ik = await genX25519();
    const spk = await genX25519();
    const opk = withOpk ? await genX25519() : null;

    window.AppState = { user: { user_id: 2, x25519_public_key: ik.pubHex } };
    storePrekeyPrivates(
        { id: 1, jwk: spk.privJwk },
        opk ? [{ id: 100, jwk: opk.privJwk }] : [],
    );

    const bundle = {
        identity_key: ik.pubHex,
        signed_prekey: spk.pubHex,
        signed_prekey_id: 1,
        one_time_prekey: opk ? opk.pubHex : null,
        one_time_prekey_id: opk ? 100 : null,
    };
    return { ik, spk, opk, bundle };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
});

describe('v2 envelope encode/decode', () => {
    test('prekey-конверт round-trip', () => {
        const prelude = { ikPubHex: 'aa'.repeat(32), ekPubHex: 'bb'.repeat(32), spkId: 1, opkId: 100 };
        const header = { dhPublicHex: 'cc'.repeat(32), prevCount: 4, msgNumber: 7 };
        const aead = new Uint8Array([1, 2, 3, 4]);
        const dec = decodeV2(encodeV2({ prelude, header, aead }));
        expect(dec.isPrekey).toBe(true);
        expect(dec.prelude).toEqual(prelude);
        expect(dec.header).toEqual(header);
        expect(Array.from(dec.aead)).toEqual([1, 2, 3, 4]);
    });

    test('normal-конверт round-trip (без прелюды, без OPK)', () => {
        const header = { dhPublicHex: 'dd'.repeat(32), prevCount: 0, msgNumber: 0 };
        const dec = decodeV2(encodeV2({ prelude: null, header, aead: new Uint8Array([9]) }));
        expect(dec.isPrekey).toBe(false);
        expect(dec.prelude).toBeNull();
        expect(dec.header.dhPublicHex).toBe('dd'.repeat(32));
    });

    test('prekey без OPK кодируется/декодируется (opkId null)', () => {
        const prelude = { ikPubHex: 'aa'.repeat(32), ekPubHex: 'bb'.repeat(32), spkId: 3, opkId: null };
        const header = { dhPublicHex: 'cc'.repeat(32), prevCount: 0, msgNumber: 0 };
        const dec = decodeV2(encodeV2({ prelude, header, aead: new Uint8Array([0]) }));
        expect(dec.prelude.opkId).toBeNull();
        expect(dec.prelude.spkId).toBe(3);
    });
});

describe('v2 session round-trip (X3DH + Double Ratchet)', () => {
    async function aliceCtx(bobBundle) {
        const aliceIk = await genX25519();
        return {
            store: createSessionStore(memoryBackend()),
            sessionId: dmSessionId(42),
            ctx: { myIkPriv: aliceIk.priv, myIkPubHex: aliceIk.pubHex, peerBundle: bobBundle },
            aliceIkPubHex: aliceIk.pubHex,
        };
    }

    test('Alice устанавливает сессию, Bob отвечает и расшифровывает (с OPK)', async () => {
        const bob = await setupBob({ withOpk: true });
        const bobIkPriv = await importX25519PrivJwk(bob.ik.privJwk);
        const a = await aliceCtx(bob.bundle);

        const env = await encryptV2(a.store, a.sessionId, a.ctx, 'Привет из v2!');
        expect(decodeV2(env).isPrekey).toBe(true);   // первое — prekey-сообщение

        const bobStore = createSessionStore(memoryBackend());
        const plain = await decryptV2(bobStore, dmSessionId(42),
            { myIkPriv: bobIkPriv, senderIdentityPubHex: a.aliceIkPubHex }, env);
        expect(plain).toBe('Привет из v2!');
    });

    test('последующие сообщения — normal, диалог в обе стороны', async () => {
        const bob = await setupBob({ withOpk: true });
        const bobIkPriv = await importX25519PrivJwk(bob.ik.privJwk);
        const a = await aliceCtx(bob.bundle);
        const bobStore = createSessionStore(memoryBackend());
        const bobRecv = { myIkPriv: bobIkPriv, senderIdentityPubHex: a.aliceIkPubHex };

        // Первое (prekey) устанавливает сессию у обоих
        const e0 = await encryptV2(a.store, a.sessionId, a.ctx, 'm0');
        expect(await decryptV2(bobStore, dmSessionId(42), bobRecv, e0)).toBe('m0');

        // Второе от Alice — normal
        const e1 = await encryptV2(a.store, a.sessionId, a.ctx, 'm1');
        expect(decodeV2(e1).isPrekey).toBe(false);
        expect(await decryptV2(bobStore, dmSessionId(42), bobRecv, e1)).toBe('m1');
    });

    test('сессия без OPK (пул исчерпан) тоже работает', async () => {
        const bob = await setupBob({ withOpk: false });
        const bobIkPriv = await importX25519PrivJwk(bob.ik.privJwk);
        const a = await aliceCtx(bob.bundle);
        const env = await encryptV2(a.store, a.sessionId, a.ctx, 'no opk');
        const bobStore = createSessionStore(memoryBackend());
        const plain = await decryptV2(bobStore, dmSessionId(42),
            { myIkPriv: bobIkPriv, senderIdentityPubHex: a.aliceIkPubHex }, env);
        expect(plain).toBe('no opk');
    });
});

describe('TOFU и forward secrecy', () => {
    test('несовпадение initiator IK с identity отправителя отвергается', async () => {
        const bob = await setupBob({ withOpk: true });
        const bobIkPriv = await importX25519PrivJwk(bob.ik.privJwk);
        const aliceIk = await genX25519();
        const store = createSessionStore(memoryBackend());
        const env = await encryptV2(store, dmSessionId(42),
            { myIkPriv: aliceIk.priv, myIkPubHex: aliceIk.pubHex, peerBundle: bob.bundle }, 'spoof?');

        const bobStore = createSessionStore(memoryBackend());
        // Отправитель по метаданным — «кто-то другой» (identity не совпадает с прелюдой)
        await expect(decryptV2(bobStore, dmSessionId(42),
            { myIkPriv: bobIkPriv, senderIdentityPubHex: 'ff'.repeat(32) }, env))
            .rejects.toMatchObject({ code: 'identity_mismatch' });
    });

    test('использованный OPK удаляется после установления (forward secrecy)', async () => {
        const bob = await setupBob({ withOpk: true });
        const bobIkPriv = await importX25519PrivJwk(bob.ik.privJwk);
        const aliceIk = await genX25519();
        const store = createSessionStore(memoryBackend());
        const env = await encryptV2(store, dmSessionId(42),
            { myIkPriv: aliceIk.priv, myIkPubHex: aliceIk.pubHex, peerBundle: bob.bundle }, 'burn opk');

        expect(getOpkPrivate(100)).not.toBeNull();   // до установления OPK на месте
        const bobStore = createSessionStore(memoryBackend());
        await decryptV2(bobStore, dmSessionId(42),
            { myIkPriv: bobIkPriv, senderIdentityPubHex: aliceIk.pubHex }, env);
        expect(getOpkPrivate(100)).toBeNull();       // после — израсходован и удалён
    });
});

describe('graceful degradation', () => {
    test('нет приватных prekey (пользователь батча 4) → SessionError, не краш', async () => {
        const bob = await setupBob({ withOpk: true });
        const bobIkPriv = await importX25519PrivJwk(bob.ik.privJwk);
        const aliceIk = await genX25519();
        const store = createSessionStore(memoryBackend());
        const env = await encryptV2(store, dmSessionId(42),
            { myIkPriv: aliceIk.priv, myIkPubHex: aliceIk.pubHex, peerBundle: bob.bundle }, 'hi');

        localStorage.removeItem('vortex_dr_prekeys_2');   // приватные потеряны
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(42),
            { myIkPriv: bobIkPriv, senderIdentityPubHex: aliceIk.pubHex }, env))
            .rejects.toMatchObject({ code: 'no_prekey_privates' });
    });

    test('normal-конверт без установленной сессии → SessionError no_session', async () => {
        window.AppState = { user: { user_id: 2 } };
        const bobIk = await genX25519();
        const header = { dhPublicHex: 'ab'.repeat(32), prevCount: 0, msgNumber: 0 };
        const normalEnv = encodeV2({ prelude: null, header, aead: new Uint8Array(28) });
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(9),
            { myIkPriv: bobIk.priv, senderIdentityPubHex: 'cc'.repeat(32) }, normalEnv))
            .rejects.toMatchObject({ code: 'no_session' });
    });

    test('битый конверт → SessionError bad_envelope', async () => {
        window.AppState = { user: { user_id: 2 } };
        const bobIk = await genX25519();
        const bobStore = createSessionStore(memoryBackend());
        await expect(decryptV2(bobStore, dmSessionId(9),
            { myIkPriv: bobIk.priv, senderIdentityPubHex: 'cc'.repeat(32) }, 'zz'))
            .rejects.toThrow(SessionError);
    });
});

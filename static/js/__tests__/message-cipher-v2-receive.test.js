/**
 * message-cipher-v2-receive.test.js
 * M3.2c приём через ПРОДОВЫЙ путь decryptV2Message: device x3dh priv этого
 * устройства, резолв пина отправителя (_resolveSenderPin), сессия по устройству-
 * отправителю. Покрывает два кейса:
 *   • сообщение от ПИРА (чужой userId) — пин фетчится и проверяется;
 *   • сообщение со СВОЕГО ДРУГОГО устройства (own-device fan-out, sender_id === мой)
 *     — корень доверия берётся ЛОКАЛЬНО, cert проверяется против своего account Ed.
 * Второй кейс — тот, что ловит device-level эхо-роутинг (иначе не расшифровался бы).
 */

const P = require('../dr/primitives.js');

const mockApi = jest.fn();
jest.mock('../utils.js', () => {
    const actual = jest.requireActual('../utils.js');
    return { ...actual, api: (...a) => mockApi(...a) };
});
jest.mock('../dr/session-store.js', () => {
    const actual = jest.requireActual('../dr/session-store.js');
    return { ...actual, indexedDbBackend: () => actual.memoryBackend() };
});

const { certMessage, loadOrCreateDeviceIdentity } = require('../dr/device-identity.js');
const { loadOrCreateEd25519Identity, edSign } = require('../dr/prekeys.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');
const { encryptV2, dmSessionId, importX25519PrivJwk } = require('../dr/session.js');
const { storePrekeyPrivates } = require('../dr/prekey-store.js');
const { decryptV2Message } = require('../chat/message-cipher.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function genX25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const raw = await globalThis.crypto.subtle.exportKey('raw', pair.publicKey);
    return { pubHex: P.toHex(raw), privJwk: JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey)) };
}
async function genEd25519() {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const raw = await globalThis.crypto.subtle.exportKey('raw', pair.publicKey);
    return { pubHex: toHex(raw), priv: pair.privateKey };
}

/** Отправитель (другое устройство) шифрует prekey-сообщение ЭТОМУ устройству. */
async function senderEncrypts(receiverBundle, roomId, plaintext, { senderDeviceId, accountEdSignFn }) {
    const x3dh = await genX25519();
    const sign = await genEd25519();
    const certSig = await accountEdSignFn(certMessage(senderDeviceId, x3dh.pubHex, sign.pubHex));
    const ctx = {
        myDeviceX3dhPriv: await importX25519PrivJwk(x3dh.privJwk),
        myDeviceX3dhPubHex: x3dh.pubHex,
        myCert: { clientDeviceId: senderDeviceId, deviceSignPub: sign.pubHex, deviceCertSig: certSig },
        getPeerBundle: async () => receiverBundle,
    };
    const store = createSessionStore(memoryBackend());
    return encryptV2(store, dmSessionId(roomId, receiverBundle.client_device_id), ctx, plaintext);
}

/** Готовит ЭТО устройство (получателя) как Bob (user 2): account Ed + device-identity + SPK/OPK. */
async function setupReceiver(opkIds) {
    window.AppState = { user: { user_id: 2 } };
    const account = await loadOrCreateEd25519Identity();     // аккаунтный Ed25519 Bob
    const myDev = await loadOrCreateDeviceIdentity();          // это устройство (получатель)
    const spk = await genX25519();
    const opks = [];
    for (const id of opkIds) { const o = await genX25519(); opks.push({ id, ...o }); }
    storePrekeyPrivates({ id: 1, jwk: spk.privJwk }, opks.map(o => ({ id: o.id, jwk: o.privJwk })));
    const bundleFor = (opkId) => ({
        client_device_id: myDev.deviceId,
        device_x3dh_pub: myDev.x3dhPub,
        signed_prekey: spk.pubHex, signed_prekey_id: 1,
        one_time_prekey: opks.find(o => o.id === opkId).pubHex, one_time_prekey_id: opkId,
    });
    return { account, myDev, bundleFor };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    mockApi.mockReset();
});

test('приём от ПИРА: пин фетчится, cert проверяется, сообщение расшифровано', async () => {
    const rx = await setupReceiver([100]);
    const alice = await genEd25519();                 // аккаунтный Ed25519 Alice (пир, user 5)
    const aliceDeviceId = '5a'.repeat(16);
    const env = await senderEncrypts(rx.bundleFor(100), 700, 'привет от пира', {
        senderDeviceId: aliceDeviceId,
        accountEdSignFn: (m) => globalThis.crypto.subtle.sign('Ed25519', alice.priv, m).then(toHex),
    });
    // _resolveSenderPin(5): фетч бандла Alice → пин identity_key_ed
    mockApi.mockImplementation(async (method, url) =>
        url.endsWith('/prekeys/5') ? { identity_key_ed: alice.pubHex } : {});

    const plain = await decryptV2Message(env, 700, 5, aliceDeviceId);
    expect(plain).toBe('привет от пира');
});

test('приём СО СВОЕГО ДРУГОГО устройства (own-device fan-out): корень локальный, расшифровано', async () => {
    const rx = await setupReceiver([200]);
    const myOtherDeviceId = '2b'.repeat(16);
    // cert моего другого устройства подписан МОИМ аккаунтным Ed25519 (Bob, user 2)
    const env = await senderEncrypts(rx.bundleFor(200), 701, 'со своего второго устройства', {
        senderDeviceId: myOtherDeviceId,
        accountEdSignFn: (m) => edSign(rx.account.privJwk, m),
    });
    // senderUserId === мой (2) → _resolveSenderPin берёт account Ed ЛОКАЛЬНО, без сети
    const plain = await decryptV2Message(env, 701, 2, myOtherDeviceId);
    expect(plain).toBe('со своего второго устройства');
    expect(mockApi).not.toHaveBeenCalled();           // локальный корень, фетча нет
});

test('cert подписан не тем аккаунтным Ed25519 → расшифровка отвергается', async () => {
    const rx = await setupReceiver([300]);
    const alice = await genEd25519();
    const attacker = await genEd25519();               // сервер подписал cert своим ключом
    const aliceDeviceId = '5c'.repeat(16);
    const env = await senderEncrypts(rx.bundleFor(300), 702, 'spoof', {
        senderDeviceId: aliceDeviceId,
        accountEdSignFn: (m) => globalThis.crypto.subtle.sign('Ed25519', attacker.priv, m).then(toHex),
    });
    // Bob запинил НАСТОЯЩИЙ account Ed25519 Alice (не attacker)
    mockApi.mockImplementation(async (method, url) =>
        url.endsWith('/prekeys/5') ? { identity_key_ed: alice.pubHex } : {});
    await expect(decryptV2Message(env, 702, 5, aliceDeviceId)).rejects.toMatchObject({ code: 'cert_invalid' });
});

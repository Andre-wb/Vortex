/**
 * pqxdh-send.test.js (P5)
 * Отправка PQXDH за флагом vortex_pqxdh_enabled через реальный encryptV2ForDm.
 *
 * Capability = валидный подписанный per-device Kyber pre-key в бандле пира
 * (device_kyber_sig над СЫРЫМИ байтами device_kyber_pub против device_sign_pub).
 * Флаг вкл + capability → 0x03 (x3dhInitiatePq); иначе классика 0x01. Битый PQSPK
 * снимается (v2 не ломается). Тест #1 (round-trip до 0x03) доказывает byte-lock
 * сырых байтов: verify над hex/чужими байтами не сошёлся бы → был бы 0x01.
 *
 * Реальная крипта; мокается только сеть (api) и backend session-store.
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

const { decodeFanout } = require('../dr/v2-fanout.js');
const { decodeV2 } = require('../dr/v2-envelope.js');
const { certMessage } = require('../dr/device-identity.js');
const { loadOrCreateEd25519Identity } = require('../dr/prekeys.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');
const { decryptV2, dmSessionId, importX25519PrivJwk } = require('../dr/session.js');
const { storePrekeyPrivates, storePqspkPrivate } = require('../dr/prekey-store.js');
const { getClientDeviceId } = require('../utils.js');
const { encryptV2ForDm } = require('../chat/message-cipher.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

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
async function edSignRaw(priv, msgBytes) {
    return toHex(await globalThis.crypto.subtle.sign('Ed25519', priv, msgBytes));
}

/** Устройство адресата с опциональным per-device Kyber pre-key (подписан device-ключом). */
async function recipientDevice(cid, spkId, opkId, acctEd, acctX25519Hex,
                               { withPqspk = false, tamperPqspkSig = false } = {}) {
    const x3dh = await genX25519();
    const sign = await genEd25519();
    const spk = await genX25519();
    const opk = await genX25519();
    const certSig = await edSignRaw(acctEd.priv, certMessage(cid, x3dh.pubHex, sign.pubHex));
    const bundle = {
        device_id: spkId,
        client_device_id: cid,
        device_x3dh_pub: x3dh.pubHex, device_sign_pub: sign.pubHex, device_cert_sig: certSig,
        signed_prekey: spk.pubHex, signed_prekey_id: spkId,
        signed_prekey_sig: await edSignRaw(sign.priv, fromHex(spk.pubHex)),
        identity_key: acctX25519Hex, identity_key_ed: acctEd.pubHex,
        identity_key_sig: await edSignRaw(acctEd.priv, fromHex(acctX25519Hex)),
        supports_v2: true,
    };
    let pqspk = null;
    if (withPqspk) {
        pqspk = mlkemKeygen();
        // Подпись device signing-ключом над СЫРЫМИ байтами kyber pub (как P2).
        let kSig = await edSignRaw(sign.priv, fromHex(pqspk.publicKeyHex));
        if (tamperPqspkSig) kSig = (kSig.endsWith('00') ? kSig.slice(0, -2) + '01' : kSig.slice(0, -2) + '00');
        bundle.device_kyber_pub = pqspk.publicKeyHex;
        bundle.device_kyber_sig = kSig;
        bundle.device_kyber_id = 1;
    }
    return { cid, x3dh, spk, opk, spkId, opkId, pqspk, bundle };
}

function installMock(devicesByUser) {
    mockApi.mockImplementation(async (method, url, body) => {
        for (const [uid, devs] of Object.entries(devicesByUser)) {
            if (url.endsWith(`/${uid}/devices`)) return { bundles: devs.map(d => d.bundle) };
            if (url.endsWith(`/${uid}/claim-opk`)) {
                const d = devs.find(x => x.bundle.device_id === body?.device_id);
                return d ? { one_time_prekey: d.opk.pubHex, one_time_prekey_id: d.opkId }
                         : { one_time_prekey: null, one_time_prekey_id: null };
            }
        }
        return { bundles: [] };
    });
}

async function setupAlice() {
    window.AppState = { user: { user_id: 1, x25519_public_key: 'aa'.repeat(32) } };
    const aliceEd = await loadOrCreateEd25519Identity();
    return { accountEdPub: aliceEd.pubHex, deviceId: getClientDeviceId() };
}

/** Расшифровывает под-конверт как устройство dev (Bob = user 2); кладёт PQSPK-priv. */
async function decryptAs(dev, roomId, senderDeviceId, envelope, trustedSenderAccountEd) {
    window.AppState = { user: { user_id: 2 } };
    storePrekeyPrivates({ id: dev.spkId, jwk: dev.spk.privJwk }, [{ id: dev.opkId, jwk: dev.opk.privJwk }]);
    if (dev.pqspk) storePqspkPrivate(dev.bundle.device_kyber_id, dev.pqspk.secretKeyHex);
    const store = createSessionStore(memoryBackend());
    return decryptV2(store, dmSessionId(roomId, senderDeviceId),
        { myDeviceX3dhPriv: await importX25519PrivJwk(dev.x3dh.privJwk), trustedSenderAccountEd },
        envelope);
}

function dmRoom(bobAcctX25519Hex, roomId) {
    return { id: roomId, is_dm: true, dm_user: { user_id: 2, x25519_public_key: bobAcctX25519Hex } };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    mockApi.mockReset();
});

test('флаг вкл + валидный PQSPK → 0x03, адресат расшифровывает (byte-lock сырых байтов)', async () => {
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '1');
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('a1'.repeat(16), 1, 101, bobEd, bobX.pubHex, { withPqspk: true });
    installMock({ '2': [dev], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 80), 'pq send');
    const blob = decodeFanout(r.ciphertext);
    expect(decodeV2(blob.subs[dev.cid]).isPrekey).toBe(true);
    expect(blob.subs[dev.cid].slice(0, 2)).toBe('03');            // PQXDH-конверт
    expect(await decryptAs(dev, 80, alice.deviceId, blob.subs[dev.cid], alice.accountEdPub)).toBe('pq send');
});

test('kill-switch (флаг=0) → классика 0x01 даже с PQSPK в бандле', async () => {
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '0');   // явное выключение (дефолт теперь ВКЛ)
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('b1'.repeat(16), 1, 101, bobEd, bobX.pubHex, { withPqspk: true });
    installMock({ '2': [dev], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 81), 'classic');
    const blob = decodeFanout(r.ciphertext);
    expect(blob.subs[dev.cid].slice(0, 2)).toBe('01');            // классический prekey
    expect(await decryptAs(dev, 81, alice.deviceId, blob.subs[dev.cid], alice.accountEdPub)).toBe('classic');
});

test('нет PQSPK в бандле + флаг вкл → классика 0x01', async () => {
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '1');
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('c1'.repeat(16), 1, 101, bobEd, bobX.pubHex);   // без PQSPK
    installMock({ '2': [dev], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 82), 'no pqspk');
    const blob = decodeFanout(r.ciphertext);
    expect(blob.subs[dev.cid].slice(0, 2)).toBe('01');
    expect(await decryptAs(dev, 82, alice.deviceId, blob.subs[dev.cid], alice.accountEdPub)).toBe('no pqspk');
});

test('битая PQSPK-подпись + флаг вкл → снята → классика 0x01 (v2 не сломан)', async () => {
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '1');
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('d1'.repeat(16), 1, 101, bobEd, bobX.pubHex,
        { withPqspk: true, tamperPqspkSig: true });
    installMock({ '2': [dev], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 83), 'bad sig');
    const blob = decodeFanout(r.ciphertext);
    expect(blob.subs[dev.cid].slice(0, 2)).toBe('01');            // PQSPK снят → классика
    expect(await decryptAs(dev, 83, alice.deviceId, blob.subs[dev.cid], alice.accountEdPub)).toBe('bad sig');
});

test('mixed fan-out: устройство A (PQSPK)→0x03, B (без PQSPK)→0x01, оба расшифровывают (per-device решение)', async () => {
    // Несущий тезис P5 vs аккаунтного Kyber: решение ПО-УСТРОЙСТВЕННОЕ. Прод-топология
    // смешанная — рефактор, поднявший capability на уровень аккаунта, молча сломал бы это.
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '1');
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const devA = await recipientDevice('a1'.repeat(16), 1, 101, bobEd, bobX.pubHex, { withPqspk: true });
    const devB = await recipientDevice('b2'.repeat(16), 2, 102, bobEd, bobX.pubHex);   // без PQSPK
    installMock({ '2': [devA, devB], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 84), 'mixed');
    const blob = decodeFanout(r.ciphertext);
    expect(blob.subs[devA.cid].slice(0, 2)).toBe('03');           // A — PQXDH
    expect(blob.subs[devB.cid].slice(0, 2)).toBe('01');           // B — классика
    expect(await decryptAs(devA, 84, alice.deviceId, blob.subs[devA.cid], alice.accountEdPub)).toBe('mixed');
    expect(await decryptAs(devB, 84, alice.deviceId, blob.subs[devB.cid], alice.accountEdPub)).toBe('mixed');
});

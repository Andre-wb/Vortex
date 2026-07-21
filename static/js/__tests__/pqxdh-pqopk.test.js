/**
 * pqxdh-pqopk.test.js (P6)
 * One-time Kyber pre-keys (PQOPK) через реальный encryptV2ForDm.
 *
 * Проверяет: (1) флаг+PQOPK → 0x03 с pqopk_id, адресат decaps'ит PQOPK-priv,
 * priv удаляется (KEM-FS), следующая сессия берёт ДРУГОЙ PQOPK; (2) fork-a:
 * flag-off → claim с want_kyber=false, пул PQOPK не тронут; (3) исчерпание пула
 * → pqopk_id=null → fallback на last-resort PQSPK, всё расшифровывается.
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
const { storePrekeyPrivates, storePqspkPrivate, storePqopkPrivates, getPqopkPrivate } = require('../dr/prekey-store.js');
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

/** Устройство адресата с PQSPK + пулом PQOPK (mutable — claim'ы его дренируют). */
async function recipientDevice(cid, spkId, opkId, acctEd, acctX25519Hex, { pqopkCount = 0 } = {}) {
    const x3dh = await genX25519();
    const sign = await genEd25519();
    const spk = await genX25519();
    const opk = await genX25519();
    const certSig = await edSignRaw(acctEd.priv, certMessage(cid, x3dh.pubHex, sign.pubHex));
    const pqspk = mlkemKeygen();
    const pqspkSig = await edSignRaw(sign.priv, fromHex(pqspk.publicKeyHex));
    const bundle = {
        device_id: spkId, client_device_id: cid,
        device_x3dh_pub: x3dh.pubHex, device_sign_pub: sign.pubHex, device_cert_sig: certSig,
        signed_prekey: spk.pubHex, signed_prekey_id: spkId,
        signed_prekey_sig: await edSignRaw(sign.priv, fromHex(spk.pubHex)),
        identity_key: acctX25519Hex, identity_key_ed: acctEd.pubHex,
        identity_key_sig: await edSignRaw(acctEd.priv, fromHex(acctX25519Hex)),
        supports_v2: true,
        device_kyber_pub: pqspk.publicKeyHex, device_kyber_sig: pqspkSig, device_kyber_id: 1,
    };
    // Пул одноразовых Kyber pre-keys (id 500+)
    const pqopkPool = [];
    for (let i = 0; i < pqopkCount; i++) {
        const kp = mlkemKeygen();
        pqopkPool.push({ id: 500 + i, pub: kp.publicKeyHex, sk: kp.secretKeyHex });
    }
    return { cid, x3dh, spk, opk, spkId, opkId, pqspk, pqopkPool, bundle };
}

/** Мок: /devices → бандлы; /claim-opk → OPK (+ PQOPK при want_kyber, дренирует пул). */
function installMock(devicesByUser) {
    mockApi.mockImplementation(async (method, url, body) => {
        for (const [uid, devs] of Object.entries(devicesByUser)) {
            if (url.endsWith(`/${uid}/devices`)) return { bundles: devs.map(d => d.bundle) };
            if (url.endsWith(`/${uid}/claim-opk`)) {
                const d = devs.find(x => x.bundle.device_id === body?.device_id);
                if (!d) return { one_time_prekey: null, one_time_prekey_id: null };
                const resp = { one_time_prekey: d.opk.pubHex, one_time_prekey_id: d.opkId };
                if (body?.want_kyber) {
                    const p = d.pqopkPool.shift();   // consume one-time
                    resp.one_time_kyber_prekey = p ? p.pub : null;
                    resp.one_time_kyber_prekey_id = p ? p.id : null;
                }
                return resp;
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

/** Расшифровывает как устройство dev; кладёт SPK/OPK/PQSPK + ВСЕ PQOPK-privs пула. */
async function decryptAs(dev, roomId, senderDeviceId, envelope, trustedSenderAccountEd, allPqopks) {
    window.AppState = { user: { user_id: 2 } };
    storePrekeyPrivates({ id: dev.spkId, jwk: dev.spk.privJwk }, [{ id: dev.opkId, jwk: dev.opk.privJwk }]);
    storePqspkPrivate(dev.bundle.device_kyber_id, dev.pqspk.secretKeyHex);
    if (allPqopks?.length) storePqopkPrivates(allPqopks.map(p => ({ id: p.id, sk: p.sk })));
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

test('PQOPK E2E: 0x03 с pqopk_id, адресат decaps + удаляет priv (KEM-FS)', async () => {
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '1');
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('a1'.repeat(16), 1, 101, bobEd, bobX.pubHex, { pqopkCount: 3 });
    const poolSnapshot = dev.pqopkPool.map(p => ({ ...p }));   // до дренажа
    installMock({ '2': [dev], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 90), 'pqopk');
    const env = decodeFanout(r.ciphertext).subs[dev.cid];
    const prelude = decodeV2(env).prelude;
    expect(env.slice(0, 2)).toBe('03');
    expect(prelude.pqopkId).toBe(500);                        // взят первый one-time
    expect(await decryptAs(dev, 90, alice.deviceId, env, alice.accountEdPub, poolSnapshot)).toBe('pqopk');
    // KEM-FS: использованный PQOPK-priv удалён у адресата
    window.AppState = { user: { user_id: 2 } };
    expect(getPqopkPrivate(500)).toBeNull();
});

test('fork-a: kill-switch (флаг=0) → claim с want_kyber=false, пул PQOPK не тронут', async () => {
    await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '0');   // явное выключение (дефолт теперь ВКЛ)
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('b1'.repeat(16), 1, 101, bobEd, bobX.pubHex, { pqopkCount: 2 });
    installMock({ '2': [dev], '1': [] });

    await encryptV2ForDm(dmRoom(bobX.pubHex, 91), 'no pq');
    const claim = mockApi.mock.calls.find(c => c[1].endsWith('/2/claim-opk'));
    expect(claim[2].want_kyber).toBe(false);                  // не запрошен
    expect(dev.pqopkPool.length).toBe(2);                     // пул не дренирован
});

test('исчерпание пула PQOPK → pqopk_id=null → fallback на PQSPK, расшифровка', async () => {
    const alice = await setupAlice();
    localStorage.setItem('vortex_pqxdh_enabled', '1');
    const bobEd = await genEd25519(); const bobX = await genX25519();
    const dev = await recipientDevice('c1'.repeat(16), 1, 101, bobEd, bobX.pubHex, { pqopkCount: 0 });  // пул пуст
    installMock({ '2': [dev], '1': [] });

    const r = await encryptV2ForDm(dmRoom(bobX.pubHex, 92), 'fallback');
    const env = decodeFanout(r.ciphertext).subs[dev.cid];
    expect(env.slice(0, 2)).toBe('03');                       // всё ещё PQXDH (last-resort PQSPK)
    expect(decodeV2(env).prelude.pqopkId).toBeNull();         // one-time не было
    expect(await decryptAs(dev, 92, alice.deviceId, env, alice.accountEdPub, [])).toBe('fallback');
});

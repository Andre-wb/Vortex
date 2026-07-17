/**
 * message-cipher-v2-send.test.js
 * M3.2c fan-out: encryptV2ForDm шифрует device-rooted по под-конверту на КАЖДОЕ
 * валидное устройство адресата, собирает один fan-out-blob `{from, subs}`, и
 * каждое устройство-получатель расшифровывает его до того же плейнтекста (после
 * проверки cert'а инициатора против припиненного аккаунтного Ed25519). Плюс:
 * флаг, пропуск устройства с битым cert'ом, блок при смене аккаунтного Ed25519.
 *
 * Реальная крипта (session/x3dh/ratchet/device-identity/fan-out); мокается только
 * сеть (`api`) и backend session-store (memory вместо IndexedDB).
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
const { certMessage } = require('../dr/device-identity.js');
const { loadOrCreateEd25519Identity } = require('../dr/prekeys.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');
const { decryptV2, dmSessionId, importX25519PrivJwk } = require('../dr/session.js');
const { storePrekeyPrivates } = require('../dr/prekey-store.js');
const { getClientDeviceId } = require('../utils.js');
const { encryptV2ForDm } = require('../chat/message-cipher.js');

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

/** Устройство адресата: полный бандл (device-cert подписан аккаунтным Ed25519 адресата). */
async function recipientDevice(cid, spkId, opkId, acctEd, acctX25519Hex, { tamperCert = false } = {}) {
    const x3dh = await genX25519();
    const sign = await genEd25519();
    const spk = await genX25519();
    const opk = await genX25519();
    let certSig = await edSignRaw(acctEd.priv, certMessage(cid, x3dh.pubHex, sign.pubHex));
    if (tamperCert) certSig = (certSig.endsWith('00') ? certSig.slice(0, -2) + '01' : certSig.slice(0, -2) + '00');
    const bundle = {
        client_device_id: cid,
        device_x3dh_pub: x3dh.pubHex, device_sign_pub: sign.pubHex, device_cert_sig: certSig,
        signed_prekey: spk.pubHex, signed_prekey_id: spkId,
        signed_prekey_sig: await edSignRaw(sign.priv, fromHex(spk.pubHex)),
        identity_key: acctX25519Hex, identity_key_ed: acctEd.pubHex,
        identity_key_sig: await edSignRaw(acctEd.priv, fromHex(acctX25519Hex)),
        supports_v2: true,
        one_time_prekey: opk.pubHex, one_time_prekey_id: opkId,
    };
    return { cid, x3dh, spk, opk, spkId, opkId, bundle };
}

/** Готовит Alice (инициатора): аккаунтный Ed25519 + device-identity через buildPrekeyBundle-путь. */
async function setupAlice() {
    window.AppState = { user: { user_id: 1, x25519_public_key: 'aa'.repeat(32) } };
    // Флаг НЕ выставляем — v2-отправка теперь ВКЛ по умолчанию (M3.3); тесты
    // проверяют дефолт-on. Kill-switch (`='0'`) — в отдельном тесте ниже.
    const aliceEd = await loadOrCreateEd25519Identity();   // корень доверия своих устройств
    return { accountEdPub: aliceEd.pubHex, deviceId: getClientDeviceId() };
}

/** Расшифровывает под-конверт устройства dev как это устройство (Bob = user 2). */
async function decryptAs(dev, roomId, senderDeviceId, envelope, trustedSenderAccountEd) {
    window.AppState = { user: { user_id: 2 } };
    storePrekeyPrivates({ id: dev.spkId, jwk: dev.spk.privJwk }, [{ id: dev.opkId, jwk: dev.opk.privJwk }]);
    const store = createSessionStore(memoryBackend());
    return decryptV2(store, dmSessionId(roomId, senderDeviceId),
        { myDeviceX3dhPriv: await importX25519PrivJwk(dev.x3dh.privJwk), trustedSenderAccountEd },
        envelope);
}

// roomId уникален на тест: message-cipher._sessionStore — модульный синглтон,
// сессии (dm:roomId:cid) переживают тесты; иначе повторный cid шлёт normal, не prekey.
function dmRoom(bobAcctX25519Hex, roomId) {
    return { id: roomId, is_dm: true, dm_user: { user_id: 2, x25519_public_key: bobAcctX25519Hex } };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    mockApi.mockReset();
});

test('kill-switch (флаг=0) → null, без сетевых запросов', async () => {
    await setupAlice();
    localStorage.setItem('vortex_v2_dm_enabled', '0');   // per-client выключение
    expect(await encryptV2ForDm(dmRoom('bb'.repeat(32), 40), 'hi')).toBeNull();
    expect(mockApi).not.toHaveBeenCalled();
});

test('fan-out на 2 устройства адресата: один blob, каждое расшифровывает тот же плейнтекст', async () => {
    const alice = await setupAlice();
    const bobEd = await genEd25519();
    const bobX25519 = await genX25519();
    const dev1 = await recipientDevice('11'.repeat(16), 1, 101, bobEd, bobX25519.pubHex);
    const dev2 = await recipientDevice('12'.repeat(16), 2, 102, bobEd, bobX25519.pubHex);

    mockApi.mockImplementation(async (method, url) => {
        if (url.endsWith('/2/devices')) return { user_id: 2, bundles: [dev1.bundle, dev2.bundle] };
        if (url.endsWith('/1/devices')) return { user_id: 1, bundles: [] };   // свои другие устройства — нет
        throw new Error('unexpected ' + url);
    });

    const r = await encryptV2ForDm(dmRoom(bobX25519.pubHex, 42), 'hello fan-out');
    expect(r.enc_v).toBe(2);

    const blob = decodeFanout(r.ciphertext);
    expect(blob.from).toBe(alice.deviceId);                       // устройство-отправитель
    expect(Object.keys(blob.subs).sort()).toEqual([dev1.cid, dev2.cid].sort());   // по под-конверту на устройство

    // Каждое устройство адресата расшифровывает СВОЙ под-конверт до того же текста
    expect(await decryptAs(dev1, 42, alice.deviceId, blob.subs[dev1.cid], alice.accountEdPub)).toBe('hello fan-out');
    expect(await decryptAs(dev2, 42, alice.deviceId, blob.subs[dev2.cid], alice.accountEdPub)).toBe('hello fan-out');
});

test('N=1 (одно устройство адресата) — вырожденный fan-out работает', async () => {
    const alice = await setupAlice();
    const bobEd = await genEd25519();
    const bobX25519 = await genX25519();
    const dev = await recipientDevice('21'.repeat(16), 1, 101, bobEd, bobX25519.pubHex);
    mockApi.mockImplementation(async (m, url) =>
        url.endsWith('/2/devices') ? { bundles: [dev.bundle] } : { bundles: [] });

    const r = await encryptV2ForDm(dmRoom(bobX25519.pubHex, 51), 'solo');
    const blob = decodeFanout(r.ciphertext);
    expect(Object.keys(blob.subs)).toEqual([dev.cid]);
    expect(await decryptAs(dev, 51, alice.deviceId, blob.subs[dev.cid], alice.accountEdPub)).toBe('solo');
});

test('устройство с битым cert отбрасывается из fan-out', async () => {
    await setupAlice();
    const bobEd = await genEd25519();
    const bobX25519 = await genX25519();
    const good = await recipientDevice('31'.repeat(16), 1, 101, bobEd, bobX25519.pubHex);
    const bad = await recipientDevice('32'.repeat(16), 2, 102, bobEd, bobX25519.pubHex, { tamperCert: true });
    mockApi.mockImplementation(async (m, url) =>
        url.endsWith('/2/devices') ? { bundles: [good.bundle, bad.bundle] } : { bundles: [] });

    const r = await encryptV2ForDm(dmRoom(bobX25519.pubHex, 52), 'skip bad');
    const blob = decodeFanout(r.ciphertext);
    expect(Object.keys(blob.subs)).toEqual([good.cid]);   // только валидное устройство
});

test('нет валидных устройств адресата → null, кэш no', async () => {
    await setupAlice();
    const bobEd = await genEd25519();
    const bobX25519 = await genX25519();
    const bad = await recipientDevice('41'.repeat(16), 2, 102, bobEd, bobX25519.pubHex, { tamperCert: true });
    mockApi.mockImplementation(async (m, url) =>
        url.endsWith('/2/devices') ? { bundles: [bad.bundle] } : { bundles: [] });

    const room = dmRoom(bobX25519.pubHex, 53);
    expect(await encryptV2ForDm(room, 'x')).toBeNull();
    expect(room._v2).toBe('no');
});

test('смена аккаунтного Ed25519 адресата → блок v2 (событие идентичности)', async () => {
    await setupAlice();
    const bobEd = await genEd25519();
    const bobX25519 = await genX25519();
    const dev = await recipientDevice('51'.repeat(16), 1, 101, bobEd, bobX25519.pubHex);
    mockApi.mockImplementation(async (m, url) =>
        url.endsWith('/2/devices') ? { bundles: [dev.bundle] } : { bundles: [] });

    // Первый контакт пиннит bobEd
    expect((await encryptV2ForDm(dmRoom(bobX25519.pubHex, 54), 'first')).enc_v).toBe(2);

    // Сервер подменяет аккаунтный Ed25519 (и cert под него) — пин ловит смену
    const evilEd = await genEd25519();
    const evilDev = await recipientDevice('52'.repeat(16), 1, 101, evilEd, bobX25519.pubHex);
    mockApi.mockImplementation(async (m, url) =>
        url.endsWith('/2/devices') ? { bundles: [evilDev.bundle] } : { bundles: [] });
    const room2 = dmRoom(bobX25519.pubHex, 55);
    expect(await encryptV2ForDm(room2, 'blocked')).toBeNull();
    expect(room2._v2).toBe('no');
});

test('discovery-кэш: второе сообщение не фетчит /devices (нет OPK-drain)', async () => {
    await setupAlice();
    const bobEd = await genEd25519();
    const bobX25519 = await genX25519();
    const dev = await recipientDevice('61'.repeat(16), 1, 101, bobEd, bobX25519.pubHex);
    mockApi.mockImplementation(async (m, url) =>
        url.endsWith('/2/devices') ? { bundles: [dev.bundle] } : { bundles: [] });

    const room = dmRoom(bobX25519.pubHex, 60);
    expect((await encryptV2ForDm(room, 'first')).enc_v).toBe(2);
    const afterFirst = mockApi.mock.calls.length;      // фетч /2/devices (+ /1/devices)
    expect(afterFirst).toBeGreaterThan(0);
    // Второе сообщение: набор устройств из кэша, сессия установлена → 0 фетчей, 0 OPK
    expect((await encryptV2ForDm(room, 'second')).enc_v).toBe(2);
    expect(mockApi.mock.calls.length).toBe(afterFirst);
});

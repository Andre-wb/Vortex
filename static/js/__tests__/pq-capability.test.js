/**
 * pq-capability.test.js
 * K4c: решение об гибрид-отправке. Флаг vortex_pq_hybrid_enabled (дефолт ВКЛ, kill-switch '0');
 * capability = проверенный аккаунтный Kyber-pub пира (подпись против TOFU-пина
 * аккаунтного Ed25519, либо fetch-and-pin по prekey-бандлу). Своя Kyber-pub для
 * self-обёртки без подписи.
 */

jest.mock('../utils.js', () => ({ api: jest.fn() }));

const { api } = require('../utils.js');
const { pqSendEnabled, resolvePeerKyberPub, myKyberPub } = require('../dr/pq-capability.js');
const { pinPeerAccountEd } = require('../dr/identity-pin.js');
const { edSign } = require('../dr/prekeys.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function makeEd() {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const pubHex = toHex(await crypto.subtle.exportKey('raw', pair.publicKey));
    const privJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
    return { pubHex, privJwk };
}

const ON = () => localStorage.setItem('vortex_pq_hybrid_enabled', '1');
const OFF = () => localStorage.setItem('vortex_pq_hybrid_enabled', '0');   // kill-switch

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState.user = {};
    api.mockReset();
});

test('флаг ВКЛ по умолчанию, kill-switch (=0) → ВЫКЛ', () => {
    expect(pqSendEnabled()).toBe(true);        // дефолт теперь ВКЛ (активировано pre-launch)
    OFF();
    expect(pqSendEnabled()).toBe(false);
});

test('kill-switch (=0) → null даже с валидной подписью против пина', async () => {
    OFF();
    const peer = 5, ed = await makeEd(), kyber = mlkemKeygen();
    pinPeerAccountEd(peer, ed.pubHex);
    const sig = await edSign(ed.privJwk, fromHex(kyber.publicKeyHex));
    expect(await resolvePeerKyberPub(peer, kyber.publicKeyHex, sig)).toBeNull();
});

test('ВКЛ + валидная подпись против пина → возвращает pub (без fetch)', async () => {
    ON();
    const peer = 5, ed = await makeEd(), kyber = mlkemKeygen();
    pinPeerAccountEd(peer, ed.pubHex);
    const sig = await edSign(ed.privJwk, fromHex(kyber.publicKeyHex));
    expect(await resolvePeerKyberPub(peer, kyber.publicKeyHex, sig)).toBe(kyber.publicKeyHex);
    expect(api).not.toHaveBeenCalled();
});

test('ВКЛ + подпись чужим Ed → null (Б2-аутентичность не прошла)', async () => {
    ON();
    const peer = 5, ed = await makeEd(), other = await makeEd(), kyber = mlkemKeygen();
    pinPeerAccountEd(peer, ed.pubHex);
    const badSig = await edSign(other.privJwk, fromHex(kyber.publicKeyHex));
    expect(await resolvePeerKyberPub(peer, kyber.publicKeyHex, badSig)).toBeNull();
});

test('ВКЛ + нет подписи → null', async () => {
    ON();
    expect(await resolvePeerKyberPub(5, mlkemKeygen().publicKeyHex, null)).toBeNull();
});

test('ВКЛ + нет пина → fetch-and-pin по prekey-бандлу, затем verify', async () => {
    ON();
    const peer = 9, ed = await makeEd(), kyber = mlkemKeygen();
    api.mockResolvedValueOnce({ identity_key_ed: ed.pubHex });
    const sig = await edSign(ed.privJwk, fromHex(kyber.publicKeyHex));
    expect(await resolvePeerKyberPub(peer, kyber.publicKeyHex, sig)).toBe(kyber.publicKeyHex);
    expect(api).toHaveBeenCalledWith('GET', `/api/keys/prekeys/${peer}`);
});

test('myKyberPub: kill-switch→null; дефолт ВКЛ + локальная идентичность→pubHex', () => {
    const uid = 3, kyber = mlkemKeygen();
    window.AppState.user = { user_id: uid };
    localStorage.setItem(`vortex_kyber_priv_${uid}`, kyber.secretKeyHex);
    OFF();
    expect(myKyberPub()).toBeNull();
    localStorage.removeItem('vortex_pq_hybrid_enabled');   // дефолт ВКЛ
    expect(myKyberPub()).toBe(kyber.publicKeyHex);
});

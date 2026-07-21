/**
 * invite-link.test.js
 * O5b: клиентская обёртка invite-escrow. createInviteLink (генерит invite-пару,
 * оборачивает room key, грузит escrow, отдаёт ссылку с приватными во фрагменте);
 * rewrapInvitesAfterRotation (GET /invites → wrap → POST). Всё за флагом.
 */

jest.mock('../utils.js', () => ({ api: jest.fn() }));

const { api } = require('../utils.js');
const { createInviteLink, rewrapInvitesAfterRotation, redeemInviteEscrow } = require('../dr/invite-link.js');
const { setRoomKey, getRoomKey, hybridEciesEncrypt } = require('../crypto.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const b64url = s => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ON = () => localStorage.setItem('vortex_offline_invite_enabled', '1');

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    api.mockReset();
    api.mockResolvedValue({});
});

test('createInviteLink: флаг ВЫКЛ → null, без api', async () => {
    expect(await createInviteLink(1, 'ABC')).toBeNull();
    expect(api).not.toHaveBeenCalled();
});

test('createInviteLink: нет room key → null', async () => {
    ON();
    expect(await createInviteLink(999, 'ABC')).toBeNull();
    expect(api).not.toHaveBeenCalled();
});

test('createInviteLink: флаг ВКЛ + ключ → гибрид-escrow POST + ссылка с фрагментом', async () => {
    ON();
    setRoomKey(5, new Uint8Array(32).map((_, i) => i));
    const link = await createInviteLink(5, 'ABC123');

    expect(api).toHaveBeenCalledWith('POST', '/api/rooms/5/invite-escrow', expect.objectContaining({
        invite_pub:       expect.stringMatching(/^[0-9a-f]{64}$/),
        invite_kyber_pub: expect.stringMatching(/^[0-9a-f]{2368}$/),
        hybrid:           true,
        kyber_ciphertext: expect.stringMatching(/^[0-9a-f]{2176}$/),
        x25519_ephemeral_pub: expect.stringMatching(/^[0-9a-f]{64}$/),
    }));
    expect(link).toMatch(/\/join\/ABC123#/);
    // фрагмент декодируется в {x: X25519-priv-JWK, k: ML-KEM-priv-hex}
    const frag = link.split('#')[1];
    const secret = JSON.parse(atob(frag.replace(/-/g, '+').replace(/_/g, '/')));
    expect(JSON.parse(secret.x)).toHaveProperty('d');          // X25519 приватный (JWK)
    expect(secret.k).toMatch(/^[0-9a-f]{4800}$/);              // ML-KEM secret = 2400 байт
});

test('rewrapInvitesAfterRotation: флаг ВКЛ → GET /invites + гибрид-POST на каждый', async () => {
    ON();
    // реальный invite-pub (X25519) + Kyber-pub, чтобы обёртка не падала
    const x = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const invitePub = toHex(await globalThis.crypto.subtle.exportKey('raw', x.publicKey));
    const kyber = mlkemKeygen();
    api.mockImplementation((method, path) => {
        if (method === 'GET' && path === '/api/rooms/7/invites')
            return Promise.resolve({ invites: [{ invite_pub: invitePub, invite_kyber_pub: kyber.publicKeyHex }] });
        return Promise.resolve({});
    });

    await rewrapInvitesAfterRotation(7, new Uint8Array(32).map((_, i) => i + 1));

    expect(api).toHaveBeenCalledWith('GET', '/api/rooms/7/invites');
    expect(api).toHaveBeenCalledWith('POST', '/api/rooms/7/invite-escrow', expect.objectContaining({
        invite_pub: invitePub, hybrid: true,
        kyber_ciphertext: expect.stringMatching(/^[0-9a-f]{2176}$/),
    }));
});

test('rewrapInvitesAfterRotation: флаг ВЫКЛ → без api', async () => {
    await rewrapInvitesAfterRotation(7, new Uint8Array(32));
    expect(api).not.toHaveBeenCalled();
});

// --- O6: вступающий забирает room key из escrow по фрагменту ---

async function _makeInvite(roomKey) {
    const x = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const invitePub = toHex(await globalThis.crypto.subtle.exportKey('raw', x.publicKey));
    const invitePrivJwk = JSON.stringify(await globalThis.crypto.subtle.exportKey('jwk', x.privateKey));
    const kyber = mlkemKeygen();
    const env = await hybridEciesEncrypt(roomKey, invitePub, kyber.publicKeyHex);
    const fragment = b64url(JSON.stringify({ x: invitePrivJwk, k: kyber.secretKeyHex }));
    return { fragment, env, invitePub };
}

test('redeemInviteEscrow: фрагмент + escrow → расшифровка room key (setRoomKey)', async () => {
    ON();
    const roomKey = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
    const { fragment, env, invitePub } = await _makeInvite(roomKey);
    let queriedPub = null;
    api.mockImplementation((method, path) => {
        if (method === 'GET' && path.startsWith('/api/rooms/60/invite-escrow')) {
            queriedPub = new URL(path, 'http://x').searchParams.get('invite_pub');
            return Promise.resolve({ has_escrow: true, ...env });
        }
        return Promise.resolve({});
    });

    const rk = await redeemInviteEscrow(60, '#' + fragment);
    expect(rk).not.toBeNull();
    expect(toHex(rk)).toBe(toHex(roomKey));
    expect(toHex(getRoomKey(60))).toBe(toHex(roomKey));   // установлен
    // load-bearing: invite_pub, выведенный из JWK (redeem), == raw-export (store)
    expect(queriedPub).toBe(invitePub);
});

test('redeemInviteEscrow: has_escrow=false (устаревший) → null (fallback в key_request)', async () => {
    ON();
    const { fragment } = await _makeInvite(new Uint8Array(32));
    api.mockResolvedValue({ has_escrow: false });
    expect(await redeemInviteEscrow(61, '#' + fragment)).toBeNull();
});

test('redeemInviteEscrow: флаг ВЫКЛ / нет фрагмента / уже есть ключ → null', async () => {
    const { fragment } = await _makeInvite(new Uint8Array(32));
    expect(await redeemInviteEscrow(62, '#' + fragment)).toBeNull();   // флаг ВЫКЛ
    ON();
    expect(await redeemInviteEscrow(62, '')).toBeNull();               // нет фрагмента
    setRoomKey(63, new Uint8Array(32));
    expect(await redeemInviteEscrow(63, '#' + fragment)).toBeNull();   // ключ уже есть
    expect(api).not.toHaveBeenCalled();
});

/**
 * key-backup-kyber.test.js
 * K4c: аккаунтный Kyber-priv портируется через key_backup в тире X25519 (не
 * Ed25519). Без этого устройство, восстановленное из бандла, имеет аккаунтный
 * X25519, но не развернёт гибридный per-user room-key → лок-аут. Round-trip:
 * backup(device с Kyber) → restore(fresh, Kyber стёрт) → расшифровка гибрида.
 */

jest.mock('../utils.js', () => ({
    api:        jest.fn(),
    showAlert:  jest.fn(),
    $:          jest.fn(),
    openModal:  jest.fn(),
    closeModal: jest.fn(),
}));

const { api } = require('../utils.js');
const { createKeyBackup, restoreKeyBackup } = require('../key_backup.js');
const { decryptRoomKeyEnvelope, hybridEciesEncrypt } = require('../crypto.js');
const { mlkemKeygen } = require('../dr/mlkem.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

let _vault;

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState = { user: {}, rooms: [] };
    _vault = null;
    api.mockImplementation((method, path, body) => {
        if (method === 'POST' && path === '/api/keys/backup') { _vault = body; return Promise.resolve({}); }
        if (method === 'GET' && path === '/api/keys/backup') {
            return _vault ? Promise.resolve(_vault) : Promise.reject(new Error('not found'));
        }
        return Promise.resolve({});
    });
});

test('Kyber-priv переживает backup→restore и разворачивает гибридный room-key', async () => {
    const uid = 77;
    const kyber = mlkemKeygen();

    // Device A: аккаунтный X25519 (иначе createKeyBackup откажет) + аккаунтный Kyber
    const xpair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const xPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', xpair.privateKey));
    const xPubHex  = toHex(await crypto.subtle.exportKey('raw', xpair.publicKey));

    window.AppState.user = { user_id: uid };
    window.AppState.x25519PrivateKey = xPrivJwk;
    localStorage.setItem(`vortex_kyber_priv_${uid}`, kyber.secretKeyHex);

    const pass = 'strongpass123';
    expect(await createKeyBackup(pass)).not.toBe(false);
    expect(_vault).toBeTruthy();

    // Fresh device: тот же аккаунт, но локального Kyber и X25519 нет
    localStorage.removeItem(`vortex_kyber_priv_${uid}`);
    sessionStorage.removeItem(`vortex_kyber_priv_${uid}`);
    localStorage.removeItem('vortex_x25519_priv');
    window.AppState.x25519PrivateKey = null;

    await restoreKeyBackup(pass);

    // Kyber-priv восстановлен в per-account слот
    expect(localStorage.getItem(`vortex_kyber_priv_${uid}`)).toBe(kyber.secretKeyHex);

    // И реально разворачивает гибридный room-key на аккаунтный Kyber-pub
    const roomKey = new Uint8Array(32).map((_, i) => (i * 3 + 1) & 0xff);
    const env = await hybridEciesEncrypt(roomKey, xPubHex, kyber.publicKeyHex);
    expect(env.hybrid).toBe(true);
    const out = await decryptRoomKeyEnvelope(env, localStorage.getItem('vortex_x25519_priv'));
    expect(Array.from(out)).toEqual(Array.from(roomKey));
});

test('без Kyber в бандле (старый бандл) restore не падает, но гибрид не развернуть', async () => {
    const uid = 78;
    const xpair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    window.AppState.user = { user_id: uid };
    window.AppState.x25519PrivateKey = JSON.stringify(await crypto.subtle.exportKey('jwk', xpair.privateKey));
    // Kyber НЕ задан → бандл без kyber_private_hex (эмуляция старого бандла)

    expect(await createKeyBackup('strongpass123')).not.toBe(false);
    expect(JSON.parse(_vault.kdf_params).alg).toBe('PBKDF2');

    await restoreKeyBackup('strongpass123');
    expect(localStorage.getItem(`vortex_kyber_priv_${uid}`)).toBeNull();
});

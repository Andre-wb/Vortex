/**
 * device-identity.test.js
 * Стабильная per-device идентичность Sesame: стабильный
 * client_device_id, тройка {X25519 X3DH, Ed25519 signing, account cert},
 * валидность cert'а под аккаунтным Ed25519, per-account изоляция, отложенный
 * cert без аккаунтного ключа.
 */

const { getClientDeviceId } = require('../utils.js');
const {
    loadOrCreateDeviceIdentity, certMessage, clearDeviceIdentity,
} = require('../dr/device-identity.js');
const { loadOrCreateEd25519Identity } = require('../dr/prekeys.js');

const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function verifyEd25519(pubHex, msgBytes, sigHex) {
    const key = await globalThis.crypto.subtle.importKey('raw', fromHex(pubHex), { name: 'Ed25519' }, false, ['verify']);
    return globalThis.crypto.subtle.verify('Ed25519', key, fromHex(sigHex), msgBytes);
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState = { user: { user_id: 42 } };
});

describe('getClientDeviceId', () => {
    test('стабильный 16-байтный hex, персистится', () => {
        const id = getClientDeviceId();
        expect(id).toMatch(/^[0-9a-f]{32}$/);
        expect(getClientDeviceId()).toBe(id);
        expect(localStorage.getItem('vortex_client_device_id')).toBe(id);
    });

    test('мигрирует legacy-формат (не 32-hex) в стабильный', () => {
        localStorage.setItem('vortex_client_device_id', '12345');   // legacy Date.now()-стиль
        const id = getClientDeviceId();
        expect(id).toMatch(/^[0-9a-f]{32}$/);
        expect(id).not.toBe('12345');
    });
});

describe('loadOrCreateDeviceIdentity — тройка ключей', () => {
    test('создаёт тройку {X3DH, signing, cert}', async () => {
        await loadOrCreateEd25519Identity();   // аккаунтный Ed25519 присутствует
        const idn = await loadOrCreateDeviceIdentity();
        expect(idn.x3dhPub).toMatch(/^[0-9a-f]{64}$/);
        expect(idn.signPub).toMatch(/^[0-9a-f]{64}$/);
        expect(JSON.parse(idn.x3dhPriv).crv).toBe('X25519');
        expect(JSON.parse(idn.signPriv).crv).toBe('Ed25519');
        expect(idn.certSig).toMatch(/^[0-9a-f]{128}$/);
    });

    test('повторный вызов возвращает ту же идентичность (стабильность)', async () => {
        await loadOrCreateEd25519Identity();
        const a = await loadOrCreateDeviceIdentity();
        const b = await loadOrCreateDeviceIdentity();
        expect(b.x3dhPub).toBe(a.x3dhPub);
        expect(b.signPub).toBe(a.signPub);
        expect(b.certSig).toBe(a.certSig);
    });

    test('cert проверяется аккаунтным Ed25519 над (device_id ‖ x3dh_pub ‖ sign_pub)', async () => {
        const acc = await loadOrCreateEd25519Identity();
        const idn = await loadOrCreateDeviceIdentity();
        const msg = certMessage(idn.deviceId, idn.x3dhPub, idn.signPub);
        expect(await verifyEd25519(acc.pubHex, msg, idn.certSig)).toBe(true);
    });

    test('подмена sign_pub ломает проверку cert (binding реален)', async () => {
        const acc = await loadOrCreateEd25519Identity();
        const idn = await loadOrCreateDeviceIdentity();
        const forged = certMessage(idn.deviceId, idn.x3dhPub, 'ff'.repeat(32));
        expect(await verifyEd25519(acc.pubHex, forged, idn.certSig)).toBe(false);
    });

    test('без аккаунтного Ed25519 cert откладывается (не создаём аккаунтный ключ)', async () => {
        // Аккаунтного Ed25519 нет локально (свежелинкованное устройство)
        const idn = await loadOrCreateDeviceIdentity();
        expect(idn.certSig).toBeNull();
        // Аккаунтный Ed25519 НЕ должен был быть создан (иначе — дивергентная идентичность)
        expect(localStorage.getItem('vortex_ed25519_identity_42')).toBeNull();
    });

    test('cert выпускается позже, когда аккаунтный Ed25519 появился', async () => {
        const first = await loadOrCreateDeviceIdentity();   // без cert
        expect(first.certSig).toBeNull();
        await loadOrCreateEd25519Identity();                // аккаунт восстановлен
        const second = await loadOrCreateDeviceIdentity();  // тот же device, теперь cert есть
        expect(second.x3dhPub).toBe(first.x3dhPub);         // ключи те же
        expect(second.certSig).toMatch(/^[0-9a-f]{128}$/);
    });

    test('cert ПЕРЕвыпускается при смене аккаунтного Ed25519 (self-heal, guard на валидность)', async () => {
        const acc1 = await loadOrCreateEd25519Identity();
        const idn1 = await loadOrCreateDeviceIdentity();
        expect(idn1.certSig).toMatch(/^[0-9a-f]{128}$/);

        // Симулируем logout→login без vault-restore: аккаунтный Ed25519 регенерирован,
        // а device-идентичность (ключи + старый cert) пережила logout.
        localStorage.removeItem('vortex_ed25519_identity_42');
        sessionStorage.removeItem('vortex_ed25519_identity_42');
        const acc2 = await loadOrCreateEd25519Identity();   // новый аккаунтный ключ
        expect(acc2.pubHex).not.toBe(acc1.pubHex);

        const idn2 = await loadOrCreateDeviceIdentity();
        expect(idn2.x3dhPub).toBe(idn1.x3dhPub);            // те же device-ключи
        expect(idn2.certSig).not.toBe(idn1.certSig);        // cert перевыпущен
        // Перевыпущенный cert валиден под НОВЫМ аккаунтным ключом (а не старым)
        const msg = certMessage(idn2.deviceId, idn2.x3dhPub, idn2.signPub);
        expect(await verifyEd25519(acc2.pubHex, msg, idn2.certSig)).toBe(true);
        expect(await verifyEd25519(acc1.pubHex, msg, idn2.certSig)).toBe(false);
    });

    test('per-account изоляция + clearDeviceIdentity', async () => {
        await loadOrCreateEd25519Identity();
        const a = await loadOrCreateDeviceIdentity();
        window.AppState.user.user_id = 99;
        const b = await loadOrCreateDeviceIdentity();
        expect(b.x3dhPub).not.toBe(a.x3dhPub);   // разные аккаунты — разные device-идентичности
        clearDeviceIdentity(42);
        window.AppState.user.user_id = 42;
        const a2 = await loadOrCreateDeviceIdentity();
        expect(a2.x3dhPub).not.toBe(a.x3dhPub);   // после clear — новая
    });
});

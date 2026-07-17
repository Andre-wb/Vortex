/**
 * prekeys.test.js
 * Тесты Ed25519-идентичности и сборки prekey-бандла.
 * Включает JS↔Python interop против векторов из app/tests/vectors/dr_vectors.json
 * (тот же spk_signature, что проверяет double_ratchet.py в test_double_ratchet.py).
 */

const fs = require('fs');
const path = require('path');

const {
    loadOrCreateEd25519Identity,
    edSign, edVerify,
    buildPrekeyBundle,
    saveAccountLinkMaterial,
} = require('../dr/prekeys.js');
const { getClientDeviceId } = require('../utils.js');
const {
    certMessage, verifyDeviceCert, loadOrCreateDeviceIdentity, applyIssuedCert,
} = require('../dr/device-identity.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    // Идентичность строго per-account — loadOrCreate требует user_id.
    window.AppState = { user: { user_id: 42 } };
});

async function verifyEd25519(pubHex, messageBytes, sigHex) {
    const key = await globalThis.crypto.subtle.importKey(
        'raw', fromHex(pubHex), { name: 'Ed25519' }, false, ['verify']
    );
    return globalThis.crypto.subtle.verify('Ed25519', key, fromHex(sigHex), messageBytes);
}

describe('Ed25519 identity', () => {
    test('генерирует и персистит идентичность в per-account слот', async () => {
        const id = await loadOrCreateEd25519Identity();
        expect(id.pubHex).toMatch(/^[0-9a-f]{64}$/);
        expect(JSON.parse(id.privJwk).crv).toBe('Ed25519');
        expect(localStorage.getItem('vortex_ed25519_identity_42')).toBe(id.privJwk);
    });

    test('повторный вызов возвращает ту же идентичность', async () => {
        const a = await loadOrCreateEd25519Identity();
        const b = await loadOrCreateEd25519Identity();
        expect(b.pubHex).toBe(a.pubHex);
        expect(b.privJwk).toBe(a.privJwk);
    });

    test('reload вкладки (sessionStorage очищен) сохраняет идентичность, pub выводится из priv', async () => {
        const a = await loadOrCreateEd25519Identity();
        sessionStorage.clear();                 // как после перезагрузки страницы
        const b = await loadOrCreateEd25519Identity();
        expect(b.pubHex).toBe(a.pubHex);        // та же идентичность, не новая
        expect(b.privJwk).toBe(a.privJwk);
    });

    test('разные аккаунты на одном устройстве получают РАЗНЫЕ идентичности', async () => {
        window.AppState.user.user_id = 1;
        const a = await loadOrCreateEd25519Identity();
        window.AppState.user.user_id = 2;
        const b = await loadOrCreateEd25519Identity();
        expect(b.pubHex).not.toBe(a.pubHex);    // нет утечки идентичности между аккаунтами
        // Возврат к первому аккаунту даёт исходную идентичность
        window.AppState.user.user_id = 1;
        const a2 = await loadOrCreateEd25519Identity();
        expect(a2.pubHex).toBe(a.pubHex);
    });

    test('без залогиненного пользователя — ошибка (нет device-global идентичности)', async () => {
        window.AppState = { user: {} };
        await expect(loadOrCreateEd25519Identity()).rejects.toThrow();
    });

    test('подпись проверяется собственным публичным ключом', async () => {
        const id = await loadOrCreateEd25519Identity();
        const msg = new TextEncoder().encode('hello ratchet');
        const sig = await edSign(id.privJwk, msg);
        expect(await verifyEd25519(id.pubHex, msg, sig)).toBe(true);
    });
});

describe('buildPrekeyBundle', () => {
    test('SPK подписан device signing-ключом, identity_key — аккаунтным (binding)', async () => {
        await loadOrCreateEd25519Identity();     // идентичность должна существовать
        const identityKeyHex = 'ab'.repeat(32);
        const bundle = await buildPrekeyBundle(identityKeyHex, 3);

        expect(bundle.identity_key).toBe(identityKeyHex);
        expect(bundle.signed_prekey).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.signed_prekey_sig).toMatch(/^[0-9a-f]{128}$/);
        expect(bundle.identity_key_ed).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.device_sign_pub).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.one_time_prekeys).toHaveLength(3);

        // SPK-подпись проверяется по DEVICE signing-ключу (не аккаунтному)
        expect(await verifyEd25519(
            bundle.device_sign_pub, fromHex(bundle.signed_prekey), bundle.signed_prekey_sig
        )).toBe(true);
        // SPK НЕ подписан аккаунтным Ed25519 (свап цепочки на device-ключ)
        expect(await verifyEd25519(
            bundle.identity_key_ed, fromHex(bundle.signed_prekey), bundle.signed_prekey_sig
        )).toBe(false);
        // Cross-signature: identity_key подписан аккаунтным ключом (binding, остаётся)
        expect(await verifyEd25519(
            bundle.identity_key_ed, fromHex(bundle.identity_key), bundle.identity_key_sig
        )).toBe(true);
    });

    test('публикует device-identity тройку с валидным cert (self-sign первого устройства)', async () => {
        await loadOrCreateEd25519Identity();     // аккаунтный Ed25519 присутствует → cert self-sign
        const bundle = await buildPrekeyBundle('ab'.repeat(32), 2);

        expect(bundle.device_x3dh_pub).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.device_sign_pub).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.device_cert_sig).toMatch(/^[0-9a-f]{128}$/);

        // Cert, СГЕНЕРИРОВАННЫЙ клиентом, верифицируется против опубликованного
        // identity_key_ed по certMessage(deviceId, x3dhPub, signPub) — именно это
        // проверит отправитель на fan-out. Замыкает серверный round-trip тест.
        const msg = certMessage(getClientDeviceId(), bundle.device_x3dh_pub, bundle.device_sign_pub);
        expect(await verifyEd25519(bundle.identity_key_ed, msg, bundle.device_cert_sig)).toBe(true);
    });

    test('M4b: устройство БЕЗ аккаунтного Ed-приватного публикует бандл, принятый sender-цепочкой', async () => {
        // Линкованное устройство: аккаунтного Ed25519-приватного НЕТ; аккаунт-материал
        // (account_ed_pub + identity_key_sig) и cert выданы одобряющим при линковке.
        const acctX25519 = 'ab'.repeat(32);                 // аккаунтный X25519 identity_key
        // Аккаунтный Ed25519 (у одобряющего; локально НЕ хранится)
        const acctEd = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
        const acctEdPub = toHex(await globalThis.crypto.subtle.exportKey('raw', acctEd.publicKey));
        const edSignRaw = async (m) => toHex(await globalThis.crypto.subtle.sign('Ed25519', acctEd.privateKey, m));

        const device = await loadOrCreateDeviceIdentity();  // тройка, certSig=null (нет локального аккаунтного Ed)
        // Одобряющий подписывает cert устройства + отдаёт аккаунт-материал:
        const certSig = await edSignRaw(certMessage(getClientDeviceId(), device.x3dhPub, device.signPub));
        applyIssuedCert(42, certSig, acctEdPub);
        const idSig = await edSignRaw(fromHex(acctX25519));
        saveAccountLinkMaterial(42, acctEdPub, idSig);

        // Аккаунтного Ed-приватного локально нет — done-signal: publish НЕ бросает
        const bundle = await buildPrekeyBundle(acctX25519, 2);

        expect(bundle.identity_key_ed).toBe(acctEdPub);
        expect(bundle.device_cert_sig).toBe(certSig);
        // Sender-цепочка принимает бандл: cert против account_ed, SPK device-ключом, idSig
        expect(await verifyDeviceCert(
            getClientDeviceId(), bundle.device_x3dh_pub, bundle.device_sign_pub, bundle.device_cert_sig, acctEdPub
        )).toBe(true);
        expect(await verifyEd25519(bundle.device_sign_pub, fromHex(bundle.signed_prekey), bundle.signed_prekey_sig)).toBe(true);
        expect(await verifyEd25519(bundle.identity_key_ed, fromHex(bundle.identity_key), bundle.identity_key_sig)).toBe(true);
    });
});

describe('JS↔Python interop (векторы)', () => {
    const vectorsPath = path.resolve(__dirname, '../../../app/tests/vectors/dr_vectors.json');

    test('подпись SPK из dr_vectors.json проверяется в Web Crypto Ed25519', async () => {
        const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
        const v = vectors.spk_signature;
        // Python (double_ratchet.sign_spk) подписал spk_pub ключом ed25519_pub —
        // Web Crypto обязан подтвердить ту же подпись над теми же 32 raw-байтами.
        expect(await verifyEd25519(v.ed25519_pub, fromHex(v.spk_pub), v.signature)).toBe(true);
    });

    test('порча подписи из вектора отвергается', async () => {
        const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
        const v = vectors.spk_signature;
        const tampered = v.signature.slice(0, -2) + (v.signature.endsWith('00') ? '01' : '00');
        expect(await verifyEd25519(v.ed25519_pub, fromHex(v.spk_pub), tampered)).toBe(false);
    });

    test('device_cert из вектора: certMessage совпадает байт-в-байт и cert валиден', async () => {
        const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
        const v = vectors.device_cert;
        // Раскладка cert-сообщения JS обязана совпасть с Python (cid‖x3dh‖sign)
        const msg = certMessage(v.client_device_id, v.device_x3dh_pub, v.device_sign_pub);
        expect(toHex(msg)).toBe(v.cert_message);
        // Cert, подписанный Python-аккаунтным Ed25519, проверяется в JS
        expect(await verifyDeviceCert(
            v.client_device_id, v.device_x3dh_pub, v.device_sign_pub, v.cert_sig, v.account_ed_pub
        )).toBe(true);
    });

    test('device_cert: порча любого поля → cert не проверяется', async () => {
        const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
        const v = vectors.device_cert;
        const flip = h => h.slice(0, -2) + (h.endsWith('00') ? '01' : '00');
        // подмена x3dh-ключа (пересборка cert-сообщения) → подпись не сходится
        expect(await verifyDeviceCert(
            v.client_device_id, flip(v.device_x3dh_pub), v.device_sign_pub, v.cert_sig, v.account_ed_pub
        )).toBe(false);
        // порча самой подписи
        expect(await verifyDeviceCert(
            v.client_device_id, v.device_x3dh_pub, v.device_sign_pub, flip(v.cert_sig), v.account_ed_pub
        )).toBe(false);
    });
});

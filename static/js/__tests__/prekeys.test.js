/**
 * prekeys.test.js
 * Тесты Ed25519-идентичности и сборки prekey-бандла (ADR-001, батч 4).
 * Включает JS↔Python interop против векторов из app/tests/vectors/dr_vectors.json
 * (тот же spk_signature, что проверяет double_ratchet.py в test_double_ratchet.py).
 */

const fs = require('fs');
const path = require('path');

const {
    loadOrCreateEd25519Identity,
    edSign,
    buildPrekeyBundle,
} = require('../dr/prekeys.js');

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
    test('SPK и identity_key подписаны Ed25519-идентичностью (обе подписи валидны)', async () => {
        const identityKeyHex = 'ab'.repeat(32);  // фиктивный X25519 pub (32 байта)
        const bundle = await buildPrekeyBundle(identityKeyHex, 3);

        expect(bundle.identity_key).toBe(identityKeyHex);
        expect(bundle.signed_prekey).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.signed_prekey_sig).toMatch(/^[0-9a-f]{128}$/);
        expect(bundle.identity_key_ed).toMatch(/^[0-9a-f]{64}$/);
        expect(bundle.one_time_prekeys).toHaveLength(3);

        // SPK-подпись проверяется по опубликованному Ed25519-ключу
        expect(await verifyEd25519(
            bundle.identity_key_ed, fromHex(bundle.signed_prekey), bundle.signed_prekey_sig
        )).toBe(true);
        // Cross-signature: identity_key подписан тем же ключом (binding, ADR §2.4г)
        expect(await verifyEd25519(
            bundle.identity_key_ed, fromHex(bundle.identity_key), bundle.identity_key_sig
        )).toBe(true);
    });
});

describe('JS↔Python interop (векторы батча 1)', () => {
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
});

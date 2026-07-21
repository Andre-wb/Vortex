// offline-invite.spec.js
// ГЕЙТ активации directed-invite pre-provision (ADR-005 O2a) в РЕАЛЬНОМ браузере.
// provisionRoomKeyForUser оборачивает room key для target и POST'ит на O1-эндпоинт
// /api/rooms/{id}/provision-key. Гейт проверяет: за флагом (дефолт ВЫКЛ → skip);
// с флагом + PQ-capable target → гибридный конверт в POST; verify подписи Kyber-pub
// против припиненного Ed (тот же resolvePeerKyberPub, real Web Crypto).
//
// Требует запущенного сервера (Vortex), раздающего static/js/* как ESM.
// Запуск: VORTEX_URL=http://localhost:8000 node_modules/.bin/playwright test offline-invite
//
// БЛОКЕР флипа vortex_offline_invite_enabled: гейт зелёный (≥ Chrome + Firefox)
// ДО включения directed-invite.

const { test, expect } = require('@playwright/test');

test.describe('Directed-invite pre-provision (real browser)', () => {
    test('flag-gated wrap + hybrid POST to provision-key', async ({ page }) => {
        const captured = [];
        // Перехватываем POST provision-key — фиксируем тело, не бьём в БД
        await page.route('**/api/rooms/*/provision-key', async (route) => {
            captured.push(JSON.parse(route.request().postData() || '{}'));
            await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
        });

        await page.goto('/');

        const out = await page.evaluate(async () => {
            const CORE = await import('/static/js/rooms/core.js');
            const CRYPTO = await import('/static/js/crypto.js');
            const MLKEM = await import('/static/js/dr/mlkem.js');
            const KID = await import('/static/js/dr/kyber-identity.js');
            const PIN = await import('/static/js/dr/identity-pin.js');

            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const res = {};

            const roomId = 4242, targetId = 77;
            const roomKey = crypto.getRandomValues(new Uint8Array(32));
            CRYPTO.setRoomKey(roomId, roomKey);

            // target: X25519 + аккаунтный Kyber, подписанный аккаунтным Ed (припинен)
            const tx = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const tX25519 = toHex(await crypto.subtle.exportKey('raw', tx.publicKey));
            const tKyber = MLKEM.mlkemKeygen();
            const edPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const edPubHex = toHex(await crypto.subtle.exportKey('raw', edPair.publicKey));
            const edPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', edPair.privateKey));
            const sig = await KID.signKyberPub(tKyber.publicKeyHex, edPrivJwk);
            PIN.pinPeerAccountEd(targetId, edPubHex);   // TOFU-пин корня доверия

            const pubkeys = {
                x25519_public_key: tX25519,
                kyber_public_key: tKyber.publicKeyHex,
                kyber_public_key_sig: sig,
            };

            // 1. Оба флага ВЫКЛ → skip, без POST
            localStorage.removeItem('vortex_offline_invite_enabled');
            localStorage.removeItem('vortex_pq_hybrid_enabled');
            res.flag_off = await CORE.provisionRoomKeyForUser(roomId, targetId, pubkeys);

            // 2. Только offline-invite → КЛАССИКА (гибрид требует и vortex_pq_hybrid_enabled)
            localStorage.setItem('vortex_offline_invite_enabled', '1');
            res.classical = await CORE.provisionRoomKeyForUser(roomId, targetId, pubkeys);

            // 3. Оба флага + capable target → ГИБРИД
            localStorage.setItem('vortex_pq_hybrid_enabled', '1');
            res.hybrid = await CORE.provisionRoomKeyForUser(roomId, targetId, pubkeys);

            return res;
        });

        expect(out.flag_off.skipped, 'both flags off → skip').toBe('flag_off');
        expect(out.classical.ok, 'offline flag on → provisioned').toBe(true);
        expect(out.classical.hybrid, 'offline flag alone → classical (PQ needs its own flag)').toBe(false);
        expect(out.hybrid.ok, 'both flags on → provisioned').toBe(true);
        expect(out.hybrid.hybrid, 'both flags + capable target → hybrid').toBe(true);

        // Ровно два POST (первый skip'нут); [0] классика, [1] гибрид
        expect(captured.length, 'two provision POSTs (both-off skipped)').toBe(2);
        const cl = captured[0], hy = captured[1];
        expect(cl.for_user_id).toBe(77);
        expect(cl.ephemeral_pub).toMatch(/^[0-9a-f]{64}$/);
        expect(cl.hybrid, 'classical POST has no hybrid marker').toBeUndefined();
        expect(cl.kyber_ciphertext, 'classical POST has no kyber_ciphertext').toBeUndefined();
        expect(hy.hybrid).toBe(true);
        expect(hy.kyber_ciphertext).toMatch(/^[0-9a-f]{2176}$/);
        expect(hy.x25519_ephemeral_pub).toMatch(/^[0-9a-f]{64}$/);
    });
});

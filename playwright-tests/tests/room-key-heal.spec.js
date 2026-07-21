// room-key-heal.spec.js
// ГЕЙТ self-heal негодного room-key (ADR-005 §4.0 / O2b) в РЕАЛЬНОМ браузере.
// LIVE/always-on/деструктивно. Два теста:
//   A. Правило детекции на РЕАЛЬНЫХ ошибках движка (неверный Kyber→AEAD→heal,
//      нет Kyber→skip; DELETE только на heal; bounded-not-spinning).
//   B. РЕАЛЬНЫЙ e2e: отравленный ключ через настоящий _pullKeyFromServer →
//      DELETE серверной строки с ПРАВИЛЬНЫМ roomId (не inspection-only wiring).
//
// Требует запущенного сервера (Vortex), раздающего static/js/* как ESM.
// Запуск: VORTEX_URL=http://localhost:8000 node_modules/.bin/playwright test room-key-heal

const { test, expect } = require('@playwright/test');

test.describe('Room-key self-heal (real browser)', () => {
    test('A. detection rule matches real engine errors + DELETE + bounded', async ({ page }) => {
        const deletes = [];
        await page.route('**/api/rooms/*/my-key', async (route) => {
            if (route.request().method() === 'DELETE') deletes.push(route.request().url());
            await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
        });
        await page.goto('/');

        const out = await page.evaluate(async () => {
            const CRYPTO = await import('/static/js/crypto.js');
            const MLKEM = await import('/static/js/dr/mlkem.js');
            const HEAL = await import('/static/js/chat/room-crypto.js');
            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const res = {};
            const uid = 4242;
            window.AppState = { user: { user_id: uid } };
            const rx = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const rxPubHex = toHex(await crypto.subtle.exportKey('raw', rx.publicKey));
            const rxPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', rx.privateKey));
            const kyber = MLKEM.mlkemKeygen();
            const roomKey = crypto.getRandomValues(new Uint8Array(32));
            const env = await CRYPTO.hybridEciesEncrypt(roomKey, rxPubHex, kyber.publicKeyHex);

            const wrong = MLKEM.mlkemKeygen();
            localStorage.setItem(`vortex_kyber_priv_${uid}`, wrong.secretKeyHex);
            let aeadErr = null;
            try { await CRYPTO.decryptRoomKeyEnvelope(env, rxPrivJwk); } catch (e) { aeadErr = e; }
            res.aead_heal = await HEAL.selfHealRoomKey(101, aeadErr, true);

            localStorage.removeItem(`vortex_kyber_priv_${uid}`);
            let kyberErr = null;
            try { await CRYPTO.decryptRoomKeyEnvelope(env, rxPrivJwk); } catch (e) { kyberErr = e; }
            res.kyber_error_msg = kyberErr && kyberErr.message;
            res.kyber_heal = await HEAL.selfHealRoomKey(202, kyberErr, true);

            HEAL.markRoomKeyHealthy(303);
            res.b1 = await HEAL.selfHealRoomKey(303, aeadErr, true);
            res.b2 = await HEAL.selfHealRoomKey(303, aeadErr, true);
            res.b3 = await HEAL.selfHealRoomKey(303, aeadErr, true);
            return res;
        });

        expect(out.aead_heal, 'wrong Kyber priv (AEAD fail) → heal').toBe('healing');
        expect(out.kyber_error_msg, 'missing Kyber → explicit error').toMatch(/Kyber identity/i);
        expect(out.kyber_heal, 'missing Kyber → skip (non-healable)').toBe('skip');
        expect(out.b1).toBe('healing');
        expect(out.b2).toBe('healing');
        expect(out.b3, 'after HEAL_MAX → unrecoverable, no spin').toBe('unrecoverable');
        expect(deletes.length, 'DELETE only on heals, never on skip').toBe(3);
    });

    test('B. e2e: poisoned key through real _pullKeyFromServer → DELETE with correct roomId', async ({ page }) => {
        const ROOM_ID = 555;
        let poisoned = null;               // тело key-bundle, заполняется после сборки в браузере
        const deletes = [];

        await page.route('**/api/rooms/*/key-bundle', async (route) => {
            await route.fulfill({ status: 200, contentType: 'application/json',
                body: JSON.stringify(poisoned || { has_key: false }) });
        });
        await page.route('**/api/rooms/*/my-key', async (route) => {
            if (route.request().method() === 'DELETE') deletes.push(route.request().url());
            await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
        });

        await page.goto('/');

        // 1. Собираем отравленный ключ в браузере: обёрнут на наш X25519 + Kyber-pub,
        //    но в слот кладём ЧУЖОЙ Kyber-priv → decaps даст другой shared → AEAD-провал.
        const built = await page.evaluate(async () => {
            const CRYPTO = await import('/static/js/crypto.js');
            const MLKEM = await import('/static/js/dr/mlkem.js');
            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const uid = 4242;
            const rx = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const rxPubHex = toHex(await crypto.subtle.exportKey('raw', rx.publicKey));
            const rxPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', rx.privateKey));
            const kyber = MLKEM.mlkemKeygen();
            const wrong = MLKEM.mlkemKeygen();
            const roomKey = crypto.getRandomValues(new Uint8Array(32));
            const env = await CRYPTO.hybridEciesEncrypt(roomKey, rxPubHex, kyber.publicKeyHex);
            return { env, rxPrivJwk, wrongKyberPriv: wrong.secretKeyHex, uid };
        });

        poisoned = { has_key: true, ...built.env };   // key-bundle отдаст его

        // 2. Прогоняем НАСТОЯЩИЙ _pullKeyFromServer с загруженным (но негодным для этого ключа) состоянием.
        await page.evaluate(async ({ built, ROOM_ID }) => {
            const WS = await import('/static/js/chat/websocket.js');
            window.AppState = {
                x25519PrivateKey: built.rxPrivJwk,
                token: '',
                user: { user_id: built.uid },
                currentRoom: { id: ROOM_ID },
            };
            localStorage.setItem(`vortex_kyber_priv_${built.uid}`, built.wrongKyberPriv);
            await WS._pullKeyFromServer(ROOM_ID);
        }, { built, ROOM_ID });

        // 3. Настоящий хендлер довёл decrypt-провал до self-heal → DELETE серверной строки
        expect(deletes.length, 'real _pullKeyFromServer wiring fired self-heal DELETE').toBe(1);
        expect(deletes[0], 'DELETE targets the correct roomId').toContain(`/api/rooms/${ROOM_ID}/my-key`);
    });
});

// invite-link.spec.js
// ГЕЙТ offline-invite escrow (ADR-005 O5b+O6) в РЕАЛЬНОМ браузере. Full round-trip:
// createInviteLink оборачивает room key на invite-pub (O5b), redeemInviteEscrow
// извлекает приватные из ФРАГМЕНТА, фетчит escrow, расшифровывает = исходный room
// key (O6). Плюс re-wrap на ротации. Всё за флагом vortex_offline_invite_enabled.
//
// Требует запущенного сервера. Запуск:
//   VORTEX_URL=http://localhost:8000 node_modules/.bin/playwright test invite-link

const { test, expect } = require('@playwright/test');

test.describe('Offline-invite escrow (real browser)', () => {
    test('createInviteLink → redeemInviteEscrow round-trip + re-wrap', async ({ page }) => {
        const state = { escrows: [], lastEscrow: null, invites: [] };

        // Один route на invite-escrow с диспетчем по методу
        await page.route('**/api/rooms/*/invite-escrow*', async (route) => {
            const req = route.request();
            if (req.method() === 'POST') {
                const body = JSON.parse(req.postData() || '{}');
                state.escrows.push(body);
                state.lastEscrow = body;
                await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
            } else { // GET — отдаём последний сохранённый escrow
                const e = state.lastEscrow;
                await route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify(e ? { has_escrow: true, hybrid: true,
                        x25519_ephemeral_pub: e.x25519_ephemeral_pub,
                        kyber_ciphertext: e.kyber_ciphertext, ciphertext: e.ciphertext }
                        : { has_escrow: false }) });
            }
        });
        await page.route('**/api/rooms/*/invites', async (route) => {
            await route.fulfill({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ invites: state.invites }) });
        });

        await page.goto('/');

        // O5b: создать ссылку (обёртка + escrow-POST)
        const created = await page.evaluate(async () => {
            const IL = await import('/static/js/dr/invite-link.js');
            const CRYPTO = await import('/static/js/crypto.js');
            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            localStorage.setItem('vortex_offline_invite_enabled', '1');
            const roomKey = crypto.getRandomValues(new Uint8Array(32));
            CRYPTO.setRoomKey(42, roomKey);
            const link = await IL.createInviteLink(42, 'ABC123');
            return { link, roomKeyHex: toHex(roomKey) };
        });

        expect(state.escrows.length).toBe(1);
        expect(state.lastEscrow.hybrid).toBe(true);
        expect(state.lastEscrow.invite_pub).toMatch(/^[0-9a-f]{64}$/);
        expect(state.lastEscrow.invite_kyber_pub).toMatch(/^[0-9a-f]{2368}$/);
        expect(created.link).toMatch(/\/join\/ABC123#/);
        state.invites = [{ invite_pub: state.lastEscrow.invite_pub, invite_kyber_pub: state.lastEscrow.invite_kyber_pub }];

        // O6: вступающий (свежая комната без ключа) забирает и расшифровывает
        const decrypted = await page.evaluate(async ({ link }) => {
            const IL = await import('/static/js/dr/invite-link.js');
            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const rk = await IL.redeemInviteEscrow(9999, '#' + link.split('#')[1]);
            return rk ? toHex(rk) : null;
        }, { link: created.link });
        expect(decrypted, 'redeem: fragment → escrow → original room key').toBe(created.roomKeyHex);

        // O5b re-wrap на ротации: GET /invites → повторный escrow-POST на persisted invite
        state.escrows = [];
        await page.evaluate(async () => {
            const IL = await import('/static/js/dr/invite-link.js');
            await IL.rewrapInvitesAfterRotation(42, crypto.getRandomValues(new Uint8Array(32)));
        });
        expect(state.escrows.length, 're-wrap POSTed for persisted invite').toBe(1);
        expect(state.escrows[0].invite_pub).toBe(state.invites[0].invite_pub);
        expect(state.escrows[0].hybrid).toBe(true);
    });
});

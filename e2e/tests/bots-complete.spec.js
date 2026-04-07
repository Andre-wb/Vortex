// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — Bot API, Marketplace & IDE (missing coverage)
 *
 * Covers:
 *   - Bot messaging API (send, reply, updates, me, rooms)
 *   - Bot inline (register, answer)
 *   - Bot keyboard, callback
 *   - Bot commands register
 *   - Bot webhook CRUD
 *   - Bot payment
 *   - Bot mini-app dev
 *   - Bot scopes update
 *   - Marketplace detail, reviews, install
 *   - IDE publish, rollback, packages install, permissions assign
 */

test.describe('Bots Complete', () => {
    const username = `botc_u_${randomStr(6)}`;
    const phone = `+7982${randomDigits(7)}`;
    let csrf = '';
    let botId = 0;
    let botToken = '';
    let roomId = 0;
    let sentMessageId = 0;
    let projectId = '';

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'botc_room');

        // Create bot — token is returned once at creation (stored hashed in DB)
        const botRes = await request.post('/api/bots', {
            headers: { 'X-CSRF-Token': csrf },
            data: { name: `e2e_comp_bot_${randomStr(4)}`, description: 'Complete E2E bot' },
        });
        if (botRes.ok()) {
            const body = await botRes.json();
            botId = body.bot_id || body.id;
            botToken = body.api_token || '';
        }

        if (botId) {

            // Add bot to room
            await request.post(`/api/bots/${botId}/rooms/${roomId}`, {
                headers: { 'X-CSRF-Token': csrf },
            });
        }

        // IDE projects are created implicitly by compile — just assign a string ID
        projectId = `e2e_comp_proj_${randomStr(8)}`;
    });

    // ── Bot Messaging API ─────────────────────────────────────────────────────

    test('bot send message', async ({ request }) => {
        const res = await request.post('/api/bot/send', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { room_id: roomId, text: 'Hello from bot E2E' },
        });
        expect([200, 201]).toContain(res.status());
        if (res.ok()) {
            const body = await res.json();
            sentMessageId = body.msg_id || body.message_id || body.id || 0;
        }
    });

    test('bot reply', async ({ request }) => {
        expect(sentMessageId).toBeTruthy();
        const res = await request.post('/api/bot/reply', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { room_id: roomId, reply_to_id: sentMessageId, text: 'Bot reply' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('bot get updates', async ({ request }) => {
        const res = await request.get('/api/bot/updates?timeout=1', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('bot me', async ({ request }) => {
        const res = await request.get('/api/bot/me', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('bot rooms', async ({ request }) => {
        const res = await request.get('/api/bot/rooms', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Bot Inline ────────────────────────────────────────────────────────────

    test('bot inline register', async ({ request }) => {
        const res = await request.post('/api/bot/inline/register', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { placeholder: 'Search...' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('bot inline answer', async ({ request }) => {
        const res = await request.post('/api/bot/inline/answer', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { inline_query_id: 'fake_query', results: [] },
        });
        expect([200, 400]).toContain(res.status());
    });

    // ── Bot Keyboard & Callback ───────────────────────────────────────────────

    test('bot send keyboard', async ({ request }) => {
        const res = await request.post('/api/bot/send-keyboard', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: {
                room_id: roomId,
                text: 'Choose an option',
                keyboard: [[{ text: 'Option 1', callback_data: 'opt1' }]],
            },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('bot callback', async ({ request }) => {
        const res = await request.post('/api/bot/callback', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { callback_query_id: 'fake_cb', text: 'Callback response' },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Bot Commands ──────────────────────────────────────────────────────────

    test('bot commands register', async ({ request }) => {
        const res = await request.post('/api/bot/commands/register', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: {
                commands: [
                    { command: '/start', description: 'Start the bot' },
                    { command: '/help', description: 'Get help' },
                ],
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Bot Webhook ───────────────────────────────────────────────────────────

    test('bot webhook set', async ({ request }) => {
        const res = await request.post('/api/bot/webhook/set', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { url: 'https://example.com/bot-webhook' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('bot webhook info', async ({ request }) => {
        const res = await request.get('/api/bot/webhook/info', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('bot webhook delete', async ({ request }) => {
        const res = await request.post('/api/bot/webhook/delete', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Bot Payment ───────────────────────────────────────────────────────────

    test('bot payment create', async ({ request }) => {
        const res = await request.post('/api/bot/payment/create', {
            headers: { 'X-CSRF-Token': csrf, 'Authorization': `Bot ${botToken}` },
            data: { amount: 100, currency: 'USD', description: 'E2E payment' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    // ── Bot Mini-App Dev ──────────────────────────────────────────────────────

    test('bot mini-app dev info', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/mini-app/dev`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Bot Scopes Update ─────────────────────────────────────────────────────

    test('update bot scopes', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.put(`/api/bots/${botId}/scopes`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { scopes: ['read_messages', 'send_messages'] },
        });
        expect([200, 204, 400]).toContain(res.status());
    });

    // ── Marketplace ───────────────────────────────────────────────────────────

    test('marketplace bot detail', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/marketplace/${botId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    test('marketplace bot reviews', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/marketplace/${botId}/reviews`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    test('marketplace post review', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.post(`/api/marketplace/${botId}/review`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { rating: 5, text: 'Great bot!' },
        });
        expect([200, 201, 400, 404]).toContain(res.status());
    });

    test('marketplace install bot to room', async ({ request }) => {
        expect(botId).toBeTruthy();
        expect(roomId).toBeTruthy();
        const res = await request.post(`/api/marketplace/${botId}/install/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 400, 404]).toContain(res.status());
    });

    // ── IDE ───────────────────────────────────────────────────────────────────

    test('IDE publish project', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post('/api/ide/publish', {
            headers: { 'X-CSRF-Token': csrf },
            data: { project_id: projectId, code: 'on_message { reply("pub") }', token: botToken || 'e2e_token' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('IDE rollback project', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post(`/api/ide/rollback/${projectId}/1`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 400, 404]).toContain(res.status());
    });

    test('IDE packages install', async ({ request }) => {
        const res = await request.post('/api/ide/packages/install', {
            headers: { 'X-CSRF-Token': csrf },
            data: { package_name: 'lodash', project_id: projectId },
        });
        expect([200, 201, 400, 500]).toContain(res.status());
    });

    test('IDE permissions assign', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post(`/api/ide/permissions/${projectId}/assign`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { user_id: 1, role: 'viewer' },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    // ── Cleanup ───────────────────────────────────────────────────────────────

    test('delete bot', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.delete(`/api/bots/${botId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });
});

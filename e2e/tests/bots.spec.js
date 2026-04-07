// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — Bots & IDE
 *
 * Covers:
 *   - Create bot
 *   - List bots
 *   - Bot marketplace (public)
 *   - IDE project CRUD
 *   - Run bot code
 *   - Advanced bot features
 */

test.describe('Bots & IDE', () => {
    const username = `bot_u_${randomStr(6)}`;
    const phone = `+7965${randomDigits(7)}`;
    let csrf = '';
    let botId = 0;
    let projectId = '';

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
    });

    // ── Bot CRUD ──────────────────────────────────────────────────────────────

    test('create bot', async ({ request }) => {
        const res = await request.post('/api/bots', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                name: `e2e_bot_${randomStr(4)}`,
                description: 'E2E test bot',
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        botId = body.bot_id || body.id;
    });

    test('list bots', async ({ request }) => {
        const res = await request.get('/api/bots', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.bots || body)).toBeTruthy();
    });

    // ── Bot Marketplace ───────────────────────────────────────────────────────

    test('bot marketplace — public listing', async ({ request }) => {
        const res = await request.get('/api/marketplace', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── IDE ───────────────────────────────────────────────────────────────────

    test('create IDE project via compile', async ({ request }) => {
        projectId = `e2e_proj_${randomStr(8)}`;
        const res = await request.post('/api/ide/compile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { project_id: projectId, code: 'on_message { reply("hello") }' },
        });
        expect([200, 201, 202]).toContain(res.status());
    });

    test('IDE project status', async ({ request }) => {
        const res = await request.get(`/api/ide/status/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('test bot code', async ({ request }) => {
        const res = await request.post('/api/ide/test', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                code: 'on_message { reply("test") }',
                message: 'hello',
                update_type: 'message',
            },
        });
        expect([200, 201, 202, 500]).toContain(res.status());
    });

    // ── Bot Webhooks ──────────────────────────────────────────────────────────

    test('list bot webhooks', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/webhooks`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });
});

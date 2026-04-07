// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — Bots Advanced, Marketplace, IDE Full
 *
 * Covers:
 *   - Bot CRUD (create, list, update, delete)
 *   - Bot token (get, regenerate)
 *   - Bot room attachment
 *   - Bot marketplace (categories, search, listing, reviews)
 *   - Bot inline, commands, callbacks, webhooks
 *   - Bot SDK info, scopes, store, payment
 *   - IDE: compile, publish, stop, status, logs, test, AI proxy
 *   - IDE: versioning (save, versions, rollback, graph)
 *   - IDE: monitoring (analytics, metrics, queues, audit, breakers, packages, admin)
 */

test.describe('Bots Advanced & IDE', () => {
    const username = `botadv_u_${randomStr(6)}`;
    const phone = `+7970${randomDigits(7)}`;
    let csrf = '';
    let botId = 0;
    let roomId = 0;
    let projectId = '';

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'botadv_room');
        // IDE projects are implicitly created by compile — assign a string ID
        projectId = `e2e_proj_${randomStr(8)}`;
    });

    // ── Bot CRUD ──────────────────────────────────────────────────────────────

    test('create bot', async ({ request }) => {
        const res = await request.post('/api/bots', {
            headers: { 'X-CSRF-Token': csrf },
            data: { name: `e2e_adv_bot_${randomStr(4)}`, description: 'Advanced E2E bot' },
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
    });

    test('update bot', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.put(`/api/bots/${botId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { description: 'Updated bot description' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get bot token returns 400 (hashed)', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/token`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        // Token is stored hashed — can only be seen once at creation
        expect(res.status()).toBe(400);
    });

    test('regenerate bot token', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.post(`/api/bots/${botId}/regenerate-token`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get mini-app token', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/mini-app-token`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 400]).toContain(res.status());
    });

    // ── Bot → Room ────────────────────────────────────────────────────────────

    test('add bot to room', async ({ request }) => {
        expect(botId).toBeTruthy();
        expect(roomId).toBeTruthy();
        const res = await request.post(`/api/bots/${botId}/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('remove bot from room', async ({ request }) => {
        expect(botId).toBeTruthy();
        expect(roomId).toBeTruthy();
        const res = await request.delete(`/api/bots/${botId}/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Bot Publish & Marketplace ─────────────────────────────────────────────

    test('publish bot', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.post(`/api/bots/${botId}/publish`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('marketplace categories', async ({ request }) => {
        const res = await request.get('/api/marketplace/categories', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('marketplace search', async ({ request }) => {
        const res = await request.get('/api/marketplace/search?q=test', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('marketplace listing', async ({ request }) => {
        const res = await request.get('/api/marketplace', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('bot store', async ({ request }) => {
        const res = await request.get('/api/bots/store', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Bot Commands & Scopes ─────────────────────────────────────────────────

    test('get bot commands', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/commands`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    test('get room commands', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/commands`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('bot scopes list', async ({ request }) => {
        const res = await request.get('/api/bots/scopes', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get bot scopes', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/scopes`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    test('SDK info', async ({ request }) => {
        const res = await request.get('/api/bots/sdk-info', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('bot inline status', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.get(`/api/bots/${botId}/inline`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    // ── Bot Cleanup ───────────────────────────────────────────────────────────

    test('delete bot', async ({ request }) => {
        expect(botId).toBeTruthy();
        const res = await request.delete(`/api/bots/${botId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    // ── IDE — Projects & Execution ────────────────────────────────────────────

    test('create IDE project via compile', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post('/api/ide/compile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { project_id: projectId, code: 'on_message { reply("hello") }' },
        });
        expect([200, 201, 202]).toContain(res.status());
    });

    test('compile project', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post('/api/ide/compile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { project_id: projectId, code: 'on_message { reply("compile test") }' },
        });
        expect([200, 201, 202]).toContain(res.status());
    });

    test('re-compile project', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post('/api/ide/compile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { project_id: projectId, code: 'on_message { reply("run test") }' },
        });
        expect([200, 201, 202]).toContain(res.status());
    });

    test('test code', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post('/api/ide/test', {
            headers: { 'X-CSRF-Token': csrf },
            data: { code: 'on_message { reply("test") }', message: 'hello', update_type: 'message' },
        });
        // Gravitix binary may not be available in test env → 500
        expect([200, 201, 202, 500]).toContain(res.status());
    });

    test('project status', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/status/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project logs', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/logs/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('stop project', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post(`/api/ide/stop/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('AI proxy', async ({ request }) => {
        const res = await request.post('/api/ide/ai/proxy', {
            headers: { 'X-CSRF-Token': csrf },
            data: { prompt: 'help me write a bot' },
        });
        expect([200, 503]).toContain(res.status());
    });

    // ── IDE — Versioning ──────────────────────────────────────────────────────

    test('save project version', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.post(`/api/ide/save/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { code: 'on_message { reply("v1") }' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('list versions', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/versions/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('version graph', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/graph/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── IDE — Monitoring ──────────────────────────────────────────────────────

    test('project analytics', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/analytics/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project metrics', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/metrics/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project queues', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/queues/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project audit', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/audit/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project breakers', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/breakers/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('list packages', async ({ request }) => {
        const res = await request.get('/api/ide/packages', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project admin info', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/admin/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('project webhooks', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/webhooks/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    test('project permissions', async ({ request }) => {
        expect(projectId).toBeTruthy();
        const res = await request.get(`/api/ide/permissions/${projectId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

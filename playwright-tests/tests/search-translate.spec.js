// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, sendMessage } = require('./helpers');

/**
 * Vortex E2E — Search, Translation, Link Previews, AI
 *
 * Covers:
 *   - User search
 *   - Global search
 *   - Message search in room
 *   - Translation (translate text, list languages)
 *   - Link preview (Open Graph)
 *   - AI assistant (status, chat, summarize, suggest)
 *   - Reports (report user, view own strikes)
 */

test.describe('Search & Translate & AI & Reports', () => {
    const username = `srch_u_${randomStr(6)}`;
    const phone = `+7961${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;
    let userId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;

        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        userId = (await meRes.json()).user_id;

        roomId = await createRoom(request, csrf, 'search_room');
        // Send some messages for search
        await sendMessage(request, csrf, roomId, 'Hello search test message alpha');
        await sendMessage(request, csrf, roomId, 'Another search beta test message');
        await sendMessage(request, csrf, roomId, 'Third gamma message for search');
    });

    // ── User Search ───────────────────────────────────────────────────────────

    test('search users by name', async ({ request }) => {
        const res = await request.get(`/api/users/search?q=${username.slice(0, 6)}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.users || body)).toBeTruthy();
    });

    test('global search', async ({ request }) => {
        const res = await request.get(`/api/users/global-search?q=search`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200]).toContain(res.status());
    });

    // ── Message Search ────────────────────────────────────────────────────────

    test('search messages in room', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/messages/search?q=alpha`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('search messages with no results', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/messages/search?q=xyznonexistent`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Translation ───────────────────────────────────────────────────────────

    test('get supported languages', async ({ request }) => {
        const res = await request.get('/api/translate/languages', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 503]).toContain(res.status());
    });

    test('translate text', async ({ request }) => {
        const res = await request.post('/api/translate', {
            headers: { 'X-CSRF-Token': csrf },
            data: { text: 'Hello world', target_lang: 'ru' },
        });
        expect([200, 503]).toContain(res.status());
    });

    // ── Link Preview ──────────────────────────────────────────────────────────

    test('get link preview', async ({ request }) => {
        const res = await request.get('/api/link-preview?url=https://example.com', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 422]).toContain(res.status());
    });

    // ── AI Assistant ──────────────────────────────────────────────────────────

    test('AI status', async ({ request }) => {
        const res = await request.get('/api/ai/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200]).toContain(res.status());
    });

    test('AI chat', async ({ request }) => {
        const res = await request.post('/api/ai/chat', {
            headers: { 'X-CSRF-Token': csrf },
            data: { message: 'What is Vortex?' },
        });
        expect([200, 422, 503]).toContain(res.status());
    });

    test('AI summarize', async ({ request }) => {
        const res = await request.post('/api/ai/summarize', {
            headers: { 'X-CSRF-Token': csrf },
            data: { room_id: roomId },
        });
        expect([200, 503]).toContain(res.status());
    });

    test('AI suggest reply', async ({ request }) => {
        const res = await request.post('/api/ai/suggest', {
            headers: { 'X-CSRF-Token': csrf },
            data: { room_id: roomId },
        });
        expect([200, 503]).toContain(res.status());
    });

    // ── Reports ───────────────────────────────────────────────────────────────

    test('report user', async ({ request }) => {
        const res = await request.post(`/api/users/report/${userId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { reason: 'e2e_test_report', details: 'Automated test' },
        });
        // 200/201 = success, 400 = can't report self, both acceptable
        expect([200, 201, 400]).toContain(res.status());
    });

    test('view own moderation strikes', async ({ request }) => {
        const res = await request.get('/api/moderation/strikes', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200]).toContain(res.status());
    });
});

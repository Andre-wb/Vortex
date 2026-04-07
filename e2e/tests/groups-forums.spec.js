// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, getMeId, makeEciesPayload } = require('./helpers');

/**
 * Vortex E2E — Groups, Topics, Forums, Permissions, AutoMod
 *
 * Covers:
 *   - Topics CRUD (create, list, update, delete)
 *   - Forum threads (create, list, get, update, upvote)
 *   - Role permissions (get, update)
 *   - AutoMod rules (create, list, update, delete)
 *   - Slowmode configuration
 *   - Room themes (set, get, delete)
 *   - Room export
 *   - Room auto-delete settings
 *   - Channel feeds (RSS)
 *   - Room webhooks
 */

test.describe('Groups & Forums', () => {
    const ownerUsername = `grp_own_${randomStr(6)}`;
    const ownerPhone = `+7962${randomDigits(7)}`;
    const memberUsername = `grp_mem_${randomStr(6)}`;
    const memberPhone = `+7963${randomDigits(7)}`;

    let ownerCsrf = '';
    let roomId = 0;
    let topicId = 0;
    let threadId = 0;
    let automodRuleId = 0;
    let memberId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = csrfToken;

        // Register member
        const { csrfToken: csrf2 } = await registerAndLogin(request, memberUsername, memberPhone);
        memberId = await getMeId(request, csrf2);

        // Re-login as owner
        const { csrfToken: oc2 } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc2;

        roomId = await createRoom(request, ownerCsrf, 'group_room');

        // Add member to room
        await request.post(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: memberId, encrypted_room_key: makeEciesPayload() },
        });
    });

    // ── Topics ────────────────────────────────────────────────────────────────

    test('create topic', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/topics`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { title: 'General Discussion', icon_emoji: '💬' },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        topicId = body.topic_id || body.id;
        expect(topicId).toBeTruthy();
    });

    test('list topics', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/topics`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update topic', async ({ request }) => {
        expect(topicId).toBeTruthy();
        const res = await request.put(`/api/rooms/${roomId}/topics/${topicId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'Updated Topic Name' },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Forum Threads ─────────────────────────────────────────────────────────

    test('create forum thread', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/forum`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                title: 'E2E Forum Thread',
                content: 'This is a test forum thread body',
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        threadId = body.thread_id || body.id;
    });

    test('list forum threads', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/forum`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get forum thread', async ({ request }) => {
        expect(threadId).toBeTruthy();
        const res = await request.get(`/api/rooms/${roomId}/forum/${threadId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update forum thread', async ({ request }) => {
        expect(threadId).toBeTruthy();
        const res = await request.put(`/api/rooms/${roomId}/forum/${threadId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { title: 'Updated Thread Title' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('upvote forum thread', async ({ request }) => {
        expect(threadId).toBeTruthy();
        const res = await request.post(`/api/rooms/${roomId}/forum/${threadId}/upvote`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Permissions ───────────────────────────────────────────────────────────

    test('get room permissions', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/permissions`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update room permissions', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/permissions`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { member: { can_send_messages: true, can_add_members: false } },
        });
        expect([200, 204, 400]).toContain(res.status());
    });

    // ── AutoMod ───────────────────────────────────────────────────────────────

    test('create automod rule', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/automod`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                name: 'Block spam links',
                rule_type: 'word_filter',
                pattern: 'spam',
                action: 'delete',
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        automodRuleId = body.rule_id || body.id;
        expect(automodRuleId).toBeTruthy();
    });

    test('list automod rules', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/automod`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update automod rule', async ({ request }) => {
        expect(automodRuleId).toBeTruthy();
        const res = await request.put(`/api/rooms/${roomId}/automod/${automodRuleId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { trigger_value: 'updated_spam' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('delete automod rule', async ({ request }) => {
        expect(automodRuleId).toBeTruthy();
        const res = await request.delete(`/api/rooms/${roomId}/automod/${automodRuleId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Slowmode ──────────────────────────────────────────────────────────────

    test('set slowmode', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/slow-mode`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { seconds: 10 },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('get slowmode users', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/slowmode/users`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Room Themes ───────────────────────────────────────────────────────────

    test('set room theme', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/theme`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                background_color: '#1a1a2e',
                accent_color: '#6c5ce7',
                text_color: '#ffffff',
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get room theme', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/theme`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('delete room theme', async ({ request }) => {
        const res = await request.delete(`/api/rooms/${roomId}/theme`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Auto-Delete ───────────────────────────────────────────────────────────

    test('set auto-delete timer', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/auto-delete`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { seconds: 86400 },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Room Export ───────────────────────────────────────────────────────────

    test('export room', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/export`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 202]).toContain(res.status());
    });

    // ── Channel Feeds (RSS) ───────────────────────────────────────────────────

    test('create RSS feed', async ({ request }) => {
        const res = await request.post(`/api/channels/${roomId}/feeds`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { url: 'https://example.com/feed.xml', name: 'Test Feed' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('list RSS feeds', async ({ request }) => {
        const res = await request.get(`/api/channels/${roomId}/feeds`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 403, 404, 422]).toContain(res.status());
    });

    test('delete RSS feed (non-existent)', async ({ request }) => {
        const res = await request.delete(`/api/channels/${roomId}/feeds/999999`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    // ── Webhook ───────────────────────────────────────────────────────────────

    test('set room webhook', async ({ request }) => {
        const res = await request.post(`/api/channels/${roomId}/webhook`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { url: 'https://example.com/webhook', events: ['message'] },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    // ── Cleanup topics ────────────────────────────────────────────────────────

    test('delete topic', async ({ request }) => {
        expect(topicId).toBeTruthy();
        const res = await request.delete(`/api/rooms/${roomId}/topics/${topicId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });
});

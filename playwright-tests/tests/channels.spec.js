// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, makeEciesPayload } = require('./helpers');

/**
 * Vortex E2E — Channels
 *
 * Covers:
 *   - Create channel
 *   - List my channels
 *   - Join channel by invite code
 *   - Post message (send)
 *   - Channel stats / analytics
 *   - Comments on posts
 *   - Reactions on posts
 *   - Schedule post
 *   - List scheduled posts
 *   - Popular / discover channels
 *   - Monetization settings
 *   - Edge cases
 */

test.describe('Channels', () => {
    const ownerUsername = `ch_own_${randomStr(6)}`;
    const ownerPhone = `+7955${randomDigits(7)}`;
    const memberUsername = `ch_mem_${randomStr(6)}`;
    const memberPhone = `+7956${randomDigits(7)}`;

    let ownerCsrf = '';
    let memberCsrf = '';
    let channelId = 0;
    let inviteCode = '';
    let postMsgId = 0;

    test.beforeAll(async ({ request }) => {
        // Register owner
        const { csrfToken: oc } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc;

        // Register member (need separate context for later, but register now)
        await registerAndLogin(request, memberUsername, memberPhone);

        // Re-login as owner
        const { csrfToken: oc2 } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc2;
    });

    test('create channel', async ({ request }) => {
        const res = await request.post('/api/channels', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                name: `E2E Channel ${randomStr(4)}`,
                description: 'Test channel for e2e',
                is_public: true,
                encrypted_room_key: makeEciesPayload(),
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        channelId = body.channel_id || body.id || body.room_id;
        inviteCode = body.invite_code || '';
    });

    test('list my channels', async ({ request }) => {
        const res = await request.get('/api/channels/my', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.channels || body)).toBeTruthy();
    });

    test('discover popular channels', async ({ request }) => {
        const res = await request.get('/api/channels/popular', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('discover channels', async ({ request }) => {
        const res = await request.get('/api/channels/discover', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('send post to channel', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.post(`/api/rooms/${channelId}/messages`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { ciphertext: 'E2E channel post content' },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        postMsgId = body.id || body.msg_id || body.message_id;
    });

    test('channel stats', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.get(`/api/channels/${channelId}/stats`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('record post view', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        expect(postMsgId).toBeTruthy();
        const res = await request.post(`/api/channels/${channelId}/posts/${postMsgId}/view`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 201, 204]).toContain(res.status());
    });

    test('react to post', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        expect(postMsgId).toBeTruthy();
        const res = await request.post(`/api/channels/${channelId}/posts/${postMsgId}/react`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { emoji: '👍' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get post reactions', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        expect(postMsgId).toBeTruthy();
        const res = await request.get(`/api/channels/${channelId}/posts/${postMsgId}/reactions`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('add comment to post', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        expect(postMsgId).toBeTruthy();
        const res = await request.post(`/api/channels/${channelId}/posts/${postMsgId}/comment`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { text: 'E2E comment on post' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get post comments', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        expect(postMsgId).toBeTruthy();
        const res = await request.get(`/api/channels/${channelId}/posts/${postMsgId}/comments`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('schedule post', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const scheduled = new Date(Date.now() + 3600_000).toISOString();
        const res = await request.post(`/api/channels/${channelId}/schedule`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { ciphertext: 'Scheduled post', scheduled_at: scheduled },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    test('list scheduled posts', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.get(`/api/channels/${channelId}/scheduled`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('monetization settings (get)', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.get(`/api/channels/${channelId}/monetization`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('monetization settings (update)', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.put(`/api/channels/${channelId}/monetization`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { enabled: false },
        });
        expect([200, 204, 422]).toContain(res.status());
    });

    test('subscribe to channel', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.post(`/api/channels/${channelId}/subscribe`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('donate to channel', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.post(`/api/channels/${channelId}/donate`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { amount: 100, currency: 'USD' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('list channel donations', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.get(`/api/channels/${channelId}/donations`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('create channel RSS feed', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.post(`/api/channels/${channelId}/feeds`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { type: 'rss', url: 'https://example.com/rss.xml' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('list channel feeds', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.get(`/api/channels/${channelId}/feeds`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('create channel webhook feed', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.post(`/api/channels/${channelId}/feeds`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { type: 'webhook' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('delete RSS feed (non-existent)', async ({ request }) => {
        expect(channelId).toBeGreaterThan(0);
        const res = await request.delete(`/api/channels/${channelId}/feeds/999999`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    test('join channel by invite code', async ({ request }) => {
        expect(inviteCode).toBeTruthy();
        // Login as member
        await request.post('/api/authentication/login', {
            data: { phone_or_username: memberUsername, password: 'E2ePass99!@' },
        });
        const csrfRes = await request.get('/api/authentication/csrf-token');
        memberCsrf = (await csrfRes.json()).csrf_token;

        const res = await request.post(`/api/channels/join/${inviteCode}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
            data: { encrypted_room_key: makeEciesPayload() },
        });
        expect([200, 201]).toContain(res.status());

        // Re-login as owner
        await request.post('/api/authentication/login', {
            data: { phone_or_username: ownerUsername, password: 'E2ePass99!@' },
        });
        const csrfRes2 = await request.get('/api/authentication/csrf-token');
        ownerCsrf = (await csrfRes2.json()).csrf_token;
    });
});

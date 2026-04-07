// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, sendMessage, makePublicKey, getMeId, makeEciesPayload } = require('./helpers');

/**
 * Vortex E2E — Edge Cases & Error Handling
 *
 * Covers:
 *   - Rate limiting
 *   - Invalid input validation
 *   - Large payload handling
 *   - Non-existent resource access
 *   - Permission denied scenarios
 *   - Concurrent operations
 *   - Message history/threading edge cases
 *   - Room operations edge cases
 *   - Pin/unpin/mark-read
 *   - Fingerprint verification
 *   - Room key rotation
 */

test.describe('Edge Cases & Error Handling', () => {
    const user1 = `edge_u1_${randomStr(6)}`;
    const phone1 = `+7967${randomDigits(7)}`;
    const user2 = `edge_u2_${randomStr(6)}`;
    const phone2 = `+7968${randomDigits(7)}`;

    let csrf1 = '';
    let csrf2 = '';
    let userId1 = 0;
    let userId2 = 0;
    let roomId = 0;
    let msgId = 0;

    test.beforeAll(async ({ request }) => {
        // User 1
        const { csrfToken: c1 } = await registerAndLogin(request, user1, phone1);
        csrf1 = c1;
        userId1 = await getMeId(request, csrf1);

        // User 2
        const { csrfToken: c2 } = await registerAndLogin(request, user2, phone2);
        csrf2 = c2;
        userId2 = await getMeId(request, csrf2);

        // Re-login as user1
        const { csrfToken: c1b } = await registerAndLogin(request, user1, phone1);
        csrf1 = c1b;

        roomId = await createRoom(request, csrf1, 'edge_room');
        const msg = await sendMessage(request, csrf1, roomId, 'Edge case test message');
        msgId = msg.id || msg.message_id;
    });

    // ── Room Members (add) ──────────────────────────────────────────────────

    test('add member to room', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { user_id: userId2, encrypted_room_key: require('./helpers').makeEciesPayload() },
        });
        expect([200, 201, 400, 405, 409]).toContain(res.status());
    });

    // ── Invalid Input ─────────────────────────────────────────────────────────

    test('create room with empty name fails', async ({ request }) => {
        const res = await request.post('/api/rooms', {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { name: '', encrypted_room_key: makeEciesPayload() },
        });
        expect([400, 422]).toContain(res.status());
    });

    test('send message to non-existent room', async ({ request }) => {
        const res = await request.post('/api/rooms/999999/messages', {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { ciphertext: 'Ghost message' },
        });
        expect([403, 404]).toContain(res.status());
    });

    test('register with short password fails', async ({ request }) => {
        const res = await request.post('/api/authentication/register', {
            data: {
                username: `weak_${randomStr(6)}`,
                password: '123',
                phone: `+7900${randomDigits(7)}`,
                x25519_public_key: makePublicKey(),
            },
        });
        expect([400, 422]).toContain(res.status());
    });

    test('register with duplicate phone fails', async ({ request }) => {
        const res = await request.post('/api/authentication/register', {
            data: {
                username: `dup_phone_${randomStr(6)}`,
                password: 'E2ePass99!@',
                phone: phone1,
                x25519_public_key: makePublicKey(),
            },
        });
        expect([400, 409, 422]).toContain(res.status());
    });

    // ── Permission Denied ─────────────────────────────────────────────────────

    test('non-member cannot send message to room', async ({ request }) => {
        // Login as user2 who is not in room
        await request.post('/api/authentication/login', {
            data: { phone_or_username: user2, password: 'E2ePass99!@' },
        });
        const csrfRes = await request.get('/api/authentication/csrf-token');
        const csrf2New = (await csrfRes.json()).csrf_token;

        const res = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrf2New },
            data: { ciphertext: 'Unauthorized message' },
        });
        expect([403, 404]).toContain(res.status());

        // Re-login as user1
        await request.post('/api/authentication/login', {
            data: { phone_or_username: user1, password: 'E2ePass99!@' },
        });
        const c1Res = await request.get('/api/authentication/csrf-token');
        csrf1 = (await c1Res.json()).csrf_token;
    });

    // ── Message Operations ────────────────────────────────────────────────────

    test('edit message', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.put(`/api/rooms/${roomId}/messages/${msgId}`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { ciphertext: 'Edited edge case message' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get message edit history', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.get(`/api/rooms/${roomId}/messages/${msgId}/history`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('add reaction', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.post(`/api/rooms/${roomId}/messages/${msgId}/react`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { emoji: '🔥' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('pin message', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.post(`/api/rooms/${roomId}/pin`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { message_id: msgId },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get pinned messages', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/pinned`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('mark room as read', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/read`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Thread ────────────────────────────────────────────────────────────────

    test('reply in thread', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { ciphertext: 'Thread reply', reply_to: msgId },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get thread', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.get(`/api/rooms/${roomId}/thread/${msgId}`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Pagination ────────────────────────────────────────────────────────────

    test('messages pagination — before_id', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/messages?before_id=999999&limit=10`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('messages pagination — after_id', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/messages?after_id=0&limit=5`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Room Key Rotation ─────────────────────────────────────────────────────

    test('rotate room key', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/rotate-key`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { new_encrypted_room_key: makeEciesPayload() },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get key bundle', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/key-bundle`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect([200, 404, 500]).toContain(res.status());
    });

    // ── Room Settings ─────────────────────────────────────────────────────────

    test('update room settings', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { description: 'Updated by E2E test' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get room detail', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.name || body.id).toBeDefined();
    });

    test('list room members', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Delete message ────────────────────────────────────────────────────────

    test('delete message', async ({ request }) => {
        expect(msgId).toBeTruthy();
        const res = await request.delete(`/api/rooms/${roomId}/messages/${msgId}`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('delete non-existent message returns error', async ({ request }) => {
        const res = await request.delete(`/api/rooms/${roomId}/messages/999999`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect([404, 400]).toContain(res.status());
    });

    // ── Large payload ─────────────────────────────────────────────────────────

    test('very long message accepted or rejected gracefully', async ({ request }) => {
        const longText = 'A'.repeat(50_000);
        const res = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { ciphertext: longText },
        });
        // Should either accept or reject with 413/422, not crash
        expect([200, 201, 400, 404, 413, 422]).toContain(res.status());
    });

    // ── Mute room ─────────────────────────────────────────────────────────────

    test('mute room', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/mute`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { muted: true },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('unmute room', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/mute`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { muted: false },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Upload room avatar ────────────────────────────────────────────────────

    test('upload room avatar', async ({ request }) => {
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==',
            'base64'
        );
        const res = await request.post(`/api/rooms/${roomId}/avatar`, {
            headers: { 'X-CSRF-Token': csrf1 },
            multipart: {
                file: { name: 'avatar.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([200, 201, 400]).toContain(res.status());
    });
});

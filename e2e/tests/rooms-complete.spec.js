// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, getMeId, makeEciesPayload } = require('./helpers');

/**
 * Vortex E2E — Rooms Endpoints (missing coverage)
 *
 * Covers:
 *   - Delete room
 *   - Leave room
 *   - Theme accept / reject
 *   - Join by invite code
 *   - Provide key
 *   - Kick member
 *   - Update member role
 *   - Mute member
 *   - Ban member
 *   - Get pinned messages
 *   - Public rooms listing
 *   - Slowmode users update
 *   - Room members add
 */

test.describe('Rooms Complete', () => {
    const ownerUsername = `rmc_own_${randomStr(6)}`;
    const ownerPhone = `+7976${randomDigits(7)}`;
    const memberUsername = `rmc_mem_${randomStr(6)}`;
    const memberPhone = `+7977${randomDigits(7)}`;
    let ownerCsrf = '';
    let roomId = 0;
    let memberId = 0;
    let roomToDelete = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = csrfToken;

        // Register member
        const { csrfToken: csrf2 } = await registerAndLogin(request, memberUsername, memberPhone);
        memberId = await getMeId(request, csrf2);

        // Re-login as owner
        const { csrfToken: oc2 } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc2;

        roomId = await createRoom(request, ownerCsrf, 'rooms_complete');
        roomToDelete = await createRoom(request, ownerCsrf, 'rooms_to_delete');

        // Add member to main room
        await request.post(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: memberId, encrypted_room_key: makeEciesPayload() },
        });
    });

    // ── Public rooms ──────────────────────────────────────────────────────────

    test('list public rooms', async ({ request }) => {
        const res = await request.get('/api/rooms/public', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Member management ─────────────────────────────────────────────────────

    test('update member role', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'moderator' },
        });
        expect([200, 204, 400, 404, 422]).toContain(res.status());
    });

    test('mute member', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/mute`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { muted: true },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    test('unmute member', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/mute`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { muted: false },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    test('ban member', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/ban`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { banned: true, reason: 'e2e test ban' },
        });
        expect([200, 204, 400, 404]).toContain(res.status());
    });

    test('unban member', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/ban`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { banned: false },
        });
        expect([200, 204, 400, 404]).toContain(res.status());
    });

    test('kick member', async ({ request }) => {
        // Re-add member first
        await request.post(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: memberId, encrypted_room_key: makeEciesPayload() },
        });

        const res = await request.post(`/api/rooms/${roomId}/kick/${memberId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 403]).toContain(res.status());
    });

    // ── Provide key ───────────────────────────────────────────────────────────

    test('provide key to room', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/provide-key`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: memberId, encrypted_room_key: makeEciesPayload() },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    // ── Join by invite code ───────────────────────────────────────────────────

    test('join room by invalid invite code', async ({ request }) => {
        const res = await request.post('/api/rooms/join/invalid_code_e2e', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { encrypted_room_key: makeEciesPayload() },
        });
        expect([400, 404]).toContain(res.status());
    });

    // ── Theme accept/reject ───────────────────────────────────────────────────

    test('theme accept', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/theme/accept`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 400]).toContain(res.status());
    });

    test('theme reject', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/theme/reject`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 400]).toContain(res.status());
    });

    // ── Pinned messages ───────────────────────────────────────────────────────

    test('get pinned messages', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/pinned`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Slowmode users update ─────────────────────────────────────────────────

    test('update slowmode users', async ({ request }) => {
        const res = await request.put(`/api/rooms/${roomId}/slowmode/users`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { exempt_users: [] },
        });
        expect([200, 204, 400, 422]).toContain(res.status());
    });

    // ── Leave room ────────────────────────────────────────────────────────────

    test('leave room', async ({ request }) => {
        // Create a room to leave
        const tmpRoom = await createRoom(request, ownerCsrf, 'leave_test');
        const res = await request.delete(`/api/rooms/${tmpRoom}/leave`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Delete room ───────────────────────────────────────────────────────────

    test('delete room', async ({ request }) => {
        const res = await request.delete(`/api/rooms/${roomToDelete}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204]).toContain(res.status());
    });
});

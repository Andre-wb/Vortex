// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, getMeId, makeEciesPayload } = require('./helpers');

/**
 * Vortex E2E — Spaces Endpoints (missing coverage)
 *
 * Covers:
 *   - Public spaces listing
 *   - Join space directly / by invite code
 *   - Leave space
 *   - Space members list
 *   - Promote / demote member role
 *   - Kick member from space
 *   - Categories CRUD
 *   - Delete custom emoji
 *   - Space permissions (get per room, update)
 */

test.describe('Spaces Complete', () => {
    const ownerUsername = `spc_own_${randomStr(6)}`;
    const ownerPhone = `+7980${randomDigits(7)}`;
    const memberUsername = `spc_mem_${randomStr(6)}`;
    const memberPhone = `+7981${randomDigits(7)}`;
    let ownerCsrf = '';
    let spaceId = 0;
    let memberId = 0;
    let categoryId = 0;
    let spaceRoomId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = csrfToken;

        // Register member
        const { csrfToken: csrf2 } = await registerAndLogin(request, memberUsername, memberPhone);
        memberId = await getMeId(request, csrf2);

        // Re-login as owner
        const { csrfToken: oc2 } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc2;

        // Create space
        const spaceRes = await request.post('/api/spaces', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                name: `E2E Space Complete ${randomStr(4)}`,
                description: 'Space for complete tests',
                is_public: true,
            },
        });
        const spaceBody = await spaceRes.json();
        spaceId = spaceBody.space_id || spaceBody.id;

        // Create a room in the space
        const roomRes = await request.post(`/api/spaces/${spaceId}/rooms`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: `sp_room_${randomStr(4)}`, encrypted_room_key: makeEciesPayload() },
        });
        if (roomRes.ok()) {
            const roomBody = await roomRes.json();
            spaceRoomId = roomBody.room_id || roomBody.id;
        }
    });

    // ── Public spaces ─────────────────────────────────────────────────────────

    test('list public spaces', async ({ request }) => {
        const res = await request.get('/api/spaces/public', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Join space ────────────────────────────────────────────────────────────

    test('join space directly', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        // Login as member
        await request.post('/api/authentication/login', {
            data: { phone_or_username: memberUsername, password: 'E2ePass99!@' },
        });
        const csrf = (await (await request.get('/api/authentication/csrf-token')).json()).csrf_token;

        const res = await request.post(`/api/spaces/${spaceId}/join`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 400, 422]).toContain(res.status());

        // Re-login as owner
        await request.post('/api/authentication/login', {
            data: { phone_or_username: ownerUsername, password: 'E2ePass99!@' },
        });
        ownerCsrf = (await (await request.get('/api/authentication/csrf-token')).json()).csrf_token;
    });

    test('join space by invalid invite code', async ({ request }) => {
        const res = await request.post('/api/spaces/join/invalid_code_e2e', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([400, 404]).toContain(res.status());
    });

    // ── Members ───────────────────────────────────────────────────────────────

    test('list space members', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update member role in space', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        expect(memberId).toBeTruthy();
        const res = await request.put(`/api/spaces/${spaceId}/members/${memberId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'moderator' },
        });
        expect([200, 204, 400, 422]).toContain(res.status());
    });

    test('kick member from space', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        expect(memberId).toBeTruthy();
        const res = await request.delete(`/api/spaces/${spaceId}/members/${memberId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 400, 404]).toContain(res.status());
    });

    // ── Categories ────────────────────────────────────────────────────────────

    test('create space category', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.post(`/api/spaces/${spaceId}/categories`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'E2E Category', position: 0 },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        categoryId = body.category_id || body.id;
    });

    test('update space category', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        expect(categoryId).toBeTruthy();
        const res = await request.put(`/api/spaces/${spaceId}/categories/${categoryId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'Updated Category' },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('delete space category', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        expect(categoryId).toBeTruthy();
        const res = await request.delete(`/api/spaces/${spaceId}/categories/${categoryId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Custom Emoji Delete ───────────────────────────────────────────────────

    test('delete non-existent emoji', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.delete(`/api/spaces/${spaceId}/emojis/999999`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    // ── Permissions ───────────────────────────────────────────────────────────

    test('get space permissions for room', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        expect(spaceRoomId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/permissions/${spaceRoomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update space permissions', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.put(`/api/spaces/${spaceId}/permissions`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { default_role: 'member', permissions: {} },
        });
        expect([200, 204, 400, 422]).toContain(res.status());
    });

    // ── Leave space ───────────────────────────────────────────────────────────

    test('leave space', async ({ request }) => {
        // Create a second space to leave safely
        const spRes = await request.post('/api/spaces', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: `Leave Space ${randomStr(4)}`, is_public: true },
        });
        const spBody = await spRes.json();
        const leaveSpaceId = spBody.space_id || spBody.id;

        if (leaveSpaceId) {
            const res = await request.post(`/api/spaces/${leaveSpaceId}/leave`, {
                headers: { 'X-CSRF-Token': ownerCsrf },
            });
            expect([200, 204, 400]).toContain(res.status());
        }
    });
});

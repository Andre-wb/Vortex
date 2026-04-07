// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, loginUser, getMeId } = require('./helpers');

/**
 * Vortex E2E — Spaces Management
 *
 * Covers:
 *   - Create space (public / private)
 *   - List my spaces
 *   - Get space detail
 *   - Update space info (name, description, emoji, visibility)
 *   - Public space discovery
 *   - Join space via invite_code (URL + body)
 *   - Leave space
 *   - List space members and member roles
 *   - Promote / demote member role
 *   - Kick member from space
 *   - Create / update / delete space categories
 *   - Create room inside a space
 *   - Delete space
 *   - Error / access-control edge cases
 */

// ── Resilient helpers ─────────────────────────────────────────────────────────

async function createSpaceRetry(request, csrf, data) {
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const res = await request.post('/api/spaces', {
                headers: { 'X-CSRF-Token': csrf },
                data,
            });
            if ([200, 201].includes(res.status())) {
                return await res.json();
            }
        } catch (_) { /* retry */ }
        if (attempt === 0) await new Promise(r => setTimeout(r, 500));
    }
    return null;
}

// ── Test suite ────────────────────────────────────────────────────────────────

test.describe('Spaces', () => {
    // Owner of the space
    const ownerUsername = `sp_owner_${randomStr(6)}`;
    const ownerPhone    = `+7920${randomDigits(7)}`;

    // Member who will join
    const memberUsername = `sp_member_${randomStr(6)}`;
    const memberPhone    = `+7921${randomDigits(7)}`;

    let ownerCsrf    = '';
    let memberCsrf   = '';
    let ownerId      = 0;
    let memberId     = 0;

    let spaceId      = 0;
    let inviteCode   = '';
    let publicSpaceId = 0;
    let categoryId   = 0;

    /** Ensure private space exists (lazy creation fallback). */
    async function ensureSpace(request) {
        if (spaceId > 0) return;
        const body = await createSpaceRetry(request, ownerCsrf, {
            name: `E2E Space ${randomStr(4)}`, description: 'E2E test space', is_public: false,
        });
        if (body) {
            spaceId    = body.id || 0;
            inviteCode = body.invite_code || '';
        }
    }

    // ── Setup ─────────────────────────────────────────────────────────────────

    test.beforeAll(async ({ request }) => {
        const { csrfToken: oc } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc;
        ownerId   = await getMeId(request, ownerCsrf);

        const { csrfToken: mc } = await registerAndLogin(request, memberUsername, memberPhone);
        memberCsrf = mc;
        memberId   = await getMeId(request, memberCsrf);

        // Re-login as owner to restore session
        ownerCsrf = await loginUser(request, ownerUsername);

        // Pre-create spaces (fallback — tests 1 & 2 also create, but this ensures state if they fail)
        await ensureSpace(request);

        const pubBody = await createSpaceRetry(request, ownerCsrf, {
            name: `Public Space ${randomStr(4)}`, is_public: true,
        });
        if (pubBody) publicSpaceId = pubBody.id || 0;
    });

    // ── 1. Create private space ───────────────────────────────────────────────

    test('1. POST /api/spaces creates a new private space', async ({ request }) => {
        const res = await request.post('/api/spaces', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                name:        `E2E Space ${randomStr(4)}`,
                description: 'E2E test space',
                is_public:   false,
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        expect(body).toHaveProperty('id');
        expect(body).toHaveProperty('invite_code');

        // Update shared state (may override beforeAll's pre-created space)
        spaceId    = body.id;
        inviteCode = body.invite_code;

        expect(body.is_public).toBe(false);
        expect(body.creator_id).toBe(ownerId);
        if (body.default_rooms) {
            expect(Array.isArray(body.default_rooms)).toBe(true);
            expect(body.default_rooms.length).toBeGreaterThanOrEqual(2);
        }
    });

    // ── 2. Create public space ────────────────────────────────────────────────

    test('2. POST /api/spaces creates a public space', async ({ request }) => {
        const res = await request.post('/api/spaces', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                name:      `Public Space ${randomStr(4)}`,
                is_public: true,
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        expect(body.is_public).toBe(true);
        publicSpaceId = body.id;
    });

    // ── 3. List my spaces ─────────────────────────────────────────────────────

    test('3. GET /api/spaces lists spaces the owner belongs to', async ({ request }) => {
        const res = await request.get('/api/spaces', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('spaces');
        expect(Array.isArray(body.spaces)).toBe(true);

        const found = body.spaces.find(s => s.id === spaceId);
        expect(found).toBeDefined();
        expect(found.my_role).toBe('owner');
    });

    // ── 4. Get space detail ───────────────────────────────────────────────────

    test('4. GET /api/spaces/{id} returns space detail with categories', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.get(`/api/spaces/${spaceId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.id).toBe(spaceId);
        expect(body).toHaveProperty('categories');
        expect(Array.isArray(body.categories)).toBe(true);
        expect(body.my_role).toBe('owner');
    });

    // ── 5. Update space name and description ──────────────────────────────────

    test('5. PUT /api/spaces/{id} updates name and description', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.put(`/api/spaces/${spaceId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'Renamed Space', description: 'Updated description' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.name).toBe('Renamed Space');
        expect(body.description).toBe('Updated description');
    });

    // ── 6. Update space avatar emoji ──────────────────────────────────────────

    test('6. PUT /api/spaces/{id} updates avatar_emoji', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.put(`/api/spaces/${spaceId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { avatar_emoji: '🚀' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.avatar_emoji).toBe('🚀');
    });

    // ── 7. Public spaces discovery ────────────────────────────────────────────

    test('7. GET /api/spaces/public lists public spaces without auth', async ({ request }) => {
        const res = await request.get('/api/spaces/public');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('spaces');
        expect(Array.isArray(body.spaces)).toBe(true);

        // Our public space should appear (may not be in top-50 if many exist)
        const found = body.spaces.find(s => s.id === publicSpaceId);
        if (found) {
            expect(found.is_public).toBe(true);
        }
        // At minimum, all returned spaces must be public
        for (const s of body.spaces) {
            expect(s.is_public).toBe(true);
        }
    });

    // ── 8. Get space members (only owner present initially) ───────────────────

    test('8. GET /api/spaces/{id}/members returns owner as sole member', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.get(`/api/spaces/${spaceId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('members');
        expect(Array.isArray(body.members)).toBe(true);

        const owner = body.members.find(m => m.user_id === ownerId);
        expect(owner).toBeDefined();
        expect(owner.role).toBe('owner');
    });

    // ── 9. Join space via invite URL ──────────────────────────────────────────

    test('9. POST /api/spaces/join/{invite_code} lets member join', async ({ request }) => {
        await ensureSpace(request); expect(inviteCode).toBeTruthy();

        // Switch to member session
        memberCsrf = await loginUser(request, memberUsername);

        const res = await request.post(`/api/spaces/join/${inviteCode}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.joined).toBe(true);
        expect(body.space.id).toBe(spaceId);
        expect(body.rooms_joined).toBeGreaterThanOrEqual(1);

        // Restore owner session
        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 10. Space member count updated after join ─────────────────────────────

    test('10. member_count increments after user joins space', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.get(`/api/spaces/${spaceId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.members.length).toBeGreaterThanOrEqual(2);

        const member = body.members.find(m => m.user_id === memberId);
        expect(member).toBeDefined();
        expect(member.role).toBe('member');
    });

    // ── 11. Join already-joined returns joined=false ──────────────────────────

    test('11. POST /api/spaces/join/{code} second time returns joined=false', async ({ request }) => {
        await ensureSpace(request); expect(inviteCode).toBeTruthy();

        memberCsrf = await loginUser(request, memberUsername);

        const res = await request.post(`/api/spaces/join/${inviteCode}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.joined).toBe(false);

        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 12. Join space via body (POST /{id}/join) ─────────────────────────────

    test('12. POST /api/spaces/{id}/join with body invite_code works', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(inviteCode).toBeTruthy();

        memberCsrf = await loginUser(request, memberUsername);

        const res = await request.post(`/api/spaces/${spaceId}/join`, {
            headers: { 'X-CSRF-Token': memberCsrf },
            data: { invite_code: inviteCode },
        });
        expect(res.ok()).toBeTruthy();

        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 13. Invalid invite_code returns 404 ───────────────────────────────────

    test('13. POST /api/spaces/join/INVALID returns 404', async ({ request }) => {
        const res = await request.post('/api/spaces/join/BADCODE99', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.status()).toBe(404);
    });

    // ── 14. Promote member to admin ───────────────────────────────────────────

    test('14. PUT /api/spaces/{id}/members/{uid}/role promotes to admin', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/spaces/${spaceId}/members/${memberId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'admin' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body.role).toBe('admin');
    });

    // ── 15. Demote admin back to member ───────────────────────────────────────

    test('15. PUT /api/spaces/{id}/members/{uid}/role demotes to member', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/spaces/${spaceId}/members/${memberId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'member' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.role).toBe('member');
    });

    // ── 16. Owner cannot change own role ──────────────────────────────────────

    test('16. PUT /api/spaces/{id}/members/{own_id}/role returns 400', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.put(`/api/spaces/${spaceId}/members/${ownerId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'admin' },
        });
        expect(res.status()).toBe(400);
    });

    // ── 17. Create category in space ──────────────────────────────────────────

    test('17. POST /api/spaces/{id}/categories creates a category', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.post(`/api/spaces/${spaceId}/categories`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'Dev Corner' },
        });
        expect(res.status()).toBe(201);
        const body = await res.json();
        expect(body).toHaveProperty('id');
        expect(body.name).toBe('Dev Corner');
        categoryId = body.id;
    });

    // ── 18. Rename category ───────────────────────────────────────────────────

    test('18. PUT /api/spaces/{id}/categories/{cat_id} renames category', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(categoryId).toBeGreaterThan(0);

        const res = await request.put(`/api/spaces/${spaceId}/categories/${categoryId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'Dev Hub' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.name).toBe('Dev Hub');
    });

    // ── 19. Create room inside space ──────────────────────────────────────────

    test('19. POST /api/spaces/{id}/rooms creates a space room', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.post(`/api/spaces/${spaceId}/rooms`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: {
                name:        'announcements',
                description: 'Important announcements',
                is_voice:    false,
                is_channel:  true,
            },
        });
        expect(res.status()).toBe(201);
        const body = await res.json();
        expect(body).toHaveProperty('id');
        expect(body.name).toBe('announcements');
        expect(body.is_channel).toBe(true);
    });

    // ── 20. Kick member from space ────────────────────────────────────────────

    test('20. DELETE /api/spaces/{id}/members/{uid} kicks a member', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.delete(`/api/spaces/${spaceId}/members/${memberId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 21. Kicked member no longer appears in members list ───────────────────

    test('21. Kicked member is absent from members list', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.get(`/api/spaces/${spaceId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const kicked = body.members.find(m => m.user_id === memberId);
        expect(kicked).toBeUndefined();
    });

    // ── 22. Non-member cannot access space detail ─────────────────────────────

    test('22. GET /api/spaces/{id} returns 403 for non-member', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        // Member was kicked — restore member session
        memberCsrf = await loginUser(request, memberUsername);

        const res = await request.get(`/api/spaces/${spaceId}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });
        expect([403, 404]).toContain(res.status());

        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 23. Delete category ───────────────────────────────────────────────────

    test('23. DELETE /api/spaces/{id}/categories/{cat_id} removes category', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0); expect(categoryId).toBeGreaterThan(0);

        const res = await request.delete(`/api/spaces/${spaceId}/categories/${categoryId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 24. Delete space ──────────────────────────────────────────────────────

    test('24. DELETE /api/spaces/{id} removes the space', async ({ request }) => {
        // Delete the private space created in test 1
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.delete(`/api/spaces/${spaceId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 25. Deleted space no longer accessible ────────────────────────────────

    test('25. GET /api/spaces after deletion shows space removed', async ({ request }) => {
        await ensureSpace(request); expect(spaceId).toBeGreaterThan(0);

        const res = await request.get('/api/spaces', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const found = body.spaces.find(s => s.id === spaceId);
        expect(found).toBeUndefined();
    });

    // ── Cleanup ───────────────────────────────────────────────────────────────

    test.afterAll(async ({ request }) => {
        // Clean up public space
        if (publicSpaceId) {
            ownerCsrf = await loginUser(request, ownerUsername);
            await request.delete(`/api/spaces/${publicSpaceId}`, {
                headers: { 'X-CSRF-Token': ownerCsrf },
            });
        }
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
    });
});

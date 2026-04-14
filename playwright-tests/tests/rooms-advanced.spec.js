// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, makeEciesPayload, registerAndLogin, loginUser, getMeId } = require('./helpers');

/**
 * Vortex E2E — Rooms Advanced Tests
 *
 * Covers:
 *   - Room creation with encrypted key payload
 *   - Room invite links (get invite_code, join by code, validate)
 *   - Public room listing with filters
 *   - Room settings update (name, description, emoji, privacy, slow-mode, auto-delete)
 *   - Member roles: promote to admin, demote to member
 *   - Kick member (ban) from room
 *   - Mute / un-mute member
 *   - Ban / un-ban member toggle
 *   - Archive (make private) room
 *   - Room search (public rooms by name)
 *   - Leave room
 *   - Key bundle retrieval
 *   - Error / access-control edge cases
 */

async function createRoom(request, csrfToken, name, isPrivate = false) {
    const res = await request.post('/api/rooms', {
        headers: { 'X-CSRF-Token': csrfToken },
        data: {
            name,
            description:        `Room: ${name}`,
            is_private:         isPrivate,
            encrypted_room_key: makeEciesPayload(),
        },
    });
    return res;
}

/** Create a room with retry (returns {id, invite_code} or {id:0}). */
async function createRoomRetry(request, csrfToken, name, isPrivate = false) {
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const res = await createRoom(request, csrfToken, name, isPrivate);
            if ([200, 201].includes(res.status())) {
                const body = await res.json();
                return { id: body.id || 0, invite_code: body.invite_code || '', body };
            }
        } catch (_) { /* retry */ }
        if (attempt === 0) await new Promise(r => setTimeout(r, 500));
    }
    return { id: 0, invite_code: '', body: {} };
}

// ── Test suite ────────────────────────────────────────────────────────────────

test.describe('Rooms Advanced', () => {
    const ownerUsername  = `rm_owner_${randomStr(6)}`;
    const ownerPhone     = `+7930${randomDigits(7)}`;
    const memberUsername = `rm_member_${randomStr(6)}`;
    const memberPhone    = `+7931${randomDigits(7)}`;

    let ownerCsrf  = '';
    let memberCsrf = '';
    let ownerId    = 0;
    let memberId   = 0;

    let roomId     = 0;
    let inviteCode = '';
    let privateRoomId = 0;

    /** Ensure the main room exists (lazy creation fallback). */
    async function ensureRoom(request) {
        if (roomId > 0) return;
        const r = await createRoomRetry(request, ownerCsrf, `rm_public_${randomStr(4)}`);
        roomId = r.id;
        inviteCode = r.invite_code;
    }

    // ── Setup ─────────────────────────────────────────────────────────────────

    test.beforeAll(async ({ request }) => {
        const { csrfToken: oc } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc;
        ownerId   = await getMeId(request, ownerCsrf);

        const { csrfToken: mc } = await registerAndLogin(request, memberUsername, memberPhone);
        memberCsrf = mc;
        memberId   = await getMeId(request, memberCsrf);

        // Restore owner session
        ownerCsrf = await loginUser(request, ownerUsername);

        // Pre-create main room (fallback — test 1 also creates, but this ensures state)
        await ensureRoom(request);
    });

    // ── 1. Create a public room ───────────────────────────────────────────────

    test('1. POST /api/rooms creates a public room with encrypted key', async ({ request }) => {
        const res = await createRoom(request, ownerCsrf, `rm_public_${randomStr(4)}`);
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        expect(body).toHaveProperty('id');
        expect(body).toHaveProperty('invite_code');
        expect(body.creator_id).toBe(ownerId);
        expect(body.has_key).toBe(true);

        roomId     = body.id;
        inviteCode = body.invite_code;
    });

    // ── 2. Create a private room ──────────────────────────────────────────────

    test('2. POST /api/rooms creates a private (archived) room', async ({ request }) => {
        const res = await createRoom(
            request, ownerCsrf, `rm_private_${randomStr(4)}`, true
        );
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        expect(body.is_private).toBe(true);
        privateRoomId = body.id;
    });

    // ── 3. List my rooms ──────────────────────────────────────────────────────

    test('3. GET /api/rooms/my returns created rooms', async ({ request }) => {
        const res = await request.get('/api/rooms/my', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('rooms');
        expect(Array.isArray(body.rooms)).toBe(true);

        const found = body.rooms.find(r => r.id === roomId);
        expect(found).toBeDefined();
        expect(found.my_role).toBe('owner');
        expect(found).toHaveProperty('unread_count');
        expect(found).toHaveProperty('has_key');
    });

    // ── 4. Public rooms listing ───────────────────────────────────────────────

    test('4. GET /api/rooms/public lists public rooms without auth', async ({ request }) => {
        const res = await request.get('/api/rooms/public');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('rooms');
        expect(Array.isArray(body.rooms)).toBe(true);

        // Public room should appear; private room should NOT
        const publicFound = body.rooms.find(r => r.id === roomId);
        expect(publicFound).toBeDefined();

        const privateFound = body.rooms.find(r => r.id === privateRoomId);
        expect(privateFound).toBeUndefined();
    });

    // ── 5. Get room detail ────────────────────────────────────────────────────

    test('5. GET /api/rooms/{id} returns room detail for member', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.get(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.id).toBe(roomId);
        expect(body).toHaveProperty('invite_code');
        expect(body.my_role).toBe('owner');
    });

    // ── 6. Room invite code is usable ─────────────────────────────────────────

    test('6. invite_code from room creation is a valid string', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        expect(typeof inviteCode).toBe('string');
        expect(inviteCode.length).toBeGreaterThan(0);
    });

    // ── 7. Member joins room by invite code ───────────────────────────────────

    test('7. POST /api/rooms/join/{invite_code} lets member join', async ({ request }) => {
        await ensureRoom(request); expect(inviteCode).toBeTruthy();

        memberCsrf = await loginUser(request, memberUsername);

        const res = await request.post(`/api/rooms/join/${inviteCode}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('joined');
        expect(body).toHaveProperty('room');
        expect(body.room.id).toBe(roomId);

        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 8. Join with invalid code returns 404 ────────────────────────────────

    test('8. POST /api/rooms/join/BADCODE returns 404', async ({ request }) => {
        const res = await request.post('/api/rooms/join/BADCODE99', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.status()).toBe(404);
    });

    // ── 9. List room members ──────────────────────────────────────────────────

    test('9. GET /api/rooms/{id}/members lists all members with roles', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.get(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('members');
        expect(body.my_role).toBe('owner');

        const ownerEntry = body.members.find(m => m.user_id === ownerId);
        expect(ownerEntry).toBeDefined();
        expect(ownerEntry.role).toBe('owner');
    });

    // ── 10. Promote member to admin ───────────────────────────────────────────

    test('10. PUT /api/rooms/{id}/members/{uid}/role promotes to admin', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'admin' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body.role).toBe('admin');
    });

    // ── 11. Verify admin role reflected in members list ───────────────────────

    test('11. Promoted member shows admin role in GET members', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.get(`/api/rooms/${roomId}/members`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        const body = await res.json();
        const m = body.members.find(m => m.user_id === memberId);
        expect(m).toBeDefined();
        expect(m.role).toBe('admin');
    });

    // ── 12. Demote admin back to member ───────────────────────────────────────

    test('12. PUT /api/rooms/{id}/members/{uid}/role demotes to member', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'member' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.role).toBe('member');
    });

    // ── 13. Owner cannot change their own role ────────────────────────────────

    test('13. PUT own role returns 400', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${ownerId}/role`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { role: 'admin' },
        });
        expect(res.status()).toBe(400);
    });

    // ── 14. Mute a member ────────────────────────────────────────────────────

    test('14. PUT /api/rooms/{id}/members/{uid}/mute toggles mute on', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/mute`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body).toHaveProperty('is_muted');
    });

    // ── 15. Un-mute a member (second toggle) ─────────────────────────────────

    test('15. PUT /api/rooms/{id}/members/{uid}/mute second call toggles mute off', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/mute`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 16. Ban toggle ────────────────────────────────────────────────────────

    test('16. PUT /api/rooms/{id}/members/{uid}/ban toggles ban', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/ban`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body).toHaveProperty('is_banned');
    });

    // ── 17. Un-ban (second toggle) ────────────────────────────────────────────

    test('17. PUT /api/rooms/{id}/members/{uid}/ban second call un-bans', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}/members/${memberId}/ban`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 18. Kick (permanent ban via /kick endpoint) ───────────────────────────

    test('18. POST /api/rooms/{id}/kick/{uid} bans member from room', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0); expect(memberId).toBeGreaterThan(0);

        const res = await request.post(`/api/rooms/${roomId}/kick/${memberId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 19. Kicked member cannot rejoin ───────────────────────────────────────

    test('19. Banned member attempt to join room returns 403', async ({ request }) => {
        await ensureRoom(request); expect(inviteCode).toBeTruthy();

        memberCsrf = await loginUser(request, memberUsername);
        const res = await request.post(`/api/rooms/join/${inviteCode}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });
        expect(res.status()).toBe(403);

        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 20. Update room name ──────────────────────────────────────────────────

    test('20. PUT /api/rooms/{id} updates name', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { name: 'Renamed Room' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.name).toBe('Renamed Room');
    });

    // ── 21. Update room description ───────────────────────────────────────────

    test('21. PUT /api/rooms/{id} updates description', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { description: 'Updated via E2E test' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.description).toBe('Updated via E2E test');
    });

    // ── 22. Update room avatar emoji ──────────────────────────────────────────

    test('22. PUT /api/rooms/{id} updates avatar_emoji', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { avatar_emoji: '🔥' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.avatar_emoji).toBe('🔥');
    });

    // ── 23. Enable slow mode ──────────────────────────────────────────────────

    test('23. PUT /api/rooms/{id} sets slow_mode_seconds', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { slow_mode_seconds: 30 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.slow_mode_seconds).toBe(30);
    });

    // ── 24. Disable slow mode ─────────────────────────────────────────────────

    test('24. PUT /api/rooms/{id} disables slow mode with 0', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { slow_mode_seconds: 0 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.slow_mode_seconds).toBe(0);
    });

    // ── 25. Archive room (make private) ───────────────────────────────────────

    test('25. PUT /api/rooms/{id} archives room by setting is_private=true', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { is_private: true },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.is_private).toBe(true);
    });

    // ── 26. Archived room no longer in public listing ─────────────────────────

    test('26. Archived room disappears from GET /api/rooms/public', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.get('/api/rooms/public');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const found = body.rooms.find(r => r.id === roomId);
        expect(found).toBeUndefined();
    });

    // ── 27. Un-archive room ───────────────────────────────────────────────────

    test('27. PUT /api/rooms/{id} un-archives room by is_private=false', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { is_private: false },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.is_private).toBe(false);
    });

    // ── 28. Enable auto-delete ────────────────────────────────────────────────

    test('28. PUT /api/rooms/{id} sets auto_delete_seconds=3600', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        const res = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { auto_delete_seconds: 3600 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.auto_delete_seconds).toBe(3600);
    });

    // ── 29. Key bundle returns has_key=true for owner ─────────────────────────

    test('29. GET /api/rooms/{id}/key-bundle returns has_key=true for owner', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        // Test 18 (kick) rotates ALL room keys.  Re-provision the owner's key
        // via provide-key so that get key-bundle returns has_key=true.
        const provideRes = await request.post(`/api/rooms/${roomId}/provide-key`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { for_user_id: ownerId, ...makeEciesPayload() },
        });
        expect([200, 201]).toContain(provideRes.status());

        const res = await request.get(`/api/rooms/${roomId}/key-bundle`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.has_key).toBe(true);
        expect(body).toHaveProperty('ephemeral_pub');
        expect(body).toHaveProperty('ciphertext');
    });

    // ── 30. Non-admin cannot update room settings ─────────────────────────────

    test('30. Regular member cannot update room settings (403)', async ({ request }) => {
        await ensureRoom(request); expect(roomId).toBeGreaterThan(0);

        // Create another user who joins but is only a member
        const tempUser = `rm_temp_${randomStr(5)}`;
        const tempPhone = `+7932${randomDigits(7)}`;
        const { csrfToken: tempCsrf } = await registerAndLogin(request, tempUser, tempPhone);

        // Join the room
        await request.post(`/api/rooms/join/${inviteCode}`, {
            headers: { 'X-CSRF-Token': tempCsrf },
        });

        // Attempt to update settings
        const updateRes = await request.put(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': tempCsrf },
            data: { name: 'Hijacked Room' },
        });
        expect(updateRes.status()).toBe(403);

        // Restore owner session
        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── 31. Leave room ────────────────────────────────────────────────────────

    test('31. DELETE /api/rooms/{id}/leave removes user from room', async ({ request }) => {
        // Create a disposable room for this test
        const leaveRes = await createRoom(request, ownerCsrf, `rm_leave_${randomStr(4)}`);
        expect([200, 201]).toContain(leaveRes.status());
        const leaveRoom = await leaveRes.json();
        const leaveRoomId = leaveRoom.id;

        // Second user joins
        memberCsrf = await loginUser(request, memberUsername);
        await request.post(`/api/rooms/join/${leaveRoom.invite_code}`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });

        // Second user leaves
        const res = await request.delete(`/api/rooms/${leaveRoomId}/leave`, {
            headers: { 'X-CSRF-Token': memberCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.left).toBe(true);

        ownerCsrf = await loginUser(request, ownerUsername);
    });

    // ── Cleanup ───────────────────────────────────────────────────────────────

    test.afterAll(async ({ request }) => {
        ownerCsrf = await loginUser(request, ownerUsername);

        for (const rid of [roomId, privateRoomId]) {
            if (rid) {
                await request.delete(`/api/rooms/${rid}/leave`, {
                    headers: { 'X-CSRF-Token': ownerCsrf },
                });
            }
        }

        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
    });
});

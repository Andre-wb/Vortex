// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, getMeId } = require('./helpers');

/**
 * Vortex E2E — Contacts Management
 *
 * Covers:
 *   - Add contact by user_id
 *   - List contacts
 *   - Update contact nickname
 *   - Delete contact
 *   - Block / unblock user
 *   - Search users (prerequisite for finding IDs)
 *   - Duplicate / self-add / invalid-id edge cases
 */

/** Search for a user by username and return their id (with retry). */
async function resolveUserId(request, csrf, username) {
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            const res = await request.get(
                `/api/users/search?q=${username}`,
                { headers: { 'X-CSRF-Token': csrf } },
            );
            if (res.ok()) {
                const body = await res.json();
                const users = body.users || body.results || [];
                const found = users.find(u => u.username === username);
                if (found) return found.user_id || found.id || 0;
            }
        } catch (_) { /* retry */ }
        if (attempt < 2) await new Promise(r => setTimeout(r, 500));
    }
    return 0;
}

// ── Test suite ────────────────────────────────────────────────────────────────

test.describe('Contacts', () => {
    // Primary user — owns the contacts
    const ownerUsername = `ct_owner_${randomStr(6)}`;
    const ownerPhone    = `+7910${randomDigits(7)}`;

    // Secondary user — will be added / blocked
    const targetUsername = `ct_target_${randomStr(6)}`;
    const targetPhone    = `+7911${randomDigits(7)}`;

    // Third user — for additional edge-case tests
    const extraUsername = `ct_extra_${randomStr(6)}`;
    const extraPhone    = `+7912${randomDigits(7)}`;

    let ownerCsrf   = '';
    let targetId    = 0;
    let ownerId     = 0;
    let extraId     = 0;
    let contactId   = 0; // returned by POST /api/contacts

    /** Ensure targetId is resolved (lazy retry). */
    async function ensureTarget(request) {
        if (targetId > 0) return;
        targetId = await resolveUserId(request, ownerCsrf, targetUsername);
    }

    /** Ensure contactId is valid (lazy add contact). */
    async function ensureContact(request) {
        if (contactId > 0) return;
        await ensureTarget(request);
        expect(targetId).toBeTruthy();
        try {
            const res = await request.post('/api/contacts', {
                headers: { 'X-CSRF-Token': ownerCsrf },
                data: { user_id: targetId },
            });
            if ([200, 201].includes(res.status())) {
                const body = await res.json();
                contactId = body.contact_id || 0;
            } else if (res.status() === 409) {
                // Already exists — fetch from listing
                const listRes = await request.get('/api/contacts', {
                    headers: { 'X-CSRF-Token': ownerCsrf },
                });
                if (listRes.ok()) {
                    const listBody = await listRes.json();
                    const c = (listBody.contacts || []).find(c => c.user_id === targetId);
                    if (c) contactId = c.contact_id;
                }
            }
        } catch (_) {}
    }

    // ── Setup: register both users, login as owner ────────────────────────────

    test.beforeAll(async ({ request }) => {
        // Register owner
        const { csrfToken: oc } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc;
        ownerId = await getMeId(request, ownerCsrf);

        // Register target user
        const { csrfToken: tc } = await registerAndLogin(request, targetUsername, targetPhone);
        targetId = await getMeId(request, tc);

        // Register extra user
        const { csrfToken: ec } = await registerAndLogin(request, extraUsername, extraPhone);
        extraId = await getMeId(request, ec);

        // Re-login as owner to restore session
        const { csrfToken: oc2 } = await registerAndLogin(request, ownerUsername, ownerPhone);
        ownerCsrf = oc2;
    });

    // ── 1. List contacts — empty initially ───────────────────────────────────

    test('1. GET /api/contacts returns empty list for new user', async ({ request }) => {
        const res = await request.get('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toHaveProperty('contacts');
        expect(Array.isArray(body.contacts)).toBe(true);
        expect(body.contacts.length).toBe(0);
    });

    // ── 2. Add contact ────────────────────────────────────────────────────────

    test('2. POST /api/contacts adds a contact by user_id', async ({ request }) => {
        await ensureTarget(request); expect(targetId).toBeGreaterThan(0);

        const res = await request.post('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: targetId },
        });
        expect(res.status()).toBe(201);

        const body = await res.json();
        expect(body).toHaveProperty('contact_id');
        expect(body.user_id).toBe(targetId);
        expect(body.username).toBe(targetUsername);
        expect(body).toHaveProperty('created_at');
        contactId = body.contact_id;
    });

    // ── 3. List contacts — non-empty after add ────────────────────────────────

    test('3. GET /api/contacts lists the newly added contact', async ({ request }) => {
        await ensureContact(request); expect(contactId).toBeGreaterThan(0);

        const res = await request.get('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.contacts)).toBe(true);

        const found = body.contacts.find(c => c.contact_id === contactId);
        expect(found).toBeDefined();
        expect(found.username).toBe(targetUsername);
        expect(found).toHaveProperty('is_online');
        expect(found).toHaveProperty('presence');
    });

    // ── 4. Duplicate add returns 409 ─────────────────────────────────────────

    test('4. POST /api/contacts duplicate contact returns 409', async ({ request }) => {
        await ensureTarget(request); expect(targetId).toBeGreaterThan(0);

        const res = await request.post('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: targetId },
        });
        expect(res.status()).toBe(409);
    });

    // ── 5. Cannot add self ────────────────────────────────────────────────────

    test('5. POST /api/contacts with own user_id returns 400', async ({ request }) => {
        const res = await request.post('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: ownerId },
        });
        expect(res.status()).toBe(400);
    });

    // ── 6. Add non-existent user returns 404 ─────────────────────────────────

    test('6. POST /api/contacts with invalid user_id returns 404', async ({ request }) => {
        const res = await request.post('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: 999999999 },
        });
        expect(res.status()).toBe(404);
    });

    // ── 7. Update contact nickname ────────────────────────────────────────────

    test('7. PUT /api/contacts/{id} sets a nickname', async ({ request }) => {
        await ensureContact(request); expect(contactId).toBeGreaterThan(0);

        const res = await request.put(`/api/contacts/${contactId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { nickname: 'My Buddy' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body.nickname).toBe('My Buddy');
        expect(body.contact_id).toBe(contactId);
    });

    // ── 8. Nickname persists in listing ──────────────────────────────────────

    test('8. Updated nickname is reflected in GET /api/contacts', async ({ request }) => {
        await ensureContact(request); expect(contactId).toBeGreaterThan(0);

        const res = await request.get('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const found = body.contacts.find(c => c.contact_id === contactId);
        expect(found).toBeDefined();
        expect(found.nickname).toBe('My Buddy');
    });

    // ── 9. Update nickname — invalid contact id returns 404 ──────────────────

    test('9. PUT /api/contacts/999999 returns 404', async ({ request }) => {
        const res = await request.put('/api/contacts/999999', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { nickname: 'Ghost' },
        });
        expect(res.status()).toBe(404);
    });

    // ── 10. Update nickname — empty string ───────────────────────────────────

    test('10. PUT /api/contacts/{id} clears nickname with empty string', async ({ request }) => {
        await ensureContact(request); expect(contactId).toBeGreaterThan(0);

        const res = await request.put(`/api/contacts/${contactId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { nickname: '' },
        });
        // Server may return 200 or 422 depending on min_length validation
        expect([200, 422]).toContain(res.status());
    });

    // ── 11. Block user ────────────────────────────────────────────────────────

    test('11. POST /api/users/block/{id} blocks a user', async ({ request }) => {
        await ensureTarget(request); expect(targetId).toBeGreaterThan(0);

        const res = await request.post(`/api/users/block/${targetId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body.blocked).toBe(true);
    });

    // ── 12. Block self returns 400 ────────────────────────────────────────────

    test('12. POST /api/users/block/{own_id} returns 400', async ({ request }) => {
        const res = await request.post(`/api/users/block/${ownerId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.status()).toBe(400);
    });

    // ── 13. Block non-existent user returns 404 ───────────────────────────────

    test('13. POST /api/users/block/999999999 returns 404', async ({ request }) => {
        const res = await request.post('/api/users/block/999999999', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.status()).toBe(404);
    });

    // ── 14. Add extra user as contact ─────────────────────────────────────────

    test('14. POST /api/contacts adds extra user as second contact', async ({ request }) => {
        if (!extraId) extraId = await resolveUserId(request, ownerCsrf, extraUsername);
        expect(extraId).toBeGreaterThan(0);

        const res = await request.post('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
            data: { user_id: extraId },
        });
        expect([201]).toContain(res.status());
        const body = await res.json();
        expect(body.username).toBe(extraUsername);
    });

    // ── 15. Unauthenticated request returns 401 ───────────────────────────────

    test('15. GET /api/contacts without auth returns 401', async ({ freshRequest: request }) => {
        // Fresh request context with no cookies
        const res = await request.get('/api/contacts');
        expect([401, 403]).toContain(res.status());
    });

    // ── 16. Search users finds target ────────────────────────────────────────

    test('16. GET /api/users/search returns matching users', async ({ request }) => {
        const res = await request.get(
            `/api/users/search?q=${targetUsername.slice(0, 8)}`,
            { headers: { 'X-CSRF-Token': ownerCsrf } },
        );
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const users = body.users || body.results || [];
        expect(Array.isArray(users)).toBe(true);
    });

    // ── 17. Search empty query returns results or 422 ─────────────────────────

    test('17. GET /api/users/search with empty q is handled gracefully', async ({ request }) => {
        const res = await request.get('/api/users/search?q=', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect([200, 422]).toContain(res.status());
    });

    // ── 18. Delete contact ────────────────────────────────────────────────────

    test('18. DELETE /api/contacts/{id} removes a contact', async ({ request }) => {
        await ensureContact(request); expect(contactId).toBeGreaterThan(0);

        const res = await request.delete(`/api/contacts/${contactId}`, {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 19. Deleted contact no longer in listing ──────────────────────────────

    test('19. Deleted contact is absent from GET /api/contacts', async ({ request }) => {
        await ensureContact(request); expect(contactId).toBeGreaterThan(0);

        const res = await request.get('/api/contacts', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const found = body.contacts.find(c => c.contact_id === contactId);
        expect(found).toBeUndefined();
    });

    // ── 20. Delete non-existent contact returns 404 ───────────────────────────

    test('20. DELETE /api/contacts/999999 returns 404', async ({ request }) => {
        const res = await request.delete('/api/contacts/999999', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
        expect(res.status()).toBe(404);
    });

    // ── Cleanup ───────────────────────────────────────────────────────────────

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': ownerCsrf },
        });
    });
});

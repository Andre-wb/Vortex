// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, makeEciesPayload, getMeId } = require('./helpers');

/**
 * Vortex E2E — Direct Messages
 *
 * Covers:
 *   - Create DM with another user
 *   - List DMs
 *   - Send message in DM
 *   - Store encrypted room key for DM
 *   - Edge cases
 */

test.describe('Direct Messages', () => {
    const user1 = `dm_u1_${randomStr(6)}`;
    const phone1 = `+7958${randomDigits(7)}`;
    const user2 = `dm_u2_${randomStr(6)}`;
    const phone2 = `+7959${randomDigits(7)}`;

    let csrf1 = '';
    let userId1 = 0;
    let userId2 = 0;
    let dmRoomId = 0;

    test.beforeAll(async ({ request }) => {
        // Register user1
        const { csrfToken: c1 } = await registerAndLogin(request, user1, phone1);
        csrf1 = c1;
        userId1 = await getMeId(request, csrf1);

        // Register user2
        const { csrfToken: csrf2 } = await registerAndLogin(request, user2, phone2);
        userId2 = await getMeId(request, csrf2);

        // Re-login as user1
        const { csrfToken: c1b } = await registerAndLogin(request, user1, phone1);
        csrf1 = c1b;
    });

    test('create DM with another user', async ({ request }) => {
        const res = await request.post(`/api/dm/${userId2}`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { encrypted_room_key: makeEciesPayload() },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        dmRoomId = body.room?.id || body.room_id || body.id;
        expect(dmRoomId).toBeGreaterThan(0);
    });

    test('list DMs', async ({ request }) => {
        const res = await request.get('/api/dm/list', {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.rooms || body.dms || [])).toBeTruthy();
    });

    test('send message in DM', async ({ request }) => {
        expect(dmRoomId).toBeGreaterThan(0);
        const res = await request.post(`/api/rooms/${dmRoomId}/messages`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { ciphertext: 'Hello from E2E DM test!' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('store encrypted key for DM', async ({ request }) => {
        expect(dmRoomId).toBeGreaterThan(0);
        const payload = makeEciesPayload();
        const res = await request.post(`/api/dm/store-key/${dmRoomId}`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: {
                user_id: userId2,
                ephemeral_pub: payload.ephemeral_pub,
                ciphertext: payload.ciphertext,
            },
        });
        expect([200, 201, 204]).toContain(res.status());
    });

    test('create DM with same user returns existing', async ({ request }) => {
        const res = await request.post(`/api/dm/${userId2}`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { encrypted_room_key: makeEciesPayload() },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.room?.id || body.room_id || body.id).toBe(dmRoomId);
    });

    test('create DM with non-existent user fails', async ({ request }) => {
        const res = await request.post('/api/dm/999999', {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { encrypted_room_key: makeEciesPayload() },
        });
        expect([404, 400]).toContain(res.status());
    });
});

// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, loginUser } = require('./helpers');

/**
 * Vortex E2E — Calls & Group Calls
 *
 * Covers:
 *   1. Individual calls — start, end, history, missed, stats, clear, delete
 *   2. Group calls — start, join, decline, leave, end, add participant, status, active
 *   3. SFU availability
 *   4. Error / edge cases
 */

test.describe('Calls', () => {
    const username = `call_u1_${randomStr(6)}`;
    const phone = `+7950${randomDigits(7)}`;
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

        roomId = await createRoom(request, csrf, 'call_room');
    });

    // ── 1-on-1 Calls ─────────────────────────────────────────────────────────

    test('start and end a call', async ({ request }) => {
        const startRes = await request.post('/api/calls/start', {
            headers: { 'X-CSRF-Token': csrf },
            data: { room_id: roomId, call_type: 'audio' },
        });
        expect([200, 201]).toContain(startRes.status());

        const endRes = await request.post('/api/calls/end', {
            headers: { 'X-CSRF-Token': csrf },
            data: { room_id: roomId },
        });
        expect([200, 204, 422]).toContain(endRes.status());
    });

    test('recent calls list', async ({ request }) => {
        const res = await request.get('/api/calls/recent', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.calls || body)).toBeTruthy();
    });

    test('missed calls list', async ({ request }) => {
        const res = await request.get('/api/calls/missed', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('call statistics', async ({ request }) => {
        const res = await request.get('/api/calls/stats', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('clear call history', async ({ request }) => {
        const res = await request.delete('/api/calls/clear', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Group Calls ───────────────────────────────────────────────────────────

    test('start group call in room', async ({ request }) => {
        const res = await request.post(`/api/group-calls/${roomId}/start`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { with_video: false },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        expect(body.call_id).toBeTruthy();
    });

    test('get active group call', async ({ request }) => {
        const res = await request.get(`/api/group-calls/${roomId}/active`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('no duplicate active calls', async ({ request }) => {
        const res = await request.post(`/api/group-calls/${roomId}/start`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { with_video: false },
        });
        // Should indicate already active
        const body = await res.json();
        expect(body.call_id || body.already_active !== undefined).toBeTruthy();
    });

    test('group call status', async ({ request }) => {
        // Get active call first
        const activeRes = await request.get(`/api/group-calls/${roomId}/active`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        const active = await activeRes.json();
        if (active.call_id) {
            const res = await request.get(`/api/group-calls/${active.call_id}/status`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect(res.ok()).toBeTruthy();
        }
    });

    test('join group call', async ({ request }) => {
        const activeRes = await request.get(`/api/group-calls/${roomId}/active`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        const active = await activeRes.json();
        if (active.call_id) {
            const res = await request.post(`/api/group-calls/${active.call_id}/join`, {
                headers: { 'X-CSRF-Token': csrf },
                data: { with_video: false },
            });
            expect([200, 201]).toContain(res.status());
        }
    });

    test('leave group call', async ({ request }) => {
        const activeRes = await request.get(`/api/group-calls/${roomId}/active`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        const active = await activeRes.json();
        if (active.call_id) {
            const res = await request.post(`/api/group-calls/${active.call_id}/leave`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect([200, 204]).toContain(res.status());
        }
    });

    test('add participant to group call', async ({ request }) => {
        const activeRes = await request.get(`/api/group-calls/${roomId}/active`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        const active = await activeRes.json();
        if (active.call_id) {
            const res = await request.post(`/api/group-calls/${active.call_id}/add/${userId}`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect([200, 201, 400]).toContain(res.status());
        }
    });

    test('end group call', async ({ request }) => {
        const activeRes = await request.get(`/api/group-calls/${roomId}/active`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        const active = await activeRes.json();
        if (active.call_id) {
            const res = await request.post(`/api/group-calls/${active.call_id}/end`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect([200, 204]).toContain(res.status());
        }
    });

    test('delete specific call from history', async ({ request }) => {
        const res = await request.delete('/api/calls/1', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    test('SFU join', async ({ request }) => {
        const res = await request.post('/api/sfu/1/join', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    test('SFU leave', async ({ request }) => {
        const res = await request.post('/api/sfu/1/leave', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('decline non-existent group call returns error', async ({ request }) => {
        const res = await request.post('/api/group-calls/999999/decline', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([404, 400, 422]).toContain(res.status());
    });

    // ── SFU ──────────────────────────────────────────────────────────────────

    test('SFU availability check', async ({ request }) => {
        const res = await request.get('/api/sfu/available', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

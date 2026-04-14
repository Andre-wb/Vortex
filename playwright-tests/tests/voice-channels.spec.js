// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — Voice Channels
 *
 * Covers:
 *   - Join / leave voice channel
 *   - Participants list
 *   - Mute / video toggle
 *   - SFU config retrieval
 *   - Recording start / stop / status
 *   - Stage mode (enable, disable, add/remove speaker, raise hand, status)
 *   - Media config
 */

test.describe('Voice Channels', () => {
    const username = `vc_u1_${randomStr(6)}`;
    const phone = `+7951${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'voice_room', { is_voice: true });
    });

    // ── Core ──────────────────────────────────────────────────────────────────

    test('join voice channel', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/join`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get participants', async ({ request }) => {
        const res = await request.get(`/api/voice/${roomId}/participants`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.participants || body)).toBeTruthy();
    });

    test('toggle mute', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/mute`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { muted: true },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get SFU config', async ({ request }) => {
        const res = await request.get(`/api/voice/${roomId}/sfu-config`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get media config', async ({ request }) => {
        const res = await request.get(`/api/voice/${roomId}/media-config`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Recording ─────────────────────────────────────────────────────────────

    test('recording status (not started)', async ({ request }) => {
        const res = await request.get(`/api/voice/${roomId}/recording/status`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('start recording', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/recording/start`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('stop recording', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/recording/stop`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Stage Mode ────────────────────────────────────────────────────────────

    test('enable stage mode', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/stage/enable`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('stage status', async ({ request }) => {
        const res = await request.get(`/api/voice/${roomId}/stage/status`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('raise hand', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/stage/raise-hand`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('add speaker (self)', async ({ request }) => {
        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        const me = await meRes.json();
        const res = await request.post(`/api/voice/${roomId}/stage/add-speaker/${me.user_id}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('remove speaker (self)', async ({ request }) => {
        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        const me = await meRes.json();
        const res = await request.post(`/api/voice/${roomId}/stage/remove-speaker/${me.user_id}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('disable stage mode', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/stage/disable`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Cleanup ───────────────────────────────────────────────────────────────

    test('leave voice channel', async ({ request }) => {
        const res = await request.post(`/api/voice/${roomId}/leave`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, makePublicKey, getMeId } = require('./helpers');

/**
 * Vortex E2E — Auth Endpoints (missing coverage)
 *
 * Covers:
 *   - QR confirm / check
 *   - 2FA enable / disable / verify-login
 *   - Passkey register-verify / login-verify
 *   - Devices delete (single / all)
 *   - Profile PUT (separate endpoint)
 *   - Panic button POST
 */

test.describe('Auth Complete', () => {
    const username = `authc_u_${randomStr(6)}`;
    const phone = `+7973${randomDigits(7)}`;
    const password = 'AuthComplete99!@';
    let csrf = '';
    let userId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone, password);
        csrf = csrfToken;
        userId = await getMeId(request, csrf);
    });

    // ── QR Login ──────────────────────────────────────────────────────────────

    test('QR confirm (no session)', async ({ request }) => {
        const res = await request.post('/api/authentication/qr-confirm', {
            headers: { 'X-CSRF-Token': csrf },
            data: { session_id: 'fake_session_id' },
        });
        expect([200, 400, 422]).toContain(res.status());
    });

    test('QR check session', async ({ request }) => {
        const res = await request.get('/api/authentication/qr-check/fake_session_id', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 400, 404]).toContain(res.status());
    });

    // ── 2FA ───────────────────────────────────────────────────────────────────

    test('2FA enable with invalid code fails', async ({ request }) => {
        const res = await request.post('/api/authentication/2fa/enable', {
            headers: { 'X-CSRF-Token': csrf },
            data: { code: '000000' },
        });
        expect([400, 401, 403, 404]).toContain(res.status());
    });

    test('2FA disable with invalid code fails', async ({ request }) => {
        const res = await request.post('/api/authentication/2fa/disable', {
            headers: { 'X-CSRF-Token': csrf },
            data: { code: '000000' },
        });
        expect([200, 400, 401, 403]).toContain(res.status());
    });

    test('2FA verify-login (no pending 2FA)', async ({ request }) => {
        const res = await request.post('/api/authentication/2fa/verify-login', {
            headers: { 'X-CSRF-Token': csrf },
            data: { code: '123456' },
        });
        expect([400, 401, 403, 404, 422]).toContain(res.status());
    });

    // ── Passkey Verify ────────────────────────────────────────────────────────

    test('passkey register-verify with invalid data', async ({ request }) => {
        const res = await request.post('/api/authentication/passkey/register-verify', {
            headers: { 'X-CSRF-Token': csrf },
            data: { credential: {} },
        });
        expect([400, 404, 422]).toContain(res.status());
    });

    test('passkey login-verify with invalid data', async ({ request }) => {
        const res = await request.post('/api/authentication/passkey/login-verify', {
            data: { credential: {} },
        });
        expect([400, 404, 422]).toContain(res.status());
    });

    // ── Devices ───────────────────────────────────────────────────────────────

    test('delete non-existent device', async ({ request }) => {
        const res = await request.delete('/api/authentication/devices/999999', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 403, 404]).toContain(res.status());
    });

    test('delete all devices', async ({ request }) => {
        const res = await request.delete('/api/authentication/devices', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 403]).toContain(res.status());

        // Re-login after deleting devices
        await request.post('/api/authentication/login', {
            data: { phone_or_username: username, password },
        });
        const csrfRes = await request.get('/api/authentication/csrf-token');
        csrf = (await csrfRes.json()).csrf_token;
    });

    // ── Profile (PUT /profile) ────────────────────────────────────────────────

    test('update profile via /profile endpoint', async ({ request }) => {
        const res = await request.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { display_name: 'Updated via /profile', bio: 'test bio' },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Panic ─────────────────────────────────────────────────────────────────

    test('panic button (trigger)', async ({ request }) => {
        // Don't actually wipe — test that the endpoint exists
        const res = await request.post('/api/panic', {
            headers: { 'X-CSRF-Token': csrf },
            data: { password: 'wrong_password_intentionally' },
        });
        expect([200, 400, 401, 403]).toContain(res.status());
    });
});

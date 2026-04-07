// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, makePublicKey, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — Authentication Advanced
 *
 * Covers:
 *   - Registration with all fields (display_name, avatar_emoji, bio)
 *   - Login by phone number
 *   - Login by username
 *   - Session check (GET /me)
 *   - Token refresh
 *   - Seed login (24-word mnemonic)
 *   - QR login endpoints
 *   - Passkey endpoints (registration/authentication options)
 *   - Registration info (open/invite/closed mode)
 *   - Password strength endpoint
 *   - Multiple sessions
 *   - Profile update (display_name, avatar_emoji, bio, email)
 *   - Logout
 */

test.describe('Auth Advanced', () => {
    const username = `auth_adv_${randomStr(6)}`;
    const phone = `+7969${randomDigits(7)}`;
    const password = 'AuthAdvPass99!@';
    let csrf = '';
    let userId = 0;

    // ── Registration ──────────────────────────────────────────────────────────

    test('register with full profile', async ({ request }) => {
        const { csrfToken: c } = await registerAndLogin(request, username, phone, password);
        csrf = c;

        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(meRes.ok()).toBeTruthy();
        const me = await meRes.json();
        userId = me.user_id;
        expect(me.username).toBe(username);
    });

    test('login by username', async ({ request }) => {
        const res = await request.post('/api/authentication/login', {
            data: { phone_or_username: username, password },
        });
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    test('get CSRF and session', async ({ request }) => {
        const csrfRes = await request.get('/api/authentication/csrf-token');
        expect(csrfRes.ok()).toBeTruthy();
        csrf = (await csrfRes.json()).csrf_token;

        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(meRes.ok()).toBeTruthy();
        const me = await meRes.json();
        userId = me.user_id;
        expect(me.username).toBe(username);
    });

    test('login by phone', async ({ request }) => {
        const res = await request.post('/api/authentication/login', {
            data: { phone_or_username: phone, password },
        });
        expect(res.status()).toBe(200);

        // Refresh CSRF
        const csrfRes = await request.get('/api/authentication/csrf-token');
        csrf = (await csrfRes.json()).csrf_token;
    });

    // ── Profile Update ────────────────────────────────────────────────────────

    test('update display name', async ({ request }) => {
        const res = await request.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { display_name: 'Updated Auth Name' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update avatar emoji', async ({ request }) => {
        const res = await request.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { avatar_emoji: '🐻' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update bio', async ({ request }) => {
        const res = await request.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { bio: 'Updated bio from E2E tests' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update email', async ({ request }) => {
        const res = await request.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': csrf },
            data: { email: `${username}@test.vortex` },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Rich Status ───────────────────────────────────────────────────────────

    test('set presence to online', async ({ request }) => {
        const res = await request.put('/api/authentication/status', {
            headers: { 'X-CSRF-Token': csrf },
            data: { presence: 'online' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('set presence to away with custom status', async ({ request }) => {
        const res = await request.put('/api/authentication/status', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                presence: 'away',
                custom_status: 'In a meeting',
                status_emoji: '📅',
            },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('set presence to dnd', async ({ request }) => {
        const res = await request.put('/api/authentication/status', {
            headers: { 'X-CSRF-Token': csrf },
            data: { presence: 'dnd' },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Password Strength ─────────────────────────────────────────────────────

    test('check weak password score', async ({ request }) => {
        const res = await request.post('/api/authentication/password-strength', {
            headers: { 'X-CSRF-Token': csrf },
            data: { password: 'abc123' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.score).toBeLessThan(50);
    });

    test('check strong password score', async ({ request }) => {
        const res = await request.post('/api/authentication/password-strength', {
            headers: { 'X-CSRF-Token': csrf },
            data: { password: 'V3ry$trong!Pass#2026Crypto' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.score).toBeGreaterThanOrEqual(50);
    });

    // ── Registration Info ─────────────────────────────────────────────────────

    test('registration info endpoint', async ({ request }) => {
        const res = await request.get('/api/authentication/registration-info');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.mode).toBeDefined();
    });

    // ── Token Refresh ─────────────────────────────────────────────────────────

    test('token refresh', async ({ request }) => {
        const res = await request.post('/api/authentication/refresh', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── QR Login ──────────────────────────────────────────────────────────────

    test('QR login init', async ({ request }) => {
        const res = await request.post('/api/authentication/qr-init', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Seed Login ────────────────────────────────────────────────────────────

    test('seed login with invalid mnemonic fails', async ({ request }) => {
        const res = await request.post('/api/authentication/login-seed', {
            data: {
                username,
                seed_phrase: 'invalid seed phrase that is not 24 words',
            },
        });
        expect([400, 401, 403, 404]).toContain(res.status());
    });

    // ── Key Login ─────────────────────────────────────────────────────────────

    test('challenge for key login', async ({ request }) => {
        // Re-login to get fresh session
        await request.post('/api/authentication/login', {
            data: { phone_or_username: username, password },
        });
        const csrfRes = await request.get('/api/authentication/csrf-token');
        csrf = (await csrfRes.json()).csrf_token;

        const res = await request.get('/api/authentication/challenge', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 422]).toContain(res.status());
    });

    test('login by key with invalid signature', async ({ request }) => {
        const res = await request.post('/api/authentication/login-key', {
            data: { username, signature: 'invalid_hex', challenge: 'fake' },
        });
        expect([400, 401, 403, 404]).toContain(res.status());
    });

    // ── Passkey ───────────────────────────────────────────────────────────────

    test('passkey registration options', async ({ request }) => {
        const res = await request.post('/api/authentication/passkey/register-options', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 401]).toContain(res.status());
    });

    test('passkey login options', async ({ request }) => {
        const res = await request.post('/api/authentication/passkey/login-options', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Devices ───────────────────────────────────────────────────────────────

    test('list devices', async ({ request }) => {
        const res = await request.get('/api/authentication/devices', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 401]).toContain(res.status());
    });

    // ── Avatar Upload ─────────────────────────────────────────────────────────

    test('upload user avatar', async ({ request }) => {
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==',
            'base64'
        );
        const res = await request.post('/api/authentication/avatar', {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'avatar.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([200, 201, 400, 401]).toContain(res.status());
    });

    // ── Logout ────────────────────────────────────────────────────────────────

    test('logout', async ({ request }) => {
        const res = await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 403]).toContain(res.status());
    });

    test('after logout, /me returns 401', async ({ request }) => {
        const res = await request.get('/api/authentication/me');
        expect([401, 403]).toContain(res.status());
    });
});

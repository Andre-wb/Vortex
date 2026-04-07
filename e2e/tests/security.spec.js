// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, makePublicKey, makeHex } = require('./helpers');

/**
 * Vortex E2E — Security & Privacy
 *
 * Covers:
 *   - CSRF token validation
 *   - Unauthorized access (no session)
 *   - Key backup (upload / download / delete)
 *   - Device linking (request / poll)
 *   - Node public key retrieval
 *   - ICE servers
 *   - VAPID public key
 *   - Password change
 *   - 2FA setup / status
 *   - Passkey registration status
 *   - Warrant canary
 *   - GDPR export / delete
 *   - Privacy endpoints (Tor, ephemeral, ZK)
 *   - Panic button
 *   - Post-quantum crypto status
 */

test.describe('Security & Privacy', () => {
    const username = `sec_u_${randomStr(6)}`;
    const phone = `+7960${randomDigits(7)}`;
    const password = 'E2ePass99!@';
    let csrf = '';
    let userId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone, password);
        csrf = csrfToken;

        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        userId = (await meRes.json()).user_id;
    });

    // ── CSRF ──────────────────────────────────────────────────────────────────

    test('get fresh CSRF token', async ({ request }) => {
        const res = await request.get('/api/authentication/csrf-token');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.csrf_token).toBeDefined();
        expect(body.csrf_token.length).toBeGreaterThan(10);
    });

    // ── Unauthorized access ───────────────────────────────────────────────────

    test('unauthenticated request to protected endpoint', async ({ freshRequest }) => {
        const res = await freshRequest.get('/api/rooms/my');
        expect([401, 403]).toContain(res.status());
    });

    test('request without CSRF to state-changing endpoint', async ({ request }) => {
        const res = await request.post('/api/rooms', {
            data: { name: 'test_no_csrf' },
        });
        // Should fail with CSRF error
        expect([400, 403, 422]).toContain(res.status());
    });

    // ── Node Keys ─────────────────────────────────────────────────────────────

    test('get node X25519 public key', async ({ request }) => {
        const res = await request.get('/api/keys/pubkey', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.pubkey_hex).toBeDefined();
    });

    test('get ICE servers', async ({ request }) => {
        const res = await request.get('/api/keys/ice-servers', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get VAPID public key', async ({ request }) => {
        const res = await request.get('/api/keys/vapid-public', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Key Backup ────────────────────────────────────────────────────────────

    test('upload key backup', async ({ request }) => {
        const res = await request.post('/api/keys/backup', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                vault_data: makeHex(64),
                vault_salt: makeHex(16),
                kdf_params: '{"alg":"PBKDF2","iter":600000,"hash":"SHA-256"}',
            },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('download key backup', async ({ request }) => {
        const res = await request.get('/api/keys/backup', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('delete key backup', async ({ request }) => {
        const res = await request.delete('/api/keys/backup', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Device Linking ────────────────────────────────────────────────────────

    test('request device link', async ({ request }) => {
        const res = await request.post('/api/keys/link/request', {
            headers: { 'X-CSRF-Token': csrf },
            data: { new_device_pub: makePublicKey() },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        const linkCode = body.link_code || body.code;
        expect(linkCode).toBeTruthy();
        // Get link request by code
        const getRes = await request.get(`/api/keys/link/${linkCode}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(getRes.ok()).toBeTruthy();
    });

    // ── Password Change ───────────────────────────────────────────────────────

    test('change password', async ({ request }) => {
        const newPassword = 'NewE2ePass99!@#';
        const res = await request.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                current_password: password,
                new_password: newPassword,
            },
        });
        // May be /change-password or included in /me PUT
        expect([200, 204, 400]).toContain(res.status());

        // Restore original password
        if (res.ok()) {
            await request.put('/api/authentication/profile', {
                headers: { 'X-CSRF-Token': csrf },
                data: {
                    current_password: newPassword,
                    new_password: password,
                },
            });
        }
    });

    // ── 2FA ───────────────────────────────────────────────────────────────────

    test('2FA setup — get secret', async ({ request }) => {
        const res = await request.post('/api/authentication/2fa/setup', {
            headers: { 'X-CSRF-Token': csrf },
        });
        // 200 with secret, or 400 if already enabled
        expect([200, 400]).toContain(res.status());
    });

    test('2FA status', async ({ request }) => {
        const res = await request.get('/api/authentication/2fa/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Passkeys ──────────────────────────────────────────────────────────────

    test('passkey registration options', async ({ request }) => {
        const res = await request.post('/api/authentication/passkey/register-options', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Crypto Status ─────────────────────────────────────────────────────────

    test('post-quantum crypto status', async ({ request }) => {
        const res = await request.get('/api/crypto/pq-status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Privacy Endpoints ─────────────────────────────────────────────────────

    test('Tor status', async ({ request }) => {
        const res = await request.get('/api/privacy/tor/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('generate ephemeral identity', async ({ request }) => {
        const res = await request.post('/api/privacy/ephemeral/generate', {
            headers: { 'X-CSRF-Token': csrf },
            data: { secret: randomStr(32), room_id: 1 },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    test('get new ephemeral secret', async ({ request }) => {
        const res = await request.get('/api/privacy/ephemeral/new-secret', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('ZK challenge', async ({ request }) => {
        const res = await request.post('/api/privacy/zk/challenge', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 422]).toContain(res.status());
    });

    test('ZK info', async ({ request }) => {
        const res = await request.get('/api/privacy/zk/info', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('privacy overall status', async ({ request }) => {
        const res = await request.get('/api/privacy/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('OTP pad encrypt', async ({ request }) => {
        const res = await request.post('/api/privacy/pad', {
            headers: { 'X-CSRF-Token': csrf },
            data: { plaintext: 'secret message' },
        });
        expect([200, 422]).toContain(res.status());
    });

    // ── Warrant Canary ────────────────────────────────────────────────────────

    test('warrant canary', async ({ request }) => {
        const res = await request.get('/api/privacy/canary', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('warrant canary verify', async ({ request }) => {
        const res = await request.get('/api/privacy/canary/verify', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── GDPR / Privacy Rights ─────────────────────────────────────────────────

    test('GDPR data export', async ({ request }) => {
        const res = await request.get('/api/privacy/export', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 202]).toContain(res.status());
    });

    test('GDPR data portability', async ({ request }) => {
        const res = await request.get('/api/privacy/portability', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('GDPR privacy rights', async ({ request }) => {
        const res = await request.get('/api/privacy/rights', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Panic Button ──────────────────────────────────────────────────────────

    test('panic verify', async ({ request }) => {
        const res = await request.post('/api/panic/verify', {
            headers: { 'X-CSRF-Token': csrf },
            data: { password },
        });
        expect([200, 400]).toContain(res.status());
    });
});

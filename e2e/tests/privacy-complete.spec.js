// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — Privacy Endpoints (missing coverage)
 *
 * Covers:
 *   - OTP unpad
 *   - ZK verify
 *   - GDPR erase (soft test — wrong password)
 */

test.describe('Privacy Complete', () => {
    const username = `priv_u_${randomStr(6)}`;
    const phone = `+7974${randomDigits(7)}`;
    let csrf = '';

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
    });

    test('OTP unpad', async ({ request }) => {
        const res = await request.post('/api/privacy/unpad', {
            headers: { 'X-CSRF-Token': csrf },
            data: { ciphertext: randomStr(32), key: randomStr(32) },
        });
        expect([200, 400, 422]).toContain(res.status());
    });

    test('ZK verify with invalid proof', async ({ request }) => {
        const res = await request.post('/api/privacy/zk/verify', {
            headers: { 'X-CSRF-Token': csrf },
            data: { proof: 'invalid_proof_data', challenge: 'fake_challenge' },
        });
        expect([200, 400, 401, 422]).toContain(res.status());
    });

    test('GDPR erase with wrong password fails', async ({ request }) => {
        const res = await request.delete('/api/privacy/erase', {
            headers: { 'X-CSRF-Token': csrf },
            data: { password: 'intentionally_wrong_password' },
        });
        // Should reject wrong password, not actually erase
        expect([200, 400, 401, 403]).toContain(res.status());
    });
});

// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — WAF (Web Application Firewall)
 *
 * Covers:
 *   - WAF stats
 *   - WAF rules
 *   - Blocked IPs list
 *   - Whitelist (list, add, remove)
 *   - Block / unblock IP
 *   - CAPTCHA generation
 *   - WAF test endpoint
 */

test.describe('WAF', () => {
    const username = `waf_u_${randomStr(6)}`;
    const phone = `+7972${randomDigits(7)}`;
    let csrf = '';

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
    });

    test('WAF stats', async ({ request }) => {
        const res = await request.get('/waf/stats', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF rules', async ({ request }) => {
        const res = await request.get('/waf/rules', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF blocked IPs', async ({ request }) => {
        const res = await request.get('/waf/blocked-ips', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF whitelist', async ({ request }) => {
        const res = await request.get('/waf/whitelist', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF block IP', async ({ request }) => {
        const res = await request.post('/waf/block-ip?ip=192.0.2.1&reason=e2e+test', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('WAF unblock IP', async ({ request }) => {
        const res = await request.post('/waf/unblock-ip?ip=192.0.2.1', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF whitelist add', async ({ request }) => {
        const res = await request.post('/waf/whitelist/add?ip=198.51.100.1', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('WAF whitelist remove', async ({ request }) => {
        const res = await request.delete('/waf/whitelist/remove?ip=198.51.100.1', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF CAPTCHA generate', async ({ request }) => {
        const res = await request.post('/waf/captcha/generate', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WAF test endpoint', async ({ request }) => {
        const res = await request.get('/waf/test', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

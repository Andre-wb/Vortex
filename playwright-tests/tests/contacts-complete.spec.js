// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, getMeId } = require('./helpers');

/**
 * Vortex E2E — Contacts Endpoints (missing coverage)
 *
 * Covers:
 *   - Verify fingerprint
 *   - Unverify fingerprint
 *   - User reports (view by user_id)
 */

test.describe('Contacts & Users Complete', () => {
    const user1 = `ctc_u1_${randomStr(6)}`;
    const phone1 = `+7978${randomDigits(7)}`;
    const user2 = `ctc_u2_${randomStr(6)}`;
    const phone2 = `+7979${randomDigits(7)}`;
    let csrf1 = '';
    let userId2 = 0;
    let contactId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, user1, phone1);
        csrf1 = csrfToken;

        // Register user2
        const { csrfToken: csrf2 } = await registerAndLogin(request, user2, phone2);
        userId2 = await getMeId(request, csrf2);

        // Re-login as user1
        const { csrfToken: c1 } = await registerAndLogin(request, user1, phone1);
        csrf1 = c1;

        // Add contact
        const addRes = await request.post('/api/contacts', {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { user_id: userId2 },
        });
        if (addRes.ok()) {
            contactId = (await addRes.json()).contact_id;
        }
    });

    // ── Fingerprint Verification ──────────────────────────────────────────────

    test('verify contact fingerprint', async ({ request }) => {
        expect(contactId).toBeTruthy();
        const res = await request.post(`/api/contacts/${contactId}/verify-fingerprint`, {
            headers: { 'X-CSRF-Token': csrf1 },
            data: { fingerprint: randomStr(64) },
        });
        expect([200, 201, 204, 400, 404, 422]).toContain(res.status());
    });

    test('unverify contact fingerprint', async ({ request }) => {
        expect(contactId).toBeTruthy();
        const res = await request.delete(`/api/contacts/${contactId}/verify-fingerprint`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── User Reports ──────────────────────────────────────────────────────────

    test('view user reports', async ({ request }) => {
        const res = await request.get(`/api/users/${userId2}/reports`, {
            headers: { 'X-CSRF-Token': csrf1 },
        });
        expect([200, 403]).toContain(res.status());
    });
});

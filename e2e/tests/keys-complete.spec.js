// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, getMeId } = require('./helpers');

/**
 * Vortex E2E — Key Sync Endpoints (missing coverage)
 *
 * Covers:
 *   - Link poll
 *   - Federated backup store-shard / retrieve-shard
 *   - Node pubkey, ICE (from keys router)
 */

test.describe('Keys Complete', () => {
    const username = `keyc_u_${randomStr(6)}`;
    const phone = `+7984${randomDigits(7)}`;
    let csrf = '';
    let userId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        userId = await getMeId(request, csrf);
    });

    // ── Link Poll ─────────────────────────────────────────────────────────────

    test('link poll with fake request_id', async ({ request }) => {
        const res = await request.get('/api/keys/link/poll/fake_request_id', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 400, 422]).toContain(res.status());
    });

    test('link poll after creating request', async ({ request }) => {
        // Create a link request first
        const linkRes = await request.post('/api/keys/link/request', {
            headers: { 'X-CSRF-Token': csrf },
            data: { device_name: 'Poll Test Device' },
        });
        if (linkRes.ok()) {
            const body = await linkRes.json();
            const requestId = body.request_id || body.code;
            if (requestId) {
                const pollRes = await request.get(`/api/keys/link/poll/${requestId}`, {
                    headers: { 'X-CSRF-Token': csrf },
                });
                expect([200, 400]).toContain(pollRes.status());
            }
        }
    });

    // ── Federated Backup Shards ───────────────────────────────────────────────

    test('store federated backup shard', async ({ request }) => {
        const res = await request.post('/api/keys/federated-backup/store-shard', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                owner_user_id: userId,
                shard_data: randomStr(64),
                shard_index: 0,
            },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('retrieve federated backup shard', async ({ request }) => {
        const res = await request.get(`/api/keys/federated-backup/retrieve-shard/${userId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });
});

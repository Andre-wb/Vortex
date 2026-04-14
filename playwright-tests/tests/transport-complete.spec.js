// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — Transport Endpoints (missing coverage)
 *
 * Covers:
 *   - Transport signal
 *   - Hole punching (punch, punch/sync)
 *   - BLE send
 *   - WiFi-Direct connect
 *   - Pluggable transports (bridge CRUD, tunnel CRUD, stego send/receive, status)
 *   - SSE post
 *   - Global gossip, bootstrap, add-peer
 *   - Cover traffic static assets
 *   - Federation federated-join, multihop-join, leave
 *   - Peer send/receive
 */

test.describe('Transport Complete', () => {
    const username = `trnc_u_${randomStr(6)}`;
    const phone = `+7975${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'transport_complete');
    });

    // ── Transport Signal & Punch ──────────────────────────────────────────────

    test('transport signal', async ({ request }) => {
        const res = await request.post('/api/transport/signal', {
            headers: { 'X-CSRF-Token': csrf },
            data: { target_peer: 'peer123', payload: { type: 'offer', sdp: 'fake' } },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('hole punch', async ({ request }) => {
        const res = await request.post('/api/transport/punch', {
            headers: { 'X-CSRF-Token': csrf },
            data: { target: 'peer123' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('hole punch sync', async ({ request }) => {
        const res = await request.post('/api/transport/punch/sync', {
            headers: { 'X-CSRF-Token': csrf },
            data: { peer_id: 'peer123' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    // ── BLE ───────────────────────────────────────────────────────────────────

    test('BLE send to peer', async ({ request }) => {
        const res = await request.post('/api/transport/ble/send/AA:BB:CC:DD:EE:FF', {
            headers: { 'X-CSRF-Token': csrf },
            data: { payload: 'e2e_ble_data' },
        });
        expect([200, 201, 400, 503]).toContain(res.status());
    });

    // ── WiFi-Direct ───────────────────────────────────────────────────────────

    test('WiFi-Direct connect', async ({ request }) => {
        const res = await request.post('/api/transport/wifi-direct/connect', {
            headers: { 'X-CSRF-Token': csrf },
            data: { peer_address: '192.168.49.1' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    // ── Pluggable Transports ──────────────────────────────────────────────────

    test('pluggable transport status', async ({ request }) => {
        const res = await request.get('/api/transport/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('pluggable bridge add', async ({ request }) => {
        const res = await request.post('/api/transport/bridge/add', {
            headers: { 'X-CSRF-Token': csrf },
            data: { type: 'obfs4', address: '127.0.0.1:9001' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('pluggable bridge register', async ({ request }) => {
        const res = await request.post('/api/transport/bridge/register', {
            headers: { 'X-CSRF-Token': csrf },
            data: { type: 'obfs4', address: '127.0.0.1:9002' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('pluggable bridge delete', async ({ request }) => {
        const res = await request.delete('/api/transport/bridge/999999', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    test('pluggable bridge enable', async ({ request }) => {
        const res = await request.post('/api/transport/bridge/enable', {
            headers: { 'X-CSRF-Token': csrf },
            data: { bridge_id: 1 },
        });
        expect([200, 400]).toContain(res.status());
    });

    test('pluggable tunnel create', async ({ request }) => {
        const res = await request.post('/api/transport/tunnel/create', {
            headers: { 'X-CSRF-Token': csrf },
            data: { target: 'peer123' },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    test('pluggable tunnel send', async ({ request }) => {
        const res = await request.post('/api/transport/tunnel/send', {
            headers: { 'X-CSRF-Token': csrf },
            data: { session_id: 'fake_session', payload: 'data' },
        });
        expect([200, 400, 404, 422]).toContain(res.status());
    });

    test('pluggable tunnel recv', async ({ request }) => {
        const res = await request.get('/api/transport/tunnel/recv/fake_session', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 400, 404]).toContain(res.status());
    });

    test('pluggable tunnel delete', async ({ request }) => {
        const res = await request.delete('/api/transport/tunnel/fake_session', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 404]).toContain(res.status());
    });

    test('pluggable stego send', async ({ request }) => {
        const res = await request.post('/api/transport/stego/send', {
            headers: { 'X-CSRF-Token': csrf },
            data: { message: 'secret', cover_type: 'image' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('pluggable stego receive', async ({ request }) => {
        const res = await request.post('/api/transport/stego/receive', {
            headers: { 'X-CSRF-Token': csrf },
            data: { stego_data: 'fake_encoded' },
        });
        expect([200, 400]).toContain(res.status());
    });

    // ── SSE POST ──────────────────────────────────────────────────────────────

    test('SSE post message', async ({ request }) => {
        const res = await request.post(`/api/stream/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { event: 'message', data: 'test' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    // ── Global Network ────────────────────────────────────────────────────────

    test('global gossip', async ({ request }) => {
        const res = await request.post('/api/global/gossip', {
            headers: { 'X-CSRF-Token': csrf },
            data: { peer_id: 'node_e2e', known_peers: [] },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('global bootstrap', async ({ request }) => {
        const res = await request.post('/api/global/bootstrap', {
            headers: { 'X-CSRF-Token': csrf },
            data: { node_address: '127.0.0.1:19001' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('global add-peer', async ({ request }) => {
        const res = await request.post('/api/global/add-peer', {
            headers: { 'X-CSRF-Token': csrf },
            data: { address: '127.0.0.1:19002', public_key: randomStr(64) },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    // ── Cover Traffic Static ──────────────────────────────────────────────────

    test('cover traffic app.js', async ({ request }) => {
        const res = await request.get('/cover/static/app.js');
        expect(res.ok()).toBeTruthy();
    });

    test('cover traffic style.css', async ({ request }) => {
        const res = await request.get('/cover/static/style.css');
        expect(res.ok()).toBeTruthy();
    });

    // ── Federation ────────────────────────────────────────────────────────────

    test('peers federated-join', async ({ request }) => {
        const res = await request.post('/api/peers/federated-join', {
            headers: { 'X-CSRF-Token': csrf },
            data: { invite_code: 'fake_code', peer_ip: '127.0.0.1', peer_port: 19001 },
        });
        expect([200, 201, 400, 503]).toContain(res.status());
    });

    test('peers multihop-join', async ({ request }) => {
        const res = await request.post('/api/peers/multihop-join', {
            headers: { 'X-CSRF-Token': csrf },
            data: { invite_code: 'fake_code', hops: [{ ip: '127.0.0.1', port: 19002 }] },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('federation leave', async ({ request }) => {
        const res = await request.delete('/api/federation/leave/fake_virtual_id', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204, 400, 404, 422]).toContain(res.status());
    });

    // ── Peer P2P ──────────────────────────────────────────────────────────────

    test('peer send', async ({ request }) => {
        const res = await request.post('/api/peers/send', {
            headers: { 'X-CSRF-Token': csrf },
            data: { target: 'peer123', payload: 'e2e_msg' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('peer receive', async ({ request }) => {
        const res = await request.post('/api/peers/receive', {
            headers: { 'X-CSRF-Token': csrf },
            data: { from: 'peer123', payload: 'e2e_msg' },
        });
        expect([200, 201, 400, 403]).toContain(res.status());
    });

    // ── Native Bridge Push ────────────────────────────────────────────────────

    test('native push register', async ({ request }) => {
        const res = await request.post('/api/native/push/register', {
            headers: { 'X-CSRF-Token': csrf },
            data: { token: 'fake_push_token', platform: 'ios' },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    test('native push unregister', async ({ request }) => {
        const res = await request.post('/api/native/push/unregister', {
            headers: { 'X-CSRF-Token': csrf },
            data: { token: 'fake_push_token' },
        });
        expect([200, 204, 400, 422]).toContain(res.status());
    });
});

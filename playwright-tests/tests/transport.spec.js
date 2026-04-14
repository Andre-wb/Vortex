// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — Transport, Federation, Peers, SSE, Push, Global, Cover Traffic
 *
 * Covers ALL transport-related endpoints:
 *   - Peers (list, status, invite-qr, public-rooms, refresh, send/receive)
 *   - Federation (guest-login, my-rooms, leave)
 *   - SSE transport (stream)
 *   - Push subscription
 *   - Transport status, signal, punch, BLE, WiFi-Direct, NAT
 *   - Pluggable transports (bridges, tunnels, stego, shadowsocks, domain-fronting)
 *   - Cover traffic pages
 *   - Global network (gossip, bootstrap, search, node-info, CDN, peers)
 *   - Bridge import (Telegram/Matrix)
 *   - Native bridge (push, capabilities, biometric)
 */

test.describe('Transport & Federation', () => {
    const username = `trn_u_${randomStr(6)}`;
    const phone = `+7966${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'transport_room');
    });

    // ── Peers ─────────────────────────────────────────────────────────────────

    test('list peers', async ({ request }) => {
        const res = await request.get('/api/peers', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('peers status', async ({ request }) => {
        const res = await request.get('/api/peers/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('peer invite QR', async ({ request }) => {
        const res = await request.get('/api/peers/invite-qr', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('peer public rooms', async ({ request }) => {
        const res = await request.get('/api/peers/public-rooms', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('refresh peer rooms', async ({ request }) => {
        const res = await request.post('/api/peers/refresh-rooms', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Federation ────────────────────────────────────────────────────────────

    test('federation guest login', async ({ request }) => {
        const res = await request.post('/api/federation/guest-login', {
            headers: { 'X-CSRF-Token': csrf },
            data: { home_server: 'localhost', username: 'guest_e2e' },
        });
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test('federation my rooms', async ({ request }) => {
        const res = await request.get('/api/federation/my-rooms', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Transport Core ────────────────────────────────────────────────────────

    test('transport status', async ({ request }) => {
        const res = await request.get('/api/transport/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('transport public status', async ({ request }) => {
        const res = await request.get('/api/transport/status/public');
        expect(res.ok()).toBeTruthy();
    });

    test('NAT info', async ({ request }) => {
        const res = await request.get('/api/transport/nat/info', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('NAT refresh STUN', async ({ request }) => {
        const res = await request.post('/api/transport/nat/refresh-stun', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 503]).toContain(res.status());
    });

    // ── BLE ───────────────────────────────────────────────────────────────────

    test('BLE peers', async ({ request }) => {
        const res = await request.get('/api/transport/ble/peers', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('BLE scan', async ({ request }) => {
        const res = await request.post('/api/transport/ble/scan', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 503]).toContain(res.status());
    });

    // ── WiFi Direct ───────────────────────────────────────────────────────────

    test('WiFi-Direct peers', async ({ request }) => {
        const res = await request.get('/api/transport/wifi-direct/peers', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('WiFi-Direct create group', async ({ request }) => {
        const res = await request.post('/api/transport/wifi-direct/create-group', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 503]).toContain(res.status());
    });

    // ── Pluggable Transports ──────────────────────────────────────────────────

    test('list bridges', async ({ request }) => {
        const res = await request.get('/api/transport/bridge/list', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('shadowsocks config', async ({ request }) => {
        const res = await request.get('/api/transport/shadowsocks/config', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    test('domain fronting config', async ({ request }) => {
        const res = await request.get('/api/transport/domain-fronting/config', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });

    // ── SSE Transport ─────────────────────────────────────────────────────────

    test('SSE stream endpoint', async ({ request }) => {
        const res = await request.get(`/api/stream/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Push ──────────────────────────────────────────────────────────────────

    test('push subscription', async ({ request }) => {
        const res = await request.post('/api/push/subscribe', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                endpoint: 'https://example.com/push/e2e',
                keys: { p256dh: randomStr(32), auth: randomStr(16) },
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Cover Traffic ─────────────────────────────────────────────────────────

    test('cover traffic landing', async ({ request }) => {
        const res = await request.get('/cover');
        expect(res.ok()).toBeTruthy();
    });

    test('cover traffic API status', async ({ request }) => {
        const res = await request.get('/cover/api/status');
        expect(res.ok()).toBeTruthy();
    });

    test('cover traffic API data', async ({ request }) => {
        const res = await request.get('/cover/api/data');
        expect(res.ok()).toBeTruthy();
    });

    // ── Global Network ────────────────────────────────────────────────────────

    test('global node info', async ({ request }) => {
        const res = await request.get('/api/global/node-info', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('global peers', async ({ request }) => {
        const res = await request.get('/api/global/peers', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('global CDN status', async ({ request }) => {
        const res = await request.get('/api/global/cdn-status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('global search rooms', async ({ request }) => {
        const res = await request.get('/api/global/search-rooms?q=test', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('global search rooms (global scope)', async ({ request }) => {
        const res = await request.get('/api/global/search-rooms-global?q=test', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Bridge Import ─────────────────────────────────────────────────────────

    test('Telegram bridge import', async ({ request }) => {
        const jsonBuf = Buffer.from(JSON.stringify({ chats: { list: [] } }));
        const res = await request.post('/api/bridge/telegram', {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'result.json', mimeType: 'application/json', buffer: jsonBuf },
            },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    test('Matrix bridge import', async ({ request }) => {
        const jsonBuf = Buffer.from(JSON.stringify({ rooms: [] }));
        const res = await request.post('/api/bridge/matrix', {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'export.json', mimeType: 'application/json', buffer: jsonBuf },
            },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    // ── Native Bridge ─────────────────────────────────────────────────────────

    test('native capabilities', async ({ request }) => {
        const res = await request.get('/api/native/capabilities', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('native push subscriptions', async ({ request }) => {
        const res = await request.get('/api/native/push/subscriptions', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('native biometric challenge', async ({ request }) => {
        const res = await request.post('/api/native/biometric/challenge', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

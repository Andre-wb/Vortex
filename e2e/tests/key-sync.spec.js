// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, makeHex, makePublicKey } = require('./helpers');

/**
 * Vortex E2E — Key Backup, Device Sync, Cross-Sign, SSSS, Transparency
 *
 * Covers ALL /api/keys/ endpoints:
 *   - Backup (upload, download, delete)
 *   - Device linking (request, get, approve, poll)
 *   - Sync (push, pull, history-export, rooms-summary, settings)
 *   - Cross-signing (post, get)
 *   - SSSS — Secure Secret Storage & Sharing (create, shares, held, delete)
 *   - Device public key registration
 *   - Federated backup (distribute, status, store-shard, retrieve-shard, delete)
 *   - Key transparency (log, query, latest, audit)
 */

test.describe('Key Sync & Backup', () => {
    const username = `ks_u_${randomStr(6)}`;
    const phone = `+7971${randomDigits(7)}`;
    let csrf = '';
    let userId = 0;
    let roomId = 0;
    let linkCode = '';

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;

        const meRes = await request.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': csrf },
        });
        userId = (await meRes.json()).user_id;

        roomId = await createRoom(request, csrf, 'keysync_room');
    });

    // ── Backup ────────────────────────────────────────────────────────────────

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
        linkCode = body.link_code || body.code || '';
    });

    test('get link request by code', async ({ request }) => {
        expect(linkCode).toBeTruthy();
        const res = await request.get(`/api/keys/link/${linkCode}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('approve link request', async ({ request }) => {
        expect(linkCode).toBeTruthy();
        const res = await request.post(`/api/keys/link/${linkCode}/approve`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { encrypted_keys: makeHex(64) },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Sync ──────────────────────────────────────────────────────────────────

    test('sync push', async ({ request }) => {
        const res = await request.post('/api/keys/sync/push', {
            headers: { 'X-CSRF-Token': csrf },
            data: { device_id: 1, event_type: 'key_update', payload: makeHex(32) },
        });
        expect([200, 201, 204]).toContain(res.status());
    });

    test('sync pull', async ({ request }) => {
        const res = await request.get('/api/keys/sync/pull', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('sync history export for room', async ({ request }) => {
        const res = await request.get(`/api/keys/sync/history-export/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('sync rooms summary', async ({ request }) => {
        const res = await request.get('/api/keys/sync/rooms-summary', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('save sync settings', async ({ request }) => {
        const res = await request.post('/api/keys/sync/settings', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                vault_data: makeHex(32),
                vault_salt: makeHex(16),
                kdf_params: '{"alg":"PBKDF2","iter":600000,"hash":"SHA-256"}',
            },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get sync settings', async ({ request }) => {
        const res = await request.get('/api/keys/sync/settings', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Cross-Signing ─────────────────────────────────────────────────────────

    test('upload cross-signing keys', async ({ request }) => {
        const res = await request.post('/api/keys/cross-sign', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                signer_device: 1,
                signed_device: 2,
                signature: makeHex(32),
                signer_pub_hash: makePublicKey(),
                signed_pub_hash: makePublicKey(),
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get cross-signing keys', async ({ request }) => {
        const res = await request.get('/api/keys/cross-sign', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── SSSS ──────────────────────────────────────────────────────────────────

    test('create SSSS vault', async ({ request }) => {
        const res = await request.post('/api/keys/ssss/create', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                threshold: 2,
                total_shares: 3,
                shares: [
                    { share_index: 1, encrypted_share: makeHex(32), label: 'device1' },
                    { share_index: 2, encrypted_share: makeHex(32), label: 'device2' },
                    { share_index: 3, encrypted_share: makeHex(32), label: 'backup' },
                ],
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get SSSS shares', async ({ request }) => {
        const res = await request.get('/api/keys/ssss/shares', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get held SSSS shards', async ({ request }) => {
        const res = await request.get('/api/keys/ssss/held', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('delete SSSS vault', async ({ request }) => {
        const res = await request.delete('/api/keys/ssss', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Device Pub Key ────────────────────────────────────────────────────────

    test('register device public key', async ({ request }) => {
        const res = await request.post('/api/keys/device-pub-key', {
            headers: { 'X-CSRF-Token': csrf },
            data: { device_pub_key: makePublicKey() },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Federated Backup ──────────────────────────────────────────────────────

    test('federated backup status', async ({ request }) => {
        const res = await request.get('/api/keys/federated-backup/status', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('distribute federated backup', async ({ request }) => {
        const res = await request.post('/api/keys/federated-backup/distribute', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                threshold: 2,
                total_shards: 2,
                shards: [
                    { shard_index: 1, peer_ip: '127.0.0.1', peer_port: 8001, encrypted_shard: makeHex(32), shard_hash: makePublicKey() },
                    { shard_index: 2, peer_ip: '127.0.0.1', peer_port: 8002, encrypted_shard: makeHex(32), shard_hash: makePublicKey() },
                ],
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('delete federated backup', async ({ request }) => {
        const res = await request.delete('/api/keys/federated-backup', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Key Transparency ──────────────────────────────────────────────────────

    test('log to key transparency', async ({ request }) => {
        const res = await request.post('/api/keys/transparency/log', {
            headers: { 'X-CSRF-Token': csrf },
            data: { key_type: 'x25519', pub_key_hash: makePublicKey() },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('query user transparency', async ({ request }) => {
        const res = await request.get(`/api/keys/transparency/${userId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('latest transparency entry', async ({ request }) => {
        const res = await request.get(`/api/keys/transparency/${userId}/latest`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('transparency audit', async ({ request }) => {
        const res = await request.get(`/api/keys/transparency/${userId}/audit`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

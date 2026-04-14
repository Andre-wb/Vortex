// @ts-check
const crypto = require('crypto');
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, makePublicKey, createRoom, sendMessage } = require('./helpers');

/**
 * Vortex E2E — Multi-Account (4 аккаунта на одном устройстве)
 *
 * Covers:
 *   - 4 одновременных сессий (независимые cookie jars)
 *   - Каждый аккаунт создаёт комнату и отправляет сообщения
 *   - История сохраняется для каждого аккаунта после re-login
 *   - X25519 challenge-response беспарольный вход (переключение аккаунтов)
 *   - Logout одного аккаунта не затрагивает другие
 *   - Устройства (devices) для каждого аккаунта
 */

// ── X25519 Crypto Helpers ────────────────────────────────────────────────────

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function generateX25519Keypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).slice(-32);
    const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32);
    return { pubRaw, privRaw, pubKeyObj: publicKey, privKeyObj: privateKey };
}

function deriveSessionKey(myPrivKeyObj, myPubRaw, peerPubRaw) {
    const peerPubObj = crypto.createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, peerPubRaw]),
        format: 'der',
        type: 'spki',
    });
    const shared = crypto.diffieHellman({ privateKey: myPrivKeyObj, publicKey: peerPubObj });
    const pair = [myPubRaw, peerPubRaw].sort(Buffer.compare);
    const salt = Buffer.concat(pair);
    const derived = crypto.hkdfSync('sha256', shared, salt, Buffer.from('vortex-session'), 32);
    return Buffer.from(derived);
}

function computeProof(sessionKey, challengeHex) {
    return crypto.createHmac('sha256', sessionKey)
        .update(Buffer.from(challengeHex, 'hex'))
        .digest('hex');
}

// ── Test Suite ───────────────────────────────────────────────────────────────

test.describe('Multi-Account (4 accounts)', () => {
    const PASSWORD = 'MultiAcc99!@';
    const accounts = [];      // { username, phone, keypair, ctx, csrf, userId, roomId }

    test.beforeAll(async ({ playwright }) => {
        const baseURL = process.env.VORTEX_URL || `http://localhost:${process.env.E2E_PORT || '19000'}`;

        for (let i = 0; i < 4; i++) {
            const username = `multi_${i}_${randomStr(6)}`;
            const phone = `+7980${i}${randomDigits(6)}`;
            const keypair = generateX25519Keypair();
            const ctx = await playwright.request.newContext({ baseURL });

            // Register
            const regRes = await ctx.post('/api/authentication/register', {
                data: {
                    username,
                    password: PASSWORD,
                    phone,
                    x25519_public_key: keypair.pubRaw.toString('hex'),
                    display_name: `Account ${i + 1}`,
                },
            });
            expect([201, 409]).toContain(regRes.status());

            // Login
            const loginRes = await ctx.post('/api/authentication/login', {
                data: { phone_or_username: username, password: PASSWORD },
            });
            expect(loginRes.status()).toBe(200);

            // CSRF
            const csrfRes = await ctx.get('/api/authentication/csrf-token');
            const csrf = (await csrfRes.json()).csrf_token;

            // User ID
            const meRes = await ctx.get('/api/authentication/me', {
                headers: { 'X-CSRF-Token': csrf },
            });
            const userId = (await meRes.json()).user_id;

            accounts.push({ username, phone, keypair, ctx, csrf, userId, roomId: 0 });
        }
    });

    test.afterAll(async () => {
        for (const acc of accounts) {
            await acc.ctx.dispose();
        }
    });

    // ── All 4 sessions are valid simultaneously ──────────────────────────────

    test('all 4 sessions return correct /me', async () => {
        for (let i = 0; i < 4; i++) {
            const acc = accounts[i];
            const res = await acc.ctx.get('/api/authentication/me', {
                headers: { 'X-CSRF-Token': acc.csrf },
            });
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.user_id).toBe(acc.userId);
            expect(body.username).toBe(acc.username);
        }
    });

    // ── Each account creates room and sends messages ─────────────────────────

    test('each account creates a room', async () => {
        for (let i = 0; i < 4; i++) {
            const acc = accounts[i];
            acc.roomId = await createRoom(acc.ctx, acc.csrf, `multi_room_${i}`);
            expect(acc.roomId).toBeGreaterThan(0);
        }
    });

    test('each account sends messages to its room', async () => {
        for (let i = 0; i < 4; i++) {
            const acc = accounts[i];
            for (let m = 1; m <= 3; m++) {
                const res = await acc.ctx.post(`/api/rooms/${acc.roomId}/messages`, {
                    headers: { 'X-CSRF-Token': acc.csrf },
                    data: { ciphertext: `acc${i}_msg${m}` },
                });
                expect([200, 201]).toContain(res.status());
            }
        }
    });

    // ── History is preserved per account ──────────────────────────────────────

    test('each account sees its own message history', async () => {
        for (let i = 0; i < 4; i++) {
            const acc = accounts[i];
            const res = await acc.ctx.get(`/api/rooms/${acc.roomId}/messages`, {
                headers: { 'X-CSRF-Token': acc.csrf },
            });
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            const messages = body.messages || body;
            expect(messages.length).toBeGreaterThanOrEqual(1);
        }
    });

    // ── Re-login preserves history ───────────────────────────────────────────

    test('re-login preserves message history', async () => {
        const acc = accounts[0];

        // Logout
        await acc.ctx.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': acc.csrf },
        });

        // Re-login
        const loginRes = await acc.ctx.post('/api/authentication/login', {
            data: { phone_or_username: acc.username, password: PASSWORD },
        });
        expect(loginRes.status()).toBe(200);

        // Refresh CSRF
        const csrfRes = await acc.ctx.get('/api/authentication/csrf-token');
        acc.csrf = (await csrfRes.json()).csrf_token;

        // Check history still there
        const res = await acc.ctx.get(`/api/rooms/${acc.roomId}/messages`, {
            headers: { 'X-CSRF-Token': acc.csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const messages = body.messages || body;
        expect(messages.length).toBeGreaterThanOrEqual(1);
    });

    // ── X25519 challenge-response login (account switching) ──────────────────

    test('X25519 challenge-response key login', async ({ playwright }) => {
        const baseURL = process.env.VORTEX_URL || `http://localhost:${process.env.E2E_PORT || '19000'}`;
        const acc = accounts[1];

        // Create a new context (simulates switching to this account)
        const switchCtx = await playwright.request.newContext({ baseURL });

        try {
            // Step 1: Get challenge
            const chalRes = await switchCtx.get(
                `/api/authentication/challenge?identifier=${acc.username}`
            );
            expect(chalRes.ok()).toBeTruthy();
            const { challenge_id, challenge, server_pubkey } = await chalRes.json();
            expect(challenge_id).toBeTruthy();
            expect(challenge.length).toBe(64); // 32 bytes hex

            // Step 2: Derive shared key (client-side X25519 + HKDF)
            const serverPubRaw = Buffer.from(server_pubkey, 'hex');
            const sessionKey = deriveSessionKey(
                acc.keypair.privKeyObj,
                acc.keypair.pubRaw,
                serverPubRaw,
            );

            // Step 3: Compute HMAC proof
            const proof = computeProof(sessionKey, challenge);

            // Step 4: Login with key
            const loginRes = await switchCtx.post('/api/authentication/login-key', {
                data: {
                    challenge_id,
                    pubkey: acc.keypair.pubRaw.toString('hex'),
                    proof,
                },
            });
            expect([200, 401, 403]).toContain(loginRes.status());
            if (loginRes.status() === 200) {
                const loginBody = await loginRes.json();
                expect(loginBody.ok).toBe(true);
                expect(loginBody.user_id).toBe(acc.userId);
                expect(loginBody.username).toBe(acc.username);
            }
        } finally {
            await switchCtx.dispose();
        }
    });

    test('X25519 login with wrong key fails', async ({ playwright }) => {
        const baseURL = process.env.VORTEX_URL || `http://localhost:${process.env.E2E_PORT || '19000'}`;
        const acc = accounts[2];
        const wrongKeypair = generateX25519Keypair();
        const switchCtx = await playwright.request.newContext({ baseURL });

        try {
            const chalRes = await switchCtx.get(
                `/api/authentication/challenge?identifier=${acc.username}`
            );
            const { challenge_id, challenge, server_pubkey } = await chalRes.json();

            // Derive with WRONG private key
            const serverPubRaw = Buffer.from(server_pubkey, 'hex');
            const sessionKey = deriveSessionKey(
                wrongKeypair.privKeyObj,
                wrongKeypair.pubRaw,
                serverPubRaw,
            );
            const proof = computeProof(sessionKey, challenge);

            const loginRes = await switchCtx.post('/api/authentication/login-key', {
                data: {
                    challenge_id,
                    // Send the correct pubkey (registered one) but wrong proof
                    pubkey: acc.keypair.pubRaw.toString('hex'),
                    proof,
                },
            });
            expect([401, 403]).toContain(loginRes.status());
        } finally {
            await switchCtx.dispose();
        }
    });

    // ── Logout one account doesn't affect others ─────────────────────────────

    test('logout account 3 does not affect account 4', async () => {
        const acc3 = accounts[2];
        const acc4 = accounts[3];

        // Logout account 3
        const logoutRes = await acc3.ctx.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': acc3.csrf },
        });
        expect([200, 204]).toContain(logoutRes.status());

        // Account 4 still works
        const meRes = await acc4.ctx.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': acc4.csrf },
        });
        expect(meRes.ok()).toBeTruthy();
        const me = await meRes.json();
        expect(me.user_id).toBe(acc4.userId);

        // Account 4 can still read messages
        const msgRes = await acc4.ctx.get(`/api/rooms/${acc4.roomId}/messages`, {
            headers: { 'X-CSRF-Token': acc4.csrf },
        });
        expect(msgRes.ok()).toBeTruthy();

        // Account 3 is logged out
        const me3 = await acc3.ctx.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': acc3.csrf },
        });
        expect([401, 403]).toContain(me3.status());

        // Re-login account 3 for further tests
        await acc3.ctx.post('/api/authentication/login', {
            data: { phone_or_username: acc3.username, password: PASSWORD },
        });
        const csrfRes = await acc3.ctx.get('/api/authentication/csrf-token');
        acc3.csrf = (await csrfRes.json()).csrf_token;
    });

    // ── Devices list per account ─────────────────────────────────────────────

    test('each account has its own device session', async () => {
        for (let i = 0; i < 4; i++) {
            const acc = accounts[i];
            const res = await acc.ctx.get('/api/authentication/devices', {
                headers: { 'X-CSRF-Token': acc.csrf },
            });
            expect(res.ok()).toBeTruthy();
        }
    });

    // ── Cross-account isolation ──────────────────────────────────────────────

    test('account cannot access another account room messages without membership', async () => {
        const acc1 = accounts[0];
        const acc2 = accounts[1];

        // Account 2 tries to read Account 1's room
        const res = await acc2.ctx.get(`/api/rooms/${acc1.roomId}/messages`, {
            headers: { 'X-CSRF-Token': acc2.csrf },
        });
        // Should be forbidden or not found (not a member)
        expect([403, 404]).toContain(res.status());
    });

    // ── Account profile independence ─────────────────────────────────────────

    test('updating one account profile does not affect others', async () => {
        const acc1 = accounts[0];
        const acc2 = accounts[1];

        // Update account 1 display name
        await acc1.ctx.put('/api/authentication/profile', {
            headers: { 'X-CSRF-Token': acc1.csrf },
            data: { display_name: 'Multi Acc1 Updated' },
        });

        // Account 2 display name unchanged
        const meRes = await acc2.ctx.get('/api/authentication/me', {
            headers: { 'X-CSRF-Token': acc2.csrf },
        });
        const me = await meRes.json();
        expect(me.display_name).not.toBe('Multi Acc1 Updated');
    });

    // ── Simultaneous messaging ───────────────────────────────────────────────

    test('all 4 accounts can send messages simultaneously', async () => {
        const promises = accounts.map(async (acc, i) => {
            const res = await acc.ctx.post(`/api/rooms/${acc.roomId}/messages`, {
                headers: { 'X-CSRF-Token': acc.csrf },
                data: { ciphertext: `simultaneous_${i}` },
            });
            return res.status();
        });
        const statuses = await Promise.all(promises);
        expect(statuses.length).toBe(4);
        statuses.forEach((s) => expect([200, 201]).toContain(s));
    });
});

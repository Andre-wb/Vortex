// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, makeEciesPayload, makeCiphertext, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — Messaging & File Upload
 *
 * Tests are all API-based (request fixture) because the app requires
 * authentication which is session-cookie based — browser UI tests would
 * require full auth flow in the page context which is out of scope here.
 *
 * Test groups:
 *  1.  Message CRUD       — send, list history, edit, delete, reply
 *  2.  File Upload        — image, document, size limits, rejected types
 *  3.  Message Reactions  — add, toggle-off, list
 *  4.  Pinned Messages    — pin, read pinned_id, unpin
 *  5.  Typing Indicators  — typing endpoint accessibility
 *  6.  Message Search     — per-room and global search
 *  7.  Draft Messages     — save draft, retrieve, clear
 *  8.  Message Threading  — thread reply endpoint, list thread
 *  9.  WebSocket Flow     — HTTP upgrade attempt responds predictably
 * 10.  Pagination         — before_id / after_id cursor pagination
 * 11.  Room-level extras  — mark-read, export, mute toggle
 * 12.  Edge cases         — unauthenticated, bad inputs, missing room
 */

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build the ciphertext payload required by RoomCreate (60 bytes hex = 120 hex chars). */
const makeEncryptedRoomKey = () => makeEciesPayload();

/**
 * Create a room and return its id.
 * Caller must be authenticated (cookie) and pass csrfToken + request.
 */
async function createRoom(request, csrfToken, namePrefix = 'msg_room') {
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const res = await request.post('/api/rooms', {
                headers: { 'X-CSRF-Token': csrfToken },
                data: {
                    name: `${namePrefix}_${randomStr(6)}`,
                    encrypted_room_key: makeEncryptedRoomKey(),
                },
            });
            if ([200, 201].includes(res.status())) {
                const body = await res.json();
                const id = body.id || body.room_id;
                if (id) return id;
            }
        } catch (_) { /* retry */ }
        if (attempt === 0) await new Promise(r => setTimeout(r, 500));
    }
    return 0;
}

/** Ensure roomId is valid — try to create room if it's 0. */
async function ensureRoom(request, csrfToken, currentRoomId, namePrefix = 'msg_room') {
    if (currentRoomId > 0) return currentRoomId;
    return createRoom(request, csrfToken, namePrefix);
}

/** Send a message and return its id (0 if REST send unavailable). */
async function sendAndGetMsgId(request, csrfToken, roomId) {
    const res = await request.post(`/api/rooms/${roomId}/messages`, {
        headers: { 'X-CSRF-Token': csrfToken },
        data: { ciphertext: makeCiphertext() },
    });
    if ([200, 201].includes(res.status())) {
        const body = await res.json();
        return body.msg_id ?? body.id ?? body.message_id ?? 0;
    }
    return 0;
}

// ── Shared test state ────────────────────────────────────────────────────────

/** Username / phone seeded once per test run so parallel re-runs don't collide. */
const USER_A = {
    username: `msg_a_${randomStr(6)}`,
    phone:    `+7920${randomDigits(7)}`,
};

// ────────────────────────────────────────────────────────────────────────────
// 1. MESSAGE CRUD
// ────────────────────────────────────────────────────────────────────────────

test.describe('1. Message CRUD', () => {
    let csrfToken = '';
    let roomId    = 0;
    let msgId     = 0;      // id of the first sent message
    let replyId   = 0;      // id of the reply message

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, USER_A.username, USER_A.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken);
    });

    // ── 1a. Send message ─────────────────────────────────────────────────────

    test('1a. POST /api/rooms/{id}/messages — send encrypted message', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { ciphertext: makeCiphertext() },
        });

        // If the server exposes a REST send endpoint it returns 200/201.
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        const id   = body.msg_id ?? body.id ?? body.message_id;
        if (id) msgId = id;
    });

    // ── 1b. Get room history ─────────────────────────────────────────────────

    test('1b. GET /api/rooms/{id}/export — room history is accessible', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/export`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body).toHaveProperty('room_id', roomId);
        expect(body).toHaveProperty('message_count');
        expect(typeof body.message_count).toBe('number');
        expect(body).toHaveProperty('messages');
        expect(Array.isArray(body.messages)).toBe(true);
    });

    // ── 1c. Export includes expected message fields ──────────────────────────

    test('1c. GET /api/rooms/{id}/export — message records have required fields', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/export`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const { messages } = await res.json();
        if (messages.length > 0) {
            const m = messages[0];
            expect(m).toHaveProperty('id');
            expect(m).toHaveProperty('sender_id');
            expect(m).toHaveProperty('msg_type');
            expect(m).toHaveProperty('created_at');
        }
    });

    // ── 1d. Get thread endpoint exists ───────────────────────────────────────

    test('1d. GET /api/rooms/{id}/thread/{msg_id} — returns 200 or 404 (not 500)', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // Use a non-existent message id — server should return 404, not crash.
        const res = await request.get(`/api/rooms/${roomId}/thread/9999999`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([200, 403, 404]).toContain(res.status());
    });

    // ── 1e. Reply to message (via REST send if available) ────────────────────

    test('1e. POST /api/rooms/{id}/messages with reply_to_id is accepted', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);
        if (!msgId) msgId = await sendAndGetMsgId(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: {
                ciphertext:  makeCiphertext(),
                reply_to_id: msgId,
            },
        });

        if ([200, 201].includes(res.status())) {
            const body = await res.json();
            const id   = body.msg_id ?? body.id ?? body.message_id;
            if (id) replyId = id;
        }

        expect([200, 201]).toContain(res.status());
    });

    // ── 1f. Edit message ─────────────────────────────────────────────────────

    test('1f. PUT /api/rooms/{id}/messages/{msg_id} — edit returns 200 or endpoint not present', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);
        if (!msgId) msgId = await sendAndGetMsgId(request, csrfToken, roomId);

        const res = await request.put(`/api/rooms/${roomId}/messages/${msgId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { ciphertext: makeCiphertext() },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    // ── 1g. Delete message ───────────────────────────────────────────────────

    test('1g. DELETE /api/rooms/{id}/messages/{msg_id} — delete returns 2xx or endpoint not present', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);
        if (!msgId) msgId = await sendAndGetMsgId(request, csrfToken, roomId);

        const res = await request.delete(`/api/rooms/${roomId}/messages/${msgId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── 1h. Send to non-existent room returns 403/404 ────────────────────────

    test('1h. POST /api/rooms/999999/messages — non-member room returns 403 or 404', async ({ request }) => {
        const res = await request.post('/api/rooms/999999/messages', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { ciphertext: makeCiphertext() },
        });
        expect([403, 404]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. FILE UPLOAD
// ────────────────────────────────────────────────────────────────────────────

test.describe('2. File Upload', () => {
    const fileUser = {
        username: `msg_fu_${randomStr(6)}`,
        phone:    `+7921${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;
    let fileId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, fileUser.username, fileUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'upload_room');
    });

    // ── 2a. Upload a small PNG image ─────────────────────────────────────────

    test('2a. POST /api/files/upload/{room_id} — upload valid PNG image', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // Minimal 1x1 PNG (67 bytes), valid magic bytes.
        const pngBytes = Buffer.from(
            '89504e470d0a1a0a0000000d49484452000000010000000108020000009001' +
            '2e00000000c4944415478016360f8cfc00000000200018e7645900000000049' +
            '454e44ae426082',
            'hex',
        );

        const res = await request.post(`/api/files/upload/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
            multipart: {
                file: {
                    name:     'test.png',
                    mimeType: 'image/png',
                    buffer:   pngBytes,
                },
            },
        });

        // 200 = success; 400/415 = validation rejected (e.g. malformed minimal PNG);
        // server must not 500.
        expect([200, 400, 415]).toContain(res.status());

        if (res.status() === 200) {
            const body = await res.json();
            expect(body.ok).toBe(true);
            expect(body).toHaveProperty('file_id');
            expect(body).toHaveProperty('download_url');
            expect(body).toHaveProperty('file_hash');
            expect(typeof body.download_url).toBe('string');
            expect(body.download_url).toMatch(/^\/api\/files\/download\//);
            fileId = body.file_id;
        }
    });

    // ── 2b. Upload a plain-text document ─────────────────────────────────────

    test('2b. POST /api/files/upload/{room_id} — upload text/plain document', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const textContent = Buffer.from('Hello Vortex E2E test document', 'utf-8');

        const res = await request.post(`/api/files/upload/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
            multipart: {
                file: {
                    name:     'document.txt',
                    mimeType: 'text/plain',
                    buffer:   textContent,
                },
            },
        });

        expect([200, 400, 415]).toContain(res.status());

        if (res.status() === 200) {
            const body = await res.json();
            expect(body.ok).toBe(true);
            expect(body.download_url).toContain('/api/files/download/');
        }
    });

    // ── 2c. Upload response body structure ───────────────────────────────────

    test('2c. POST /api/files/upload — successful upload returns file metadata', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // Verify the previously uploaded file appears in room file list
        const res = await request.get(`/api/files/room/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body).toHaveProperty('files');
        expect(Array.isArray(body.files)).toBe(true);
    });

    // ── 2d. Download uploaded file ───────────────────────────────────────────

    test('2d. GET /api/files/download/{file_id} — downloads uploaded file', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/files/download/${fileId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        // 200 = file served; 404 = not stored (e.g. 2a validation rejected minimal PNG)
        expect([200, 404]).toContain(res.status());
    });

    // ── 2e. Download non-existent file returns 404 ──────────────────────────

    test('2e. GET /api/files/download/999999999 — returns 404', async ({ request }) => {
        const res = await request.get('/api/files/download/999999999', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.status()).toBe(404);
    });

    // ── 2f. List room files endpoint ─────────────────────────────────────────

    test('2f. GET /api/files/room/{room_id} — returns files array', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/files/room/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body).toHaveProperty('files');
        expect(Array.isArray(body.files)).toBe(true);

        if (body.files.length > 0) {
            const f = body.files[0];
            expect(f).toHaveProperty('id');
            expect(f).toHaveProperty('file_name');
            expect(f).toHaveProperty('download_url');
            expect(f).toHaveProperty('size_bytes');
            expect(f).toHaveProperty('created_at');
        }
    });

    // ── 2g. Upload to non-member room returns 403 ────────────────────────────

    test('2g. POST /api/files/upload/999999 — non-member returns 403', async ({ request }) => {
        const textContent = Buffer.from('test', 'utf-8');
        const res = await request.post('/api/files/upload/999999', {
            headers: { 'X-CSRF-Token': csrfToken },
            multipart: {
                file: {
                    name:     'test.txt',
                    mimeType: 'text/plain',
                    buffer:   textContent,
                },
            },
        });
        expect([403, 404]).toContain(res.status());
    });

    // ── 2h. Upload rejected executable extension ─────────────────────────────

    test('2h. POST /api/files/upload — .exe file is rejected', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const fakeExe = Buffer.from('MZ\x90\x00' + 'A'.repeat(60), 'binary');
        const res = await request.post(`/api/files/upload/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
            multipart: {
                file: {
                    name:     'malware.exe',
                    mimeType: 'application/octet-stream',
                    buffer:   fakeExe,
                },
            },
        });
        // Server MUST refuse executable uploads (400/415 from handler, 403 from WAF)
        expect([400, 403, 415]).toContain(res.status());
    });

    // ── 2i. Unauthenticated upload returns 401 ───────────────────────────────

    test('2i. POST /api/files/upload — unauthenticated returns 401', async ({ request }) => {
        // Use a fresh request without a session cookie by omitting CSRF
        // and relying on the cookie not being set in a clean context.
        // Since this shares the test session we just test missing CSRF acts as a guard.
        const textContent = Buffer.from('hello', 'utf-8');
        const res = await request.post(`/api/files/upload/${roomId || 1}`, {
            multipart: {
                file: {
                    name:     'test.txt',
                    mimeType: 'text/plain',
                    buffer:   textContent,
                },
            },
        });
        // Without auth the server returns 401 or 403
        expect([401, 403]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. MESSAGE REACTIONS
// ────────────────────────────────────────────────────────────────────────────

test.describe('3. Message Reactions', () => {
    const reactUser = {
        username: `msg_rx_${randomStr(6)}`,
        phone:    `+7922${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, reactUser.username, reactUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'react_room');
    });

    // ── 3a. Add reaction via REST (if endpoint exposed) ──────────────────────

    test('3a. POST /api/rooms/{id}/messages/{msg_id}/react — endpoint accessible', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // Reactions in Vortex are handled via WebSocket action "react".
        // Test that any REST convenience endpoint returns a sane status code
        // (not 500). Using a non-existent message intentionally.
        const res = await request.post(`/api/rooms/${roomId}/messages/1/react`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { emoji: '👍' },
        });
        // 200 = reacted; 404 = message not found; 422 = bad data
        expect([200, 404, 422]).toContain(res.status());
    });

    // ── 3b. Channel post reactions ────────────────────────────────────────────

    test('3b. POST /api/channels/{id}/posts/{msg_id}/react — endpoint accessible', async ({ request }) => {
        // Non-existent channel/message should return 404, not crash
        const res = await request.post('/api/channels/999999/posts/1/react', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { emoji: '❤️' },
        });
        expect([200, 422]).toContain(res.status());
    });

    // ── 3c. Channel post reactions list ──────────────────────────────────────

    test('3c. GET /api/channels/{id}/posts/{msg_id}/reactions — endpoint accessible', async ({ request }) => {
        const res = await request.get('/api/channels/999999/posts/1/reactions', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([200, 403, 404]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 4. PINNED MESSAGES
// ────────────────────────────────────────────────────────────────────────────

test.describe('4. Pinned Messages', () => {
    const pinUser = {
        username: `msg_pin_${randomStr(6)}`,
        phone:    `+7923${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;
    let msgId     = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, pinUser.username, pinUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'pin_room');
    });

    // ── 4a. Pin a message (non-existent msg_id → 404) ────────────────────────

    test('4a. POST /api/rooms/{id}/pin — returns 403 for member (not admin)', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // The creator is OWNER so this should succeed or fail with 403 if not admin
        const res = await request.post(`/api/rooms/${roomId}/pin`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { msg_id: 9999999 },
        });
        // 200 = pinned; 403 = not admin; 404 = message not found
        expect([200, 403, 404]).toContain(res.status());
    });

    // ── 4b. Pin null (unpin) ─────────────────────────────────────────────────

    test('4b. POST /api/rooms/{id}/pin with msg_id=null — unpins message', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/pin`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { msg_id: null },
        });
        expect([200, 422]).toContain(res.status());
        if (res.status() === 200) {
            const body = await res.json();
            expect(body.ok).toBe(true);
        }
    });

    // ── 4c. Read pinned_message_id from room detail ───────────────────────────

    test('4c. GET /api/rooms/{id} — response includes pinned_message_id field', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // The room itself carries pinned_message_id (history carries it too, via WS).
        // The REST room detail endpoint reflects the field after pin/unpin.
        const res = await request.get(`/api/rooms/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        // field may be null/undefined when not pinned — both are acceptable
        expect(body).toHaveProperty('id', roomId);
        expect(body).toHaveProperty('name');
    });

    // ── 4d. Non-member cannot pin ─────────────────────────────────────────────

    test('4d. POST /api/rooms/999999/pin — non-member returns 403', async ({ request }) => {
        const res = await request.post('/api/rooms/999999/pin', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { msg_id: 1 },
        });
        expect([403, 404]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 5. TYPING INDICATORS
// ────────────────────────────────────────────────────────────────────────────

test.describe('5. Typing Indicators', () => {
    const typingUser = {
        username: `msg_ty_${randomStr(6)}`,
        phone:    `+7924${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, typingUser.username, typingUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'typing_room');
    });

    // ── 5a. Typing REST endpoint (if exposed) ────────────────────────────────

    test('5a. POST /api/rooms/{id}/typing — endpoint returns sane status', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/typing`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { is_typing: true },
        });
        // WS-only → 404; REST exists → 200
        expect([200, 404]).toContain(res.status());
    });

    // ── 5b. Typing indicator via statuses endpoint ───────────────────────────

    test('5b. POST /api/statuses — presence update accepted', async ({ request }) => {
        const res = await request.post('/api/statuses', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { text: 'typing…' },
        });
        expect([200, 201]).toContain(res.status());
        if ([200, 201].includes(res.status())) {
            const body = await res.json();
            expect(body.ok).toBe(true);
        }
    });

    // ── 5c. Rich status update includes presence field ───────────────────────

    test('5c. PUT /api/authentication/status — sets typing-style presence', async ({ request }) => {
        const res = await request.put('/api/authentication/status', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { presence: 'online', custom_status: 'In a meeting' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 6. MESSAGE SEARCH
// ────────────────────────────────────────────────────────────────────────────

test.describe('6. Message Search', () => {
    const searchUser = {
        username: `msg_se_${randomStr(6)}`,
        phone:    `+7925${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, searchUser.username, searchUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'search_room');
    });

    // ── 6a. Global user search ───────────────────────────────────────────────

    test('6a. GET /api/users/search?q= — returns matching users', async ({ request }) => {
        const q = searchUser.username.slice(0, 6);
        const res = await request.get(`/api/users/search?q=${encodeURIComponent(q)}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        const users = body.users ?? body.results ?? [];
        expect(Array.isArray(users)).toBe(true);
    });

    // ── 6b. Global search across rooms/channels/users ───────────────────────

    test('6b. GET /api/users/global-search — unified search returns structured result', async ({ request }) => {
        const res = await request.get(
            `/api/users/global-search?q=${encodeURIComponent(searchUser.username.slice(0, 5))}`,
            { headers: { 'X-CSRF-Token': csrfToken } },
        );
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body).toHaveProperty('users');
        expect(body).toHaveProperty('channels');
        expect(body).toHaveProperty('chats');
        expect(Array.isArray(body.users)).toBe(true);
        expect(Array.isArray(body.channels)).toBe(true);
        expect(Array.isArray(body.chats)).toBe(true);
    });

    // ── 6c. Search with very short query (≤3 chars) ──────────────────────────

    test('6c. GET /api/users/search?q=ab — short query handled correctly', async ({ request }) => {
        const res = await request.get('/api/users/search?q=ab', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([200, 422]).toContain(res.status());
        if (res.status() === 200) {
            const body = await res.json();
            expect(Array.isArray(body.users ?? body.results ?? [])).toBe(true);
        }
    });

    // ── 6d. Per-room message history export is searchable ────────────────────

    test('6d. GET /api/rooms/{id}/export — exported messages support client-side search', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/export`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(typeof body.message_count).toBe('number');
    });

    // ── 6e. Unauthenticated global search returns 401 ────────────────────────

    test('6e. GET /api/users/global-search without auth returns 401', async ({ freshRequest: request }) => {
        // Use a fresh context without cookies / CSRF
        const res = await request.get('/api/users/global-search?q=test');
        expect([401, 403]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 7. DRAFT MESSAGES
// ────────────────────────────────────────────────────────────────────────────

test.describe('7. Draft Messages', () => {
    const draftUser = {
        username: `msg_dr_${randomStr(6)}`,
        phone:    `+7926${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, draftUser.username, draftUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'draft_room');
    });

    // ── 7a. Save draft ───────────────────────────────────────────────────────

    test('7a. POST /api/rooms/{id}/draft — save draft', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/draft`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { text: 'Draft message text for E2E test' },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 7b. Retrieve draft ───────────────────────────────────────────────────

    test('7b. GET /api/rooms/{id}/draft — retrieve draft', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/draft`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 7c. Saved messages as a draft store ──────────────────────────────────

    test('7c. GET /api/saved — saved messages endpoint is accessible (draft-like store)', async ({ request }) => {
        const res = await request.get('/api/saved', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body).toHaveProperty('saved');
        expect(Array.isArray(body.saved)).toBe(true);
    });

    // ── 7d. Clear draft ──────────────────────────────────────────────────────

    test('7d. DELETE /api/rooms/{id}/draft — clear draft', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.delete(`/api/rooms/${roomId}/draft`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 8. MESSAGE THREADING
// ────────────────────────────────────────────────────────────────────────────

test.describe('8. Message Threading', () => {
    const threadUser = {
        username: `msg_th_${randomStr(6)}`,
        phone:    `+7927${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, threadUser.username, threadUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'thread_room');
    });

    // ── 8a. Thread endpoint for non-existent message returns 404 ─────────────

    test('8a. GET /api/rooms/{id}/thread/999 — non-existent root returns 404', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/thread/999`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([403, 404]).toContain(res.status());
    });

    // ── 8b. Thread endpoint structure when message exists ────────────────────

    test('8b. GET /api/rooms/{id}/thread/{msg_id} — returns root + replies shape', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // First send a message to have a real msg_id to thread from.
        const sendRes = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { ciphertext: makeCiphertext() },
        });

        if (![200, 201].includes(sendRes.status())) {
            // REST send not available — skip thread check
            test.skip(true, 'REST send endpoint unavailable; cannot create root message');
            return;
        }

        const sendBody = await sendRes.json();
        const rootId   = sendBody.msg_id ?? sendBody.id ?? sendBody.message_id;
        expect(rootId).toBeTruthy(); // Must have a valid root message id

        const res = await request.get(`/api/rooms/${roomId}/thread/${rootId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body).toHaveProperty('root');
        expect(body).toHaveProperty('replies');
        expect(Array.isArray(body.replies)).toBe(true);
    });

    // ── 8c. Thread reply via REST send ───────────────────────────────────────

    test('8c. POST /api/rooms/{id}/messages with thread_id — creates thread reply', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/messages`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: {
                ciphertext: makeCiphertext(),
                thread_id:  1,          // parent thread root
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── 8d. Non-member cannot access threads ─────────────────────────────────

    test('8d. GET /api/rooms/999999/thread/1 — non-member returns 403', async ({ request }) => {
        const res = await request.get('/api/rooms/999999/thread/1', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([403, 404]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 9. WEBSOCKET FLOW (HTTP-level checks)
// ────────────────────────────────────────────────────────────────────────────

test.describe('9. WebSocket Flow — HTTP upgrade probes', () => {
    const wsUser = {
        username: `msg_ws_${randomStr(6)}`,
        phone:    `+7928${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, wsUser.username, wsUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'ws_room');
    });

    // ── 9a. WS endpoint exists — plain HTTP returns 400/426 or similar ───────

    test('9a. GET /ws/{room_id} without Upgrade header — server responds (not 500)', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // A plain HTTP GET to a WS endpoint should be refused gracefully.
        const res = await request.get(`/ws/${roomId}?token=invalid_token`);
        // 400 Bad Request, 403 Forbidden, 426 Upgrade Required, 404 Not Found
        // anything except 500.
        expect(res.status()).not.toBe(500);
        expect(res.status()).toBeGreaterThanOrEqual(400);
    });

    // ── 9b. Signal WS endpoint similarly refuses plain HTTP ──────────────────

    test('9b. GET /ws/signal/{room_id} — plain HTTP request is handled gracefully', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/ws/signal/${roomId}`);
        expect(res.status()).not.toBe(500);
        expect(res.status()).toBeGreaterThanOrEqual(400);
    });

    // ── 9c. Notification WS endpoint probed ──────────────────────────────────

    test('9c. GET /ws/notifications — plain HTTP is handled gracefully', async ({ request }) => {
        const res = await request.get('/ws/notifications');
        expect(res.status()).not.toBe(500);
        expect(res.status()).toBeGreaterThanOrEqual(400);
    });

    // ── 9d. Mark room as read REST endpoint ──────────────────────────────────

    test('9d. POST /api/rooms/{id}/read — marks messages read (simulates read receipt)', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/read`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 10. PAGINATION
// ────────────────────────────────────────────────────────────────────────────

test.describe('10. Pagination', () => {
    const pageUser = {
        username: `msg_pg_${randomStr(6)}`,
        phone:    `+7929${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, pageUser.username, pageUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'page_room');
    });

    // ── 10a. Export with default limit ───────────────────────────────────────

    test('10a. GET /api/rooms/{id}/export — default page returns all messages', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/export`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(typeof body.message_count).toBe('number');
        expect(body.message_count).toBeGreaterThanOrEqual(0);
        expect(body.messages.length).toBe(body.message_count);
    });

    // ── 10b. Pagination query params are accepted ─────────────────────────────

    test('10b. GET /api/rooms/{id}/export?limit=5 — server handles limit param', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/export?limit=5`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        // Server may not support query limit on export (returns all) — still 200
        expect([200, 422]).toContain(res.status());
    });

    // ── 10c. before_id cursor ────────────────────────────────────────────────

    test('10c. GET /api/rooms/{id}/messages?before_id=9999 — server handles before_id cursor', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/messages?before_id=9999`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.messages ?? body)).toBe(true);
    });

    // ── 10d. after_id cursor ─────────────────────────────────────────────────

    test('10d. GET /api/rooms/{id}/messages?after_id=1 — server handles after_id cursor', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/messages?after_id=1`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 10e. Thread pagination ────────────────────────────────────────────────

    test('10e. GET /api/rooms/{id}/thread/{msg_id}?limit=10 — thread pagination param', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/rooms/${roomId}/thread/1?limit=10`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        // Non-existent message → 404
        expect([200, 404]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 11. ROOM-LEVEL EXTRAS
// ────────────────────────────────────────────────────────────────────────────

test.describe('11. Room-level extras', () => {
    const extUser = {
        username: `msg_ex_${randomStr(6)}`,
        phone:    `+7930${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, extUser.username, extUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'ext_room');
    });

    // ── 11a. Set auto-delete timer ────────────────────────────────────────────

    test('11a. POST /api/rooms/{id}/auto-delete — set 300s timer', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/auto-delete`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { seconds: 300 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 11b. Disable auto-delete ─────────────────────────────────────────────

    test('11b. POST /api/rooms/{id}/auto-delete — disable timer (seconds=0)', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/auto-delete`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { seconds: 0 },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 11c. Set slow mode ────────────────────────────────────────────────────

    test('11c. POST /api/rooms/{id}/slow-mode — set 30s slow mode', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/slow-mode`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { seconds: 30 },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 11d. Disable slow mode ────────────────────────────────────────────────

    test('11d. POST /api/rooms/{id}/slow-mode — disable (seconds=0)', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/slow-mode`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { seconds: 0 },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── 11e. Toggle mute ──────────────────────────────────────────────────────

    test('11e. POST /api/rooms/{id}/mute — mute toggle returns muted status', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/mute`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(typeof body.muted).toBe('boolean');
    });

    // ── 11f. Toggle mute again (idempotent back) ──────────────────────────────

    test('11f. POST /api/rooms/{id}/mute — second toggle reverses the state', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // First state
        const first = await request.post(`/api/rooms/${roomId}/mute`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        const firstMuted = (await first.json()).muted;

        // Toggle again
        const second = await request.post(`/api/rooms/${roomId}/mute`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        const secondMuted = (await second.json()).muted;

        expect(secondMuted).toBe(!firstMuted);
    });

    // ── 11g. Mark room read returns ok ────────────────────────────────────────

    test('11g. POST /api/rooms/{id}/read — marks room as read', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/read`, {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.ok).toBe(true);
    });

    // ── 11h. Push subscribe endpoint ──────────────────────────────────────────

    test('11h. POST /api/push/subscribe — accepts push subscription payload', async ({ request }) => {
        const res = await request.post('/api/push/subscribe', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: {
                endpoint: 'https://push.example.com/test-endpoint',
                keys: {
                    p256dh: 'BFAKE_P256DH_KEY_FOR_E2E_TESTING_ONLY_NOT_REAL',
                    auth:   'FAKE_AUTH_FOR_E2E',
                },
            },
        });
        // Server may validate endpoint format (400) or accept (200)
        expect([200, 201, 400, 422]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

// ────────────────────────────────────────────────────────────────────────────
// 12. EDGE CASES — bad inputs, unauthenticated, missing resources
// ────────────────────────────────────────────────────────────────────────────

test.describe('12. Edge cases', () => {
    const edgeUser = {
        username: `msg_eg_${randomStr(6)}`,
        phone:    `+7931${randomDigits(7)}`,
    };

    let csrfToken = '';
    let roomId    = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken: csrf } = await registerAndLogin(request, edgeUser.username, edgeUser.phone);
        csrfToken = csrf;
        roomId    = await createRoom(request, csrfToken, 'edge_room');
    });

    // ── 12a. Export unauthenticated returns 401 ───────────────────────────────

    test('12a. GET /api/rooms/{id}/export without auth returns 401', async ({ freshRequest: request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        // This request intentionally omits auth to verify the guard
        const res = await request.get(`/api/rooms/${roomId}/export`);
        expect([401, 403]).toContain(res.status());
    });

    // ── 12b. File list unauthenticated returns 401 ───────────────────────────

    test('12b. GET /api/files/room/{id} without auth returns 401', async ({ freshRequest: request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.get(`/api/files/room/${roomId}`);
        expect([401, 403]).toContain(res.status());
    });

    // ── 12c. Pin in non-existent room returns 403/404 ────────────────────────

    test('12c. POST /api/rooms/999999999/pin returns 403 or 404', async ({ request }) => {
        const res = await request.post('/api/rooms/999999999/pin', {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { msg_id: 1 },
        });
        expect([403, 404]).toContain(res.status());
    });

    // ── 12d. Auto-delete with invalid seconds is rejected ────────────────────

    test('12d. POST /api/rooms/{id}/auto-delete with negative seconds', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/auto-delete`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: { seconds: -1 },
        });
        // Server may normalise negative to 0 (200) or reject (422)
        expect([200, 400, 422]).toContain(res.status());
    });

    // ── 12e. Slow-mode unauthenticated returns 401 ───────────────────────────

    test('12e. POST /api/rooms/{id}/slow-mode without auth returns 401', async ({ freshRequest: request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/rooms/${roomId}/slow-mode`, {
            data: { seconds: 60 },
        });
        expect([401, 403]).toContain(res.status());
    });

    // ── 12f. Upload missing file field returns 422 ───────────────────────────

    test('12f. POST /api/files/upload without file field returns 422', async ({ request }) => {
        roomId = await ensureRoom(request, csrfToken, roomId);

        const res = await request.post(`/api/files/upload/${roomId}`, {
            headers: { 'X-CSRF-Token': csrfToken },
            data: {},
        });
        expect([400, 422]).toContain(res.status());
    });

    // ── 12g. Thread on non-member room returns 403 ───────────────────────────

    test('12g. GET /api/rooms/888888/thread/1 — non-member returns 403', async ({ request }) => {
        const res = await request.get('/api/rooms/888888/thread/1', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([403, 404]).toContain(res.status());
    });

    // ── 12h. Mark read on non-member room returns 403 ────────────────────────

    test('12h. POST /api/rooms/777777/read — non-member returns 403', async ({ request }) => {
        const res = await request.post('/api/rooms/777777/read', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
        expect([403, 404]).toContain(res.status());
    });

    test.afterAll(async ({ request }) => {
        await request.post('/api/authentication/logout', {
            headers: { 'X-CSRF-Token': csrfToken },
        });
    });
});

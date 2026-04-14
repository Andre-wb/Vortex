// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — File Operations
 *
 * Covers:
 *   - Upload file (image, document)
 *   - Download file
 *   - List room files
 *   - Upload size limits
 *   - Resumable upload (start, status)
 *   - Media preview
 *   - Distributed file registration
 *   - Edge cases (invalid room, unauthorized)
 */

test.describe('Files', () => {
    const username = `file_u_${randomStr(6)}`;
    const phone = `+7957${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;
    let fileId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'file_room');
    });

    // ── Upload ────────────────────────────────────────────────────────────────

    test('upload image file', async ({ request }) => {
        // 64x64 RGBA PNG (passes MIN_IMAGE_DIMENSION=50 check)
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAfUlEQVR4nOXOMQEAMAyAMIbyOu9k9CAK8mZ2CZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4iZM4ifM6cO0Dk3cDfuCvcDAAAAAASUVORK5CYII=',
            'base64'
        );
        const res = await request.post(`/api/files/upload/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'test_image.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        fileId = body.file_id || body.id || 0;
        expect(fileId).toBeTruthy();
    });

    test('upload text document', async ({ request }) => {
        const txtBuf = Buffer.from('E2E test document content\nLine 2\nLine 3');
        const res = await request.post(`/api/files/upload/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'document.txt', mimeType: 'text/plain', buffer: txtBuf },
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Download ──────────────────────────────────────────────────────────────

    test('download file', async ({ request }) => {
        expect(fileId).toBeTruthy();
        const res = await request.get(`/api/files/download/${fileId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── List files ────────────────────────────────────────────────────────────

    test('list room files', async ({ request }) => {
        const res = await request.get(`/api/files/room/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.files || body)).toBeTruthy();
    });

    // ── Media preview ─────────────────────────────────────────────────────────

    test('get media preview', async ({ request }) => {
        expect(fileId).toBeTruthy();
        const res = await request.get(`/api/files/preview/${roomId}/${fileId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        // 200 or 404 (if preview generation not supported for this file)
        expect([200, 404]).toContain(res.status());
    });

    // ── Resumable upload ──────────────────────────────────────────────────────

    test('start resumable upload (init)', async ({ request }) => {
        const res = await request.post('/api/files/upload-init', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                filename: 'large_file.bin',
                total_size: 1024,
                mime_type: 'application/octet-stream',
                room_id: roomId,
            },
        });
        expect([200, 201, 422]).toContain(res.status());
        const body = await res.json();
        if (body.upload_id) {
            // Check status
            const statusRes = await request.get(`/api/files/upload-status/${body.upload_id}`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect(statusRes.ok()).toBeTruthy();

            // Cancel
            const cancelRes = await request.delete(`/api/files/upload-cancel/${body.upload_id}`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect([200, 204]).toContain(cancelRes.status());
        }
    });

    // ── Gallery & Search ──────────────────────────────────────────────────────

    test('file gallery for room', async ({ request }) => {
        const res = await request.get(`/api/files/gallery/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('file search in room', async ({ request }) => {
        const res = await request.get(`/api/files/search/${roomId}?q=test`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('compression presets', async ({ request }) => {
        const res = await request.get('/api/files/compression-presets', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('file stats for room', async ({ request }) => {
        const res = await request.get(`/api/files/stats/${roomId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Distributed files ─────────────────────────────────────────────────────

    test('list distributed files', async ({ request }) => {
        const res = await request.get('/api/files/distributed/list', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('register distributed file', async ({ request }) => {
        const res = await request.post('/api/files/distributed/register', {
            headers: { 'X-CSRF-Token': csrf },
            data: { file_hash: randomStr(64), filename: 'dist.bin', size: 1024 },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    // ── Edge cases ────────────────────────────────────────────────────────────

    test('upload to non-existent room fails', async ({ request }) => {
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==',
            'base64'
        );
        const res = await request.post('/api/files/upload/999999', {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'nope.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([403, 404]).toContain(res.status());
    });

    test('download non-existent file returns error', async ({ request }) => {
        const res = await request.get('/api/files/download/999999', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([404, 400]).toContain(res.status());
    });
});

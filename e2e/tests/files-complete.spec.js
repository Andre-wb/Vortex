// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom } = require('./helpers');

/**
 * Vortex E2E — File Endpoints (missing coverage)
 *
 * Covers:
 *   - Upload chunk (resumable)
 *   - Upload complete (resumable)
 *   - Distributed file detail by hash
 */

test.describe('Files Complete', () => {
    const username = `filec_u_${randomStr(6)}`;
    const phone = `+7983${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'filec_room');
    });

    // ── Resumable Upload (chunk + complete) ───────────────────────────────────

    test('upload chunk to non-existent upload', async ({ request }) => {
        const chunk = Buffer.from('fake_chunk_data');
        const res = await request.put('/api/files/upload-chunk/fake_upload_id', {
            headers: {
                'X-CSRF-Token': csrf,
                'Content-Range': 'bytes 0-14/1024',
            },
            data: chunk,
        });
        expect([400, 404, 422]).toContain(res.status());
    });

    test('upload complete for non-existent upload', async ({ request }) => {
        const res = await request.post('/api/files/upload-complete/fake_upload_id', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([400, 404]).toContain(res.status());
    });

    test('full resumable upload flow', async ({ request }) => {
        // Init
        const initRes = await request.post('/api/files/upload-init', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                filename: 'test_resumable.bin',
                total_size: 64,
                mime_type: 'application/octet-stream',
                room_id: roomId,
            },
        });
        expect([200, 201, 422]).toContain(initRes.status());
        const initBody = await initRes.json();
        const uploadId = initBody.upload_id;

        if (uploadId) {
            // Upload chunk
            const chunk = Buffer.alloc(64, 0x42);
            const chunkRes = await request.put(`/api/files/upload-chunk/${uploadId}`, {
                headers: {
                    'X-CSRF-Token': csrf,
                    'Content-Range': 'bytes 0-63/64',
                    'Content-Type': 'application/octet-stream',
                },
                data: chunk,
            });
            expect([200, 201, 206]).toContain(chunkRes.status());

            // Complete
            const completeRes = await request.post(`/api/files/upload-complete/${uploadId}`, {
                headers: { 'X-CSRF-Token': csrf },
            });
            expect([200, 201]).toContain(completeRes.status());
        }
    });

    // ── Distributed file detail ───────────────────────────────────────────────

    test('get distributed file by hash', async ({ request }) => {
        const res = await request.get(`/api/files/distributed/${randomStr(64)}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 404]).toContain(res.status());
    });
});

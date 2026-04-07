// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — Sticker Packs
 *
 * Covers:
 *   - Create pack
 *   - List own packs
 *   - List public packs
 *   - Get pack detail
 *   - Update pack info
 *   - Upload sticker to pack
 *   - Delete sticker
 *   - Favorite / unfavorite pack
 *   - Delete pack
 *   - Edge cases
 */

test.describe('Stickers', () => {
    const username = `stk_u_${randomStr(6)}`;
    const phone = `+7953${randomDigits(7)}`;
    let csrf = '';
    let packId = 0;
    let stickerId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
    });

    test('create sticker pack', async ({ request }) => {
        const res = await request.post('/api/stickers/packs', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                name: `E2E Pack ${randomStr(4)}`,
                description: 'Test sticker pack',
                is_public: true,
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        packId = body.pack?.id || body.pack_id || body.id;
        expect(packId).toBeGreaterThan(0);
    });

    test('list own sticker packs', async ({ request }) => {
        const res = await request.get('/api/stickers/packs', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.own || body.packs || [])).toBeTruthy();
    });

    test('list public sticker packs', async ({ request }) => {
        const res = await request.get('/api/stickers/packs/public', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('get pack detail', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        const res = await request.get(`/api/stickers/packs/${packId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const pack = body.pack || body;
        expect(pack.name || pack.id).toBeDefined();
    });

    test('update pack info', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        const res = await request.put(`/api/stickers/packs/${packId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { name: `Updated Pack ${randomStr(3)}`, description: 'Updated desc' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('upload sticker to pack', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        // Create a minimal PNG buffer (1x1 transparent pixel)
        // Proper 1x1 RGBA PNG (Pillow-safe)
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==',
            'base64'
        );
        const res = await request.post(`/api/stickers/packs/${packId}/stickers`, {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                emoji: '😎',
                file: { name: 'sticker.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        stickerId = body.sticker?.id || body.sticker_id || body.id || 0;
    });

    test('favorite pack', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        const res = await request.post(`/api/stickers/packs/${packId}/favorite`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 204]).toContain(res.status());
    });

    test('unfavorite pack', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        const res = await request.delete(`/api/stickers/packs/${packId}/favorite`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('delete sticker', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        expect(stickerId).toBeGreaterThan(0);
        const res = await request.delete(`/api/stickers/packs/${packId}/stickers/${stickerId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('delete pack', async ({ request }) => {
        expect(packId).toBeGreaterThan(0);
        const res = await request.delete(`/api/stickers/packs/${packId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('get non-existent pack returns error', async ({ request }) => {
        const res = await request.get('/api/stickers/packs/999999', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([404, 400]).toContain(res.status());
    });
});

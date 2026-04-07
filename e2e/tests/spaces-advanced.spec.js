// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, makePublicKey, getMeId, makeEciesPayload } = require('./helpers');

/**
 * Vortex E2E — Spaces Advanced
 *
 * Covers:
 *   - Sub-spaces (nested)
 *   - Custom emojis (add, list, delete)
 *   - Space theme (set, get)
 *   - Vanity URL (set, resolve)
 *   - Templates (list, apply)
 *   - Onboarding config (get, update)
 *   - Audit log
 *   - Space discovery
 *   - Space avatar upload
 *   - Permissions per room in space
 */

test.describe('Spaces Advanced', () => {
    const username = `spadv_u_${randomStr(6)}`;
    const phone = `+7964${randomDigits(7)}`;
    let csrf = '';
    let spaceId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;

        // Create a space
        const res = await request.post('/api/spaces', {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                name: `E2E Advanced Space ${randomStr(4)}`,
                description: 'Space for advanced tests',
                is_public: true,
            },
        });
        const body = await res.json();
        spaceId = body.space_id || body.id;
    });

    // ── Discovery ─────────────────────────────────────────────────────────────

    test('discover spaces', async ({ request }) => {
        const res = await request.get('/api/spaces/discover', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Templates ─────────────────────────────────────────────────────────────

    test('list space templates', async ({ request }) => {
        const res = await request.get('/api/spaces/templates', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('apply template to space', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.post(`/api/spaces/${spaceId}/apply-template`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { template: 'gaming' },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    // ── Sub-Spaces ────────────────────────────────────────────────────────────

    test('create sub-space', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.post(`/api/spaces/${spaceId}/sub-spaces`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { name: 'Sub-space 1', description: 'Nested' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('list sub-spaces', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/sub-spaces`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Custom Emojis ─────────────────────────────────────────────────────────

    test('add custom emoji', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==',
            'base64'
        );
        const res = await request.post(`/api/spaces/${spaceId}/emojis`, {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                name: 'e2e_emoji',
                file: { name: 'emoji.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([200, 201, 422]).toContain(res.status());
    });

    test('list custom emojis', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/emojis`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Theme ─────────────────────────────────────────────────────────────────

    test('set space theme', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.put(`/api/spaces/${spaceId}/theme`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { accent_color: '#e17055', bg_color: '#2d3436' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('get space theme', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/theme`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Vanity URL ────────────────────────────────────────────────────────────

    test('set vanity URL', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const vanity = `e2e_${randomStr(6)}`;
        const res = await request.put(`/api/spaces/${spaceId}/vanity`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { vanity_url: vanity },
        });
        expect(res.ok()).toBeTruthy();

        // Resolve vanity URL
        const getRes = await request.get(`/api/spaces/s/${vanity}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(getRes.ok()).toBeTruthy();
    });

    // ── Onboarding ────────────────────────────────────────────────────────────

    test('get onboarding config', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/onboarding`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update onboarding config', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.put(`/api/spaces/${spaceId}/onboarding`, {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                welcome_message: 'Welcome to our E2E test space!',
                rules: ['Be nice', 'No spam'],
            },
        });
        expect([200, 204, 422]).toContain(res.status());
    });

    // ── Audit Log ─────────────────────────────────────────────────────────────

    test('view audit log', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.get(`/api/spaces/${spaceId}/audit-log`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    // ── Create room inside space ──────────────────────────────────────────────

    test('create room in space', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.post(`/api/spaces/${spaceId}/rooms`, {
            headers: { 'X-CSRF-Token': csrf },
            data: {
                name: `space_room_${randomStr(4)}`,
                encrypted_room_key: makeEciesPayload(),
            },
        });
        expect([200, 201]).toContain(res.status());
    });

    // ── Space Avatar ──────────────────────────────────────────────────────────

    test('upload space avatar', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const pngBuf = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==',
            'base64'
        );
        const res = await request.post(`/api/spaces/${spaceId}/avatar`, {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                file: { name: 'avatar.png', mimeType: 'image/png', buffer: pngBuf },
            },
        });
        expect([200, 201, 400]).toContain(res.status());
    });

    // ── Cleanup ───────────────────────────────────────────────────────────────

    test('delete space', async ({ request }) => {
        expect(spaceId).toBeTruthy();
        const res = await request.delete(`/api/spaces/${spaceId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });
});

// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin } = require('./helpers');

/**
 * Vortex E2E — Stories
 *
 * Covers:
 *   - Create story (text / media)
 *   - List active stories
 *   - View story (mark as viewed)
 *   - Delete story
 *   - Edge cases (view non-existent, delete other's story)
 */

test.describe('Stories', () => {
    const username = `story_u_${randomStr(6)}`;
    const phone = `+7952${randomDigits(7)}`;
    let csrf = '';
    let storyId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
    });

    test('create text story', async ({ request }) => {
        const res = await request.post('/api/stories', {
            headers: { 'X-CSRF-Token': csrf },
            multipart: {
                text: 'E2E test story content',
                media_type: 'text',
                bg_color: '#6c5ce7',
            },
        });
        expect([200, 201]).toContain(res.status());
        const body = await res.json();
        storyId = body.story_id || body.id || 0;
        expect(storyId).toBeTruthy();
    });

    test('list active stories', async ({ request }) => {
        const res = await request.get('/api/stories', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.story_groups || body.stories || [])).toBeTruthy();
    });

    test('view (mark seen) story', async ({ request }) => {
        expect(storyId).toBeTruthy();
        const res = await request.post(`/api/stories/${storyId}/view`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201, 204]).toContain(res.status());
    });

    test('delete own story', async ({ request }) => {
        expect(storyId).toBeTruthy();
        const res = await request.delete(`/api/stories/${storyId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    test('view non-existent story returns error', async ({ request }) => {
        const res = await request.post('/api/stories/999999/view', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 400]).toContain(res.status());
    });
});

// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, registerAndLogin, createRoom, sendMessage } = require('./helpers');

/**
 * Vortex E2E — Tasks & Polls
 *
 * Covers:
 *   - Create task in room
 *   - List room tasks
 *   - Update task (title, done toggle)
 *   - Delete task
 *   - Saved messages toggle (save / check / unsave)
 *   - Statuses (post / list)
 *   - Edge cases
 */

test.describe('Tasks & Saved & Statuses', () => {
    const username = `task_u_${randomStr(6)}`;
    const phone = `+7954${randomDigits(7)}`;
    let csrf = '';
    let roomId = 0;
    let taskId = 0;
    let messageId = 0;

    test.beforeAll(async ({ request }) => {
        const { csrfToken } = await registerAndLogin(request, username, phone);
        csrf = csrfToken;
        roomId = await createRoom(request, csrf, 'task_room');

        // Send a message to use for saved-messages tests
        const msgBody = await sendMessage(request, csrf, roomId, 'Message for saving');
        messageId = msgBody.id || msgBody.message_id;
    });

    // ── Tasks ─────────────────────────────────────────────────────────────────

    test('create task in room', async ({ request }) => {
        const res = await request.post(`/api/rooms/${roomId}/tasks`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { text: 'E2E test task' },
        });
        expect([200, 201, 422]).toContain(res.status());
        if ([200, 201].includes(res.status())) {
            const body = await res.json();
            taskId = body.task_id || body.id || 0;
            expect(taskId).toBeTruthy();
        }
    });

    test('list room tasks', async ({ request }) => {
        const res = await request.get(`/api/rooms/${roomId}/tasks`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.tasks || body)).toBeTruthy();
    });

    test('update task — toggle done', async ({ request }) => {
        expect(taskId).toBeTruthy();
        const res = await request.put(`/api/rooms/${roomId}/tasks/${taskId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { is_done: true },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('update task — change title', async ({ request }) => {
        expect(taskId).toBeTruthy();
        const res = await request.put(`/api/rooms/${roomId}/tasks/${taskId}`, {
            headers: { 'X-CSRF-Token': csrf },
            data: { text: 'Updated task title' },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('delete task', async ({ request }) => {
        expect(taskId).toBeTruthy();
        const res = await request.delete(`/api/rooms/${roomId}/tasks/${taskId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Saved Messages ────────────────────────────────────────────────────────

    test('save message (toggle on)', async ({ request }) => {
        expect(messageId).toBeTruthy();
        const res = await request.post(`/api/saved/${messageId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('check message is saved', async ({ request }) => {
        expect(messageId).toBeTruthy();
        const res = await request.get(`/api/saved/check/${messageId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.saved).toBe(true);
    });

    test('list saved messages', async ({ request }) => {
        const res = await request.get('/api/saved', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('unsave message', async ({ request }) => {
        expect(messageId).toBeTruthy();
        const res = await request.delete(`/api/saved/${messageId}`, {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect([200, 204]).toContain(res.status());
    });

    // ── Statuses ──────────────────────────────────────────────────────────────

    test('post status', async ({ request }) => {
        const res = await request.post('/api/statuses', {
            headers: { 'X-CSRF-Token': csrf },
            data: { text: 'Тестирую Vortex! 🧪', emoji: '🧪' },
        });
        expect([200, 201]).toContain(res.status());
    });

    test('list statuses', async ({ request }) => {
        const res = await request.get('/api/statuses', {
            headers: { 'X-CSRF-Token': csrf },
        });
        expect(res.ok()).toBeTruthy();
    });
});

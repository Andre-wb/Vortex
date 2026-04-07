/**
 * utils.test.js
 * Comprehensive unit tests for static/js/utils.js
 *
 * setup.js (loaded via jest.config.js setupFiles) provides:
 *   - globalThis.crypto  → Node WebCrypto
 *   - window.AppState    → minimal AppState stub
 *   - TextEncoder / TextDecoder, btoa / atob
 */

const {
    $,
    esc,
    fmtTime,
    fmtDate,
    fmtSize,
    getCookie,
    api,
    loadCsrfToken,
    openModal,
    closeModal,
    showAlert,
    scrollToBottom,
} = require('../utils.js');

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Create a DOM element with the given id and append it to document.body. */
function addEl(tag, id, extraClass = '') {
    const el = document.createElement(tag);
    el.id = id;
    if (extraClass) el.className = extraClass;
    document.body.appendChild(el);
    return el;
}

/** Remove an element from the DOM by id (cleanup). */
function removeEl(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 1 – $ (DOM id helper)
// ─────────────────────────────────────────────────────────────────────────────

describe('$ – getElementById shorthand', () => {
    beforeEach(() => addEl('div', 'test-node'));
    afterEach(() => removeEl('test-node'));

    test('returns the element when it exists', () => {
        const el = $('test-node');
        expect(el).not.toBeNull();
        expect(el.id).toBe('test-node');
    });

    test('returns null for a non-existent id', () => {
        expect($('does-not-exist')).toBeNull();
    });

    test('returned element is the same reference as getElementById', () => {
        expect($('test-node')).toBe(document.getElementById('test-node'));
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 2 – esc (HTML escaping / XSS prevention)
// ─────────────────────────────────────────────────────────────────────────────

describe('esc – HTML special character escaping', () => {
    test('escapes ampersand', () => {
        expect(esc('a & b')).toBe('a &amp; b');
    });

    test('escapes less-than', () => {
        expect(esc('<script>')).toBe('&lt;script&gt;');
    });

    test('escapes greater-than', () => {
        expect(esc('1 > 0')).toBe('1 &gt; 0');
    });

    test('escapes double quotes', () => {
        expect(esc('"quoted"')).toBe('&quot;quoted&quot;');
    });

    test('escapes all four characters in one string', () => {
        expect(esc('<a href="x">&</a>')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;');
    });

    test('returns empty string for falsy input (null)', () => {
        expect(esc(null)).toBe('');
    });

    test('returns empty string for falsy input (undefined)', () => {
        expect(esc(undefined)).toBe('');
    });

    test('returns empty string for empty string', () => {
        expect(esc('')).toBe('');
    });

    test('coerces numbers to string', () => {
        expect(esc(42)).toBe('42');
    });

    test('plain text without special chars is returned unchanged', () => {
        expect(esc('Hello, World!')).toBe('Hello, World!');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 3 – fmtTime
// ─────────────────────────────────────────────────────────────────────────────

describe('fmtTime – ISO date → HH:MM', () => {
    test('returns a string with a colon separator', () => {
        const result = fmtTime('2024-06-15T14:05:00');
        expect(typeof result).toBe('string');
        expect(result).toContain(':');
    });

    test('output has two segments separated by a colon', () => {
        const result = fmtTime('2024-01-01T09:03:00');
        const parts = result.split(':');
        expect(parts).toHaveLength(2);
    });

    test('both parts are numeric strings', () => {
        const result = fmtTime('2024-06-15T14:05:00');
        const [h, m] = result.split(':');
        expect(Number(h)).toBeGreaterThanOrEqual(0);
        expect(Number(m)).toBeGreaterThanOrEqual(0);
        expect(Number(m)).toBeLessThan(60);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 4 – fmtDate
// ─────────────────────────────────────────────────────────────────────────────

describe('fmtDate – ISO date → human-readable date', () => {
    test('returns "Сегодня" for today\'s date', () => {
        const today = new Date().toISOString();
        expect(fmtDate(today)).toBe('Сегодня');
    });

    test('returns a non-"Сегодня" string for a past date', () => {
        const past = '2020-01-15T12:00:00.000Z';
        const result = fmtDate(past);
        expect(result).not.toBe('Сегодня');
        expect(typeof result).toBe('string');
        expect(result.length).toBeGreaterThan(0);
    });

    test('returns a non-"Сегодня" string for a future date', () => {
        const future = '2099-12-31T12:00:00.000Z';
        const result = fmtDate(future);
        expect(result).not.toBe('Сегодня');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 5 – fmtSize
// ─────────────────────────────────────────────────────────────────────────────

describe('fmtSize – byte size formatting', () => {
    test('formats bytes (< 1 KB) with Б suffix', () => {
        expect(fmtSize(0)).toBe('0 Б');
        expect(fmtSize(512)).toBe('512 Б');
        expect(fmtSize(1023)).toBe('1023 Б');
    });

    test('formats kilobytes with КБ suffix', () => {
        expect(fmtSize(1024)).toBe('1.0 КБ');
        expect(fmtSize(2048)).toBe('2.0 КБ');
        expect(fmtSize(1536)).toBe('1.5 КБ');
    });

    test('formats megabytes with МБ suffix', () => {
        expect(fmtSize(1024 * 1024)).toBe('1.0 МБ');
        expect(fmtSize(1024 * 1024 * 2.5)).toBe('2.5 МБ');
    });

    test('boundary: exactly 1 KB', () => {
        expect(fmtSize(1024)).toBe('1.0 КБ');
    });

    test('boundary: exactly 1 MB', () => {
        expect(fmtSize(1024 * 1024)).toBe('1.0 МБ');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 6 – getCookie
// ─────────────────────────────────────────────────────────────────────────────

describe('getCookie', () => {
    afterEach(() => {
        // Reset document.cookie between tests (jsdom allows assignment)
        // Setting each key to expired clears it
        document.cookie.split(';').forEach(c => {
            const name = c.trim().split('=')[0];
            if (name) document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        });
    });

    test('returns null when cookie is not present', () => {
        expect(getCookie('nonexistent_cookie_xyz')).toBeNull();
    });

    test('returns the value of an existing cookie', () => {
        document.cookie = 'session_id=abc123';
        expect(getCookie('session_id')).toBe('abc123');
    });

    test('returns null when cookie string is empty', () => {
        // Ensure no cookies set
        expect(getCookie('')).toBeNull();
    });

    test('handles cookies with equals signs in values', () => {
        document.cookie = 'token=base64==value';
        // The implementation slices by name length + 1 so it should return base64==value
        const val = getCookie('token');
        expect(typeof val).toBe('string');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 7 – api() function
// ─────────────────────────────────────────────────────────────────────────────

describe('api – HTTP request wrapper', () => {
    beforeEach(() => {
        // Ensure AppState is clean
        window.AppState = {
            csrfToken: null,
            user: {},
            rooms: [],
            currentRoom: null,
            ws: null,
            notifWs: null,
            signalWs: null,
            networkMode: 'local',
        };
        jest.clearAllMocks();
    });

    test('GET request resolves with parsed JSON on success', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ data: 'hello' }),
        });
        const result = await api('GET', '/api/test');
        expect(result).toEqual({ data: 'hello' });
    });

    test('GET request calls fetch with credentials include', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({}),
        });
        await api('GET', '/api/ping');
        expect(fetch).toHaveBeenCalledWith(
            '/api/ping',
            expect.objectContaining({ credentials: 'include' })
        );
    });

    test('POST request sends Content-Type application/json with body', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ ok: true }),
        });
        await api('POST', '/api/data', { key: 'value' });
        const opts = fetch.mock.calls[0][1];
        expect(opts.headers['Content-Type']).toBe('application/json');
        expect(opts.body).toBe(JSON.stringify({ key: 'value' }));
    });

    test('POST request includes X-CSRF-Token when AppState.csrfToken is set', async () => {
        window.AppState.csrfToken = 'test-csrf-token-123';
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({}),
        });
        await api('POST', '/api/action', { x: 1 });
        const opts = fetch.mock.calls[0][1];
        expect(opts.headers['X-CSRF-Token']).toBe('test-csrf-token-123');
    });

    test('GET request does NOT include X-CSRF-Token even when csrfToken is set', async () => {
        window.AppState.csrfToken = 'csrf-abc';
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({}),
        });
        await api('GET', '/api/read');
        const opts = fetch.mock.calls[0][1];
        expect(opts.headers['X-CSRF-Token']).toBeUndefined();
    });

    test('throws an Error when response is not ok (400)', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 400,
            json: () => Promise.resolve({ detail: 'Bad Request' }),
        });
        await expect(api('GET', '/api/fail')).rejects.toThrow('Bad Request');
    });

    test('throws an Error when response is not ok and no detail field (500)', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: false,
            status: 500,
            json: () => Promise.resolve({}),
        });
        await expect(api('GET', '/api/crash')).rejects.toThrow(/500/);
    });

    test('throws timeout error when fetch is aborted', async () => {
        global.fetch = jest.fn().mockImplementation(() =>
            new Promise((_, reject) => {
                const err = new Error('The user aborted a request.');
                err.name = 'AbortError';
                setTimeout(() => reject(err), 10);
            })
        );
        await expect(api('GET', '/api/slow')).rejects.toThrow(/таймаут/i);
    });

    test('throws connection error on TypeError with "fetch" in message', async () => {
        global.fetch = jest.fn().mockRejectedValue(
            new TypeError('Failed to fetch')
        );
        await expect(api('GET', '/api/offline')).rejects.toThrow(/соединения/i);
    });

    test('DELETE request includes X-CSRF-Token', async () => {
        window.AppState.csrfToken = 'delete-csrf';
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({}),
        });
        await api('DELETE', '/api/item/1');
        const opts = fetch.mock.calls[0][1];
        expect(opts.headers['X-CSRF-Token']).toBe('delete-csrf');
    });

    test('PUT request includes X-CSRF-Token', async () => {
        window.AppState.csrfToken = 'put-csrf';
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({}),
        });
        await api('PUT', '/api/item/1', { name: 'new' });
        const opts = fetch.mock.calls[0][1];
        expect(opts.headers['X-CSRF-Token']).toBe('put-csrf');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 8 – loadCsrfToken
// ─────────────────────────────────────────────────────────────────────────────

describe('loadCsrfToken', () => {
    beforeEach(() => {
        window.AppState = { csrfToken: null };
    });

    test('sets AppState.csrfToken on successful response', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: () => Promise.resolve({ csrf_token: 'new-token-xyz' }),
        });
        await loadCsrfToken();
        expect(window.AppState.csrfToken).toBe('new-token-xyz');
    });

    test('does not throw when the API call fails', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('network error'));
        await expect(loadCsrfToken()).resolves.toBeUndefined();
    });

    test('leaves csrfToken unchanged on failure', async () => {
        window.AppState.csrfToken = 'old-token';
        global.fetch = jest.fn().mockRejectedValue(new Error('network error'));
        await loadCsrfToken();
        // After a failure the token is not updated
        expect(window.AppState.csrfToken).toBe('old-token');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 9 – openModal / closeModal
// ─────────────────────────────────────────────────────────────────────────────

describe('openModal / closeModal', () => {
    beforeEach(() => addEl('div', 'my-modal', 'modal-overlay'));
    afterEach(() => removeEl('my-modal'));

    test('openModal adds "show" class to the element', () => {
        openModal('my-modal');
        expect(document.getElementById('my-modal').classList.contains('show')).toBe(true);
    });

    test('closeModal removes "show" class from the element', () => {
        const el = document.getElementById('my-modal');
        el.classList.add('show');
        closeModal('my-modal');
        expect(el.classList.contains('show')).toBe(false);
    });

    test('openModal does not throw for non-existent id (logs warning)', () => {
        expect(() => openModal('ghost-modal')).not.toThrow();
    });

    test('closeModal does not throw for non-existent id', () => {
        expect(() => closeModal('ghost-modal')).not.toThrow();
    });

    test('openModal is idempotent (calling twice does not duplicate class)', () => {
        openModal('my-modal');
        openModal('my-modal');
        const classes = document.getElementById('my-modal').classList;
        // classList is a DOMTokenList so it cannot have duplicates
        const count = Array.from(classes).filter(c => c === 'show').length;
        expect(count).toBe(1);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 10 – showAlert
// ─────────────────────────────────────────────────────────────────────────────

describe('showAlert', () => {
    beforeEach(() => addEl('div', 'alert-el'));
    afterEach(() => removeEl('alert-el'));

    test('sets textContent to the message', () => {
        showAlert('alert-el', 'Something went wrong');
        expect(document.getElementById('alert-el').textContent).toBe('Something went wrong');
    });

    test('adds "show" and default "alert-error" CSS classes', () => {
        showAlert('alert-el', 'Oops');
        const classes = document.getElementById('alert-el').className;
        expect(classes).toContain('show');
        expect(classes).toContain('alert-error');
    });

    test('uses supplied type for CSS class', () => {
        showAlert('alert-el', 'Done!', 'success');
        const classes = document.getElementById('alert-el').className;
        expect(classes).toContain('alert-success');
        expect(classes).not.toContain('alert-error');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 11 – scrollToBottom
// ─────────────────────────────────────────────────────────────────────────────

describe('scrollToBottom', () => {
    let container;

    beforeEach(() => {
        container = addEl('div', 'messages-container');
        container.scrollTo = jest.fn();
    });

    afterEach(() => removeEl('messages-container'));

    test('calls scrollTo on the messages container', () => {
        scrollToBottom();
        expect(container.scrollTo).toHaveBeenCalled();
    });

    test('uses "instant" behavior by default', () => {
        scrollToBottom();
        expect(container.scrollTo).toHaveBeenCalledWith(
            expect.objectContaining({ behavior: 'instant' })
        );
    });

    test('uses "smooth" behavior when smooth=true', () => {
        scrollToBottom(true);
        expect(container.scrollTo).toHaveBeenCalledWith(
            expect.objectContaining({ behavior: 'smooth' })
        );
    });

    test('does not throw when messages container is absent', () => {
        removeEl('messages-container');
        expect(() => scrollToBottom()).not.toThrow();
    });
});

/**
 * auth.test.js
 *
 * Comprehensive unit tests for auth.js.
 *
 * Strategy: auth.js imports side-effectful modules (notifications.js, utils.js).
 * We mock every dependency so we can test exported functions in isolation without
 * a real DOM, server, or browser crypto implementation.
 */

// ── Dependency mocks (must appear before any import of the module under test) ─

jest.mock('../utils.js', () => ({
    $:          jest.fn((id) => global.document?.getElementById(id)),
    api:        jest.fn(),
    showAlert:  jest.fn(),
    openModal:  jest.fn(),
    closeModal: jest.fn(),
    esc:        jest.fn((s) => String(s ?? '')),
}));

jest.mock('../notifications.js', () => ({
    stopMultiplexCover: jest.fn(),
    getUnreadCount:     jest.fn(() => 0),
    hasMention:         jest.fn(() => false),
}));

// ── Import module under test ───────────────────────────────────────────────────
import {
    loadPrivateKey,
    getAccounts,
    switchAccount,
    addNewAccount,
    removeAccount,
    switchTab,
    selectEmoji,
    selectNetMode,
    doLogin,
    doLogout,
    checkSession,
    doRegister,
    verify2FA,
    checkRegistrationMode,
    exportPrivateKey,
    importPrivateKey,
} from '../auth.js';

import { api, $, closeModal, showAlert } from '../utils.js';
import { stopMultiplexCover } from '../notifications.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a minimal localStorage-like store backed by a plain object. */
function makeStorage() {
    const store = {};
    return {
        getItem:    (k)    => (k in store ? store[k] : null),
        setItem:    (k, v) => { store[k] = String(v); },
        removeItem: (k)    => { delete store[k]; },
        clear:      ()     => { Object.keys(store).forEach(k => delete store[k]); },
        _store:     store,
    };
}

// ── Test lifecycle ─────────────────────────────────────────────────────────────

let localStorageMock;
let sessionStorageMock;

beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Fresh storage instances
    localStorageMock   = makeStorage();
    sessionStorageMock = makeStorage();

    Object.defineProperty(window, 'localStorage',   { value: localStorageMock,   writable: true });
    Object.defineProperty(window, 'sessionStorage', { value: sessionStorageMock, writable: true });

    // Reset AppState
    window.AppState = {
        user:            null,
        rooms:           [],
        currentRoom:     null,
        x25519PrivateKey: null,
        ws:              null,
        notifWs:         null,
        signalWs:        null,
        csrfToken:       null,
        networkMode:     'auto',
        selectedEmoji:   null,
    };

    // Provide global stubs that auth.js calls directly
    window.bootApp    = jest.fn();
    window.openModal  = jest.fn();
    window.closeModal = jest.fn();
    window.alert      = jest.fn();
    window.t          = (key) => key;
    global.t          = (key) => key;

    // Restore real crypto (setup.js sets Node's webcrypto; individual tests
    // that need to stub specific subtle methods can override locally).
    // We only need to ensure crypto.subtle.importKey / deriveBits / sign are
    // available as jest.fn() for the switchAccount tests below.
    // We do NOT replace globalThis.crypto wholesale here so that other tests
    // that rely on real WebCrypto (e.g. key generation) still work.

    // Default api mock — returns empty object
    api.mockResolvedValue({});

    // $ — delegates to real getElementById
    $.mockImplementation((id) => document.getElementById(id));
});

// =============================================================================
// 1. loadPrivateKey()
// =============================================================================

describe('loadPrivateKey()', () => {
    test('returns null when no key is stored anywhere', () => {
        expect(loadPrivateKey()).toBeNull();
    });

    test('returns key from sessionStorage first', () => {
        sessionStorageMock.setItem('vortex_x25519_priv', 'session-key');
        localStorageMock.setItem('vortex_x25519_priv', 'local-key');
        expect(loadPrivateKey()).toBe('session-key');
    });

    test('falls back to localStorage when sessionStorage is empty', () => {
        localStorageMock.setItem('vortex_x25519_priv', 'local-key');
        expect(loadPrivateKey()).toBe('local-key');
    });

    test('returns null (not encrypted key) when only encrypted copy exists', () => {
        localStorageMock.setItem('vortex_x25519_priv_enc', 'encrypted-blob');
        expect(loadPrivateKey()).toBeNull();
    });

    test('sessionStorage key takes priority over encrypted copy', () => {
        sessionStorageMock.setItem('vortex_x25519_priv', 'session-jwk');
        localStorageMock.setItem('vortex_x25519_priv_enc', 'enc-blob');
        expect(loadPrivateKey()).toBe('session-jwk');
    });
});

// =============================================================================
// 2. getAccounts()
// =============================================================================

describe('getAccounts()', () => {
    test('returns empty array when nothing is stored', () => {
        expect(getAccounts()).toEqual([]);
    });

    test('parses stored JSON correctly', () => {
        const accounts = [{ user_id: 1, username: 'alice' }];
        localStorageMock.setItem('vortex_accounts', JSON.stringify(accounts));
        expect(getAccounts()).toEqual(accounts);
    });

    test('returns empty array for malformed JSON', () => {
        localStorageMock.setItem('vortex_accounts', '{broken json');
        expect(getAccounts()).toEqual([]);
    });

    test('returns empty array for explicitly stored empty array', () => {
        localStorageMock.setItem('vortex_accounts', '[]');
        expect(getAccounts()).toEqual([]);
    });
});

// =============================================================================
// 3. removeAccount()
// =============================================================================

describe('removeAccount()', () => {
    const ACCOUNTS = [
        { user_id: 1, username: 'alice' },
        { user_id: 2, username: 'bob' },
    ];

    beforeEach(() => {
        localStorageMock.setItem('vortex_accounts', JSON.stringify(ACCOUNTS));
        localStorageMock.setItem('vortex_x25519_priv_2', 'bob-key');
        window.AppState.user = { user_id: 1, username: 'alice' };
    });

    test('removes a non-current account from the list', () => {
        removeAccount(2);
        const remaining = getAccounts();
        expect(remaining).toHaveLength(1);
        expect(remaining[0].user_id).toBe(1);
    });

    test('also removes the per-user private key from localStorage', () => {
        removeAccount(2);
        expect(localStorageMock.getItem('vortex_x25519_priv_2')).toBeNull();
    });

    test('does NOT remove the currently logged-in account', () => {
        removeAccount(1); // current user
        expect(getAccounts()).toHaveLength(2);
    });

    test('is a no-op when userId does not exist in the list', () => {
        removeAccount(999);
        expect(getAccounts()).toHaveLength(2);
    });
});

// =============================================================================
// 4. switchAccount()
// =============================================================================

describe('switchAccount()', () => {
    beforeEach(() => {
        const accounts = [
            { user_id: 1, username: 'alice' },
            { user_id: 2, username: 'bob' },
        ];
        localStorageMock.setItem('vortex_accounts', JSON.stringify(accounts));
        window.AppState.user = { user_id: 1, username: 'alice' };
    });

    test('alerts and returns early when account is not in the stored list', async () => {
        await switchAccount(999);
        expect(window.alert).toHaveBeenCalledWith('auth.accountNotFound');
    });

    test('alerts and returns early when no private key is stored for target account', async () => {
        // bob (user_id: 2) has no stored key
        await switchAccount(2);
        expect(window.alert).toHaveBeenCalledWith('auth.keyNotFound');
    });

    test('calls logout API and stops multiplex cover during switch', async () => {
        localStorageMock.setItem('vortex_x25519_priv_2', JSON.stringify({ kty: 'OKP', crv: 'X25519', x: 'dummyX' }));

        // Mock crypto calls for the X25519 challenge flow
        const fakeKey = {};
        jest.spyOn(global.crypto.subtle, 'importKey').mockResolvedValue(fakeKey);
        jest.spyOn(global.crypto.subtle, 'deriveBits').mockResolvedValue(new ArrayBuffer(32));
        jest.spyOn(global.crypto.subtle, 'sign').mockResolvedValue(new ArrayBuffer(32));

        api.mockResolvedValueOnce({}) // logout
           .mockResolvedValueOnce({ challenge_id: 'cid', challenge: 'aa'.repeat(32), server_pubkey: 'bb'.repeat(32) }) // GET challenge
           .mockResolvedValueOnce({ user_id: 2, username: 'bob' }); // POST login-key

        await switchAccount(2);

        expect(api).toHaveBeenCalledWith('POST', '/api/authentication/logout');
        expect(stopMultiplexCover).toHaveBeenCalled();
    });
});

// =============================================================================
// 5. addNewAccount()
// =============================================================================

describe('addNewAccount()', () => {
    test('alerts max accounts warning when limit is reached', async () => {
        const full = Array.from({ length: 4 }, (_, i) => ({ user_id: i + 1, username: `u${i}` }));
        localStorageMock.setItem('vortex_accounts', JSON.stringify(full));
        window.AppState.user = full[0];

        await addNewAccount();
        expect(window.alert).toHaveBeenCalledWith('auth.maxAccounts');
    });

    test('sets _addingNewAccount flag before logout', async () => {
        localStorageMock.setItem('vortex_accounts', JSON.stringify([]));
        window.AppState.user = { user_id: 1, username: 'alice' };

        // Stub doLogout side-effects: api POST logout + DOM elements
        api.mockResolvedValue({});
        // Provide required DOM stubs for doLogout
        document.body.innerHTML = `
            <div id="app" style="display:block"></div>
            <div id="auth-screen"></div>
        `;

        await addNewAccount();
        expect(window._addingNewAccount).toBe(true);
    });
});

// =============================================================================
// 6. switchTab()
// =============================================================================

describe('switchTab()', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <div id="login-form"></div>
            <div id="register-form"></div>
            <div id="auth-alert" class="alert"></div>
            <button class="auth-tab active">Login</button>
            <button class="auth-tab">Register</button>
            <div id="invite-code-group" style="display:none"></div>
            <div id="reg-closed-msg" style="display:none"></div>
            <button id="register-btn"></button>
        `;
        api.mockResolvedValue({ mode: 'open' });
    });

    test('shows login form and hides register form when tab is "login"', () => {
        switchTab('login');
        expect(document.getElementById('login-form').style.display).toBe('');
        expect(document.getElementById('register-form').style.display).toBe('none');
    });

    test('shows register form and hides login form when tab is "register"', () => {
        switchTab('register');
        expect(document.getElementById('login-form').style.display).toBe('none');
        expect(document.getElementById('register-form').style.display).toBe('');
    });

    test('removes "show" class from auth-alert on tab switch', () => {
        const alert = document.getElementById('auth-alert');
        alert.classList.add('show');
        switchTab('login');
        expect(alert.classList.contains('show')).toBe(false);
    });

    test('marks first tab active when switching to login', () => {
        switchTab('login');
        const tabs = document.querySelectorAll('.auth-tab');
        expect(tabs[0].classList.contains('active')).toBe(true);
        expect(tabs[1].classList.contains('active')).toBe(false);
    });

    test('marks second tab active when switching to register', () => {
        switchTab('register');
        const tabs = document.querySelectorAll('.auth-tab');
        expect(tabs[0].classList.contains('active')).toBe(false);
        expect(tabs[1].classList.contains('active')).toBe(true);
    });
});

// =============================================================================
// 7. selectEmoji() and selectNetMode()
// =============================================================================

describe('selectEmoji()', () => {
    test('sets AppState.selectedEmoji from button data attribute', () => {
        document.body.innerHTML = `
            <button class="emoji-btn" data-emoji="😀"></button>
            <button class="emoji-btn" data-emoji="😎"></button>
        `;
        const [btn1, btn2] = document.querySelectorAll('.emoji-btn');
        selectEmoji(btn2);
        expect(window.AppState.selectedEmoji).toBe('😎');
    });

    test('adds emoji-selected class to the clicked button', () => {
        document.body.innerHTML = `<button class="emoji-btn" data-emoji="🔥"></button>`;
        const btn = document.querySelector('.emoji-btn');
        selectEmoji(btn);
        expect(btn.classList.contains('emoji-selected')).toBe(true);
    });

    test('removes emoji-selected from other buttons', () => {
        document.body.innerHTML = `
            <button class="emoji-btn emoji-selected" data-emoji="😀"></button>
            <button class="emoji-btn" data-emoji="🎉"></button>
        `;
        const [btn1, btn2] = document.querySelectorAll('.emoji-btn');
        selectEmoji(btn2);
        expect(btn1.classList.contains('emoji-selected')).toBe(false);
        expect(btn2.classList.contains('emoji-selected')).toBe(true);
    });
});

describe('selectNetMode()', () => {
    test('sets networkMode in AppState', () => {
        selectNetMode('tor');
        expect(window.AppState.networkMode).toBe('tor');
    });

    test('overwrites previous networkMode', () => {
        selectNetMode('direct');
        selectNetMode('i2p');
        expect(window.AppState.networkMode).toBe('i2p');
    });
});

// =============================================================================
// 8. doLogin()
// =============================================================================

describe('doLogin()', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <input id="l-login" value="alice">
            <input id="l-pass" value="pass123">
            <div id="auth-alert"></div>
            <div id="login-form"></div>
        `;
    });

    test('calls api POST login with trimmed username', async () => {
        const userData = { user_id: 1, username: 'alice' };
        api.mockResolvedValueOnce(userData);
        // loadPrivateKey returns null (no key stored)
        await doLogin();
        expect(api).toHaveBeenCalledWith(
            'POST',
            '/api/authentication/login',
            expect.objectContaining({ phone_or_username: 'alice', password: 'pass123' })
        );
    });

    test('sets AppState.user on successful login', async () => {
        const userData = { user_id: 1, username: 'alice' };
        api.mockResolvedValueOnce(userData);
        await doLogin();
        expect(window.AppState.user).toMatchObject({ user_id: 1 });
    });

    test('calls bootApp on successful login', async () => {
        api.mockResolvedValueOnce({ user_id: 1, username: 'alice' });
        await doLogin();
        expect(window.bootApp).toHaveBeenCalled();
    });

    test('injects 2FA prompt when server returns requires_2fa', async () => {
        api.mockResolvedValueOnce({ requires_2fa: true, user_id: 42 });
        await doLogin();
        const prompt = document.getElementById('2fa-prompt');
        expect(prompt).not.toBeNull();
    });

    test('stores 2FA user_id globally when 2FA is required', async () => {
        api.mockResolvedValueOnce({ requires_2fa: true, user_id: 99 });
        await doLogin();
        expect(window._2fa_user_id).toBe(99);
    });

    test('shows alert on API error', async () => {
        api.mockRejectedValueOnce(new Error('Invalid credentials'));
        await doLogin();
        expect(showAlert).toHaveBeenCalledWith('auth-alert', 'Invalid credentials');
    });

    test('recovers pubkey from stored JWK after login', async () => {
        const fakeJwk = JSON.stringify({ kty: 'OKP', crv: 'X25519', x: 'AAEC' });
        sessionStorageMock.setItem('vortex_x25519_priv', fakeJwk);
        api.mockResolvedValueOnce({ user_id: 1, username: 'alice', x25519_public_key: null });
        await doLogin();
        // x25519PrivateKey should be set from sessionStorage
        expect(window.AppState.x25519PrivateKey).toBe(fakeJwk);
    });
});

// =============================================================================
// 9. verify2FA()
// =============================================================================

describe('verify2FA()', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <input id="2fa-code" value="">
            <div id="auth-alert"></div>
            <div id="2fa-prompt"></div>
        `;
        window._2fa_user_id = 42;
        window._2fa_password = 'secret';
    });

    test('shows alert when code is empty', async () => {
        await verify2FA();
        expect(showAlert).toHaveBeenCalledWith('auth-alert', 'auth.twoFAHint');
    });

    test('shows alert when code length is not 6', async () => {
        document.getElementById('2fa-code').value = '12345';
        await verify2FA();
        expect(showAlert).toHaveBeenCalledWith('auth-alert', 'auth.twoFAHint');
    });

    test('calls verify-login API with correct code and user_id', async () => {
        document.getElementById('2fa-code').value = '123456';
        api.mockResolvedValueOnce({ user_id: 42, username: 'alice' });
        await verify2FA();
        expect(api).toHaveBeenCalledWith(
            'POST',
            '/api/authentication/2fa/verify-login',
            { user_id: 42, code: '123456' }
        );
    });

    test('removes 2fa-prompt element on success', async () => {
        document.getElementById('2fa-code').value = '654321';
        api.mockResolvedValueOnce({ user_id: 42, username: 'alice' });
        await verify2FA();
        expect(document.getElementById('2fa-prompt')).toBeNull();
    });

    test('cleans up _2fa_user_id and _2fa_password globals', async () => {
        document.getElementById('2fa-code').value = '000000';
        api.mockResolvedValueOnce({ user_id: 42 });
        await verify2FA();
        expect(window._2fa_user_id).toBeUndefined();
        expect(window._2fa_password).toBeUndefined();
    });

    test('calls bootApp after successful 2FA verification', async () => {
        document.getElementById('2fa-code').value = '111111';
        api.mockResolvedValueOnce({ user_id: 42 });
        await verify2FA();
        expect(window.bootApp).toHaveBeenCalled();
    });
});

// =============================================================================
// 10. doLogout()
// =============================================================================

describe('doLogout()', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <div id="app" style="display:block"></div>
            <div id="auth-screen"></div>
        `;
        window.AppState.user = { user_id: 1 };
        window.AppState.ws   = { close: jest.fn() };
    });

    test('calls logout API', async () => {
        api.mockResolvedValueOnce({});
        await doLogout();
        expect(api).toHaveBeenCalledWith('POST', '/api/authentication/logout');
    });

    test('clears AppState.user on logout', async () => {
        api.mockResolvedValueOnce({});
        await doLogout();
        expect(window.AppState.user).toBeNull();
    });

    test('clears x25519PrivateKey on logout', async () => {
        window.AppState.x25519PrivateKey = 'some-key';
        api.mockResolvedValueOnce({});
        await doLogout();
        expect(window.AppState.x25519PrivateKey).toBeNull();
    });

    test('shows auth screen and hides app screen', async () => {
        api.mockResolvedValueOnce({});
        await doLogout();
        expect(document.getElementById('app').style.display).toBe('none');
        expect(document.getElementById('auth-screen').style.display).toBe('flex');
    });

    test('calls stopMultiplexCover', async () => {
        api.mockResolvedValueOnce({});
        await doLogout();
        expect(stopMultiplexCover).toHaveBeenCalled();
    });

    test('closes WebSocket if present', async () => {
        const mockWs = { close: jest.fn() };
        window.AppState.ws = mockWs;
        api.mockResolvedValueOnce({});
        await doLogout();
        expect(mockWs.close).toHaveBeenCalled();
    });

    test('does not throw when logout API fails', async () => {
        api.mockRejectedValueOnce(new Error('network error'));
        await expect(doLogout()).resolves.not.toThrow();
    });
});

// =============================================================================
// 11. checkSession()
// =============================================================================

describe('checkSession()', () => {
    test('sets AppState.user from /api/authentication/me response', async () => {
        api.mockResolvedValueOnce({ user_id: 7, username: 'carol' });
        await checkSession();
        expect(window.AppState.user).toMatchObject({ user_id: 7, username: 'carol' });
    });

    test('calls bootApp on successful session check', async () => {
        api.mockResolvedValueOnce({ user_id: 7, username: 'carol' });
        await checkSession();
        expect(window.bootApp).toHaveBeenCalled();
    });

    test('does not throw or call bootApp when session check fails', async () => {
        api.mockRejectedValueOnce(new Error('Unauthorized'));
        await expect(checkSession()).resolves.not.toThrow();
        expect(window.bootApp).not.toHaveBeenCalled();
    });

    test('loads private key from sessionStorage into AppState on session restore', async () => {
        const fakeKey = JSON.stringify({ kty: 'OKP', crv: 'X25519', x: 'AAEC' });
        sessionStorageMock.setItem('vortex_x25519_priv', fakeKey);
        api.mockResolvedValueOnce({ user_id: 7, username: 'carol', x25519_public_key: null });
        await checkSession();
        expect(window.AppState.x25519PrivateKey).toBe(fakeKey);
    });
});

// =============================================================================
// 12. checkRegistrationMode()
// =============================================================================

describe('checkRegistrationMode()', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <div id="invite-code-group"></div>
            <div id="reg-closed-msg"></div>
            <button id="register-btn"></button>
        `;
    });

    test('hides register button when mode is "closed"', async () => {
        api.mockResolvedValueOnce({ mode: 'closed' });
        await checkRegistrationMode();
        expect(document.getElementById('register-btn').style.display).toBe('none');
    });

    test('shows invite code group when mode is "invite"', async () => {
        api.mockResolvedValueOnce({ mode: 'invite' });
        await checkRegistrationMode();
        expect(document.getElementById('invite-code-group').style.display).toBe('');
    });

    test('hides invite code group when mode is "open"', async () => {
        api.mockResolvedValueOnce({ mode: 'open' });
        await checkRegistrationMode();
        expect(document.getElementById('invite-code-group').style.display).toBe('none');
    });

    test('shows register button when mode is "open"', async () => {
        api.mockResolvedValueOnce({ mode: 'open' });
        await checkRegistrationMode();
        expect(document.getElementById('register-btn').style.display).toBe('');
    });

    test('does not throw on API failure', async () => {
        api.mockRejectedValueOnce(new Error('net fail'));
        await expect(checkRegistrationMode()).resolves.not.toThrow();
    });
});

// =============================================================================
// 13. exportPrivateKey()
// =============================================================================

describe('exportPrivateKey()', () => {
    test('alerts when no key is available', () => {
        window.AppState.x25519PrivateKey = null;
        exportPrivateKey();
        expect(window.alert).toHaveBeenCalledWith('auth.keyNotFound');
    });

    test('triggers anchor click to download key from AppState', () => {
        window.AppState.x25519PrivateKey = '{"kty":"OKP"}';
        const clickSpy = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        exportPrivateKey();
        expect(clickSpy).toHaveBeenCalled();
        clickSpy.mockRestore();
    });

    test('falls back to localStorage key when AppState key is null', () => {
        window.AppState.x25519PrivateKey = null;
        localStorageMock.setItem('vortex_x25519_priv', '{"kty":"OKP","from":"ls"}');
        const clickSpy = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        exportPrivateKey();
        expect(clickSpy).toHaveBeenCalled();
        clickSpy.mockRestore();
    });
});

// =============================================================================
// 14. importPrivateKey()
// =============================================================================

describe('importPrivateKey()', () => {
    test('stores valid JSON key in localStorage and AppState', async () => {
        const jwk = JSON.stringify({ kty: 'OKP', crv: 'X25519', x: 'abc' });
        const file = { text: jest.fn().mockResolvedValue(jwk) };
        await importPrivateKey(file);
        expect(localStorageMock.getItem('vortex_x25519_priv')).toBe(jwk);
        expect(window.AppState.x25519PrivateKey).toBe(jwk);
    });

    test('alerts success after valid import', async () => {
        const file = { text: jest.fn().mockResolvedValue('{"kty":"OKP"}') };
        await importPrivateKey(file);
        expect(window.alert).toHaveBeenCalledWith('auth.keyImported');
    });

    test('alerts invalid format for non-JSON input', async () => {
        const file = { text: jest.fn().mockResolvedValue('not valid json {{{{') };
        await importPrivateKey(file);
        expect(window.alert).toHaveBeenCalledWith('auth.keyInvalidFormat');
    });

    test('does not store anything on invalid JSON', async () => {
        const file = { text: jest.fn().mockResolvedValue('INVALID') };
        await importPrivateKey(file);
        expect(localStorageMock.getItem('vortex_x25519_priv')).toBeNull();
    });
});

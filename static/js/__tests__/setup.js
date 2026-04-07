// static/js/__tests__/setup.js
// Global setup shared across all test suites.

// ── Web Crypto API ─────────────────────────────────────────────────────────────
// Use Node's built-in WebCrypto so that tests that exercise the real crypto.js
// module (ECIES, AES-GCM, ratchet, …) can call crypto.subtle for real.
// Tests that need mock behaviour can override globalThis.crypto locally.
const { webcrypto } = require('crypto');
Object.defineProperty(globalThis, 'crypto', {
    value:        webcrypto,
    writable:     true,
    configurable: true,
});

// ── AppState global ────────────────────────────────────────────────────────────
window.AppState = {
    user:            {},
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

// ── i18n stub ──────────────────────────────────────────────────────────────────
global.t = (key) => key;

// ── TextEncoder / TextDecoder (jsdom sometimes omits these) ───────────────────
const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// ── btoa / atob ────────────────────────────────────────────────────────────────
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');

// ── URL.createObjectURL / revokeObjectURL stubs ───────────────────────────────
global.URL.createObjectURL = jest.fn(() => 'blob:mock-url');
global.URL.revokeObjectURL = jest.fn();

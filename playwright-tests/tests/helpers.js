// @ts-check
/**
 * Shared helpers for all Vortex E2E tests.
 * Import with:  const { randomStr, ... } = require('./helpers');
 */

const crypto = require('crypto');

const randomStr = (n = 8) =>
    crypto.randomBytes(n).toString('hex').slice(0, n);

const randomDigits = (n = 7) =>
    crypto.randomInt(0, 10 ** n).toString().padStart(n, '0');

const makePublicKey = () =>
    Array.from({ length: 32 }, () =>
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('');

const makeEciesPayload = () => ({
    ephemeral_pub: makePublicKey(),
    ciphertext: Array.from({ length: 60 }, () =>
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join(''),
});

const makeCiphertext = (extraBytes = 0) =>
    Array.from({ length: 24 + extraBytes }, () =>
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('');

/**
 * Register + login a user, return csrfToken + pubkey.
 * On 409 — try to login (user exists from previous run), else regenerate and retry.
 */
async function registerAndLogin(request, username, phone, password = 'E2ePass99!@') {
    let currentUser = username;
    let currentPhone = phone;
    const pubkey = makePublicKey();

    for (let attempt = 0; attempt < 5; attempt++) {
        const regRes = await request.post('/api/authentication/register', {
            data: {
                username: currentUser,
                password,
                phone: currentPhone,
                x25519_public_key: pubkey,
                display_name: `E2E ${currentUser}`,
            },
        });

        if (regRes.status() === 201 || regRes.status() === 409) {
            // 201 = new user, 409 = already exists — either way, try to login
            const loginRes = await request.post('/api/authentication/login', {
                data: { phone_or_username: currentUser, password },
            });
            if (loginRes.status() === 200) {
                const csrfRes = await request.get('/api/authentication/csrf-token');
                const { csrf_token } = await csrfRes.json();
                return { csrfToken: csrf_token, pubkey };
            }
            // Login failed (wrong user/password) — phone taken by different user, regenerate
            currentUser = `${username}_${randomStr(4)}`;
            currentPhone = phone.slice(0, 4) + randomDigits(7);
            continue;
        }

        throw new Error(`Registration failed: ${regRes.status()} ${await regRes.text()}`);
    }

    throw new Error(`Registration failed after 5 attempts (phone/username collisions)`);
}

/**
 * Login only (user already registered).
 */
async function loginUser(request, username, password = 'E2ePass99!@') {
    await request.post('/api/authentication/login', {
        data: { phone_or_username: username, password },
    });
    const csrfRes = await request.get('/api/authentication/csrf-token');
    return (await csrfRes.json()).csrf_token;
}

/**
 * Get current user ID.
 */
async function getMeId(request, csrfToken) {
    const res = await request.get('/api/authentication/me', {
        headers: { 'X-CSRF-Token': csrfToken },
    });
    return (await res.json()).user_id;
}

/**
 * Create a room, return its id.
 */
async function createRoom(request, csrfToken, namePrefix = 'e2e_room', opts = {}) {
    const res = await request.post('/api/rooms', {
        headers: { 'X-CSRF-Token': csrfToken },
        data: {
            name: `${namePrefix}_${randomStr(6)}`,
            encrypted_room_key: makeEciesPayload(),
            ...opts,
        },
    });
    const body = await res.json();
    return body.id || body.room_id;
}

/**
 * Generate a valid hex string of n bytes (2n hex chars).
 */
const makeHex = (nBytes = 32) =>
    Array.from({ length: nBytes }, () =>
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('');

/**
 * Send a message to a room, return message object.
 */
async function sendMessage(request, csrfToken, roomId, text) {
    const res = await request.post(`/api/rooms/${roomId}/messages`, {
        headers: { 'X-CSRF-Token': csrfToken },
        data: { ciphertext: text },
    });
    return res.json();
}

module.exports = {
    randomStr,
    randomDigits,
    makePublicKey,
    makeEciesPayload,
    makeCiphertext,
    makeHex,
    registerAndLogin,
    loginUser,
    getMeId,
    createRoom,
    sendMessage,
};

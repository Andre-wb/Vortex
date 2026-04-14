/**
 * bmp-client.js — Blind Mailbox Protocol Client (Unified Transport)
 *
 * All message types (text, typing, reaction, edit, delete, signal, etc.)
 * flow through BMP as encrypted fixed-size envelopes.
 * Server sees only anonymous {mailbox_id, blob} — cannot distinguish types.
 *
 * Features:
 *   - Rotating mailbox IDs (HMAC-SHA256, hourly rotation)
 *   - Cover traffic: 5x fake mailbox IDs per real + periodic fake deposits
 *   - Fixed-size envelope buckets (1KB, 4KB, 16KB)
 *   - Handler registry for message type dispatch
 *   - Fast-poll mode for WebRTC signaling (500ms)
 *   - Deduplication via envelope nonce
 */

import { packEnvelope, unpackEnvelope, packCoverEnvelope, MSG } from './bmp-envelope.js';

// ── Constants ───────────────────────────────────────────────────────────────

const ROTATION_PERIOD = 3600;          // 1 hour base rotation
const ROTATION_JITTER = 600;           // ±10 min per-pair jitter
const POLL_ACTIVE     = 500;           // 500ms when current chat is active
const POLL_RECENT     = 1500;          // 1.5s when recent activity (<30s)
const POLL_IDLE       = 5000;          // 5s background idle
const POLL_JITTER     = 200;           // ±100ms jitter
const COVER_RATIO     = 10;           // 10x cover mailboxes per real (was 5)
const COVER_LIFETIME  = 604800;        // cover IDs live 7 days
const COVER_DEPOSIT_MIN = 8000;        // cover deposit every 8-25s
const COVER_DEPOSIT_MAX = 25000;
const FAST_POLL_INTERVAL = 500;        // 500ms during calls
const FAST_POLL_TIMEOUT  = 60000;      // auto-disable after 60s of no activity
const DEDUP_CACHE_SIZE   = 5000;
const CLOCK_SKEW_EPOCHS  = 1;          // accept ±1 epoch for clock skew tolerance

const COVER_STORAGE_KEY = 'vortex_bmp_cover_ids';
const LAST_TS_KEY = 'vortex_bmp_last_ts';

// ── State ───────────────────────────────────────────────────────────────────

let _pollTimer = null;
let _enabled = false;
let _handlers = {};              // {typeCode: [handler, ...]}
let _dedupCache = new Set();     // Set of nonce hex strings
let _fastPollTimer = null;
let _fastPollRoom = null;
let _fastPollLastActivity = 0;
let _coverDepositTimer = null;
let _roomSecrets = {};           // {roomId: secretHex} — cached secrets
let _lastMessageReceived = 0;   // timestamp of last real message received
let _lastUserInteraction = 0;   // timestamp of last send/typing/UI action

// ── Mailbox ID derivation ───────────────────────────────────────────────────

/**
 * Derive per-pair rotation jitter from shared secret.
 * Each conversation rotates at a different time (±10 min from hour boundary).
 * Prevents server from observing synchronized mass rotation.
 */
async function _pairJitter(sharedSecretHex) {
    const keyBytes = Uint8Array.from(sharedSecretHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const hmacKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const jitterSig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode('jitter'));
    // Use first 2 bytes as jitter offset: 0..65535 mod ROTATION_JITTER → 0..599 seconds
    const jitterBytes = new Uint8Array(jitterSig);
    return ((jitterBytes[0] << 8) | jitterBytes[1]) % ROTATION_JITTER;
}

/**
 * Derive mailbox ID with per-pair rotation jitter and clock skew tolerance.
 * Returns array of IDs (current epoch + adjacent epochs for clock skew).
 */
async function deriveMailboxId(sharedSecretHex, timestamp) {
    const ts = timestamp || Math.floor(Date.now() / 1000);
    const jitter = await _pairJitter(sharedSecretHex);
    const adjustedTs = ts - jitter; // shift by per-pair jitter
    const epoch = Math.floor(adjustedTs / ROTATION_PERIOD);

    const keyBytes = Uint8Array.from(sharedSecretHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const hmacKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

    // Current epoch ID
    const epochBytes = new Uint8Array(8);
    new DataView(epochBytes.buffer).setBigUint64(0, BigInt(epoch), false);
    const sig = await crypto.subtle.sign('HMAC', hmacKey, epochBytes);
    return Array.from(new Uint8Array(sig).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get all valid mailbox IDs for a secret (current + adjacent for clock skew).
 * Used during polling to catch messages from slightly skewed clocks.
 */
async function deriveMailboxIds(sharedSecretHex, timestamp) {
    const ts = timestamp || Math.floor(Date.now() / 1000);
    const jitter = await _pairJitter(sharedSecretHex);
    const adjustedTs = ts - jitter;
    const epoch = Math.floor(adjustedTs / ROTATION_PERIOD);

    const keyBytes = Uint8Array.from(sharedSecretHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const hmacKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

    const ids = [];
    for (let e = epoch - CLOCK_SKEW_EPOCHS; e <= epoch + CLOCK_SKEW_EPOCHS; e++) {
        const eb = new Uint8Array(8);
        new DataView(eb.buffer).setBigUint64(0, BigInt(Math.max(0, e)), false);
        const sig = await crypto.subtle.sign('HMAC', hmacKey, eb);
        ids.push(Array.from(new Uint8Array(sig).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    return ids; // [prev_epoch_id, current_id, next_epoch_id]
}

async function getRoomMailboxSecret(roomId) {
    if (_roomSecrets[roomId]) return _roomSecrets[roomId];

    const { getRoomKey } = await import('./crypto.js');
    const roomKey = getRoomKey(roomId);
    if (!roomKey) return null;

    const hkdfKey = await crypto.subtle.importKey('raw', roomKey, 'HKDF', false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('bmp-mailbox') },
        hkdfKey, 256
    );
    const hex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
    _roomSecrets[roomId] = hex;
    return hex;
}

/**
 * Get room key as Uint8Array for envelope encryption.
 */
async function _getRoomKeyBytes(roomId) {
    const { getRoomKey } = await import('./crypto.js');
    return getRoomKey(roomId);
}

// ── Cover Traffic ───────────────────────────────────────────────────────────

function _loadCoverIds() {
    try {
        const data = JSON.parse(localStorage.getItem(COVER_STORAGE_KEY) || '{}');
        const now = Date.now() / 1000;
        const clean = {};
        for (const [id, ts] of Object.entries(data)) {
            if (now - ts < COVER_LIFETIME) clean[id] = ts;
        }
        return clean;
    } catch { return {}; }
}

function _saveCoverIds(ids) {
    try { localStorage.setItem(COVER_STORAGE_KEY, JSON.stringify(ids)); } catch {}
}

function _generateCoverId() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getCoverMailboxIds(realCount) {
    const coverIds = _loadCoverIds();
    const needed = Math.max(realCount * COVER_RATIO, 20);
    const now = Date.now() / 1000;
    while (Object.keys(coverIds).length < needed) {
        const jitter = Math.random() * 86400 * 2;
        coverIds[_generateCoverId()] = now - jitter;
    }
    _saveCoverIds(coverIds);
    return Object.keys(coverIds);
}

function _shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

// ── Handler Registry ────────────────────────────────────────────────────────

/**
 * Register a handler for a BMP message type.
 * Multiple handlers per type are supported.
 *
 * @param {number} typeCode - MSG.MESSAGE, MSG.TYPING, etc.
 * @param {function} handler - handler(roomId, payload, timestamp)
 */
export function registerBMPHandler(typeCode, handler) {
    if (!_handlers[typeCode]) _handlers[typeCode] = [];
    _handlers[typeCode].push(handler);
}

// Map WS message type strings to MSG codes (for server-side JSON deposits)
const _TYPE_MAP = {
    'message': MSG.MESSAGE, 'message_edited': MSG.EDIT, 'message_deleted': MSG.DELETE,
    'typing': MSG.TYPING, 'messages_read': MSG.READ_RECEIPT, 'reaction': MSG.REACTION,
    'file': MSG.FILE_META, 'message_pinned': MSG.PIN, 'poll': MSG.POLL, 'poll_update': MSG.POLL,
    'signal': MSG.SIGNAL, 'screenshot_taken': MSG.SCREENSHOT, 'thread_message': MSG.THREAD,
    'thread_update': MSG.THREAD, 'forward': MSG.FORWARD, 'voice_update': MSG.VOICE_EVENT,
    'voice_state': MSG.VOICE_EVENT, 'file_sending': MSG.FILE_SENDING,
    'stop_file_sending': MSG.FILE_SENDING, 'notification': MSG.MESSAGE, 'new_dm': MSG.MESSAGE,
    'incoming_call': MSG.SIGNAL, 'group_call_invite': MSG.SIGNAL, 'group_call_update': MSG.SIGNAL,
    'stream_state': MSG.VOICE_EVENT, 'stream_update': MSG.VOICE_EVENT,
    'auto_delete_changed': MSG.MESSAGE, 'slow_mode_changed': MSG.MESSAGE,
};
function _typeToCode(typeStr) { return _TYPE_MAP[typeStr] || MSG.MESSAGE; }

function _dispatch(roomId, typeCode, payload, timestamp) {
    const handlers = _handlers[typeCode];
    if (!handlers || !handlers.length) {
        console.debug('[BMP] No handler for type 0x%s', typeCode.toString(16));
        return;
    }
    // Mark activity on real message receive (not cover/typing from self)
    _lastMessageReceived = Date.now();
    for (const fn of handlers) {
        try { fn(roomId, payload, timestamp); }
        catch (e) { console.warn('[BMP] Handler error for type 0x%s:', typeCode.toString(16), e); }
    }
}

// ── Deduplication ───────────────────────────────────────────────────────────

function _isDuplicate(nonce) {
    const key = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
    if (_dedupCache.has(key)) return true;
    _dedupCache.add(key);
    if (_dedupCache.size > DEDUP_CACHE_SIZE) {
        // Remove oldest entries (Sets maintain insertion order)
        const iter = _dedupCache.values();
        for (let i = 0; i < 1000; i++) iter.next();
        const keep = new Set();
        for (const v of _dedupCache) { if (keep.size >= _dedupCache.size - 1000) keep.add(v); else keep.add(v); }
        // Simpler: just clear and rebuild (acceptable for 5000 entries)
        const arr = [..._dedupCache];
        _dedupCache = new Set(arr.slice(-DEDUP_CACHE_SIZE + 1000));
    }
    return false;
}

// ── Polling ─────────────────────────────────────────────────────────────────

async function _poll() {
    if (!_enabled) return;
    const S = window.AppState;

    // Collect ALL room types: rooms, channels, DMs, federated, spaces
    const allRooms = [];
    if (S?.rooms?.length) allRooms.push(...S.rooms);
    if (S?.channels?.length) allRooms.push(...S.channels);
    if (S?.dmRooms?.length) allRooms.push(...S.dmRooms);
    if (S?.federatedRooms?.length) allRooms.push(...S.federatedRooms);
    // Spaces contain rooms — already included in S.rooms
    if (!allRooms.length) return;

    try {
        const realIds = {};
        const roomKeys = {};
        for (const room of allRooms) {
            const rid = room.id || room.room_id;
            if (!rid) continue;
            const secret = await getRoomMailboxSecret(rid);
            if (!secret) continue;
            // Clock skew tolerance: derive IDs for current + adjacent epochs
            const mbIds = await deriveMailboxIds(secret);
            for (const mbId of mbIds) {
                realIds[mbId] = rid;
            }
            const rk = await _getRoomKeyBytes(rid);
            if (rk) roomKeys[rid] = rk;
        }

        const realIdList = Object.keys(realIds);
        if (!realIdList.length) return;

        const coverIds = getCoverMailboxIds(realIdList.length);
        const allIds = _shuffle([...realIdList, ...coverIds]);

        const sinceTs = parseFloat(localStorage.getItem(LAST_TS_KEY) || '0');
        const bucketedSince = Math.floor(sinceTs / 300) * 300;

        const resp = await fetch('/api/bmp/batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'omit',
            body: JSON.stringify({ ids: allIds.slice(0, 100), since: bucketedSince }),
        });
        if (!resp.ok) return;

        const data = await resp.json();
        const mailboxes = data.mailboxes || {};

        let maxTs = sinceTs;
        for (const [mbId, messages] of Object.entries(mailboxes)) {
            const roomId = realIds[mbId];
            if (!roomId) continue;

            const roomKey = roomKeys[roomId];
            if (!roomKey) continue;

            for (const msg of messages) {
                if (msg.ts > maxTs) maxTs = msg.ts;

                // Try to unpack as encrypted envelope first
                const env = await unpackEnvelope(msg.ct, roomKey);
                if (env) {
                    if (!_isDuplicate(env.nonce)) {
                        _dispatch(roomId, env.type, env.payload, msg.ts);
                    }
                    continue;
                }

                // Server-side BMP deposit: plaintext JSON (not encrypted envelope)
                // This happens when server deposits via broadcast_to_room → _BMP_TYPES
                try {
                    const payload = JSON.parse(msg.ct);
                    if (payload && payload.type) {
                        // Dedup server-side JSON by msg_id or hash of content+ts
                        const dedupKey = payload.msg_id || payload.client_msg_id
                            || ('json_' + msg.ts + '_' + (payload.type || '') + '_' + (payload.msg_id || payload.sender_id || '') + '_' + msg.ct.length);
                        const dedupBytes = new TextEncoder().encode(dedupKey);
                        if (!_isDuplicate(dedupBytes)) {
                            _dispatch(roomId, _typeToCode(payload.type), payload, msg.ts);
                        }
                        continue;
                    }
                } catch {}

                // Legacy: raw E2E ciphertext (not envelope, not JSON)
                {
                    const legacyKey = new TextEncoder().encode('legacy_' + msg.ts + '_' + msg.ct.substring(0, 32));
                    if (!_isDuplicate(legacyKey)) {
                        _dispatch(roomId, MSG.MESSAGE, { _legacy: true, ct: msg.ct }, msg.ts);
                    }
                }
            }
        }

        if (maxTs > sinceTs) {
            localStorage.setItem(LAST_TS_KEY, String(maxTs));
        }
    } catch (e) {
        console.debug('[BMP] Poll error:', e.message);
    }
}

// ── Send via BMP ────────────────────────────────────────────────────────────

/**
 * Send a typed message through BMP as an encrypted fixed-size envelope.
 *
 * @param {number} roomId
 * @param {number} typeCode - MSG.MESSAGE, MSG.TYPING, etc.
 * @param {Object} payload - JSON-serializable payload
 */
export async function bmpSend(roomId, typeCode, payload) {
    const secret = await getRoomMailboxSecret(roomId);
    if (!secret) throw new Error('No BMP secret for room ' + roomId);

    const roomKey = await _getRoomKeyBytes(roomId);
    if (!roomKey) throw new Error('No room key for room ' + roomId);

    const envelopeHex = await packEnvelope(typeCode, payload, roomKey);
    const mbId = await deriveMailboxId(secret);

    await fetch('/api/bmp/post/' + mbId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'omit',
        body: JSON.stringify({ ct: envelopeHex }),
    });

    // Mark send activity → switches to fast polling
    _lastUserInteraction = Date.now();

    // If this is a signal message, activate fast-poll
    if (typeCode === MSG.SIGNAL) {
        setFastPollMode(true, roomId);
    }
}

/**
 * Legacy send (raw ciphertext, no envelope).
 * Used during hybrid transition period.
 */
export async function bmpSendRaw(roomId, ciphertextHex) {
    const secret = await getRoomMailboxSecret(roomId);
    if (!secret) throw new Error('No BMP secret for room');
    const mbId = await deriveMailboxId(secret);
    await fetch('/api/bmp/post/' + mbId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'omit',
        body: JSON.stringify({ ct: ciphertextHex }),
    });
}

// ── Register Room Secret on Server ──────────────────────────────────────────

/**
 * Register room's BMP secret on the server so it can deposit envelopes.
 * Called after room key is established.
 */
export async function registerRoomSecret(roomId) {
    const secret = await getRoomMailboxSecret(roomId);
    if (!secret) return;

    const csrf = window.AppState?.csrfToken;
    const headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF-Token'] = csrf;

    try {
        await fetch('/api/bmp/room-secret/' + roomId, {
            method: 'POST',
            credentials: 'include',
            headers,
            body: JSON.stringify({ secret }),
        });
    } catch (e) {
        console.debug('[BMP] Failed to register room secret:', e.message);
    }
}

// ── Cover Traffic Deposits ──────────────────────────────────────────────────

async function _coverDepositLoop() {
    if (!_enabled) return;
    try {
        // Deposit 1-3 fake 1KB envelopes to random mailbox IDs
        const count = 1 + Math.floor(Math.random() * 3);
        const fakeKey = crypto.getRandomValues(new Uint8Array(32));
        for (let i = 0; i < count; i++) {
            const fakeId = _generateCoverId();
            const coverHex = await packCoverEnvelope(fakeKey);
            fetch('/api/bmp/post/' + fakeId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'omit',
                body: JSON.stringify({ ct: coverHex }),
            }).catch(() => {});
        }
    } catch {}
    // Schedule next with jitter
    const delay = COVER_DEPOSIT_MIN + Math.random() * (COVER_DEPOSIT_MAX - COVER_DEPOSIT_MIN);
    _coverDepositTimer = setTimeout(_coverDepositLoop, delay);
}

// ── Fast Poll Mode (for WebRTC) ─────────────────────────────────────────────

/**
 * Enable/disable fast polling for a room (500ms instead of 3s).
 * Auto-disables after 60s of no signal activity.
 */
export function setFastPollMode(enabled, roomId) {
    if (enabled) {
        _fastPollRoom = roomId;
        _fastPollLastActivity = Date.now();
        if (!_fastPollTimer) {
            _fastPollTimer = setInterval(_fastPoll, FAST_POLL_INTERVAL);
            console.debug('[BMP] Fast-poll ON for room', roomId);
        }
    } else {
        if (_fastPollTimer) {
            clearInterval(_fastPollTimer);
            _fastPollTimer = null;
            _fastPollRoom = null;
            console.debug('[BMP] Fast-poll OFF');
        }
    }
}

async function _fastPoll() {
    // Auto-disable after timeout
    if (Date.now() - _fastPollLastActivity > FAST_POLL_TIMEOUT) {
        setFastPollMode(false);
        return;
    }
    if (!_fastPollRoom || !_enabled) return;

    try {
        const secret = await getRoomMailboxSecret(_fastPollRoom);
        if (!secret) return;
        const mbId = await deriveMailboxId(secret);
        const coverIds = getCoverMailboxIds(1).slice(0, 3);
        const allIds = _shuffle([mbId, ...coverIds]);

        const sinceTs = parseFloat(localStorage.getItem(LAST_TS_KEY) || '0');
        const resp = await fetch('/api/bmp/fast-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'omit',
            body: JSON.stringify({ ids: allIds, since: Math.floor(sinceTs / 300) * 300 }),
        });
        if (!resp.ok) return;

        const data = await resp.json();
        const mailboxes = data.mailboxes || {};
        const msgs = mailboxes[mbId];
        if (!msgs?.length) return;

        const roomKey = await _getRoomKeyBytes(_fastPollRoom);
        if (!roomKey) return;

        let maxTs = sinceTs;
        for (const msg of msgs) {
            if (msg.ts > maxTs) maxTs = msg.ts;
            const env = await unpackEnvelope(msg.ct, roomKey);
            if (env && !_isDuplicate(env.nonce)) {
                _dispatch(_fastPollRoom, env.type, env.payload, msg.ts);
                if (env.type === MSG.SIGNAL) _fastPollLastActivity = Date.now();
                continue;
            }
            // Server-side JSON deposit fallback
            try {
                const p = JSON.parse(msg.ct);
                if (p?.type) { _dispatch(_fastPollRoom, _typeToCode(p.type), p, msg.ts); continue; }
            } catch {}
        }
        if (maxTs > sinceTs) localStorage.setItem(LAST_TS_KEY, String(maxTs));
    } catch {}
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

/**
 * Compute adaptive poll interval based on activity.
 * Active chat → 500ms, recent activity → 1.5s, idle → 5s.
 * All mailboxes polled in one batch — server can't distinguish which is "active".
 */
function _getAdaptivePollInterval() {
    const now = Date.now();
    const sinceMsg = now - _lastMessageReceived;
    const sinceUser = now - _lastUserInteraction;
    const sinceAny = Math.min(sinceMsg, sinceUser);

    // Fast-poll mode for calls overrides everything
    if (_fastPollTimer) return FAST_POLL_INTERVAL;

    // Active: user sent/typed or received message in last 10s
    if (sinceAny < 10000) return POLL_ACTIVE;

    // Recent: activity in last 30s
    if (sinceAny < 30000) return POLL_RECENT;

    // Idle
    return POLL_IDLE;
}

/**
 * Mark activity — called on send, typing, or message receive.
 */
export function bmpMarkActivity(type) {
    if (type === 'send' || type === 'typing') {
        _lastUserInteraction = Date.now();
    } else if (type === 'receive') {
        _lastMessageReceived = Date.now();
    }
}

export function startBMP() {
    if (_pollTimer) return;
    _enabled = true;
    // Adaptive polling: interval changes based on activity
    function _scheduleNext() {
        const base = _getAdaptivePollInterval();
        const jitter = base + Math.floor(Math.random() * POLL_JITTER * 2) - POLL_JITTER;
        _pollTimer = setTimeout(function() { _poll().then(_scheduleNext); }, Math.max(200, jitter));
    }
    _poll().then(_scheduleNext);
    // Start cover deposit loop
    const delay = COVER_DEPOSIT_MIN + Math.random() * (COVER_DEPOSIT_MAX - COVER_DEPOSIT_MIN);
    _coverDepositTimer = setTimeout(_coverDepositLoop, delay);
    console.info('[BMP] Adaptive transport started (active=%dms, recent=%dms, idle=%dms, cover=%dx)', POLL_ACTIVE, POLL_RECENT, POLL_IDLE, COVER_RATIO);
}

export function stopBMP() {
    _enabled = false;
    if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    if (_fastPollTimer) { clearInterval(_fastPollTimer); _fastPollTimer = null; }
    if (_coverDepositTimer) { clearTimeout(_coverDepositTimer); _coverDepositTimer = null; }
    _handlers = {};
    console.info('[BMP] Stopped');
}

export function isBMPEnabled() { return _enabled; }

// ── Exports ─────────────────────────────────────────────────────────────────

export { deriveMailboxId, getRoomMailboxSecret, MSG };

window.bmpSend = bmpSend;
window.bmpSendRaw = bmpSendRaw;
window.startBMP = startBMP;
window.stopBMP = stopBMP;
window.isBMPEnabled = isBMPEnabled;
window.registerBMPHandler = registerBMPHandler;
window.setFastPollMode = setFastPollMode;
window.registerRoomSecret = registerRoomSecret;
window.bmpMarkActivity = bmpMarkActivity;

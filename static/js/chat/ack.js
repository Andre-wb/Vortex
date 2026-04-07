// static/js/chat/ack.js — ACK system: guaranteed message delivery
// Features: exponential backoff, persistent IndexedDB offline queue

import { appendSystemMessage } from './messages.js';

const _pendingAcks = new Map();

const ACK_BASE_TIMEOUT = 2000;   // base timeout 2s
const ACK_MAX_RETRY    = 5;      // 5 retries: 2s, 4s, 8s, 16s, 32s

// ── IndexedDB persistent offline queue ─────────────────────────────────────

const _DB_NAME    = 'vortex_offline';
const _DB_VERSION = 1;
const _STORE      = 'queue';
let _idb = null;

function _openDB() {
    if (_idb) return Promise.resolve(_idb);
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_DB_NAME, _DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(_STORE)) {
                db.createObjectStore(_STORE, { keyPath: 'msg_id' });
            }
        };
        req.onsuccess = () => { _idb = req.result; resolve(_idb); };
        req.onerror   = () => { console.warn('[ACK] IndexedDB unavailable, fallback to memory'); reject(); };
    });
}

async function _idbPut(payload) {
    try {
        const db = await _openDB();
        const tx = db.transaction(_STORE, 'readwrite');
        tx.objectStore(_STORE).put({ msg_id: payload.msg_id, payload, ts: Date.now() });
    } catch { _memQueue.push(payload); }
}

async function _idbDelete(msgId) {
    try {
        const db = await _openDB();
        const tx = db.transaction(_STORE, 'readwrite');
        tx.objectStore(_STORE).delete(msgId);
    } catch {}
}

async function _idbGetAll() {
    try {
        const db = await _openDB();
        return new Promise((resolve) => {
            const tx  = db.transaction(_STORE, 'readonly');
            const req = tx.objectStore(_STORE).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror   = () => resolve([]);
        });
    } catch { return []; }
}

// In-memory fallback if IndexedDB unavailable
const _memQueue = [];

// ── Core ACK logic ─────────────────────────────────────────────────────────

export function sendWithAck(payload) {
    const msgId = crypto.randomUUID();
    payload     = { ...payload, msg_id: msgId };

    return new Promise((resolve, reject) => {
        _pendingAcks.set(msgId, {
            payload,
            retries:   0,
            timeoutId: null,
            resolve,
            reject,
        });
        _trySend(msgId);
    });
}

function _getBackoffMs(retries) {
    // Exponential backoff: 2s, 4s, 8s, 16s, 32s + jitter
    return ACK_BASE_TIMEOUT * Math.pow(2, retries) + Math.random() * 500;
}

function _trySend(msgId) {
    const entry = _pendingAcks.get(msgId);
    if (!entry) return;

    const S  = window.AppState;
    const ws = S.ws;

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        // Persist to IndexedDB for cross-session survival
        _idbPut(entry.payload);
        return;
    }

    ws.send(JSON.stringify(entry.payload));

    const backoff = _getBackoffMs(entry.retries);
    entry.timeoutId = setTimeout(() => {
        const e = _pendingAcks.get(msgId);
        if (!e) return;

        if (e.retries < ACK_MAX_RETRY) {
            e.retries++;
            console.warn(`[ACK] retry ${e.retries}/${ACK_MAX_RETRY} (${Math.round(backoff)}ms) для ${msgId}`);
            _trySend(msgId);
        } else {
            _pendingAcks.delete(msgId);
            _idbDelete(msgId);
            e.reject(new Error(`Not delivered after ${ACK_MAX_RETRY} retries`));
            appendSystemMessage(t('chat.notDelivered'));
        }
    }, backoff);
}

export function _handleAck(msg) {
    const entry = _pendingAcks.get(msg.msg_id);
    if (!entry) return;

    clearTimeout(entry.timeoutId);
    _pendingAcks.delete(msg.msg_id);
    _idbDelete(msg.msg_id);
    entry.resolve(msg.server_id ?? msg.msg_id);
    console.debug(`[ACK] confirmed ${msg.msg_id} → server_id=${msg.server_id}`);
}

export function _cancelAllPendingAcks() {
    for (const [msgId, entry] of _pendingAcks) {
        clearTimeout(entry.timeoutId);
        // Don't delete from IDB — will retry on reconnect
    }
    _pendingAcks.clear();
}

export async function _flushOfflineQueue() {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;

    // Flush IndexedDB persistent queue
    const stored = await _idbGetAll();
    const oneHourAgo = Date.now() - 3600_000;
    for (const item of stored) {
        if (item.ts < oneHourAgo) {
            // Drop messages older than 1 hour
            await _idbDelete(item.msg_id);
            continue;
        }
        const payload = item.payload;
        const msgId   = payload.msg_id;
        if (!_pendingAcks.has(msgId)) {
            // Re-create pending entry for ACK tracking
            _pendingAcks.set(msgId, {
                payload,
                retries: 0,
                timeoutId: null,
                resolve: () => {},
                reject:  () => {},
            });
        }
        _trySend(msgId);
    }

    // Flush in-memory fallback queue
    while (_memQueue.length > 0) {
        const payload = _memQueue.shift();
        try { S.ws.send(JSON.stringify(payload)); } catch {}
    }
}

export function getAckStats() {
    return {
        pending:      _pendingAcks.size,
        memQueue:     _memQueue.length,
    };
}

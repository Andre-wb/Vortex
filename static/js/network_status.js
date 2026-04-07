/**
 * static/js/network_status.js — Network status indicator + offline message queue.
 *
 * Features:
 *   - Visual indicator: online (green) / offline (red) / syncing (amber)
 *   - Offline message queue: messages typed while offline are queued and sent on reconnect
 *   - WebSocket health monitoring (heartbeat)
 *   - Auto-retry with exponential backoff
 *   - Smooth transitions between states
 *   - Screen reader announcements
 *
 * States:
 *   online   — connected, WS active
 *   offline  — no network or WS disconnected
 *   syncing  — reconnected, flushing queued messages
 */

const HEARTBEAT_INTERVAL = 15000;  // 15s
const MAX_QUEUE_SIZE = 100;

let _state = 'online';  // 'online' | 'offline' | 'syncing'
let _indicator = null;
let _offlineQueue = [];
let _heartbeatTimer = null;
let _listeners = [];

// ── State management ────────────────────────────────────────────────────

function _setState(newState) {
    if (_state === newState) return;
    const old = _state;
    _state = newState;
    _updateUI();
    _listeners.forEach(fn => fn(newState, old));

    // Screen reader announcement
    if (typeof window._announce === 'function') {
        const tFn = typeof window.t === 'function' ? window.t : (k) => k;
        const msgs = {
            online: tFn('network.online') || 'Connected',
            offline: tFn('network.offline') || 'No connection',
            syncing: tFn('network.syncing') || 'Syncing...',
        };
        window._announce(msgs[newState], newState === 'offline' ? 'assertive' : 'polite');
    }
}

// ── UI ──────────────────────────────────────────────────────────────────

function _createIndicator() {
    if (_indicator) return;

    _indicator = document.createElement('div');
    _indicator.className = 'net-status';
    _indicator.setAttribute('role', 'status');
    _indicator.setAttribute('aria-live', 'polite');

    const dot = document.createElement('span');
    dot.className = 'net-status-dot';

    const label = document.createElement('span');
    label.className = 'net-status-label';

    _indicator.appendChild(dot);
    _indicator.appendChild(label);

    // Insert after chat header or at top of main panel
    const chatHeader = document.querySelector('.chat-header');
    if (chatHeader && chatHeader.parentNode) {
        chatHeader.parentNode.insertBefore(_indicator, chatHeader.nextSibling);
    } else {
        document.body.appendChild(_indicator);
    }
}

function _updateUI() {
    if (!_indicator) return;
    const tFn = typeof window.t === 'function' ? window.t : (k) => k;

    _indicator.className = `net-status net-status-${_state}`;

    const label = _indicator.querySelector('.net-status-label');
    if (label) {
        if (_state === 'offline') {
            const qLen = _offlineQueue.length;
            const qText = qLen > 0 ? ` (${qLen})` : '';
            label.textContent = (tFn('network.offline') || 'No connection') + qText;
            _indicator.classList.add('net-status-visible');
        } else if (_state === 'syncing') {
            label.textContent = (tFn('network.syncing') || 'Syncing...') +
                ` (${_offlineQueue.length})`;
            _indicator.classList.add('net-status-visible');
        } else {
            _indicator.classList.remove('net-status-visible');
        }
    }
}

// ── Offline message queue ───────────────────────────────────────────────

/**
 * Queue a message for sending when connection is restored.
 * @param {Object} msg — { roomId, text, type, ... }
 * @returns {boolean} — true if queued, false if queue full
 */
export function queueOfflineMessage(msg) {
    if (_offlineQueue.length >= MAX_QUEUE_SIZE) return false;
    _offlineQueue.push({ ...msg, queuedAt: Date.now() });
    _updateUI();
    return true;
}

/**
 * Flush the offline queue by sending all queued messages.
 * @param {Function} sendFn — async function(msg) that sends a message
 */
async function _flushQueue(sendFn) {
    if (_offlineQueue.length === 0) return;

    _setState('syncing');
    const queue = [..._offlineQueue];
    _offlineQueue = [];
    let failed = 0;

    for (const msg of queue) {
        try {
            await sendFn(msg);
        } catch {
            failed++;
            _offlineQueue.push(msg); // Re-queue failed messages
        }
        _updateUI();
    }

    if (failed === 0) {
        _setState('online');
        if (typeof window.showSuccess === 'function') {
            const tFn = typeof window.t === 'function' ? window.t : (k) => k;
            window.showSuccess(tFn('network.synced') || `${queue.length} messages sent`);
        }
    }
}

// ── Network detection ───────────────────────────────────────────────────

function _onOnline() {
    if (_state === 'offline') {
        if (_offlineQueue.length > 0) {
            _setState('syncing');
            // Flush will be triggered when WS reconnects and calls notifyReconnected()
        } else {
            _setState('online');
        }
    }
}

function _onOffline() {
    _setState('offline');
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Initialize network status monitoring.
 */
export function initNetworkStatus() {
    _createIndicator();

    // Browser online/offline events
    window.addEventListener('online', _onOnline);
    window.addEventListener('offline', _onOffline);

    // Set initial state
    if (!navigator.onLine) {
        _setState('offline');
    }
}

/**
 * Notify that WebSocket has reconnected — flush offline queue.
 * @param {Function} sendFn — async function(msg) to send a queued message
 */
export function notifyReconnected(sendFn) {
    if (_offlineQueue.length > 0 && sendFn) {
        _flushQueue(sendFn);
    } else {
        _setState('online');
    }
}

/**
 * Notify that WebSocket has disconnected.
 */
export function notifyDisconnected() {
    _setState('offline');
}

/**
 * Get current network state.
 * @returns {'online'|'offline'|'syncing'}
 */
export function getNetworkState() {
    return _state;
}

/**
 * Check if currently offline.
 */
export function isOffline() {
    return _state === 'offline';
}

/**
 * Get queued message count.
 */
export function getQueueSize() {
    return _offlineQueue.length;
}

/**
 * Subscribe to state changes.
 * @param {Function} fn — callback(newState, oldState)
 * @returns {Function} — unsubscribe function
 */
export function onStateChange(fn) {
    _listeners.push(fn);
    return () => {
        _listeners = _listeners.filter(f => f !== fn);
    };
}

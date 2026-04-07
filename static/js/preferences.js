/**
 * static/js/preferences.js — User preference persistence.
 *
 * Persists user preferences in localStorage with structured keys:
 *   - Font size (accessibility)
 *   - Sidebar collapsed state
 *   - Last active room per session
 *   - Scroll position per room
 *   - Message density (compact/default/cozy)
 *   - Notification sound preference
 *   - Gesture preference (on/off)
 *
 * All preferences survive page reload and browser restart.
 * Accessible via keyboard shortcut (Ctrl+, opens settings with these options).
 */

const STORAGE_PREFIX = 'vortex_pref_';
const SCROLL_PREFIX = 'vortex_scroll_';
const MAX_SCROLL_ENTRIES = 50;

// Defaults
const DEFAULTS = {
    fontSize: 14,           // px (range: 12–20)
    messageDensity: 'default',  // 'compact' | 'default' | 'cozy'
    sidebarCollapsed: false,
    lastRoomId: null,
    enterToSend: true,
    notifSound: true,
    gesturesEnabled: true,
    animationsEnabled: true,
    autoPlayMedia: true,
    showAvatars: true,
};

// ── Core get/set ────────────────────────────────────────────────────────

function _get(key) {
    try {
        const raw = localStorage.getItem(STORAGE_PREFIX + key);
        return raw !== null ? JSON.parse(raw) : undefined;
    } catch {
        return undefined;
    }
}

function _set(key, value) {
    try {
        localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(value));
    } catch { /* quota exceeded — fail silently */ }
}

function _remove(key) {
    try { localStorage.removeItem(STORAGE_PREFIX + key); } catch {}
}

// ── Preferences API ─────────────────────────────────────────────────────

/**
 * Get a preference value with fallback to default.
 */
export function getPref(key) {
    const val = _get(key);
    return val !== undefined ? val : DEFAULTS[key];
}

/**
 * Set a preference value and apply immediately.
 */
export function setPref(key, value) {
    _set(key, value);
    _applyPref(key, value);
}

/**
 * Reset all preferences to defaults.
 */
export function resetPrefs() {
    Object.keys(DEFAULTS).forEach(key => _remove(key));
    applyAllPrefs();
}

// ── Font Size ───────────────────────────────────────────────────────────

/**
 * Get current font size (12–20px).
 */
export function getFontSize() { return getPref('fontSize'); }

/**
 * Set font size and apply to document.
 */
export function setFontSize(size) {
    const clamped = Math.max(12, Math.min(20, Math.round(size)));
    setPref('fontSize', clamped);
}

/**
 * Increase font size by 1px.
 */
export function increaseFontSize() { setFontSize(getFontSize() + 1); }

/**
 * Decrease font size by 1px.
 */
export function decreaseFontSize() { setFontSize(getFontSize() - 1); }

// ── Message Density ─────────────────────────────────────────────────────

export function getMessageDensity() { return getPref('messageDensity'); }

export function setMessageDensity(density) {
    if (['compact', 'default', 'cozy'].includes(density)) {
        setPref('messageDensity', density);
    }
}

// ── Scroll Position (per room) ──────────────────────────────────────────

/**
 * Save scroll position for a room.
 */
export function saveScrollPosition(roomId, position) {
    if (!roomId) return;
    try {
        const data = JSON.parse(localStorage.getItem(SCROLL_PREFIX + 'data') || '{}');
        data[roomId] = { pos: position, ts: Date.now() };

        // Evict oldest entries if over limit
        const keys = Object.keys(data);
        if (keys.length > MAX_SCROLL_ENTRIES) {
            keys.sort((a, b) => data[a].ts - data[b].ts);
            keys.slice(0, keys.length - MAX_SCROLL_ENTRIES).forEach(k => delete data[k]);
        }

        localStorage.setItem(SCROLL_PREFIX + 'data', JSON.stringify(data));
    } catch {}
}

/**
 * Restore scroll position for a room.
 */
export function getScrollPosition(roomId) {
    if (!roomId) return null;
    try {
        const data = JSON.parse(localStorage.getItem(SCROLL_PREFIX + 'data') || '{}');
        return data[roomId]?.pos ?? null;
    } catch {
        return null;
    }
}

// ── Last Active Room ────────────────────────────────────────────────────

export function getLastRoom() { return getPref('lastRoomId'); }
export function setLastRoom(roomId) { setPref('lastRoomId', roomId); }

// ── Apply preferences to DOM ────────────────────────────────────────────

function _applyPref(key, value) {
    switch (key) {
        case 'fontSize':
            document.documentElement.style.setProperty('--user-font-size', value + 'px');
            // Apply to message bubbles and input
            document.documentElement.style.setProperty('--msg-font-size', value + 'px');
            break;

        case 'messageDensity':
            document.body.dataset.density = value;
            break;

        case 'sidebarCollapsed': {
            const sb = document.getElementById('sidebar');
            if (sb) sb.classList.toggle('collapsed', !!value);
            break;
        }

        case 'animationsEnabled':
            document.body.classList.toggle('no-animations', !value);
            break;

        case 'showAvatars':
            document.body.classList.toggle('hide-avatars', !value);
            break;

        case 'gesturesEnabled':
            if (typeof window.setGesturesEnabled === 'function') {
                window.setGesturesEnabled(value);
            }
            break;
    }
}

/**
 * Apply all saved preferences on startup.
 */
export function applyAllPrefs() {
    Object.keys(DEFAULTS).forEach(key => {
        const val = getPref(key);
        _applyPref(key, val);
    });
}

// ── Initialize ──────────────────────────────────────────────────────────

/**
 * Initialize preference system — apply saved prefs and set up listeners.
 */
export function initPreferences() {
    applyAllPrefs();

    // Listen for Ctrl+= / Ctrl+- for font size
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey) {
            if (e.key === '=' || e.key === '+') {
                e.preventDefault();
                increaseFontSize();
            } else if (e.key === '-') {
                e.preventDefault();
                decreaseFontSize();
            } else if (e.key === '0') {
                e.preventDefault();
                setFontSize(DEFAULTS.fontSize);
            }
        }
    });

    // Save scroll position on room switch
    const chatArea = document.getElementById('messages') || document.getElementById('chat-messages');
    if (chatArea) {
        let scrollTimer = null;
        chatArea.addEventListener('scroll', () => {
            if (scrollTimer) clearTimeout(scrollTimer);
            scrollTimer = setTimeout(() => {
                const roomId = window.AppState?.currentRoom?.id;
                if (roomId) saveScrollPosition(roomId, chatArea.scrollTop);
            }, 300);
        }, { passive: true });
    }
}

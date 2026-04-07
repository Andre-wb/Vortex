/**
 * static/js/gestures.js — Mobile gesture support.
 *
 * Gestures:
 *   - Swipe right on message → reply
 *   - Swipe left on sidebar → close sidebar
 *   - Swipe right from edge → open sidebar
 *   - Pull-to-refresh on chat → load older messages
 *   - Long press on message → context menu
 *   - Pinch-to-zoom on images
 *   - Double-tap message → react with default emoji
 */

const SWIPE_THRESHOLD = 50;      // px minimum for swipe detection
const SWIPE_MAX_TIME = 300;      // ms max for a swipe gesture
const LONG_PRESS_MS = 500;       // ms for long press
const EDGE_ZONE = 20;            // px from screen edge for edge swipe
const PULL_THRESHOLD = 80;       // px for pull-to-refresh trigger

let _touchStartX = 0, _touchStartY = 0, _touchStartTime = 0;
let _longPressTimer = null;
let _isPinching = false;
let _initialPinchDist = 0;
let _gesturesEnabled = true;

// ── Edge swipe (sidebar) ─────────────────────────────────────────────

function _initEdgeSwipe() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    document.addEventListener('touchstart', (e) => {
        if (!_gesturesEnabled) return;
        const touch = e.touches[0];
        if (touch.clientX < EDGE_ZONE) {
            _touchStartX = touch.clientX;
            _touchStartY = touch.clientY;
            _touchStartTime = Date.now();
        }
    }, { passive: true });

    document.addEventListener('touchend', (e) => {
        if (!_gesturesEnabled || !_touchStartTime) return;
        const touch = e.changedTouches[0];
        const dx = touch.clientX - _touchStartX;
        const dy = Math.abs(touch.clientY - _touchStartY);
        const dt = Date.now() - _touchStartTime;

        if (dx > SWIPE_THRESHOLD && dy < dx && dt < SWIPE_MAX_TIME && _touchStartX < EDGE_ZONE) {
            // На мобильном: вернуться к списку чатов
            document.body.classList.remove('mobile-chat-open');
        }
        _touchStartTime = 0;
    }, { passive: true });
}

// ── Message swipe-to-reply ───────────────────────────────────────────

function _initMessageSwipe() {
    const chatArea = document.getElementById('messages') || document.getElementById('chat-messages');
    if (!chatArea) return;

    let swipeTarget = null;
    let startX = 0, startY = 0, currentX = 0;
    let swiping = false;

    chatArea.addEventListener('touchstart', (e) => {
        if (!_gesturesEnabled) return;
        const msg = e.target.closest('.message, .chat-message');
        if (!msg) return;
        swipeTarget = msg;
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
        swiping = false;
    }, { passive: true });

    chatArea.addEventListener('touchmove', (e) => {
        if (!swipeTarget || !_gesturesEnabled) return;
        const touch = e.touches[0];
        const dx = touch.clientX - startX;
        const dy = Math.abs(touch.clientY - startY);

        if (!swiping && dx > 10 && dy < dx) {
            swiping = true;
        }
        if (swiping) {
            currentX = Math.max(0, Math.min(dx, 100));
            swipeTarget.style.transform = `translateX(${currentX}px)`;
            swipeTarget.style.transition = 'none';

            // Show reply indicator
            if (currentX > SWIPE_THRESHOLD) {
                swipeTarget.classList.add('swipe-reply-hint');
            } else {
                swipeTarget.classList.remove('swipe-reply-hint');
            }
        }
    }, { passive: true });

    chatArea.addEventListener('touchend', () => {
        if (!swipeTarget) return;
        swipeTarget.style.transition = 'transform 0.2s ease';
        swipeTarget.style.transform = '';
        swipeTarget.classList.remove('swipe-reply-hint');

        if (swiping && currentX > SWIPE_THRESHOLD) {
            // Trigger reply
            const msgId = swipeTarget.dataset.messageId || swipeTarget.dataset.id;
            if (msgId && typeof window.replyToMessage === 'function') {
                window.replyToMessage(parseInt(msgId));
            }
        }

        swipeTarget = null;
        swiping = false;
        currentX = 0;
    }, { passive: true });
}

// ── Long press context menu ──────────────────────────────────────────

function _initLongPress() {
    const chatArea = document.getElementById('messages') || document.getElementById('chat-messages');
    if (!chatArea) return;

    chatArea.addEventListener('touchstart', (e) => {
        if (!_gesturesEnabled) return;
        const msg = e.target.closest('.message, .chat-message');
        if (!msg) return;

        _longPressTimer = setTimeout(() => {
            // Haptic feedback if available
            if (navigator.vibrate) navigator.vibrate(30);

            const msgId = msg.dataset.messageId || msg.dataset.id;
            if (msgId && typeof window.showMessageContextMenu === 'function') {
                const rect = msg.getBoundingClientRect();
                window.showMessageContextMenu(parseInt(msgId), rect.left + rect.width / 2, rect.top);
            }
        }, LONG_PRESS_MS);
    }, { passive: true });

    chatArea.addEventListener('touchmove', () => {
        if (_longPressTimer) {
            clearTimeout(_longPressTimer);
            _longPressTimer = null;
        }
    }, { passive: true });

    chatArea.addEventListener('touchend', () => {
        if (_longPressTimer) {
            clearTimeout(_longPressTimer);
            _longPressTimer = null;
        }
    }, { passive: true });
}

// ── Double tap to react ──────────────────────────────────────────────

function _initDoubleTap() {
    const chatArea = document.getElementById('messages') || document.getElementById('chat-messages');
    if (!chatArea) return;

    let lastTap = 0;
    let lastTarget = null;

    chatArea.addEventListener('touchend', (e) => {
        if (!_gesturesEnabled) return;
        const msg = e.target.closest('.message, .chat-message');
        if (!msg) return;

        const now = Date.now();
        if (now - lastTap < 300 && lastTarget === msg) {
            // Double tap — react with ❤️
            const msgId = msg.dataset.messageId || msg.dataset.id;
            if (msgId && typeof window.toggleReaction === 'function') {
                window.toggleReaction(parseInt(msgId), '❤️');
                if (navigator.vibrate) navigator.vibrate(15);
            }
            lastTap = 0;
            lastTarget = null;
        } else {
            lastTap = now;
            lastTarget = msg;
        }
    }, { passive: true });
}

// ── Pinch to zoom images ─────────────────────────────────────────────

function _initPinchZoom() {
    document.addEventListener('touchstart', (e) => {
        if (!_gesturesEnabled || e.touches.length !== 2) return;
        const img = e.target.closest('img.chat-image, img.media-image, .image-viewer img');
        if (!img) return;

        _isPinching = true;
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        _initialPinchDist = Math.sqrt(dx * dx + dy * dy);
    }, { passive: true });

    document.addEventListener('touchmove', (e) => {
        if (!_isPinching || e.touches.length !== 2) return;
        const img = e.target.closest('img.chat-image, img.media-image, .image-viewer img');
        if (!img) return;

        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const scale = Math.max(1, Math.min(dist / _initialPinchDist, 4));

        img.style.transform = `scale(${scale})`;
        img.style.transition = 'none';
    }, { passive: true });

    document.addEventListener('touchend', () => {
        if (!_isPinching) return;
        _isPinching = false;
        document.querySelectorAll('img.chat-image, img.media-image, .image-viewer img').forEach(img => {
            img.style.transition = 'transform 0.3s ease';
            img.style.transform = '';
        });
    }, { passive: true });
}

// ── Pull to refresh (load older messages) ────────────────────────────

function _initPullToRefresh() {
    const chatArea = document.getElementById('messages') || document.getElementById('chat-messages');
    if (!chatArea) return;

    let startY = 0;
    let pulling = false;
    let indicator = null;

    chatArea.addEventListener('touchstart', (e) => {
        if (!_gesturesEnabled || chatArea.scrollTop > 5) return;
        startY = e.touches[0].clientY;
        pulling = true;
    }, { passive: true });

    chatArea.addEventListener('touchmove', (e) => {
        if (!pulling || !_gesturesEnabled) return;
        const dy = e.touches[0].clientY - startY;
        if (dy > 10 && chatArea.scrollTop <= 0) {
            if (!indicator) {
                indicator = document.createElement('div');
                indicator.className = 'pull-refresh-indicator';
                const tFn = typeof window.t === 'function' ? window.t : (k) => k;
                indicator.textContent = dy > PULL_THRESHOLD
                    ? (tFn('gestures.release') || 'Release to refresh')
                    : (tFn('gestures.pull') || 'Pull to refresh');
                chatArea.parentElement.insertBefore(indicator, chatArea);
            }
            const tFn = typeof window.t === 'function' ? window.t : (k) => k;
            indicator.textContent = dy > PULL_THRESHOLD
                ? (tFn('gestures.release') || 'Release to refresh')
                : (tFn('gestures.pull') || 'Pull to refresh');
            indicator.style.height = Math.min(dy * 0.5, 50) + 'px';
            indicator.style.opacity = Math.min(dy / PULL_THRESHOLD, 1);
        }
    }, { passive: true });

    chatArea.addEventListener('touchend', (e) => {
        if (!pulling) return;
        pulling = false;

        if (indicator) {
            const dy = parseFloat(indicator.style.height);
            indicator.remove();
            indicator = null;

            if (dy >= PULL_THRESHOLD * 0.5 && typeof window.loadOlderMessages === 'function') {
                window.loadOlderMessages();
            }
        }
    }, { passive: true });
}

// ── Public API ───────────────────────────────────────────────────────

export function initGestures() {
    if (!('ontouchstart' in window)) return; // Desktop — skip

    _initEdgeSwipe();
    _initMessageSwipe();
    _initLongPress();
    _initDoubleTap();
    _initPinchZoom();
    _initPullToRefresh();

    logger('Gestures initialized');
}

export function setGesturesEnabled(enabled) {
    _gesturesEnabled = enabled;
}

export function isGesturesEnabled() {
    return _gesturesEnabled;
}

function logger(msg) {
    if (typeof console !== 'undefined') console.debug('[gestures]', msg);
}

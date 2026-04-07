/**
 * static/js/toast.js — Universal toast notification system.
 *
 * Features:
 *   - 4 types: success, error, warning, info
 *   - Auto-dismiss (configurable per-type)
 *   - Action buttons: undo, retry, custom
 *   - Stack management (max 5 visible)
 *   - Swipe-to-dismiss on mobile
 *   - Screen reader announcements (aria-live)
 *   - Respects prefers-reduced-motion
 *   - i18n-aware (uses t() for built-in labels)
 *
 * Usage:
 *   showToast('Message sent', 'success');
 *   showToast('Network error', 'error', { retry: () => resend() });
 *   showToast('Message deleted', 'info', { undo: () => restore(id), duration: 6000 });
 */

const MAX_TOASTS = 5;
const DEFAULT_DURATIONS = {
    success: 3000,
    info: 4000,
    warning: 5000,
    error: 7000,
};

let _container = null;
let _toastId = 0;
const _activeToasts = [];

function _ensureContainer() {
    if (_container) return _container;
    _container = document.createElement('div');
    _container.className = 'toast-container';
    _container.setAttribute('role', 'status');
    _container.setAttribute('aria-live', 'polite');
    _container.setAttribute('aria-atomic', 'false');
    document.body.appendChild(_container);
    return _container;
}

function _createIcon(type) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2.5');
    svg.setAttribute('stroke-linecap', 'round');

    const paths = {
        success: ['M20 6L9 17l-5-5'],
        error: ['M12 12m-10 0a10 10 0 1020 0a10 10 0 10-20 0', 'M15 9l-6 6', 'M9 9l6 6'],
        warning: ['M12 9v4', 'M12 17h.01', 'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z'],
        info: ['M12 12m-10 0a10 10 0 1020 0a10 10 0 10-20 0', 'M12 16v-4', 'M12 8h.01'],
    };

    (paths[type] || paths.info).forEach(d => {
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
    });

    return svg;
}

/**
 * Show a toast notification.
 *
 * @param {string} message — text to display
 * @param {'success'|'error'|'warning'|'info'} type — toast type
 * @param {Object} [opts] — options
 * @param {number} [opts.duration] — auto-dismiss ms (0 = manual dismiss)
 * @param {Function} [opts.undo] — undo callback (adds Undo button)
 * @param {Function} [opts.retry] — retry callback (adds Retry button)
 * @param {string} [opts.actionLabel] — custom action label
 * @param {Function} [opts.action] — custom action callback
 * @returns {number} — toast ID for manual dismissal
 */
export function showToast(message, type = 'info', opts = {}) {
    const container = _ensureContainer();
    const id = ++_toastId;
    const duration = opts.duration ?? DEFAULT_DURATIONS[type] ?? 4000;
    const tFn = typeof window.t === 'function' ? window.t : (k) => k;

    // Build toast element safely (no innerHTML)
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.dataset.toastId = id;
    el.setAttribute('role', type === 'error' ? 'alert' : 'status');

    // Icon
    const iconSpan = document.createElement('span');
    iconSpan.className = 'toast-icon';
    iconSpan.appendChild(_createIcon(type));
    el.appendChild(iconSpan);

    // Message
    const msgSpan = document.createElement('span');
    msgSpan.className = 'toast-message';
    msgSpan.textContent = message;
    el.appendChild(msgSpan);

    // Action buttons
    const hasActions = opts.undo || opts.retry || (opts.action && opts.actionLabel);
    if (hasActions) {
        const actionsSpan = document.createElement('span');
        actionsSpan.className = 'toast-actions';

        if (opts.undo) {
            const btn = document.createElement('button');
            btn.className = 'toast-action toast-undo';
            btn.textContent = tFn('toast.undo') || 'Undo';
            btn.addEventListener('click', () => { opts.undo(); dismissToast(id); });
            actionsSpan.appendChild(btn);
        }
        if (opts.retry) {
            const btn = document.createElement('button');
            btn.className = 'toast-action toast-retry';
            btn.textContent = tFn('toast.retry') || 'Retry';
            btn.addEventListener('click', () => { dismissToast(id); opts.retry(); });
            actionsSpan.appendChild(btn);
        }
        if (opts.action && opts.actionLabel) {
            const btn = document.createElement('button');
            btn.className = 'toast-action';
            btn.textContent = opts.actionLabel;
            btn.addEventListener('click', () => { opts.action(); dismissToast(id); });
            actionsSpan.appendChild(btn);
        }

        el.appendChild(actionsSpan);
    }

    // Close button
    const closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.setAttribute('aria-label', tFn('toast.close') || 'Close');
    closeBtn.textContent = '\u00D7';
    closeBtn.addEventListener('click', () => dismissToast(id));
    el.appendChild(closeBtn);

    // Progress bar
    let bar = null;
    if (duration > 0) {
        const progress = document.createElement('div');
        progress.className = 'toast-progress';
        bar = document.createElement('div');
        bar.className = 'toast-progress-bar';
        progress.appendChild(bar);
        el.appendChild(progress);
    }

    // Swipe-to-dismiss on mobile
    _initSwipeDismiss(el, id);

    // Add to DOM
    container.appendChild(el);

    // Trigger entrance animation
    requestAnimationFrame(() => el.classList.add('toast-show'));

    // Progress bar animation
    if (bar) {
        bar.style.transition = `width ${duration}ms linear`;
        requestAnimationFrame(() => {
            requestAnimationFrame(() => { bar.style.width = '0%'; });
        });
    }

    // Track
    const entry = { id, el, timer: null };
    if (duration > 0) {
        entry.timer = setTimeout(() => dismissToast(id), duration);
    }
    _activeToasts.push(entry);

    // Enforce max visible
    while (_activeToasts.length > MAX_TOASTS) {
        dismissToast(_activeToasts[0].id);
    }

    // Screen reader announcement
    if (typeof window._announce === 'function') {
        window._announce(message, type === 'error' ? 'assertive' : 'polite');
    }

    return id;
}

/**
 * Dismiss a toast by ID.
 */
export function dismissToast(id) {
    const idx = _activeToasts.findIndex(t => t.id === id);
    if (idx === -1) return;

    const entry = _activeToasts[idx];
    if (entry.timer) clearTimeout(entry.timer);

    entry.el.classList.remove('toast-show');
    entry.el.classList.add('toast-hide');

    entry.el.addEventListener('animationend', () => {
        entry.el.remove();
    }, { once: true });

    // Fallback removal
    setTimeout(() => { if (entry.el.parentNode) entry.el.remove(); }, 400);
    _activeToasts.splice(idx, 1);
}

/**
 * Dismiss all active toasts.
 */
export function dismissAllToasts() {
    [..._activeToasts].forEach(e => dismissToast(e.id));
}

// Convenience wrappers
export function showSuccess(msg, opts) { return showToast(msg, 'success', opts); }
export function showError(msg, opts) { return showToast(msg, 'error', opts); }
export function showWarning(msg, opts) { return showToast(msg, 'warning', opts); }
export function showInfo(msg, opts) { return showToast(msg, 'info', opts); }

// ── Swipe-to-dismiss ────────────────────────────────────────────────────

function _initSwipeDismiss(el, id) {
    let startX = 0, currentX = 0, swiping = false;

    el.addEventListener('touchstart', (e) => {
        startX = e.touches[0].clientX;
        swiping = true;
    }, { passive: true });

    el.addEventListener('touchmove', (e) => {
        if (!swiping) return;
        currentX = e.touches[0].clientX - startX;
        if (Math.abs(currentX) > 10) {
            el.style.transform = `translateX(${currentX}px)`;
            el.style.opacity = String(Math.max(0, 1 - Math.abs(currentX) / 200));
            el.style.transition = 'none';
        }
    }, { passive: true });

    el.addEventListener('touchend', () => {
        if (!swiping) return;
        swiping = false;
        if (Math.abs(currentX) > 80) {
            dismissToast(id);
        } else {
            el.style.transition = 'transform 0.2s ease, opacity 0.2s ease';
            el.style.transform = '';
            el.style.opacity = '';
        }
        currentX = 0;
    }, { passive: true });
}

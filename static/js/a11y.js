/**
 * Vortex Accessibility (a11y) Utilities
 *
 * - Focus trap for modals (Tab cycles within modal)
 * - Screen reader announcements (aria-live)
 * - Escape key to close modals
 * - Focus restoration on modal close
 * - Keyboard navigation for room list
 */

let _lastFocusedElement = null;
let _activeTrap = null;

// ── Focus Trap for Modals ───────────────────────────────────────────────────

/**
 * Activate focus trap inside a modal element.
 * Tab/Shift+Tab cycle through focusable elements within the modal.
 * @param {HTMLElement} modalEl — the modal container
 */
export function trapFocus(modalEl) {
    if (!modalEl) return;
    _lastFocusedElement = document.activeElement;
    _activeTrap = modalEl;

    // Focus first focusable element
    requestAnimationFrame(() => {
        const first = _getFocusable(modalEl)[0];
        if (first) first.focus();
    });

    modalEl.addEventListener('keydown', _trapHandler);
}

/**
 * Release focus trap and restore focus to the element that was focused before.
 */
export function releaseFocus() {
    if (_activeTrap) {
        _activeTrap.removeEventListener('keydown', _trapHandler);
        _activeTrap = null;
    }
    if (_lastFocusedElement && _lastFocusedElement.focus) {
        _lastFocusedElement.focus();
        _lastFocusedElement = null;
    }
}

function _trapHandler(e) {
    if (e.key !== 'Tab') return;

    const focusable = _getFocusable(_activeTrap);
    if (!focusable.length) return;

    const first = focusable[0];
    const last  = focusable[focusable.length - 1];

    if (e.shiftKey) {
        // Shift+Tab: if at first element, wrap to last
        if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
        }
    } else {
        // Tab: if at last element, wrap to first
        if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    }
}

function _getFocusable(container) {
    const selector = [
        'a[href]',
        'button:not([disabled])',
        'input:not([disabled]):not([type="hidden"])',
        'textarea:not([disabled])',
        'select:not([disabled])',
        '[tabindex]:not([tabindex="-1"])',
    ].join(',');
    return Array.from(container.querySelectorAll(selector))
        .filter(el => el.offsetParent !== null); // visible only
}


// ── Screen Reader Announcements ─────────────────────────────────────────────

let _announceEl = null;

/**
 * Announce a message to screen readers via aria-live region.
 * @param {string} message — text to announce
 * @param {'polite'|'assertive'} priority — urgency
 */
export function announce(message, priority = 'polite') {
    if (!_announceEl) {
        _announceEl = document.createElement('div');
        _announceEl.id = 'a11y-announcer';
        _announceEl.setAttribute('role', 'status');
        _announceEl.setAttribute('aria-live', priority);
        _announceEl.setAttribute('aria-atomic', 'true');
        _announceEl.style.cssText =
            'position:absolute;width:1px;height:1px;overflow:hidden;' +
            'clip:rect(0,0,0,0);white-space:nowrap;border:0;';
        document.body.appendChild(_announceEl);
    }

    _announceEl.setAttribute('aria-live', priority);
    // Clear then set (forces re-announcement)
    _announceEl.textContent = '';
    requestAnimationFrame(() => {
        _announceEl.textContent = message;
    });
}


// ── Modal open/close helpers with a11y ──────────────────────────────────────

/**
 * Open a modal with proper a11y: set aria-hidden on main, trap focus.
 * @param {string} modalId
 */
export function openModalA11y(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;

    // Hide main content from screen readers
    const app = document.getElementById('app');
    if (app) app.setAttribute('aria-hidden', 'true');

    modal.style.display = 'flex';
    modal.setAttribute('aria-hidden', 'false');

    trapFocus(modal);
    announce(t('a11y.modalOpened'));
}

/**
 * Close a modal with proper a11y: remove aria-hidden, release focus.
 * @param {string} modalId
 */
export function closeModalA11y(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;

    modal.style.display = 'none';
    modal.setAttribute('aria-hidden', 'true');

    // Restore main content
    const app = document.getElementById('app');
    if (app) app.removeAttribute('aria-hidden');

    releaseFocus();
}


// ── Keyboard navigation for room list ───────────────────────────────────────

export function initRoomListKeyboard() {
    const roomsList = document.getElementById('rooms-list');
    if (!roomsList) return;

    roomsList.addEventListener('keydown', (e) => {
        const items = roomsList.querySelectorAll('.room-item');
        if (!items.length) return;

        const active = document.activeElement;
        const idx = Array.from(items).indexOf(active);

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            const next = idx < items.length - 1 ? idx + 1 : 0;
            items[next].focus();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const prev = idx > 0 ? idx - 1 : items.length - 1;
            items[prev].focus();
        } else if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            active?.click();
        }
    });
}


// ── Initialize a11y features ────────────────────────────────────────────────

export function initA11y() {
    // Room list keyboard navigation
    initRoomListKeyboard();

    // Global Escape handler for modals (supplement existing handlers)
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && _activeTrap) {
            // Find the modal overlay and close it
            const overlay = _activeTrap.closest('.modal-overlay') || _activeTrap;
            if (overlay && overlay.style.display !== 'none') {
                overlay.style.display = 'none';
                overlay.setAttribute('aria-hidden', 'true');
                const app = document.getElementById('app');
                if (app) app.removeAttribute('aria-hidden');
                releaseFocus();
            }
        }
    });

    // Announce page ready
    requestAnimationFrame(() => announce(t('a11y.appLoaded')));
}

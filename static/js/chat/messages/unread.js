// =========================================================================
// Unread divider & jump-to-unread button
// =========================================================================

let _unreadObserver = null;

/**
 * Inserts the unread divider before the first unread message and shows the
 * jump-to-unread floating button.
 *
 * @param {number} unreadCount - number of unread messages from the end of history
 */
export function insertUnreadDivider(unreadCount) {
    cleanupUnreadDivider();
    if (!unreadCount || unreadCount <= 0) return;

    const container = document.getElementById('messages-container');
    if (!container) return;

    const children = Array.from(container.children);
    const total = children.length;
    if (total === 0) return;

    // The divider goes before the (total - unreadCount)-th child
    const insertBefore = Math.max(0, total - unreadCount);
    const refNode = children[insertBefore] || null;

    // Build divider
    const divider = document.createElement('div');
    divider.className = 'unread-divider';
    divider.id = 'unread-divider';
    divider.innerHTML = `<span>${unreadCount} ${unreadCount === 1 ? 'новое сообщение' : unreadCount < 5 ? 'новых сообщения' : 'новых сообщений'}</span>`;

    if (refNode) {
        container.insertBefore(divider, refNode);
    } else {
        container.appendChild(divider);
    }

    // Build jump button
    const btn = document.createElement('button');
    btn.id = 'jump-unread-btn';
    btn.className = 'jump-unread-btn';
    btn.innerHTML = `↓ ${unreadCount} новых`;
    btn.setAttribute('onclick', 'jumpToUnread()');

    // Insert into the chat-screen (parent of messages-container)
    const chatScreen = document.getElementById('chat-screen');
    if (chatScreen) chatScreen.appendChild(btn);

    // IntersectionObserver: hide button when divider is visible
    _unreadObserver = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                _hideJumpButton();
            }
        });
    }, { root: container, threshold: 0.1 });

    _unreadObserver.observe(divider);
}

function _hideJumpButton() {
    const btn = document.getElementById('jump-unread-btn');
    if (btn) btn.remove();
    if (_unreadObserver) {
        _unreadObserver.disconnect();
        _unreadObserver = null;
    }
}

/**
 * Removes the unread divider and the jump button. Called on room switch.
 */
export function cleanupUnreadDivider() {
    const divider = document.getElementById('unread-divider');
    if (divider) divider.remove();
    _hideJumpButton();
}

/**
 * Scrolls to the unread divider smoothly and hides the jump button.
 * Exposed as window.jumpToUnread for inline onclick.
 */
export function jumpToUnread() {
    const divider = document.getElementById('unread-divider');
    if (divider) {
        divider.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    _hideJumpButton();
}

// Expose globally for inline onclick handlers
window.jumpToUnread = jumpToUnread;

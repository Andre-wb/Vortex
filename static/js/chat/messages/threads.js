import { _msgElements } from './shared.js';

// =============================================================================
// Треды — badge и helpers
// =============================================================================

export function _pluralReplies(n) {
    const mod10 = n % 10;
    const mod100 = n % 100;
    if (n === 1) return `${n} reply`;
    return `${n} replies`;
}

/**
 * Обновляет или создаёт badge с количеством ответов в треде.
 *
 * @param {number|string} msgId
 * @param {number} threadCount
 */
export function updateThreadBadge(msgId, threadCount) {
    const group = _msgElements.get(msgId) || document.querySelector(`[data-msg-id="${msgId}"]`);
    if (!group) return;

    let badge = document.getElementById(`thread-badge-${msgId}`);
    if (threadCount > 0) {
        if (!badge) {
            badge = document.createElement('div');
            badge.className = 'thread-badge';
            badge.id = `thread-badge-${msgId}`;
            badge.addEventListener('click', (e) => {
                e.stopPropagation();
                window.openThread(msgId);
            });
            group.appendChild(badge);
        }
        badge.textContent = _pluralReplies(threadCount);
    } else if (badge) {
        badge.remove();
    }
}

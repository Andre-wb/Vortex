import { esc } from '../../utils.js';

// ══════════════════════════════════════════════════════════════════════════════
// Reaction "who reacted" popover
// ══════════════════════════════════════════════════════════════════════════════

function _fmtReactionTime(iso) {
    if (!iso) return '';
    try {
        const d = new Date(iso);
        return d.toLocaleString('ru', {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', second:'2-digit'});
    } catch { return iso; }
}

function _showReactionWhoPopover(btn) {
    document.getElementById('reaction-who-popover')?.remove();
    const users = JSON.parse(btn.dataset.users || '[]');
    const emoji = btn.dataset.emoji || '';
    if (!users.length) return;

    const pop = document.createElement('div');
    pop.id = 'reaction-who-popover';
    pop.className = 'reaction-who-popover';
    pop.innerHTML = `
        <div class="rwp-header">${emoji} Реакции</div>
        <div class="rwp-list">
            ${users.map(u => `
                <div class="rwp-user" title="${_fmtReactionTime(u.created_at)}">
                    <span class="rwp-name">${esc(u.display_name)}</span>
                    <span class="rwp-time">${_fmtReactionTime(u.created_at)}</span>
                </div>
            `).join('')}
        </div>`;
    document.body.appendChild(pop);

    const rect = btn.getBoundingClientRect();
    const popH = pop.offsetHeight || 120;
    const top = rect.top - popH - 8 < 0 ? rect.bottom + 8 : rect.top - popH - 8;
    pop.style.top  = `${top + window.scrollY}px`;
    pop.style.left = `${Math.min(rect.left, window.innerWidth - pop.offsetWidth - 8)}px`;
    pop.classList.add('open');

    const close = e => { if (!pop.contains(e.target) && e.target !== btn) { pop.remove(); document.removeEventListener('click', close); document.removeEventListener('touchstart', close); } };
    setTimeout(() => { document.addEventListener('click', close); document.addEventListener('touchstart', close); }, 100);
}

export function _attachReactionLongPress(btn) {
    let timer = null;
    const clear = () => clearTimeout(timer);

    // Mobile: long press (500ms)
    btn.addEventListener('touchstart', e => {
        timer = setTimeout(() => { e.preventDefault(); _showReactionWhoPopover(btn); }, 500);
    }, {passive: true});
    btn.addEventListener('touchend',  clear);
    btn.addEventListener('touchmove', clear);

    // Desktop: right-click or hold 600ms
    btn.addEventListener('mousedown', e => {
        if (e.button !== 0) return;
        timer = setTimeout(() => _showReactionWhoPopover(btn), 600);
    });
    btn.addEventListener('mouseup',   clear);
    btn.addEventListener('mouseleave',clear);
    btn.addEventListener('contextmenu', e => { e.preventDefault(); _showReactionWhoPopover(btn); });
}

// Extended Reactions — send, track recent, and full emoji picker for reactions
// ══════════════════════════════════════════════════════════════════════════════

const _RECENT_REACTIONS_KEY = 'vortex_recent_reactions';
const _MAX_RECENT_REACTIONS = 12;

export function _getRecentReactions() {
    try { return JSON.parse(localStorage.getItem(_RECENT_REACTIONS_KEY) || '[]'); }
    catch { return []; }
}

function _addRecentReaction(emoji) {
    let recent = _getRecentReactions().filter(e => e !== emoji);
    recent.unshift(emoji);
    if (recent.length > _MAX_RECENT_REACTIONS) recent = recent.slice(0, _MAX_RECENT_REACTIONS);
    localStorage.setItem(_RECENT_REACTIONS_KEY, JSON.stringify(recent));
}

function _sendReaction(msgId, emoji) {
    _addRecentReaction(emoji);
    const S = window.AppState;
    if (S.ws?.readyState === WebSocket.OPEN) {
        S.ws.send(JSON.stringify({ action: 'react', msg_id: msgId, emoji }));
    }
}

/**
 * Opens a full emoji picker positioned near the message for custom reactions.
 * Reuses the chat emoji picker module but in "reaction mode".
 */
let _reactionPickerEl = null;
let _reactionMsgId = null;

export function _openReactionPicker(msgId) {
    _closeReactionPicker();
    _reactionMsgId = msgId;

    // Import emoji data from emoji-picker module (or use inline mini-set)
    const picker = document.createElement('div');
    picker.className = 'reaction-picker';
    picker.id = 'reaction-picker';

    // Build a compact inline emoji grid with search
    const QUICK_EMOJIS = [
        '😀','😂','🤣','😍','🥰','😘','😎','🤩','🥳','😇','🤗','🤔',
        '😏','😒','🙄','😬','🤯','😱','😭','😤','🤬','😈','💀','🤡',
        '👍','👎','👏','🙌','🤝','✊','👊','🤞','✌️','🤟','🤘','👋',
        '❤️','🧡','💛','💚','💙','💜','🖤','🤍','💔','❤️‍🔥','💯','💥',
        '🔥','✨','⭐','🌟','💫','🎉','🎊','🏆','🥇','💎','🚀','💡',
        '✅','❌','⚠️','🔔','💬','👀','🫡','🫶','🤌','💪','🧠','🎯',
    ];

    let html = `
        <div class="rp-search-wrap">
            <input type="text" class="rp-search" id="rp-search" placeholder="${t('app.search')}" autocomplete="off" spellcheck="false">
        </div>
        <div class="rp-grid" id="rp-grid">`;

    QUICK_EMOJIS.forEach(emoji => {
        html += `<button class="rp-emoji" data-emoji="${emoji}">${emoji}</button>`;
    });

    html += '</div>';
    picker.innerHTML = html;

    // Position near the message bubble
    const msgEl = document.querySelector(`[data-msg-id="${msgId}"]`) || document.getElementById(`msg-${msgId}`);
    if (msgEl) {
        const rect = msgEl.getBoundingClientRect();
        const container = document.getElementById('messages-container');
        if (container) {
            container.appendChild(picker);
            // Position above the message
            const containerRect = container.getBoundingClientRect();
            picker.style.top = (rect.top - containerRect.top - picker.offsetHeight - 8) + 'px';
            picker.style.left = Math.max(8, Math.min(rect.left - containerRect.left, containerRect.width - 320)) + 'px';
        }
    } else {
        // Fallback: append to messages container centered
        const container = document.getElementById('messages-container');
        if (container) container.appendChild(picker);
    }

    requestAnimationFrame(() => picker.classList.add('open'));

    // Emoji click handler
    picker.addEventListener('click', (e) => {
        const btn = e.target.closest('.rp-emoji');
        if (btn) {
            const emoji = btn.dataset.emoji;
            _sendReaction(_reactionMsgId, emoji);
            _closeReactionPicker();
        }
    });

    // Search filter
    const searchInput = picker.querySelector('#rp-search');
    searchInput?.focus();
    searchInput?.addEventListener('input', () => {
        const q = searchInput.value.trim().toLowerCase();
        picker.querySelectorAll('.rp-emoji').forEach(btn => {
            btn.style.display = (!q || btn.dataset.emoji.includes(q)) ? '' : 'none';
        });
    });
    searchInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { _closeReactionPicker(); e.preventDefault(); }
    });

    // Close on outside click (delayed to avoid immediate close)
    _reactionPickerEl = picker;
    setTimeout(() => {
        document.addEventListener('click', _onReactionPickerOutsideClick);
    }, 50);
}

function _closeReactionPicker() {
    if (_reactionPickerEl) {
        _reactionPickerEl.classList.remove('open');
        setTimeout(() => _reactionPickerEl?.remove(), 200);
        _reactionPickerEl = null;
    }
    _reactionMsgId = null;
    document.removeEventListener('click', _onReactionPickerOutsideClick);
}

function _onReactionPickerOutsideClick(e) {
    if (_reactionPickerEl && !_reactionPickerEl.contains(e.target)) {
        _closeReactionPicker();
    }
}

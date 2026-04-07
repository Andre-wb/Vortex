// static/js/chat/indicators.js — typing/file-sending indicators, reactions, pinned bar

import { _attachReactionLongPress } from './messages.js';

const _typers      = {};
const _fileSenders = {};

// =============================================================================
// Индикаторы набора текста и отправки файла
// =============================================================================

export function _showTyping(username, isTyping) {
    if (isTyping) _typers[username] = true;
    else delete _typers[username];
    _renderTypingBar();
}

export function _showFileSending(username, filename) {
    if (filename) _fileSenders[username] = filename;
    else          delete _fileSenders[username];
    _renderTypingBar();
}

function _renderTypingBar() {
    const typers = Object.keys(_typers);
    const filers = Object.entries(_fileSenders);
    const el     = document.getElementById('typing-indicator');
    const textEl = document.getElementById('typing-text');
    const parts  = [];
    if (typers.length)
        parts.push(typers.join(', ') + ' ' + (typers.length === 1 ? t('chat.typing') : t('chat.typingMany')));
    filers.forEach(([name, fname]) => {
        const short = fname.length > 24 ? fname.slice(0, 22) + '…' : fname;
        parts.push(t('chat.sendingFileMsg').replace('{name}', name).replace('{file}', short));
    });
    if (parts.length) {
        el.classList.add('visible');
        textEl.textContent = parts.join(' · ');
    } else {
        el.classList.remove('visible');
    }
}

// =============================================================================
// Реакции — обновление DOM
// =============================================================================

export function _updateReaction(msgId, userId, emoji, added, username, displayName, createdAt) {
    const S = window.AppState;
    let container = document.getElementById(`reactions-${msgId}`);
    if (!container) {
        const msgGroup = document.querySelector(`[data-msg-id="${msgId}"]`);
        if (!msgGroup) return;
        const bubble = msgGroup.querySelector('.msg-bubble');
        if (!bubble) return;
        container = document.createElement('div');
        container.className = 'msg-reactions';
        container.id = `reactions-${msgId}`;
        bubble.after(container);
    }

    const existingBtn = container.querySelector(`[data-emoji="${CSS.escape(emoji)}"]`);
    if (added) {
        if (existingBtn) {
            let count = parseInt(existingBtn.dataset.count || '1') + 1;
            existingBtn.dataset.count = count;
            existingBtn.innerHTML = `${emoji}<span class="reaction-count">${count}</span>`;
            if (userId === S.user?.user_id || userId === S.user?.id) existingBtn.classList.add('own');
            // append user to stored list
            const users = JSON.parse(existingBtn.dataset.users || '[]');
            if (!users.find(u => u.user_id === userId)) {
                users.push({user_id: userId, display_name: displayName || username || String(userId), created_at: createdAt || null});
                existingBtn.dataset.users = JSON.stringify(users);
            }
            existingBtn.classList.remove('count-bump');
            void existingBtn.offsetWidth;
            existingBtn.classList.add('count-bump');
            setTimeout(() => existingBtn.classList.remove('count-bump'), 250);
        } else {
            const btn = document.createElement('span');
            btn.className = `msg-reaction just-added${(userId === S.user?.user_id || userId === S.user?.id) ? ' own' : ''}`;
            btn.dataset.emoji = emoji;
            btn.dataset.count = '1';
            btn.dataset.users = JSON.stringify([{user_id: userId, display_name: displayName || username || String(userId), created_at: createdAt || null}]);
            btn.innerHTML = emoji;
            btn.onclick = () => {
                if (S.ws?.readyState === WebSocket.OPEN) {
                    S.ws.send(JSON.stringify({action: 'react', msg_id: msgId, emoji}));
                }
            };
            _attachReactionLongPress(btn);
            container.appendChild(btn);
            setTimeout(() => btn.classList.remove('just-added'), 300);
        }
    } else {
        if (existingBtn) {
            let count = parseInt(existingBtn.dataset.count || '1') - 1;
            if (count <= 0) {
                existingBtn.remove();
            } else {
                existingBtn.dataset.count = count;
                existingBtn.innerHTML = `${emoji}<span class="reaction-count">${count}</span>`;
                if (userId === S.user?.user_id || userId === S.user?.id) existingBtn.classList.remove('own');
                // remove user from stored list
                const users = JSON.parse(existingBtn.dataset.users || '[]').filter(u => u.user_id !== userId);
                existingBtn.dataset.users = JSON.stringify(users);
            }
        }
    }
}

// =============================================================================
// Закреплённое сообщение — UI
// =============================================================================

export function _showPinnedBar(msgId) {
    let bar = document.getElementById('pinned-bar');
    if (!bar) {
        bar = document.createElement('div');
        bar.id = 'pinned-bar';
        bar.className = 'pinned-bar';
        const header = document.getElementById('chat-header');
        if (header) header.after(bar);
    }
    // Try to extract actual message text from the DOM
    let pinnedPreview = t('chat.pinnedMessage');
    const msgEl = document.querySelector(`[data-msg-id="${msgId}"]`);
    if (msgEl) {
        const bodyEl = msgEl.querySelector('.msg-body');
        if (bodyEl) {
            const raw = bodyEl.textContent.trim();
            pinnedPreview = raw.length > 80 ? raw.slice(0, 80) + '...' : raw;
        }
    }
    bar.innerHTML = `<span class="pinned-icon"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M14 4v5c0 1.12.37 2.16 1 3H9c.65-.86 1-1.9 1-3V4h4zm3-2H7c-.55 0-1 .45-1 1s.45 1 1 1h1v5c0 1.66-1.34 3-3 3v2h5.97v7l1 1 1-1v-7H19v-2c-1.66 0-3-1.34-3-3V4h1c.55 0 1-.45 1-1s-.45-1-1-1z"/></svg></span><span class="pinned-text">${pinnedPreview}</span><span class="pinned-close" onclick="unpinMessage()">&times;</span>`;
    bar.style.display = 'flex';
    bar.onclick = (e) => {
        if (e.target.classList.contains('pinned-close')) return;
        const el = document.querySelector(`[data-msg-id="${msgId}"]`);
        if (el) {
            el.scrollIntoView({behavior: 'smooth', block: 'center'});
            el.classList.add('msg-highlight');
            setTimeout(() => el.classList.remove('msg-highlight'), 1500);
        }
    };
    bar.dataset.msgId = msgId;
}

export function _hidePinnedBar() {
    const bar = document.getElementById('pinned-bar');
    if (bar) bar.style.display = 'none';
}

window.unpinMessage = () => {
    const S = window.AppState;
    if (S.ws?.readyState === WebSocket.OPEN) {
        S.ws.send(JSON.stringify({action: 'pin_message', msg_id: null}));
    }
};

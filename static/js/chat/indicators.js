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

export function _showPinnedBar(msgId, ciphertext, senderName) {
    let bar = document.getElementById('pinned-bar');
    if (!bar) {
        bar = document.createElement('div');
        bar.id = 'pinned-bar';
        bar.className = 'pinned-bar';
        const header = document.getElementById('chat-header');
        if (header) header.after(bar);
    }

    const _buildPinnedContent = (preview, sender) => {
        // Clear old content
        bar.textContent = '';

        const icon = document.createElement('span');
        icon.className = 'pinned-icon';
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('width', '16');
        svg.setAttribute('height', '16');
        svg.setAttribute('fill', 'currentColor');
        svg.setAttribute('viewBox', '0 0 24 24');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', 'M14 4v5c0 1.12.37 2.16 1 3H9c.65-.86 1-1.9 1-3V4h4zm3-2H7c-.55 0-1 .45-1 1s.45 1 1 1h1v5c0 1.66-1.34 3-3 3v2h5.97v7l1 1 1-1v-7H19v-2c-1.66 0-3-1.34-3-3V4h1c.55 0 1-.45 1-1s-.45-1-1-1z');
        svg.appendChild(path);
        icon.appendChild(svg);
        bar.appendChild(icon);

        const textSpan = document.createElement('span');
        textSpan.className = 'pinned-text';
        const truncated = preview && preview.length > 80 ? preview.slice(0, 80) + '...' : (preview || '');
        if (sender) {
            const senderSpan = document.createElement('span');
            senderSpan.className = 'pinned-sender';
            senderSpan.textContent = sender + ': ';
            textSpan.appendChild(senderSpan);
        }
        textSpan.appendChild(document.createTextNode(truncated || t('chat.pinnedMessage')));
        bar.appendChild(textSpan);

        const closeBtn = document.createElement('span');
        closeBtn.className = 'pinned-close';
        closeBtn.textContent = '\u00d7';
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            window.unpinMessage?.();
        });
        bar.appendChild(closeBtn);
    };

    // Try to get text from DOM first
    let pinnedPreview = null;
    const msgEl = document.querySelector(`[data-msg-id="${msgId}"]`);
    if (msgEl) {
        const textEl = msgEl.querySelector('.msg-text');
        if (textEl) pinnedPreview = textEl.textContent.trim();
    }

    if (pinnedPreview) {
        _buildPinnedContent(pinnedPreview, senderName);
    } else if (ciphertext) {
        _buildPinnedContent(t('chat.pinnedMessage'), senderName);
        (async () => {
            try {
                const { getRoomKey, decryptText } = await import('../crypto.js');
                const S = window.AppState;
                const roomKey = getRoomKey(S.currentRoom?.id);
                if (roomKey) {
                    const text = await decryptText(ciphertext, roomKey);
                    _buildPinnedContent(text, senderName);
                }
            } catch {}
        })();
    } else {
        _buildPinnedContent(t('chat.pinnedMessage'), senderName);
    }

    bar.style.display = 'flex';
    bar.onclick = async (e) => {
        if (e.target.classList.contains('pinned-close')) return;
        // Use _scrollToMsg for consistent behavior
        if (window._scrollToMsg) {
            window._scrollToMsg(msgId);
            return;
        }
        let el = document.querySelector(`[data-msg-id="${msgId}"]`);
        if (el) {
            el.scrollIntoView({behavior: 'smooth', block: 'center'});
            el.classList.add('msg-highlight');
            setTimeout(() => el.classList.remove('msg-highlight'), 1500);
            return;
        }
        // Сообщение не в DOM — загружаем контекст вокруг него
        try {
            const S = window.AppState;
            const roomId = S.currentRoom?.id;
            if (!roomId) return;
            const { api } = await import('../utils.js');
            const data = await api('GET', `/api/rooms/${roomId}/messages?around_id=${msgId}&limit=50`);
            if (!data?.messages?.length) return;
            const container = document.getElementById('messages-container');
            if (!container) return;
            // Очищаем и рендерим новые сообщения
            while (container.firstChild) container.removeChild(container.firstChild);
            const { appendMessage, appendFileMessage, resetMessageState } = await import('./messages.js');
            const { decryptText } = await import('./room-crypto.js');
            const { getRoomKey } = await import('../crypto.js');
            resetMessageState();
            const roomKey = getRoomKey(roomId);
            for (const m of data.messages) {
                // Расшифровка
                if (m.ciphertext && roomKey) {
                    try { m.text = await decryptText(m.ciphertext, roomKey); } catch { m.text = m.ciphertext; }
                }
                m.sender_id = m.sender_id || m.id;
                if (m.file_name || m.file_url) {
                    appendFileMessage(m);
                } else {
                    appendMessage(m);
                }
            }
            // Скроллим к целевому сообщению
            await new Promise(r => setTimeout(r, 50));
            el = document.querySelector(`[data-msg-id="${msgId}"]`);
            if (el) {
                el.scrollIntoView({behavior: 'smooth', block: 'center'});
                el.classList.add('msg-highlight');
                setTimeout(() => el.classList.remove('msg-highlight'), 1500);
            }
        } catch (err) {
            console.warn('Failed to load pinned message context', err);
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

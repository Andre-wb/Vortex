// static/js/chat/thread.js — thread panel (open, close, reply, live update)

import { getRoomKey, ratchetDecrypt, ratchetEncrypt } from '../crypto.js';
import { appendSystemMessage } from './messages.js';
import { sendWithAck } from './ack.js';
import { decryptText } from './room-crypto.js';

let _openThreadId = null;

/**
 * Открывает панель треда, загружает сообщения из REST API.
 */
window.openThread = async function(msgId) {
    const S = window.AppState;
    if (!S.currentRoom) return;

    _openThreadId = msgId;

    const panel = document.getElementById('thread-panel');
    if (!panel) return;

    panel.classList.add('open');

    const messagesEl = document.getElementById('thread-messages');
    const titleEl    = document.getElementById('thread-title');
    if (messagesEl) messagesEl.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text2);">${t('app.loading')}</div>`;
    if (titleEl) titleEl.textContent = t('chat.thread');

    try {
        const { api } = await import('../utils.js');
        const data = await api('GET', `/api/rooms/${S.currentRoom.id}/thread/${msgId}`);

        if (titleEl) {
            const rootAuthor = data.root?.display_name || data.root?.sender || '';
            const count = data.replies?.length || 0;
            const countText = count > 0 ? ` · ${count} ${_pluralRepliesThread(count)}` : '';
            titleEl.textContent = rootAuthor ? `${t('chat.thread')} — ${rootAuthor}${countText}` : t('chat.thread') + countText;
        }

        if (messagesEl) {
            messagesEl.innerHTML = '';

            // Рендер корневого сообщения
            const rootEl = await _renderThreadMessage(data.root, true);
            messagesEl.appendChild(rootEl);

            // Разделитель
            if (data.replies?.length) {
                const divider = document.createElement('div');
                divider.className = 'thread-divider';
                divider.textContent = `${data.replies.length} ${_pluralRepliesThread(data.replies.length)}`;
                messagesEl.appendChild(divider);
            }

            // Рендер ответов
            for (const reply of (data.replies || [])) {
                const el = await _renderThreadMessage(reply, false);
                messagesEl.appendChild(el);
            }

            messagesEl.scrollTop = messagesEl.scrollHeight;
        }
    } catch (e) {
        if (messagesEl) messagesEl.innerHTML = `<div style="padding:20px;text-align:center;color:var(--red);">${t('chat.errorLabel').replace('{error}', e.message)}</div>`;
    }
};

/**
 * Закрывает панель треда.
 */
window.closeThread = function() {
    _openThreadId = null;
    const panel = document.getElementById('thread-panel');
    if (panel) panel.classList.remove('open');
};

/**
 * Отправляет ответ в тред через WebSocket.
 */
window.sendThreadReply = async function() {
    const input = document.getElementById('thread-input');
    const text  = input?.value?.trim();
    const S     = window.AppState;
    if (!text || !_openThreadId || !S.currentRoom) return;

    const roomKey = getRoomKey(S.currentRoom.id);
    if (!roomKey) {
        appendSystemMessage(t('chat.noRoomKeyShort'));
        return;
    }

    const ciphertext = await ratchetEncrypt(text, S.currentRoom.id, S.user.id, roomKey);

    sendWithAck({
        action:    'thread_reply',
        thread_id: _openThreadId,
        ciphertext,
    }).catch(err => {
        console.error('[ACK] thread reply не доставлено:', err.message);
    });

    if (input) { input.value = ''; input.style.height = 'auto'; }
};

/**
 * Open channel discussion — close settings and open thread of the last post.
 */
window._openChannelDiscussion = function() {
    if (typeof window.closeRoomSettingsScreen === 'function') {
        window.closeRoomSettingsScreen();
    }
    // Find the last message in the channel that has comments or is the latest post
    const mc = document.getElementById('messages-container');
    if (mc) {
        const rows = mc.querySelectorAll('.message-row[data-msg-id]');
        if (rows.length > 0) {
            const lastRow = rows[rows.length - 1];
            const msgId = parseInt(lastRow.dataset.msgId, 10);
            if (msgId) {
                window.openThread(msgId);
                return;
            }
        }
    }
};

function _pluralRepliesThread(n) {
    const mod10 = n % 10;
    const mod100 = n % 100;
    if (mod10 === 1 && mod100 !== 11) return t('chat.reply1');
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return t('chat.reply2');
    return t('chat.reply5');
}

/**
 * Рендерит одно сообщение треда (корневое или ответ).
 */
async function _renderThreadMessage(msg, isRoot) {
    const S       = window.AppState;
    const roomKey = getRoomKey(S.currentRoom?.id);

    let text = `[${t('chat.encrypted')}]`;

    // Try to use already-decrypted text from the main chat message cache first.
    // This avoids ratchet chain state issues when re-decrypting a message
    // that was already decrypted during history loading.
    const cached = window._msgTexts?.get(msg.msg_id);
    if (cached?.text) {
        text = cached.text;
    } else if (msg.ciphertext && roomKey) {
        try {
            text = await ratchetDecrypt(msg.ciphertext, S.currentRoom?.id, msg.sender_id, roomKey);
        } catch {
            try { text = await decryptText(msg.ciphertext, roomKey); }
            catch { text = `[${t('chat.decryptError')}]`; }
        }
    }

    const { esc, fmtTime } = await import('../utils.js');
    const isOwn = msg.sender_id === S.user?.user_id;

    const el = document.createElement('div');
    el.className = `thread-msg${isRoot ? ' thread-msg-root' : ''}${isOwn ? ' own' : ''}`;
    el.dataset.msgId = msg.msg_id || '';

    const avatarEmoji = msg.avatar_emoji || '\u{1F464}';
    const avatarHtml = msg.avatar_url
        ? `<img src="${esc(msg.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
        : esc(avatarEmoji);

    el.innerHTML = `
        <div class="thread-msg-header">
            <div class="thread-msg-avatar">${avatarHtml}</div>
            <span class="thread-msg-name">${esc(msg.display_name || msg.sender || '?')}</span>
            <span class="thread-msg-time">${fmtTime(msg.created_at)}</span>
        </div>
        <div class="thread-msg-text">${esc(text)}</div>
    `;
    return el;
}

/**
 * Обновляет заголовок панели, если тред открыт для этого сообщения.
 */
export function _updateThreadPanelCount(msgId, count) {
    if (_openThreadId != msgId) return;
    const titleEl = document.getElementById('thread-title');
    if (titleEl) titleEl.textContent = count > 0 ? t('chat.threadCount').replace('{count}', count) : t('chat.thread');
}

/**
 * Добавляет сообщение в открытую панель треда (live update).
 */
export async function _appendToOpenThread(msg) {
    if (!msg.thread_id || _openThreadId != msg.thread_id) return;

    const messagesEl = document.getElementById('thread-messages');
    if (!messagesEl) return;

    const el = await _renderThreadMessage(msg, false);
    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

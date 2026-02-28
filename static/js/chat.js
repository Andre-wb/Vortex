import { $, api, esc, fmtTime, fmtDate, fmtSize, scrollToBottom, getCookie } from './utils.js';
import { renderRoomsList, updateRoomMeta } from './rooms.js';
import { showWelcome } from './ui.js';

// ============================================================================
// CHAT
// ============================================================================

let _lastDate = null;
let _lastSenderId = null;
let _typingActive = false;
const _typers = {};

export function connectWS(roomId) {
    const S = window.AppState;
    const token = getCookie('access_token');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${location.host}/ws/${roomId}?token=${token}`;
    S.ws = new WebSocket(url);

    S.ws.onopen = () => {
        console.log('WS connected, room', roomId);
    };

    S.ws.onmessage = e => {
        const msg = JSON.parse(e.data);
        handleWsMessage(msg);
    };

    S.ws.onclose = e => {
        if (e.code === 4401) { window.doLogout(); return; }
        if (e.code === 4403) { alert('Нет доступа к комнате'); return; }
        if (S.currentRoom?.id === roomId) {
            setTimeout(() => connectWS(roomId), 3000);
        }
    };

    S.ws._ping = setInterval(() => {
        if (S.ws?.readyState === WebSocket.OPEN) S.ws.send(JSON.stringify({ action: 'ping' }));
    }, 25000);
}

function handleWsMessage(msg) {
    const S = window.AppState;
    switch (msg.type) {
        case 'node_pubkey':
            S.nodePublicKey = msg.pubkey_hex;
            break;
        case 'history':
            msg.messages.forEach(m => appendMessage(m));
            scrollToBottom();
            break;
        case 'message':
        case 'peer_message':
            appendMessage(msg);
            scrollToBottom(true);
            break;
        case 'file':
            appendFileMessage(msg);
            scrollToBottom(true);
            break;
        case 'online':
            updateOnlineList(msg.users);
            break;
        case 'user_joined':
        case 'user_left':
            appendSystemMessage(msg.type === 'user_joined'
                ? `${msg.display_name || msg.username} вошёл в чат`
                : `${msg.username} покинул чат`);
            updateRoomMeta(); // из rooms.js
            break;
        case 'typing':
            showTyping(msg.username, msg.is_typing);
            break;
        case 'kicked':
            alert('Вы были исключены из комнаты');
            S.rooms = S.rooms.filter(r => r.id !== S.currentRoom?.id);
            renderRoomsList(); // из rooms.js
            showWelcome(); // из ui.js
            break;
        case 'room_deleted':
            alert('Комната была удалена');
            S.rooms = S.rooms.filter(r => r.id !== S.currentRoom?.id);
            renderRoomsList();
            showWelcome();
            break;
        case 'system':
            appendSystemMessage(msg.text);
            break;
        case 'pong':
            break;
    }
}

function appendMessage(msg) {
    const S = window.AppState;
    const container = $('messages-container');
    const isOwn = msg.sender_id === S.user?.user_id;
    const isPeer = msg.from_peer;

    const date = fmtDate(msg.created_at || new Date().toISOString());
    if (date !== _lastDate) {
        _lastDate = date;
        const div = document.createElement('div');
        div.className = 'date-divider';
        div.textContent = date;
        container.appendChild(div);
        _lastSenderId = null;
    }

    const showAuthor = msg.sender_id !== _lastSenderId;
    _lastSenderId = msg.sender_id;

    const group = document.createElement('div');
    group.className = 'fade-in';

    if (showAuthor && !isOwn) {
        const author = document.createElement('div');
        author.className = 'msg-author';
        author.innerHTML = `
      <div class="msg-avatar">${esc(msg.avatar_emoji || '👤')}</div>
      <span class="msg-name">${esc(msg.display_name || msg.sender || '?')}</span>
      <span class="msg-time">${fmtTime(msg.created_at)}</span>
      ${isPeer ? '<span class="msg-peer-badge">P2P</span>' : ''}
    `;
        group.appendChild(author);
    }

    const bubble = document.createElement('div');
    bubble.className = `msg-bubble ${isOwn ? 'own' : ''}`;
    bubble.innerHTML = esc(msg.text || '');

    if (isOwn) {
        const timeEl = document.createElement('div');
        timeEl.style.cssText = 'font-size:10px;color:var(--text3);margin-top:3px;text-align:right;font-family:var(--mono);';
        timeEl.textContent = fmtTime(msg.created_at);
        group.appendChild(bubble);
        group.appendChild(timeEl);
    } else {
        group.appendChild(bubble);
    }

    container.appendChild(group);
}

function appendFileMessage(msg) {
    const S = window.AppState;
    const container = $('messages-container');
    const isOwn = msg.sender_id === S.user?.user_id;
    const div = document.createElement('div');
    div.className = 'fade-in';

    const isImage = msg.mime_type?.startsWith('image/');
    const icon = isImage ? '🖼' : msg.mime_type?.startsWith('video/') ? '🎬'
        : msg.mime_type?.startsWith('audio/') ? '🎵' : '📄';

    div.innerHTML = `
    <div class="msg-author">
      <div class="msg-avatar">${esc(msg.avatar_emoji || '👤')}</div>
      <span class="msg-name">${esc(msg.display_name || msg.sender)}</span>
      <span class="msg-time">${fmtTime(msg.created_at)}</span>
    </div>
    <div class="msg-bubble ${isOwn ? 'own' : ''} file-msg">
      <span class="file-icon">${icon}</span>
      <div class="file-info">
        <div class="file-name">${esc(msg.file_name)}</div>
        <div class="file-size">${fmtSize(msg.file_size)}</div>
      </div>
      <a class="file-download" href="${msg.download_url}" download>↓ Скачать</a>
    </div>
  `;
    container.appendChild(div);
}

function appendSystemMessage(text) {
    const div = document.createElement('div');
    div.innerHTML = `<div class="msg-bubble system">${esc(text)}</div>`;
    $('messages-container').appendChild(div);
    _lastSenderId = null;
}

export function sendMessage() {
    const input = $('msg-input');
    const text = input.value.trim();
    const S = window.AppState;
    if (!text || !S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    S.ws.send(JSON.stringify({ action: 'message', text }));
    input.value = '';
    input.style.height = 'auto';
}

export function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
}

export function handleTyping() {
    const input = $('msg-input');
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';
    const S = window.AppState;
    if (!_typingActive && S.ws?.readyState === WebSocket.OPEN) {
        _typingActive = true;
        S.ws.send(JSON.stringify({ action: 'typing', is_typing: true }));
    }
    clearTimeout(window.AppState.typingTimeout);
    window.AppState.typingTimeout = setTimeout(() => {
        _typingActive = false;
        S.ws?.send(JSON.stringify({ action: 'typing', is_typing: false }));
    }, 2000);
}

function showTyping(username, isTyping) {
    if (isTyping) _typers[username] = true;
    else delete _typers[username];
    const names = Object.keys(_typers);
    const el = $('typing-indicator');
    if (names.length) {
        el.classList.add('visible');
        $('typing-text').textContent = names.join(', ') + (names.length === 1 ? ' печатает' : ' печатают');
    } else {
        el.classList.remove('visible');
    }
}

function updateOnlineList(users) {
    const S = window.AppState;
    if (S.currentRoom) {
        $('chat-room-meta').textContent = `${S.currentRoom.member_count} участников · ${users.length} онлайн`;
    }
}

export function triggerFileUpload() {
    $('file-input').click();
}

export async function uploadFile(e) {
    const file = e.target.files[0];
    const S = window.AppState;
    if (!file || !S.currentRoom) return;
    const fd = new FormData();
    fd.append('file', file);
    try {
        const r = await fetch(`/api/files/upload/${S.currentRoom.id}`, {
            method: 'POST', credentials: 'include', body: fd,
        });
        if (!r.ok) throw new Error((await r.json()).detail);
    } catch (err) {
        alert('Ошибка загрузки: ' + err.message);
    }
    e.target.value = '';
}

export async function showRoomFilesModal() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    openModal('files-modal'); // из utils
    const el = $('files-list');
    el.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text2);">Загрузка...</div>';
    try {
        const data = await api('GET', `/api/files/room/${S.currentRoom.id}`);
        el.innerHTML = data.files.length ? data.files.map(f => {
            const icon = f.mime_type?.startsWith('image/') ? '🖼' : f.mime_type?.startsWith('video/') ? '🎬'
                : f.mime_type?.startsWith('audio/') ? '🎵' : '📄';
            return `
        <div style="padding:10px 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;">
          <span style="font-size:24px;">${icon}</span>
          <div style="flex:1;min-width:0;">
            <div style="font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(f.file_name)}</div>
            <div style="font-size:11px;color:var(--text2);font-family:var(--mono);">${fmtSize(f.size_bytes)} · ${f.uploader}</div>
          </div>
          <a href="${f.download_url}" download class="btn btn-secondary btn-sm">↓</a>
        </div>
      `;
        }).join('') : '<div style="padding:24px;text-align:center;color:var(--text2);">Файлов нет</div>';
    } catch { }
}
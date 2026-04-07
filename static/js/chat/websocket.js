// static/js/chat/websocket.js — WebSocket connection management + message handler

import { scrollToBottom } from '../utils.js';
import { renderRoomsList } from '../rooms.js';
import { showWelcome } from '../ui.js';
import { eciesDecrypt, eciesEncrypt, getRoomKey, setRoomKey, ratchetDecrypt, clearRatchet } from '../crypto.js';
import {
    appendMessage,
    appendFileMessage,
    appendSystemMessage,
    appendPollMessage,
    updatePoll,
    resetMessageState,
    deleteMessageAnim,
    updateMessageText,
    updateThreadBadge,
    insertUnreadDivider,
    cleanupUnreadDivider,
} from './messages.js';
import { showMessagesSkeleton, hideMessagesSkeleton, showConnectingSpinner } from './skeletons.js';
import { decryptText, _saveRoomKeyToSession, _loadRoomKeyFromSession, _clearRoomKeyFromSession } from './room-crypto.js';
import { _handleAck, _cancelAllPendingAcks, _flushOfflineQueue } from './ack.js';
import { _updateOnlineMembersCache } from './mention.js';
import { _showTyping, _showFileSending, _updateReaction, _showPinnedBar, _hidePinnedBar } from './indicators.js';
import { _showNotContactBanner, _hideNotContactBanner, _showThemeProposalBanner } from './banners.js';
import { _updateAutoDeleteIndicator, _updateSlowModeIndicator, _startSlowModeCooldown } from './features.js';
import { _updateThreadPanelCount, _appendToOpenThread } from './thread.js';
import { queueHistoryMessage } from '../key_backup.js';

// ─── Детекция скриншотов ────────────────────────────────────────────────────
document.addEventListener('keyup', e => {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;

    const isMacScreenshot = e.metaKey && e.shiftKey &&
        (e.key === '3' || e.key === '4' || e.key === '5');
    const isWinScreenshot = e.key === 'PrintScreen';

    if (isMacScreenshot || isWinScreenshot) {
        S.ws.send(JSON.stringify({ action: 'screenshot' }));
    }
});

let _msgQueue    = Promise.resolve();
let _pendingHistory = null;

export async function connectWS(roomId) {
    const S = window.AppState;

    if (S.ws) {
        if (S.ws._ping) clearInterval(S.ws._ping);
        S.ws.onclose = null;
        S.ws.close();
        S.ws = null;
    }

    _pendingHistory  = null;
    _cancelAllPendingAcks();

    // Закрываем панель треда при смене комнаты
    if (window.closeThread) window.closeThread();

    const cachedKey = _loadRoomKeyFromSession(roomId);
    if (cachedKey) {
        setRoomKey(roomId, cachedKey);
        console.info('🔑 Ключ комнаты восстановлен из sessionStorage для room', roomId);
    }

    const proto  = location.protocol === 'https:' ? 'wss' : 'ws';
    const wsPath = S.currentRoom?.is_federated ? `/ws/fed/${roomId}` : `/ws/${roomId}`;

    // Anti-probing: knock sequence в global mode
    if (window.AppState.user?.network_mode === 'global') {
        try {
            await fetch('/cover/pricing', {credentials: 'include'});
            await fetch('/cover/about', {credentials: 'include'});
        } catch {}
    }
    const knockCookie = document.cookie.split(';').find(c => c.trim().startsWith('_vk='))?.split('=')[1];
    const knockParam = knockCookie ? `${wsPath.includes('?') ? '&' : '?'}knock=${knockCookie}` : '';
    showConnectingSpinner();
    S.ws      = new WebSocket(`${proto}://${location.host}${wsPath}${knockParam}`);
    _msgQueue = Promise.resolve();

    S.ws.onopen = () => {
        console.log('WS connected, room', roomId);
        showMessagesSkeleton();
        _flushOfflineQueue();
    };

    S.ws.onmessage = e => {
        // Фильтрация cover-трафика (бинарные данные с первым байтом 0x00)
        if (e.data instanceof Blob || e.data instanceof ArrayBuffer) return;
        if (typeof e.data === 'string' && e.data.charCodeAt(0) === 0) return;
        const data = JSON.parse(e.data);
        _msgQueue  = _msgQueue
            .then(() => handleWsMessage(data))
            .catch(err => console.error('WS msg error:', err));
    };

    S.ws.onclose = e => {
        if (e.code === 4401) { window.doLogout(); return; }
        if (e.code === 4403) { alert(t('chat.noAccess')); return; }
        if (S.currentRoom?.id === roomId)
            setTimeout(() => connectWS(roomId), 2000 + Math.random() * 6000);
    };

    // Рандомизация ping-интервала (15-50 сек) — защита от timing fingerprint
    function _schedulePing() {
        const interval = 15000 + Math.random() * 35000;
        S.ws._ping = setTimeout(() => {
            if (S.ws?.readyState === WebSocket.OPEN) {
                S.ws.send(JSON.stringify({ action: 'ping' }));
                _schedulePing();
            }
        }, interval);
    }
    _schedulePing();
}

async function handleWsMessage(msg) {
    const S = window.AppState;
    switch (msg.type) {

        case 'ack':
            _handleAck(msg);
            break;

        case 'room_key': {
            const privKey = S.x25519PrivateKey;
            const roomId  = msg.room_id ?? S.currentRoom?.id;
            if (!roomId) { console.warn('room_key: нет roomId'); break; }
            if (!privKey) {
                appendSystemMessage(
                    t('chat.keyDecryptErrorFull').replace('{importKey}', t('chat.importKey'))
                );
                break;
            }
            try {
                const keyBytes = await eciesDecrypt(msg.ephemeral_pub, msg.ciphertext, privKey);
                setRoomKey(roomId, keyBytes);
                _saveRoomKeyToSession(roomId, keyBytes);
                console.info('🔑 Ключ комнаты получен и сохранён, room', roomId);

                if (_pendingHistory) {
                    const pendingMessages = _pendingHistory;
                    _pendingHistory = null;
                    resetMessageState();
                    document.getElementById('messages-container').innerHTML = '';
                    for (const m of pendingMessages) await _decryptAndAppend(m);
                    const pendingUnread = S.currentRoom?.unread_count || 0;
                    if (pendingUnread > 0) {
                        insertUnreadDivider(pendingUnread);
                    } else {
                        scrollToBottom();
                    }
                }
            } catch (e) {
                appendSystemMessage(t('chat.keyDecryptErrorDetail').replace('{error}', e.message));
            }
            break;
        }

        case 'key_request': {
            const roomId  = S.currentRoom?.id;
            const roomKey = getRoomKey(roomId);
            if (!roomKey) break;
            try {
                const enc = await eciesEncrypt(roomKey, msg.for_pubkey);
                S.ws.send(JSON.stringify({
                    action:        'key_response',
                    for_user_id:   msg.for_user_id,
                    ephemeral_pub: enc.ephemeral_pub,
                    ciphertext:    enc.ciphertext,
                }));
            } catch (e) { console.error('Ошибка re-encryption:', e); }
            break;
        }

        case 'waiting_for_key':
            appendSystemMessage(t('chat.waitingKeyDots'));
            break;

        case 'node_pubkey':
            S.nodePublicKey = msg.pubkey_hex;
            break;

        case 'history': {
            hideMessagesSkeleton();
            const roomKey = getRoomKey(S.currentRoom?.id);
            if (!roomKey && msg.messages?.length) {
                _pendingHistory = msg.messages;
                resetMessageState();
                document.getElementById('messages-container').innerHTML = '';
                appendSystemMessage(t('chat.waitingKeyHistory') + '...');
            } else {
                _pendingHistory = null;
                resetMessageState();
                document.getElementById('messages-container').innerHTML = '';
                for (const m of msg.messages) await _decryptAndAppend(m);

                // Вставляем разделитель непрочитанных перед прокруткой вниз
                const unreadCnt = S.currentRoom?.unread_count || 0;
                if (unreadCnt > 0) {
                    insertUnreadDivider(unreadCnt);
                } else {
                    scrollToBottom();
                }

                // Отправляем mark_read для непрочитанных
                const unreadIds = msg.messages
                    .filter(m => m.sender_id !== S.user?.user_id)
                    .map(m => m.msg_id)
                    .filter(Boolean);
                if (unreadIds.length && S.ws?.readyState === WebSocket.OPEN) {
                    S.ws.send(JSON.stringify({action: 'mark_read', msg_ids: unreadIds}));
                }

                // Cache messages for cross-device history sync
                if (S.currentRoom?.id && msg.messages?.length) {
                    for (const m of msg.messages) {
                        queueHistoryMessage(S.currentRoom.id, m);
                    }
                }
            }

            // Обработка закреплённого сообщения
            if (msg.pinned_message_id) {
                _showPinnedBar(msg.pinned_message_id);
            } else {
                _hidePinnedBar();
            }

            // Room settings from history (Features 3 & 4)
            if (S.currentRoom) {
                S.currentRoom.auto_delete_seconds = msg.auto_delete_seconds || 0;
                S.currentRoom.slow_mode_seconds = msg.slow_mode_seconds || 0;
                _updateAutoDeleteIndicator(msg.auto_delete_seconds || 0);
                _updateSlowModeIndicator(msg.slow_mode_seconds || 0);
            }

            // Show "not in contacts" banner for DMs with non-contacts
            if (msg.is_dm && msg.other_user_is_contact === false && msg.other_user_id) {
                _showNotContactBanner(msg.other_user_id);
            } else {
                _hideNotContactBanner();
            }
            break;
        }

        case 'theme_changed': {
            // Room theme was changed by admin — apply immediately
            const S2 = window.AppState;
            if (S2.currentRoom && msg.room_id === S2.currentRoom.id) {
                S2.currentRoom.theme_json = msg.theme ? JSON.stringify(msg.theme) : null;
                if (typeof window.applyRoomThemeToChat === 'function') {
                    window.applyRoomThemeToChat(msg.theme);
                }
            }
            break;
        }

        case 'theme_proposal': {
            // DM theme proposal from the other participant
            const S3 = window.AppState;
            if (msg.proposed_by === S3.user?.user_id) break; // ignore own proposal
            _showThemeProposalBanner(msg);
            break;
        }

        case 'theme_accepted': {
            const S4 = window.AppState;
            if (S4.currentRoom && msg.room_id === S4.currentRoom.id) {
                S4.currentRoom.theme_json = msg.theme ? JSON.stringify(msg.theme) : null;
                if (typeof window.applyRoomThemeToChat === 'function') {
                    window.applyRoomThemeToChat(msg.theme);
                }
            }
            break;
        }

        case 'theme_rejected': {
            const S5 = window.AppState;
            if (S5.currentRoom && msg.room_id === S5.currentRoom.id) {
                S5.currentRoom.theme_json = null;
                if (typeof window.applyRoomThemeToChat === 'function') {
                    window.applyRoomThemeToChat(null);
                }
            }
            break;
        }

        case 'signal':
            if (typeof window.handleFederatedSignal === 'function')
                window.handleFederatedSignal(msg);
            break;

        case 'message':
        case 'peer_message': {
            // ── FIX: дедупликация — не рендерим если это наш ACK-ожидаемый
            // client_msg_id, который уже есть в _pendingAcks (ещё не подтверждён).
            // ACK придёт отдельно и разрешит промис. Само сообщение рендерим
            // только когда сервер прислал его как broadcast (т.е. оно уже в БД).
            //
            // НО: если ACK уже обработан (_pendingAcks не содержит этот id),
            // значит broadcast пришёл позже ACK или это чужое сообщение — рендерим.
            //
            // Итого: рендерим ВСЕГДА, но пропускаем если для этого client_msg_id
            // ещё висит pending ACK (значит мы уже знаем что отправили, и
            // рендер произойдёт когда ACK придёт и снимет ожидание... нет,
            // без оптимистичного рендера нам нужен broadcast).
            //
            // Правильная логика: сервер теперь шлёт broadcast ВСЕМ включая
            // отправителя. Отправитель получает и ACK и message. ACK — для
            // подтверждения записи в БД. message — для рендера. Рендерим
            // message всегда. Чтобы не было дубля — проверяем DOM.
            if (msg.client_msg_id) {
                const existing = document.querySelector(
                    `[data-client-msg-id="${CSS.escape(msg.client_msg_id)}"]`
                );
                if (existing) break; // уже отрендерено (оптимистично или ранее)
            }
            await _decryptAndAppend(msg);
            scrollToBottom(true);
            // Отправляем mark_read для входящего сообщения
            if (msg.sender_id !== S.user?.user_id && msg.msg_id && S.ws?.readyState === WebSocket.OPEN) {
                S.ws.send(JSON.stringify({action: 'mark_read', msg_ids: [msg.msg_id]}));
            }
            // Queue for cross-device history sync
            if (S.currentRoom?.id) queueHistoryMessage(S.currentRoom.id, msg);
            break;
        }

        case 'file':
            appendFileMessage(msg);
            scrollToBottom(true);
            break;

        case 'online':
            _updateOnlineList(msg.users);
            break;

        case 'user_joined':
            appendSystemMessage(`${msg.display_name || msg.username} ${t('chat.joined')}`);
            if (msg.online_users) _updateOnlineList(msg.online_users);
            break;

        case 'user_left':
            appendSystemMessage(`${msg.username} ${t('chat.left')}`);
            if (msg.online_users) _updateOnlineList(msg.online_users);
            break;

        case 'typing':
            _showTyping(msg.username, msg.is_typing);
            break;

        case 'file_sending':
            _showFileSending(msg.display_name || msg.username, msg.filename);
            break;

        case 'stop_file_sending':
            _showFileSending(msg.sender, null);
            break;

        case 'kicked':
            alert(t('chat.kicked'));
            _clearRoomKeyFromSession(S.currentRoom?.id);
            S.rooms = S.rooms.filter(r => r.id !== S.currentRoom?.id);
            renderRoomsList();
            showWelcome();
            break;

        case 'room_deleted':
            alert(t('chat.roomDeleted'));
            _clearRoomKeyFromSession(S.currentRoom?.id);
            S.rooms = S.rooms.filter(r => r.id !== S.currentRoom?.id);
            renderRoomsList();
            showWelcome();
            break;

        case 'room_updated': {
            const updRoom = msg.room;
            if (updRoom) {
                S.rooms = S.rooms.map(r => r.id === updRoom.id ? {...r, ...updRoom} : r);
                if (S.currentRoom && S.currentRoom.id === updRoom.id) {
                    const keepFields = ['is_dm', 'dm_user', 'is_federated', 'peer_ip', 'has_key', 'is_muted', 'unread_count', 'is_owner', 'is_admin', 'my_role'];
                    keepFields.forEach(k => { if (S.currentRoom[k] !== undefined && updRoom[k] === undefined) updRoom[k] = S.currentRoom[k]; });
                    S.currentRoom = {...S.currentRoom, ...updRoom};
                    const nameEl = document.getElementById('chat-room-name');
                    if (nameEl) nameEl.textContent = updRoom.name;
                    const metaEl = document.getElementById('chat-room-meta');
                    if (metaEl) metaEl.textContent = t('rooms.membersOnline').replace('{n}', updRoom.member_count).replace('{m}', updRoom.online_count);
                }
                renderRoomsList();
            }
            break;
        }

        case 'system':
            appendSystemMessage(msg.message || msg.text);
            break;

        case 'key_rotated': {
            const roomId = S.currentRoom?.id;
            if (roomId) {
                // Clear old key and ratchet chains
                setRoomKey(roomId, null);
                clearRatchet(roomId);
                _clearRoomKeyFromSession(roomId);

                // Generate new room key and distribute to self
                const newKey   = crypto.getRandomValues(new Uint8Array(32));
                const myPubkey = S.user?.x25519_public_key;
                if (myPubkey) {
                    try {
                        const enc = await eciesEncrypt(newKey, myPubkey);
                        setRoomKey(roomId, newKey);
                        _saveRoomKeyToSession(roomId, newKey);
                        S.ws?.send(JSON.stringify({
                            action:        'key_response',
                            for_user_id:   S.user.id,
                            ephemeral_pub: enc.ephemeral_pub,
                            ciphertext:    enc.ciphertext,
                        }));
                        appendSystemMessage(t('chat.newRoomKey'));
                    } catch (e) {
                        console.error('key_rotated: ошибка генерации нового ключа', e);
                        appendSystemMessage(t('chat.keyUpdated'));
                    }
                } else {
                    appendSystemMessage(t('chat.keyUpdated'));
                }
            }
            break;
        }

        case 'messages_read': {
            // Обновляем статус прочтения
            const readIds = msg.msg_ids || [];
            readIds.forEach(id => {
                const el = document.querySelector(`[data-msg-id="${id}"] .msg-status`);
                if (el) { el.textContent = '\u2713\u2713'; el.classList.add('read'); }
            });
            break;
        }

        case 'reaction': {
            _updateReaction(msg.msg_id, msg.user_id, msg.emoji, msg.added, msg.username, msg.display_name, msg.created_at);
            break;
        }

        case 'message_pinned': {
            if (msg.msg_id) {
                _showPinnedBar(msg.msg_id);
                appendSystemMessage(t('chat.pinned'));
            } else {
                _hidePinnedBar();
                appendSystemMessage(t('chat.unpinned'));
            }
            break;
        }

        case 'panic_wipe':
            if (window._handlePanicWipe) window._handlePanicWipe(msg.user_id);
            break;

        case 'message_deleted':
            deleteMessageAnim(msg.msg_id);
            break;

        case 'message_edited':
            await _decryptAndUpdateMessage(msg);
            break;

        case 'error':
            if (msg.code === 'slow_mode') {
                appendSystemMessage(msg.message);
                // Extract seconds from message and start cooldown
                const match = msg.message.match(/(\d+)/);
                if (match) _startSlowModeCooldown(parseInt(match[1]));
            } else if (msg.code === 'flood_muted' || msg.code === 'flood_banned') {
                appendSystemMessage(msg.message);
            } else if (msg.code === 'global_muted') {
                appendSystemMessage(msg.message);
            } else if (msg.code !== 'rate_limited') {
                console.warn('[WS error]', msg.message);
            } else {
                appendSystemMessage(t('chat.tooFast'));
            }
            break;

        case 'poll':
            appendPollMessage(msg);
            scrollToBottom(true);
            break;

        case 'poll_update':
            updatePoll(msg);
            break;

        case 'auto_delete_changed':
            S.currentRoom && (S.currentRoom.auto_delete_seconds = msg.seconds);
            _updateAutoDeleteIndicator(msg.seconds);
            appendSystemMessage(msg.seconds > 0
                ? t('chat.autoDelete').replace('{time}', _fmtSeconds(msg.seconds))
                : t('chat.autoDeleteOff'));
            break;

        case 'slow_mode_changed':
            S.currentRoom && (S.currentRoom.slow_mode_seconds = msg.seconds);
            _updateSlowModeIndicator(msg.seconds);
            appendSystemMessage(msg.seconds > 0
                ? t('chat.slowMode').replace('{time}', _fmtSeconds(msg.seconds))
                : t('chat.slowModeOff'));
            break;

        case 'thread_update':
            updateThreadBadge(msg.msg_id, msg.thread_count);
            // Если панель треда открыта для этого сообщения — обновить заголовок
            _updateThreadPanelCount(msg.msg_id, msg.thread_count);
            break;

        case 'thread_message':
            // Если панель треда открыта для этого thread_id — добавить сообщение
            await _appendToOpenThread(msg);
            break;

        case 'screenshot_taken':
            appendSystemMessage(`\u26a0\ufe0f ${msg.username} ${t('chat.screenshotTaken')}`, 'screenshot-warn');
            scrollToBottom(true);
            break;

        case 'pong':
            break;
    }
}

async function _decryptAndAppend(msg) {
    // Polls are not encrypted — render as poll card
    if (msg.type === 'poll') {
        appendPollMessage(msg);
        return;
    }

    // Bot messages are plaintext — skip decryption
    if (msg.is_bot && msg.plaintext) {
        msg.text = msg.plaintext;
    } else {
        const S       = window.AppState;
        const roomKey = getRoomKey(S.currentRoom?.id);

        if (msg.ciphertext) {
            if (roomKey) {
                try {
                    msg.text = await ratchetDecrypt(msg.ciphertext, S.currentRoom?.id, msg.sender_id, roomKey);
                } catch {
                    // Fallback to legacy (non-ratchet) decrypt
                    try { msg.text = await decryptText(msg.ciphertext, roomKey); }
                    catch { msg.text = `[${t('chat.decryptError')}]`; }
                }
            } else {
                msg.text = `[${t('chat.encryptedNoKey')}]`;
            }
        }
    }
    if (msg.reply_to_id && !msg.reply_to_text) {
        const cached = window._msgTexts?.get(msg.reply_to_id);
        if (cached) {
            msg.reply_to_text   = cached.text;
            msg.reply_to_sender = cached.sender;
        }
    }
    appendMessage(msg);
}

async function _decryptAndUpdateMessage(msg) {
    const S       = window.AppState;
    const roomKey = getRoomKey(S.currentRoom?.id);
    let   text    = `[${t('chat.decryptError')}]`;
    if (roomKey && msg.ciphertext) {
        try {
            text = await ratchetDecrypt(msg.ciphertext, S.currentRoom?.id, msg.sender_id, roomKey);
        } catch {
            // Fallback to legacy (non-ratchet) decrypt
            try { text = await decryptText(msg.ciphertext, roomKey); } catch {}
        }
    }
    updateMessageText(msg.msg_id, text, msg.is_edited);
}

function _updateOnlineList(users) {
    const S  = window.AppState;
    const el = document.getElementById('chat-room-meta');
    if (!el || !S.currentRoom) return;

    // Cache members for @mention autocomplete
    _updateOnlineMembersCache(users);

    if (S.currentRoom.is_dm) {
        // Для DM показываем "в сети" / "не в сети"
        const otherOnline = users.some(u => u.user_id !== S.user?.id);
        el.textContent = otherOnline ? t('chat.online') : t('chat.offline');
        el.style.color = otherOnline ? 'var(--green)' : '';
    } else {
        const memberCount = S.currentRoom.member_count ?? S.currentRoom.subscriber_count ?? 0;
        el.textContent = t('rooms.membersOnline').replace('{n}', memberCount).replace('{m}', users.length);
    }
}

function _fmtSeconds(s) {
    if (s >= 86400) return t('chat.days').replace('{n}', Math.round(s / 86400));
    if (s >= 3600) return t('chat.hoursShort').replace('{n}', Math.round(s / 3600));
    if (s >= 60) return t('chat.minsShort').replace('{n}', Math.round(s / 60));
    return t('chat.secsShort').replace('{n}', s);
}

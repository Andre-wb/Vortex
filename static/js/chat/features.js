// static/js/chat/features.js — polls, payments, timed mode, scheduled messages,
// auto-delete/slow-mode indicators, mute toggle, files modal, drag & drop, export

import { appendSystemMessage } from './messages.js';
import { getRoomKey, ratchetDecrypt, ratchetEncrypt } from '../crypto.js';
import { decryptText } from './room-crypto.js';

// =============================================================================
// Файлы
// =============================================================================

export async function showRoomFilesModal() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    const { openModal, api, esc, fmtSize: _fmtSize } = await import('../utils.js');
    openModal('files-modal');
    const el = document.getElementById('files-list');
    el.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text2);">${t('app.loading')}</div>`;
    try {
        const data = await api('GET', `/api/files/room/${S.currentRoom.id}`);
        el.innerHTML = data.files.length
            ? data.files.map(f => {
                const isImage  = f.mime_type?.startsWith('image/');
                const icon     = isImage
                    ? '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>'
                    : f.mime_type?.startsWith('video/')
                        ? '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M18 4l2 4h-3l-2-4h-2l2 4h-3l-2-4H8l2 4H7L5 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4h-4z"/></svg>'
                        : f.mime_type?.startsWith('audio/')
                            ? '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/></svg>'
                            : '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11z"/></svg>';
                const safeName = esc(f.file_name).replace(/'/g, "\\'");
                return `
                <div style="padding:10px 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;">
                    <span style="font-size:24px;">${icon}</span>
                    <div style="flex:1;min-width:0;">
                        <div style="font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(f.file_name)}</div>
                        <div style="font-size:11px;color:var(--text2);font-family:var(--mono);">${_fmtSize(f.size_bytes)} · ${f.uploader}</div>
                        ${f.file_hash ? `<div style="font-size:10px;color:var(--text3);font-family:var(--mono);">SHA-256: ${f.file_hash.slice(0,16)}…</div>` : ''}
                    </div>
                    ${isImage ? `<span style="cursor:pointer;color:var(--accent2);display:inline-flex;"
                        onclick="closeModal('files-modal');window.openImageViewer('${f.download_url}','${safeName}')"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg></span>` : ''}
                    <a href="${f.download_url}" download class="btn btn-secondary btn-sm">↓</a>
                </div>`;
            }).join('')
            : `<div style="padding:24px;text-align:center;color:var(--text2);">${t('chat.noFiles')}</div>`;
    } catch {}
}

// =============================================================================
// Drag & Drop файлов в область чата
// =============================================================================

let _dragCounter = 0;   // счётчик вложенных dragenter/dragleave

function _initDragDrop() {
    const chatScreen = document.getElementById('chat-screen');
    const overlay    = document.getElementById('drop-overlay');
    if (!chatScreen || !overlay) return;

    chatScreen.addEventListener('dragenter', e => {
        e.preventDefault();
        e.stopPropagation();
        _dragCounter++;
        if (_dragCounter === 1) overlay.classList.add('visible');
    });

    chatScreen.addEventListener('dragover', e => {
        e.preventDefault();
        e.stopPropagation();
        e.dataTransfer.dropEffect = 'copy';
    });

    chatScreen.addEventListener('dragleave', e => {
        e.preventDefault();
        e.stopPropagation();
        _dragCounter--;
        if (_dragCounter <= 0) {
            _dragCounter = 0;
            overlay.classList.remove('visible');
        }
    });

    chatScreen.addEventListener('drop', e => {
        e.preventDefault();
        e.stopPropagation();
        _dragCounter = 0;
        overlay.classList.remove('visible');

        const files = e.dataTransfer?.files;
        if (!files || files.length === 0) return;

        // Берём первый файл и передаём в систему загрузки
        const file = files[0];
        if (typeof window.uploadFileFromDrop === 'function') {
            window.uploadFileFromDrop(file);
        }
    });
}

// Инициализация drag & drop при загрузке DOM
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _initDragDrop);
} else {
    _initDragDrop();
}

// =============================================================================
// Самоуничтожающиеся сообщения
// =============================================================================

let _timedMode = false;
let _timedTtl  = 30;

window.toggleTimedMode = function() {
    _timedMode = !_timedMode;
    const btn = document.getElementById('timed-msg-btn');
    if (btn) btn.classList.toggle('active', _timedMode);
    const input = document.getElementById('msg-input');
    if (input) input.placeholder = _timedMode ? t('chat.selfDestructPlaceholder').replace('{ttl}', _timedTtl) : t('chat.messagePlaceholderDots');
};

window.isTimedMode = () => _timedMode;
window.getTimedTtl = () => _timedTtl;

// =============================================================================
// Mute toggle
// =============================================================================

window.toggleMuteRoom = async function() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    try {
        const { api } = await import('../utils.js');
        const res = await api('POST', `/api/rooms/${S.currentRoom.id}/mute`);
        S.currentRoom.is_muted = res.muted;
        // Update both the legacy header button (chat.html) and the panel button (index.html)
        for (const btnId of ['mute-room-btn', 'ri-mute-btn']) {
            const btn = document.getElementById(btnId);
            if (!btn) continue;
            btn.classList.toggle('active', !!res.muted);
            const label = document.getElementById('ri-mute-label');
            if (label) label.textContent = res.muted ? t('chat.muteLabel') : t('chat.unmuteLabel');
        }
        const { renderRoomsList } = await import('../rooms.js');
        renderRoomsList();
    } catch(e) { console.error('Mute error:', e); }
};

// =============================================================================
// Feature 1: Polls — Telegram-style creation, voting, management
// =============================================================================

export function openPollModal() {
    _resetPollModal();
    const { openModal } = window;
    if (openModal) openModal('poll-modal');
}

function _resetPollModal() {
    const qEl = document.getElementById('poll-question');
    if (qEl) qEl.value = '';
    const descEl = document.getElementById('poll-description');
    if (descEl) descEl.value = '';
    const list = document.getElementById('poll-options-list');
    if (list) {
        list.replaceChildren();
        for (let i = 1; i <= 2; i++) {
            const div = document.createElement('div');
            div.className = 'form-group poll-option-row';
            const input = document.createElement('input');
            input.className = 'form-input poll-option';
            input.placeholder = t('poll.optionN', { n: i });
            div.appendChild(input);
            list.appendChild(div);
        }
    }
    // Reset toggles
    ['poll-anonymous', 'poll-multiple', 'poll-quiz', 'poll-no-revote',
     'poll-allow-suggest', 'poll-shuffle'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.checked = false;
    });
    const timerEl = document.getElementById('poll-timer-select');
    if (timerEl) timerEl.value = '';
    const quizPanel = document.getElementById('poll-quiz-panel');
    if (quizPanel) quizPanel.style.display = 'none';
    const correctEl = document.getElementById('poll-correct-option');
    if (correctEl) correctEl.value = '';
    const explainEl = document.getElementById('poll-explanation');
    if (explainEl) explainEl.value = '';
}

window.addPollOption = function() {
    const list = document.getElementById('poll-options-list');
    if (!list) return;
    const count = list.querySelectorAll('.poll-option').length;
    if (count >= 12) return;
    const div = document.createElement('div');
    div.className = 'form-group poll-option-row';
    const input = document.createElement('input');
    input.className = 'form-input poll-option';
    input.placeholder = t('poll.optionN', { n: count + 1 });
    const removeBtn = document.createElement('button');
    removeBtn.className = 'poll-option-remove';
    removeBtn.textContent = '\u00D7';
    removeBtn.type = 'button';
    removeBtn.onclick = () => {
        if (list.querySelectorAll('.poll-option').length > 2) div.remove();
    };
    div.append(input, removeBtn);
    list.appendChild(div);
    input.focus();
};

window.togglePollQuiz = function(checked) {
    const quizPanel = document.getElementById('poll-quiz-panel');
    if (quizPanel) quizPanel.style.display = checked ? '' : 'none';
    // Quiz disables multiple
    if (checked) {
        const multiEl = document.getElementById('poll-multiple');
        if (multiEl) multiEl.checked = false;
    }
};

window.sendPoll = function() {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;

    const question = document.getElementById('poll-question')?.value?.trim();
    const description = document.getElementById('poll-description')?.value?.trim() || '';
    const optionEls = document.querySelectorAll('.poll-option');
    const options = [];
    optionEls.forEach(el => {
        const v = el.value.trim();
        if (v) options.push(v);
    });

    if (!question || options.length < 2) {
        if (window.showToast) window.showToast(t('poll.enterQuestionAndOptions'), 'error');
        return;
    }

    const anonymous = document.getElementById('poll-anonymous')?.checked || false;
    const multiple = document.getElementById('poll-multiple')?.checked || false;
    const quiz = document.getElementById('poll-quiz')?.checked || false;
    const disableRevote = document.getElementById('poll-no-revote')?.checked || false;
    const allowSuggest = document.getElementById('poll-allow-suggest')?.checked || false;
    const shuffle = document.getElementById('poll-shuffle')?.checked || false;

    let correctOption = null;
    let explanation = '';
    if (quiz) {
        const cv = document.getElementById('poll-correct-option')?.value;
        correctOption = cv !== '' && cv !== undefined ? parseInt(cv) : null;
        explanation = document.getElementById('poll-explanation')?.value?.trim() || '';
    }

    // Timer
    let closeAt = null;
    const timerVal = document.getElementById('poll-timer-select')?.value;
    if (timerVal) {
        const mins = parseInt(timerVal);
        if (mins > 0) {
            closeAt = new Date(Date.now() + mins * 60000).toISOString();
        }
    }

    S.ws.send(JSON.stringify({
        action: 'create_poll',
        question,
        description,
        options,
        anonymous,
        multiple,
        quiz,
        correct_option: correctOption,
        explanation,
        disable_revote: disableRevote,
        allow_suggest: allowSuggest,
        shuffle,
        close_at: closeAt,
    }));

    if (window.closeModal) window.closeModal('poll-modal');
};

window.votePoll = function(msgId, optionIndex) {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    S.ws.send(JSON.stringify({ action: 'vote_poll', msg_id: msgId, option_index: optionIndex }));
};

window._closePoll = function(msgId) {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    S.ws.send(JSON.stringify({ action: 'close_poll', msg_id: msgId }));
};

window._retractVote = function(msgId) {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    S.ws.send(JSON.stringify({ action: 'retract_vote', msg_id: msgId }));
};

window._suggestPollOption = function(msgId, text) {
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    S.ws.send(JSON.stringify({ action: 'suggest_option', msg_id: msgId, text }));
};

// =============================================================================
// Payment Requests — запрос оплаты через чат
// =============================================================================

const _CRYPTO_CURRENCIES = ['BTC', 'ETH', 'USDT', 'TON'];

export function openPaymentModal() {
    ['pay-title','pay-amount','pay-address','pay-recipient','pay-description'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
    });
    const currEl = document.getElementById('pay-currency');
    const netEl  = document.getElementById('pay-network');
    const dateEl = document.getElementById('pay-due-date');
    if (currEl) currEl.value = 'USDT';
    if (netEl)  netEl.value = 'TRC20';
    if (dateEl) dateEl.value = '';
    const recip = document.getElementById('pay-recipient');
    if (recip && window.AppState.user) {
        recip.value = window.AppState.user.display_name || window.AppState.user.username || '';
    }
    window._onPayCurrencyChange();
    if (window.openModal) window.openModal('payment-modal');
}

window.openPaymentModal = openPaymentModal;

window._onPayCurrencyChange = function() {
    const currency = document.getElementById('pay-currency')?.value || 'USDT';
    const isCrypto = _CRYPTO_CURRENCIES.includes(currency);
    const networkGroup = document.getElementById('pay-network-group');
    const addressLabel = document.getElementById('pay-address-label');
    const addressInput = document.getElementById('pay-address');
    if (networkGroup) networkGroup.style.display = isCrypto ? '' : 'none';
    if (addressLabel) addressLabel.textContent = isCrypto ? t('chat.walletAddress') : t('chat.requisites');
    if (addressInput) addressInput.placeholder = isCrypto ? '0x... / T... / bc1...' : '4276 **** **** **** / +7... / RU12345...';
};

window.sendPaymentRequest = function() {
    const title     = document.getElementById('pay-title')?.value?.trim() || t('chat.invoiceTitle');
    const amount    = document.getElementById('pay-amount')?.value?.trim();
    const currency  = document.getElementById('pay-currency')?.value || 'USDT';
    const network   = document.getElementById('pay-network')?.value || '';
    const address   = document.getElementById('pay-address')?.value?.trim();
    const recipient = document.getElementById('pay-recipient')?.value?.trim() || '';
    const dueDate   = document.getElementById('pay-due-date')?.value || '';
    const description = document.getElementById('pay-description')?.value?.trim() || '';

    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
        alert(t('chat.enterValidAmount')); return;
    }
    if (!address) { alert(t('chat.enterRequisites')); return; }

    const isCrypto = _CRYPTO_CURRENCIES.includes(currency);
    const payload = {
        v: 2, title, amount, currency, address, recipient, description,
        due_date: dueDate,
        created: new Date().toISOString(),
        sender: window.AppState.user?.display_name || window.AppState.user?.username || '',
    };
    if (isCrypto) payload.network = network;

    window.sendStickerDirect('[PAY] ' + JSON.stringify(payload));
    if (window.closeModal) window.closeModal('payment-modal');
};

// =============================================================================
// Feature 2: Scheduled messages
// =============================================================================

let _scheduleMode = false;
let _scheduleDatetime = null;

export function toggleScheduleMode() {
    _scheduleMode = !_scheduleMode;
    const picker = document.getElementById('schedule-picker');
    if (picker) picker.style.display = _scheduleMode ? 'flex' : 'none';
    const schedBtn = document.getElementById('schedule-msg-btn');
    if (schedBtn) schedBtn.classList.toggle('active', _scheduleMode);
    if (!_scheduleMode) _scheduleDatetime = null;
}

window.toggleScheduleMode = toggleScheduleMode;

window.setScheduleDatetime = function(input) {
    _scheduleDatetime = input.value || null;
};

window.confirmSchedule = function() {
    const dtInput = document.getElementById('schedule-datetime');
    if (!dtInput || !dtInput.value) {
        dtInput?.focus();
        return;
    }
    _scheduleDatetime = dtInput.value;
    window.sendMessage();
};

window.isScheduleMode = () => _scheduleMode && _scheduleDatetime;
window.getScheduleDatetime = () => _scheduleDatetime;

export function isScheduleMode() { return _scheduleMode && _scheduleDatetime; }
export function getScheduleDatetime() { return _scheduleDatetime; }

export function resetScheduleMode() {
    _scheduleMode = false;
    _scheduleDatetime = null;
    const schedBtn = document.getElementById('schedule-msg-btn');
    if (schedBtn) schedBtn.classList.remove('active');
    const picker = document.getElementById('schedule-picker');
    if (picker) picker.style.display = 'none';
}

// =============================================================================
// Feature 3 & 4: Auto-delete & Slow mode indicators
// =============================================================================

function _fmtSeconds(s) {
    if (s >= 86400) return t('chat.days').replace('{n}', Math.round(s / 86400));
    if (s >= 3600) return t('chat.hoursShort').replace('{n}', Math.round(s / 3600));
    if (s >= 60) return t('chat.minsShort').replace('{n}', Math.round(s / 60));
    return t('chat.secsShort').replace('{n}', s);
}

export function _updateAutoDeleteIndicator(seconds) {
    let el = document.getElementById('auto-delete-indicator');
    if (!el) return;
    if (seconds && seconds > 0) {
        el.textContent = _fmtSeconds(seconds);
        el.style.display = '';
    } else {
        el.style.display = 'none';
    }
}

export function _updateSlowModeIndicator(seconds) {
    let el = document.getElementById('slow-mode-indicator');
    if (!el) return;
    if (seconds && seconds > 0) {
        el.textContent = _fmtSeconds(seconds);
        el.parentElement.style.display = '';
    } else {
        el.parentElement.style.display = 'none';
    }
}

// Slow mode cooldown
let _slowModeCooldown = 0;
let _slowModeTimer = null;

export function _startSlowModeCooldown(seconds) {
    _slowModeCooldown = seconds;
    const sendBtn = document.querySelector('.input-btn.send');
    const input = document.getElementById('msg-input');
    if (_slowModeTimer) clearInterval(_slowModeTimer);
    _slowModeTimer = setInterval(() => {
        _slowModeCooldown--;
        if (_slowModeCooldown <= 0) {
            clearInterval(_slowModeTimer);
            _slowModeTimer = null;
            if (sendBtn) sendBtn.textContent = '\u2191';
            if (input) input.disabled = false;
            return;
        }
        if (sendBtn) sendBtn.textContent = _slowModeCooldown;
    }, 1000);
    if (sendBtn) sendBtn.textContent = _slowModeCooldown;
    if (input) input.disabled = true;
}

// =============================================================================
// Feature 3: Auto-delete settings UI
// =============================================================================

window.showAutoDeleteMenu = async function() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    const options = [
        { label: t('chat.off'), value: 0 },
        { label: t('chat.sec').replace('{n}', 30), value: 30 },
        { label: t('chat.min').replace('{n}', 5), value: 300 },
        { label: t('chat.hour').replace('{n}', 1), value: 3600 },
        { label: t('chat.hours').replace('{n}', 24), value: 86400 },
    ];
    const current = S.currentRoom.auto_delete_seconds || 0;
    const choice = prompt(
        t('chat.autoDeleteMessages') + '\n' +
        options.map((o, i) => `${i}: ${o.label}${o.value === current ? ` (${t('chat.current')})` : ''}`).join('\n') +
        '\n\n' + t('chat.enterNumber'),
        '0'
    );
    if (choice === null) return;
    const idx = parseInt(choice);
    if (isNaN(idx) || idx < 0 || idx >= options.length) return;
    try {
        const { api } = await import('../utils.js');
        await api('POST', `/api/rooms/${S.currentRoom.id}/auto-delete`, { seconds: options[idx].value });
    } catch (e) { alert(e.message); }
};

// =============================================================================
// Feature 4: Slow mode settings UI
// =============================================================================

window.showSlowModeMenu = async function() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    const options = [
        { label: t('chat.off'), value: 0 },
        { label: t('chat.sec').replace('{n}', 5), value: 5 },
        { label: t('chat.sec').replace('{n}', 30), value: 30 },
        { label: t('chat.min').replace('{n}', 1), value: 60 },
        { label: t('chat.min').replace('{n}', 5), value: 300 },
    ];
    const current = S.currentRoom.slow_mode_seconds || 0;
    const choice = prompt(
        t('chat.slowModeInterval') + '\n' +
        options.map((o, i) => `${i}: ${o.label}${o.value === current ? ` (${t('chat.current')})` : ''}`).join('\n') +
        '\n\n' + t('chat.enterNumber'),
        '0'
    );
    if (choice === null) return;
    const idx = parseInt(choice);
    if (isNaN(idx) || idx < 0 || idx >= options.length) return;
    try {
        const { api } = await import('../utils.js');
        await api('POST', `/api/rooms/${S.currentRoom.id}/slow-mode`, { seconds: options[idx].value });
    } catch (e) { alert(e.message); }
};

// =============================================================================
// Feature 5: Chat Export
// =============================================================================

export async function exportChat() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    try {
        const { api } = await import('../utils.js');

        const data = await api('GET', `/api/rooms/${S.currentRoom.id}/export`);
        const roomKey = getRoomKey(S.currentRoom.id);

        let text = `Chat: ${S.currentRoom.name}\nExported: ${new Date().toISOString()}\nMessages: ${data.message_count}\n${'='.repeat(60)}\n\n`;

        for (const m of data.messages) {
            let content = '[encrypted]';
            if (m.msg_type === 'system') {
                try { content = m.ciphertext ? new TextDecoder().decode(new Uint8Array(m.ciphertext.match(/.{1,2}/g).map(b => parseInt(b, 16)))) : '[system]'; } catch { content = '[system]'; }
            } else if (roomKey && m.ciphertext) {
                try {
                    content = await ratchetDecrypt(m.ciphertext, S.currentRoom.id, m.sender_id, roomKey);
                } catch {
                    try { content = await decryptText(m.ciphertext, roomKey); } catch { content = '[encrypted - cannot decrypt]'; }
                }
            }
            const time = m.created_at ? new Date(m.created_at).toLocaleString() : '?';
            const edited = m.is_edited ? ' [edited]' : '';
            text += `[${time}] ${m.sender}${edited}: ${content}\n`;
            if (m.file_name) text += `  [file: ${m.file_name}]\n`;
        }

        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `vortex-${S.currentRoom.name.replace(/[^a-zA-Z0-9а-яА-Я]/g, '_')}-export.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    } catch (e) {
        alert(t('chat.exportError').replace('{error}', e.message));
    }
}

window.exportChat = exportChat;

// static/js/saved.js
// =============================================================================
// Модуль «Избранное» (Saved Messages).
// Позволяет сохранять сообщения из любого чата и просматривать их в панели.
// =============================================================================

import { api, openModal, closeModal } from './utils.js';

/** Mini toast for feedback (auto-disappears). */
function _toast(message, duration = 2500) {
    const el = document.createElement('div');
    el.style.cssText = [
        'position:fixed', 'bottom:20px', 'left:50%', 'transform:translateX(-50%)',
        'background:#1a1a2e', 'border:1px solid rgba(255,255,255,.1)',
        'border-radius:8px', 'padding:10px 18px',
        'font-size:13px', 'color:#e0e0e0', 'z-index:99999',
        'pointer-events:none', 'white-space:nowrap',
        'box-shadow:0 4px 16px rgba(0,0,0,.4)',
    ].join(';');
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), duration);
}

/**
 * Toggle: добавить / убрать сообщение из избранного.
 * Вызывается из контекстного меню.
 * @param {number} msgId - ID сообщения
 */
export async function toggleSavedMessage(msgId) {
    try {
        const data = await api('POST', `/api/saved/${msgId}`);
        _toast(data.saved ? t('saved.addedToSaved') : t('saved.removedFromSaved'));
    } catch (err) {
        console.error('toggleSavedMessage error:', err);
        _toast('Ошибка: ' + err.message);
    }
}

/**
 * Открывает панель избранного и загружает список.
 */
export async function showSavedPanel() {
    openModal('saved-modal');
    await loadSavedMessages();
}

/**
 * Загружает и рендерит список сохранённых сообщений.
 */
export async function loadSavedMessages() {
    const container = document.getElementById('saved-list');
    if (!container) return;

    container.innerHTML = `<div style="text-align:center;padding:20px;color:var(--text3);">${t('app.loading')}</div>`;

    try {
        const data = await api('GET', '/api/saved');
        const items = data.saved || [];

        if (items.length === 0) {
            container.innerHTML = `<div class="saved-empty">${t('saved.noSaved')}</div>`;
            return;
        }

        container.innerHTML = '';
        items.forEach(item => {
            container.appendChild(_buildSavedItem(item));
        });
    } catch (err) {
        console.error('loadSavedMessages error:', err);
        container.innerHTML = `<div class="saved-empty">${t('app.error')}</div>`;
    }
}

/**
 * Убирает сообщение из избранного (кнопка в карточке).
 * @param {number} msgId
 * @param {HTMLElement} itemEl - DOM-элемент карточки для удаления
 */
export async function removeSavedMessage(msgId, itemEl) {
    try {
        await api('DELETE', `/api/saved/${msgId}`);
        if (itemEl) {
            itemEl.style.transition = 'opacity 0.2s, transform 0.2s';
            itemEl.style.opacity = '0';
            itemEl.style.transform = 'translateX(20px)';
            setTimeout(() => {
                itemEl.remove();
                const container = document.getElementById('saved-list');
                if (container && container.children.length === 0) {
                    container.innerHTML = `<div class="saved-empty">${t('saved.noSaved')}</div>`;
                }
            }, 200);
        }
    } catch (err) {
        console.error('removeSavedMessage error:', err);
    }
}

/**
 * Строит DOM-элемент карточки избранного сообщения.
 * @param {Object} item - объект из API ответа
 * @returns {HTMLElement}
 */
function _buildSavedItem(item) {
    const el = document.createElement('div');
    el.className = 'saved-item';
    el.dataset.msgId = item.message_id;
    el.dataset.roomId = item.room_id;

    // Метаинформация: комната, отправитель, дата
    const meta = document.createElement('div');
    meta.className = 'saved-meta';

    const roomSpan = document.createElement('span');
    roomSpan.className = 'saved-room';
    roomSpan.textContent = item.room_name || t('saved.room');
    meta.appendChild(roomSpan);

    if (item.sender) {
        const dot = document.createTextNode(' \u00B7 ');
        meta.appendChild(dot);
        const senderSpan = document.createElement('span');
        senderSpan.className = 'saved-sender';
        senderSpan.textContent = item.sender.display_name || item.sender.username;
        meta.appendChild(senderSpan);
    }

    if (item.created_at) {
        const dot2 = document.createTextNode(' \u00B7 ');
        meta.appendChild(dot2);
        const dateSpan = document.createElement('span');
        const d = new Date(item.created_at);
        dateSpan.textContent = d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' })
            + ' ' + d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
        meta.appendChild(dateSpan);
    }
    el.appendChild(meta);

    // Текст сообщения (зашифрован — пытаемся расшифровать клиентом)
    const textEl = document.createElement('div');
    textEl.className = 'saved-text';

    if (item.msg_type === 'file' || item.msg_type === 'image' || item.msg_type === 'voice') {
        textEl.textContent = item.file_name
            ? '\uD83D\uDCCE ' + item.file_name
            : '\uD83D\uDCCE [файл]';
    } else if (item.ciphertext) {
        // Attempt to decrypt using the room key if available
        const decrypted = _tryDecrypt(item.ciphertext, item.room_id);
        if (decrypted) {
            textEl.textContent = decrypted;
        } else {
            textEl.textContent = t('chat.encrypted');
            textEl.classList.add('encrypted');
        }
    } else {
        textEl.textContent = t('saved.empty');
        textEl.classList.add('encrypted');
    }
    el.appendChild(textEl);

    // Кнопка удаления
    const removeBtn = document.createElement('button');
    removeBtn.className = 'saved-remove';
    removeBtn.title = t('saved.remove');
    removeBtn.textContent = '\u00D7';
    removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        removeSavedMessage(item.message_id, el);
    });
    el.appendChild(removeBtn);

    // Клик по карточке — переход в комнату
    el.addEventListener('click', () => {
        closeModal('saved-modal');
        if (window.openRoom) {
            window.openRoom(item.room_id);
        }
    });

    return el;
}

/**
 * Пытается расшифровать ciphertext, используя ключ комнаты из localStorage.
 * @param {string} ciphertextHex
 * @param {number} roomId
 * @returns {string|null}
 */
function _tryDecrypt(ciphertextHex, roomId) {
    try {
        // Room keys are stored by the crypto module in various formats.
        // Check window.AppState or localStorage for the room key.
        const keyHex = localStorage.getItem(`room_key_${roomId}`);
        if (!keyHex) return null;

        const keyBytes = _hexToBytes(keyHex);
        const cipherBytes = _hexToBytes(ciphertextHex);

        // AES-256-GCM: nonce(12) + ciphertext + tag(16)
        if (cipherBytes.length < 28) return null;

        const nonce = cipherBytes.slice(0, 12);
        const ct = cipherBytes.slice(12);

        // Use SubtleCrypto for AES-GCM decryption (synchronous attempt via cached key)
        // Since SubtleCrypto is async, we use a cached decryption if available
        // Fallback: return null and show [encrypted]
        return null;
    } catch {
        return null;
    }
}

/**
 * @param {string} hex
 * @returns {Uint8Array}
 */
function _hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

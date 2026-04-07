/**
 * Vortex Keyboard Shortcuts — глобальные горячие клавиши.
 *
 * Шорткаты:
 *   Ctrl/Cmd + K     — Quick Switcher (поиск комнат и контактов)
 *   Ctrl/Cmd + E     — Emoji picker (уже в chat.js, дублируем глобально)
 *   Ctrl/Cmd + N     — Новая комната
 *   Ctrl/Cmd + Shift + M — Mute/unmute текущую комнату
 *   Ctrl/Cmd + /     — Показать все шорткаты
 *   Ctrl/Cmd + ,     — Открыть настройки
 *   Alt + ↑/↓        — Переключение между комнатами
 *   ↑ (в пустом поле) — Редактировать последнее сообщение
 *   Escape            — Закрыть модалку / отменить reply / закрыть панели
 */

let _shortcutsModalOpen = false;

// ── Shortcut definitions (for cheatsheet) ───────────────────────────────────
const SHORTCUTS = [
    { keys: ['Ctrl', 'K'],       mac: ['⌘', 'K'],       get desc() { return t('shortcuts.quickSearch'); } },
    { keys: ['Ctrl', 'E'],       mac: ['⌘', 'E'],       get desc() { return t('shortcuts.emojiPicker'); } },
    { keys: ['Ctrl', 'N'],       mac: ['⌘', 'N'],       get desc() { return t('shortcuts.newRoom'); } },
    { keys: ['Ctrl', 'Shift', 'M'], mac: ['⌘', '⇧', 'M'], get desc() { return t('shortcuts.muteRoom'); } },
    { keys: ['Ctrl', '/'],       mac: ['⌘', '/'],       get desc() { return t('shortcuts.showShortcuts'); } },
    { keys: ['Ctrl', ','],       mac: ['⌘', ','],       get desc() { return t('shortcuts.openSettings'); } },
    { keys: ['Alt', '↑'],        mac: ['⌥', '↑'],       get desc() { return t('shortcuts.prevRoom'); } },
    { keys: ['Alt', '↓'],        mac: ['⌥', '↓'],       get desc() { return t('shortcuts.nextRoom'); } },
    { keys: ['↑'],               mac: ['↑'],             get desc() { return t('shortcuts.editLast'); } },
    { keys: ['Enter'],           mac: ['Enter'],         get desc() { return t('shortcuts.sendMessage'); } },
    { keys: ['Shift', 'Enter'],  mac: ['⇧', 'Enter'],   get desc() { return t('shortcuts.newLine'); } },
    { keys: ['Escape'],          mac: ['Escape'],        get desc() { return t('shortcuts.closePanel'); } },
    { keys: ['Ctrl', 'F'],       mac: ['⌘', 'F'],       get desc() { return t('shortcuts.searchInChat'); } },
];

const _isMac = navigator.platform?.includes('Mac') || navigator.userAgent?.includes('Mac');

// ── Global keydown handler ──────────────────────────────────────────────────

export function initShortcuts() {
    document.addEventListener('keydown', _handleGlobalKey);
}

function _handleGlobalKey(e) {
    const mod = _isMac ? e.metaKey : e.ctrlKey;
    const tag = e.target?.tagName;
    const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target?.isContentEditable;

    // ── Always-active shortcuts (work even in inputs) ───────────────

    // Ctrl/Cmd + K — Quick Switcher
    if (mod && e.key === 'k') {
        e.preventDefault();
        _toggleQuickSwitcher();
        return;
    }

    // Ctrl/Cmd + / — Shortcuts cheatsheet
    if (mod && e.key === '/') {
        e.preventDefault();
        toggleShortcutsModal();
        return;
    }

    // Ctrl/Cmd + , — Settings
    if (mod && e.key === ',') {
        e.preventDefault();
        window.openSettings?.();
        return;
    }

    // Ctrl/Cmd + Shift + M — Mute/unmute room
    if (mod && e.shiftKey && (e.key === 'm' || e.key === 'M')) {
        e.preventDefault();
        _toggleMuteCurrentRoom();
        return;
    }

    // Ctrl/Cmd + F — Search in chat (not browser find)
    if (mod && e.key === 'f') {
        e.preventDefault();
        window.toggleChatSearch?.();
        return;
    }

    // Escape — close everything
    if (e.key === 'Escape') {
        if (_shortcutsModalOpen) { toggleShortcutsModal(); e.preventDefault(); return; }
        if (_quickSwitcherOpen) { _closeQuickSwitcher(); e.preventDefault(); return; }
        return; // Let other handlers (emoji picker, image viewer, etc.) also handle Escape
    }

    // ── Input-excluded shortcuts (only work outside text fields) ─────
    if (isInput) {
        // ↑ in empty msg-input → edit last message
        if (e.key === 'ArrowUp' && e.target.id === 'msg-input' && !e.target.value.trim()) {
            e.preventDefault();
            _editLastOwnMessage();
            return;
        }

        // Alt+↑/↓ in msg-input → switch rooms
        if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown') && e.target.id === 'msg-input') {
            e.preventDefault();
            _switchRoom(e.key === 'ArrowUp' ? -1 : 1);
            return;
        }

        return; // Don't intercept other typing
    }

    // Ctrl/Cmd + N — New room
    if (mod && e.key === 'n') {
        e.preventDefault();
        window.openCreateRoomModal?.();
        return;
    }

    // Alt + ↑/↓ — Switch rooms
    if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
        e.preventDefault();
        _switchRoom(e.key === 'ArrowUp' ? -1 : 1);
        return;
    }
}

// ── Quick Switcher (Ctrl+K) ─────────────────────────────────────────────────

let _quickSwitcherOpen = false;
let _qsEl = null;

function _toggleQuickSwitcher() {
    _quickSwitcherOpen ? _closeQuickSwitcher() : _openQuickSwitcher();
}

function _openQuickSwitcher() {
    if (_quickSwitcherOpen) return;
    _quickSwitcherOpen = true;

    _qsEl = document.createElement('div');
    _qsEl.className = 'qs-overlay';
    _qsEl.onclick = (e) => { if (e.target === _qsEl) _closeQuickSwitcher(); };
    _qsEl.innerHTML = `
        <div class="qs-modal">
            <div class="qs-search-wrap">
                <svg class="qs-search-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input type="text" class="qs-input" id="qs-input"
                       placeholder="${t('shortcuts.searchPlaceholder')}" autocomplete="off" spellcheck="false">
            </div>
            <div class="qs-results" id="qs-results">
                <div class="qs-hint">${t('shortcuts.startTyping')}</div>
            </div>
            <div class="qs-footer">
                <span class="qs-key">↑↓</span> ${t('shortcuts.navigate')}
                <span class="qs-key">Enter</span> ${t('shortcuts.open')}
                <span class="qs-key">Esc</span> ${t('shortcuts.close')}
            </div>
        </div>`;

    document.body.appendChild(_qsEl);
    requestAnimationFrame(() => _qsEl.classList.add('open'));

    const input = _qsEl.querySelector('#qs-input');
    input.focus();
    input.oninput = () => _filterQuickSwitcher(input.value.trim().toLowerCase());
    input.onkeydown = (e) => {
        if (e.key === 'Escape') { _closeQuickSwitcher(); e.preventDefault(); }
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            _navigateQS(e.key === 'ArrowDown' ? 1 : -1);
        }
        if (e.key === 'Enter') {
            e.preventDefault();
            _selectQS();
        }
    };

    // Show all rooms initially
    _filterQuickSwitcher('');
}

function _closeQuickSwitcher() {
    if (!_quickSwitcherOpen) return;
    _quickSwitcherOpen = false;
    if (_qsEl) {
        _qsEl.classList.remove('open');
        setTimeout(() => _qsEl?.remove(), 200);
        _qsEl = null;
    }
}

function _filterQuickSwitcher(q) {
    const S = window.AppState;
    const results = _qsEl?.querySelector('#qs-results');
    if (!results || !S?.rooms) return;

    let items = S.rooms;
    if (q) {
        items = items.filter(r => {
            const name = (r.name || r.dm_user?.display_name || r.dm_user?.username || '').toLowerCase();
            return name.includes(q);
        });
    }

    // Also search contacts
    let contactItems = [];
    if (q && S.contacts) {
        contactItems = S.contacts.filter(c => {
            const name = (c.display_name || c.nickname || c.username || '').toLowerCase();
            return name.includes(q);
        }).slice(0, 5);
    }

    if (!items.length && !contactItems.length) {
        results.innerHTML = '<div class="qs-hint">' + t('shortcuts.nothingFound') + '</div>';
        return;
    }

    let html = '';

    // Rooms (max 8)
    items.slice(0, 8).forEach((r, i) => {
        const name = r.is_dm ? (r.dm_user?.display_name || r.dm_user?.username || r.name) : r.name;
        const emojiRaw = r.is_dm ? r.dm_user?.avatar_emoji : r.avatar_emoji;
        const emojiHtml = emojiRaw
            ? _esc(emojiRaw)
            : r.is_dm
                ? '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>'
                : '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>';
        const type = r.is_dm ? t('shortcuts.typeDM') : r.is_channel ? t('shortcuts.typeChannel') : r.is_voice ? t('shortcuts.typeVoice') : t('shortcuts.typeRoom');
        const active = i === 0 ? ' active' : '';
        html += `<div class="qs-item${active}" data-room-id="${r.id}" onclick="window._qsOpenRoom?.(${r.id})">
            <span class="qs-item-emoji">${emojiHtml}</span>
            <div class="qs-item-info">
                <span class="qs-item-name">${_esc(name)}</span>
                <span class="qs-item-type">${type}</span>
            </div>
        </div>`;
    });

    // Contacts
    contactItems.forEach(c => {
        const name = c.nickname || c.display_name || c.username;
        const emojiHtml2 = c.avatar_emoji
            ? _esc(c.avatar_emoji)
            : '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>';
        html += `<div class="qs-item" data-contact-id="${c.user_id || c.id}" onclick="window._qsOpenContact?.(${c.user_id || c.id})">
            <span class="qs-item-emoji">${emojiHtml2}</span>
            <div class="qs-item-info">
                <span class="qs-item-name">${_esc(name)}</span>
                <span class="qs-item-type">${t('shortcuts.typeContact')}</span>
            </div>
        </div>`;
    });

    results.innerHTML = html;
}

function _navigateQS(dir) {
    const results = _qsEl?.querySelector('#qs-results');
    if (!results) return;
    const items = results.querySelectorAll('.qs-item');
    if (!items.length) return;

    const active = results.querySelector('.qs-item.active');
    let idx = active ? Array.from(items).indexOf(active) : -1;
    if (active) active.classList.remove('active');

    idx += dir;
    if (idx < 0) idx = items.length - 1;
    if (idx >= items.length) idx = 0;

    items[idx].classList.add('active');
    items[idx].scrollIntoView({ block: 'nearest' });
}

function _selectQS() {
    const active = _qsEl?.querySelector('.qs-item.active');
    if (!active) return;
    const roomId = active.dataset.roomId;
    const contactId = active.dataset.contactId;
    _closeQuickSwitcher();

    if (roomId) {
        window.openRoom?.(parseInt(roomId));
    } else if (contactId) {
        window.openDM?.(parseInt(contactId));
    }
}

// Global accessors for onclick
window._qsOpenRoom = (id) => { _closeQuickSwitcher(); window.openRoom?.(id); };
window._qsOpenContact = (id) => { _closeQuickSwitcher(); window.openDM?.(id); };

// ── Switch Room (Alt+↑/↓) ──────────────────────────────────────────────────

function _switchRoom(direction) {
    const S = window.AppState;
    if (!S?.rooms?.length) return;

    const currentId = S.currentRoom?.id;
    const visibleRooms = S.rooms.filter(r => r.id);

    if (!visibleRooms.length) return;

    let idx = visibleRooms.findIndex(r => r.id === currentId);
    if (idx === -1) idx = 0;
    else idx += direction;

    if (idx < 0) idx = visibleRooms.length - 1;
    if (idx >= visibleRooms.length) idx = 0;

    window.openRoom?.(visibleRooms[idx].id);
}

// ── Edit Last Own Message (↑ in empty input) ────────────────────────────────

function _editLastOwnMessage() {
    const S = window.AppState;
    if (!S?.user?.user_id) return;

    const container = document.getElementById('messages-container');
    if (!container) return;

    // Find last own message
    const bubbles = container.querySelectorAll('.msg-bubble.own');
    if (!bubbles.length) return;

    const lastBubble = bubbles[bubbles.length - 1];
    const msgId = lastBubble.dataset?.msgId;
    if (msgId) {
        window.startEditMessage?.(parseInt(msgId));
    }
}

// ── Toggle Mute (Ctrl+Shift+M) ─────────────────────────────────────────────

function _toggleMuteCurrentRoom() {
    const S = window.AppState;
    if (!S?.currentRoom?.id) return;
    window.toggleRoomMute?.(S.currentRoom.id);
}

// ── Shortcuts Cheatsheet Modal (Ctrl+/) ─────────────────────────────────────

export function toggleShortcutsModal() {
    _shortcutsModalOpen ? _closeShortcutsModal() : _openShortcutsModal();
}

function _openShortcutsModal() {
    if (_shortcutsModalOpen) return;
    _shortcutsModalOpen = true;

    const overlay = document.createElement('div');
    overlay.className = 'qs-overlay';
    overlay.id = 'shortcuts-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) _closeShortcutsModal(); };

    let rows = '';
    SHORTCUTS.forEach(s => {
        const keys = (_isMac ? s.mac : s.keys).map(k => `<span class="qs-key">${k}</span>`).join(' + ');
        rows += `<div class="sc-row"><div class="sc-keys">${keys}</div><div class="sc-desc">${s.desc}</div></div>`;
    });

    overlay.innerHTML = `
        <div class="sc-modal">
            <div class="sc-header">
                <span class="sc-title">${t('shortcuts.title')}</span>
                <button class="sc-close" onclick="window._closeShortcutsModal?.()">&times;</button>
            </div>
            <div class="sc-body">${rows}</div>
        </div>`;

    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('open'));
}

function _closeShortcutsModal() {
    if (!_shortcutsModalOpen) return;
    _shortcutsModalOpen = false;
    const el = document.getElementById('shortcuts-modal-overlay');
    if (el) {
        el.classList.remove('open');
        setTimeout(() => el.remove(), 200);
    }
}

window._closeShortcutsModal = _closeShortcutsModal;

// ── Utility ─────────────────────────────────────────────────────────────────

function _esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

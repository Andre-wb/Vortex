import { Haptic, switchBottomTab, loadRecentCalls, filterCalls, clearCallHistory, callUser } from './core.js';

// ══════════════════════════════════════════════════════════════════════════════
// 11. Contacts Tab — fullscreen contact management
// ══════════════════════════════════════════════════════════════════════════════

let _allContacts = [];

async function loadContacts() {
    const container = document.getElementById('contacts-list');
    const empty = document.getElementById('contacts-empty');
    if (!container) return;

    try {
        const resp = await fetch('/api/contacts', { credentials: 'include' });
        if (!resp.ok) return;
        const data = await resp.json();
        _allContacts = data.contacts || [];
        _renderContacts(_allContacts);
    } catch (e) {
        console.warn('Failed to load contacts:', e);
    }
}

function _renderContacts(contacts) {
    const container = document.getElementById('contacts-list');
    const empty = document.getElementById('contacts-empty');
    if (!container) return;

    if (!contacts.length) {
        container.innerHTML = '';
        if (empty) empty.style.display = 'flex';
        return;
    }
    if (empty) empty.style.display = 'none';

    // Group by first letter
    const grouped = {};
    contacts.forEach(c => {
        const name = c.nickname || c.display_name || c.username || '?';
        const letter = name[0].toUpperCase();
        if (!grouped[letter]) grouped[letter] = [];
        grouped[letter].push(c);
    });

    const letters = Object.keys(grouped).sort();
    let html = '';

    letters.forEach(letter => {
        html += `<div class="contact-letter-header">${letter}</div>`;
        grouped[letter].forEach(c => {
            const name = _esc(c.nickname || c.display_name || c.username);
            const username = _esc(c.username || '');
            const avatarInner = c.avatar_url
                ? `<img src="${_esc(c.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
                : (c.avatar_emoji ? _esc(c.avatar_emoji) : '<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>');
            const presence = c.is_online ? 'online' : 'offline';
            const status = c.custom_status ? _esc(c.custom_status) : '';
            const statusEmoji = c.status_emoji ? _esc(c.status_emoji) + ' ' : '';

            html += `<div class="contact-item" onclick="openContactDM(${c.user_id})">
                <div class="avatar-status-wrap">
                    <div class="avatar">${avatarInner}</div>
                    <div class="status-dot ${presence}"></div>
                </div>
                <div class="contact-info">
                    <div class="contact-name">${name}</div>
                    ${status ? `<div class="contact-status-line">${statusEmoji}${status}</div>` : ''}
                    <div class="contact-meta">@${username}</div>
                </div>
                <div class="contact-actions">
                    <button class="btn-icon" onclick="event.stopPropagation();callContact(${c.user_id},'audio')" title="${t('calls.callBack')}">
                        <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M20.01 15.38c-1.23 0-2.42-.2-3.53-.56-.35-.12-.74-.03-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z"/></svg>
                    </button>
                    <button class="btn-icon" onclick="event.stopPropagation();callContact(${c.user_id},'video')" title="${t('calls.callBack')}">
                        <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>
                    </button>
                    <button class="btn-icon danger" onclick="event.stopPropagation();showContactMenu(event,${c.contact_id},${c.user_id},'${_esc(name)}')" title="...">
                        <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>
                    </button>
                </div>
            </div>`;
        });
    });

    container.innerHTML = html;
}

function searchContacts(query) {
    if (!query) { _renderContacts(_allContacts); return; }
    const q = query.toLowerCase();
    const filtered = _allContacts.filter(c => {
        const name = (c.nickname || c.display_name || c.username || '').toLowerCase();
        return name.includes(q);
    });
    _renderContacts(filtered);
}

async function searchUsersForAdd(query) {
    const container = document.getElementById('add-contact-results');
    if (!container || !query || query.length < 2) { if (container) container.innerHTML = ''; return; }

    try {
        const resp = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`, { credentials: 'include' });
        if (!resp.ok) return;
        const data = await resp.json();
        const users = data.users || data.results || [];

        container.innerHTML = users.map(u => {
            const name = _esc(u.display_name || u.username);
            const avatarInner = u.avatar_url
                ? `<img src="${_esc(u.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
                : (u.avatar_emoji ? _esc(u.avatar_emoji) : '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>');
            return `<div class="search-result" onclick="addContactById(${u.user_id || u.id})" style="cursor:pointer;">
                <div class="avatar">${avatarInner}</div>
                <div class="search-result-info">
                    <div class="search-result-name">${name}</div>
                    <div class="search-result-meta">@${_esc(u.username || '')}</div>
                </div>
                <button class="contacts-add-btn" style="padding:6px 14px;font-size:11px;">${t('contacts.add')}</button>
            </div>`;
        }).join('') || `<div style="padding:24px;text-align:center;color:var(--text3);font-size:13px;">${t('app.nothingFound')}</div>`;
    } catch {}
}

async function addContactById(userId) {
    try {
        await window.api('POST', '/api/contacts', { user_id: userId });
        Haptic.success();
        closeModal('add-contact-modal');
        if (typeof window.loadContacts === 'function') window.loadContacts();
    } catch (e) {
        alert(e.message || t('contacts.failedToAdd'));
    }
}

function openContactDM(userId) {
    if (window.openDM) window.openDM(userId);
    else if (window.createDM) window.createDM(userId);
    // Switch to chats tab to see the DM
    switchBottomTab('chats');
}

async function callContact(userId, type) {
    if (window.startCall) {
        await window.startCall(userId, type === 'video');
    }
}

function showContactMenu(event, contactId, userId, name) {
    event.preventDefault();
    const actions = [
        { label: t('contacts.rename'), action: () => renameContact(contactId) },
        { label: t('contacts.deleteConfirm'), action: () => deleteContact(contactId), danger: true },
        { label: t('contacts.block'), action: () => blockContact(userId), danger: true },
    ];
    // Simple inline menu
    const el = event.currentTarget;
    const menu = document.createElement('div');
    menu.style.cssText = 'position:fixed;z-index:200;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:4px;box-shadow:0 4px 16px rgba(0,0,0,0.3);min-width:160px;';
    const rect = el.getBoundingClientRect();
    menu.style.left = Math.min(rect.left, window.innerWidth - 180) + 'px';
    menu.style.top = rect.bottom + 4 + 'px';
    actions.forEach(a => {
        const btn = document.createElement('button');
        btn.textContent = a.label;
        const color = a.danger ? 'var(--red)' : 'var(--text)';
        btn.style.cssText = `display:block;width:100%;text-align:left;padding:8px 12px;border:none;background:none;color:${color};cursor:pointer;font-size:13px;border-radius:6px;transition:background .15s,color .15s;`;
        btn.onmouseover = () => { btn.style.background = a.danger ? 'rgba(239,68,68,0.15)' : 'rgba(124,58,237,0.15)'; if (!a.danger) btn.style.color = 'var(--accent)'; };
        btn.onmouseout = () => { btn.style.background = 'none'; btn.style.color = color; };
        btn.onclick = () => { menu.remove(); a.action(); };
        menu.appendChild(btn);
    });
    document.body.appendChild(menu);
    const dismiss = (e) => { if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('click', dismiss); } };
    setTimeout(() => document.addEventListener('click', dismiss), 10);
}

async function renameContact(contactId) {
    const name = await window.vxPrompt(t('contacts.newName'));
    if (!name) return;
    try {
        await window.api('PUT', `/api/contacts/${contactId}`, { nickname: name });
        loadContacts();
    } catch (e) {
        console.error('renameContact failed:', e);
    }
}

async function deleteContact(contactId) {
    if (!confirm(t('contacts.deleteConfirm'))) return;
    try {
        await window.api('DELETE', `/api/contacts/${contactId}`);
        Haptic.medium();
        loadContacts();
    } catch (e) {
        console.error('deleteContact failed:', e);
    }
}

async function blockContact(userId) {
    if (!confirm(t('contacts.blockConfirm') || 'Block this user?')) return;
    try {
        await fetch(`/api/users/block/${userId}`, { method: 'POST', credentials: 'include' });
        Haptic.heavy();
        loadContacts();
    } catch {}
}

function openAddContactModal() {
    if (window.openModal) window.openModal('add-contact-modal');
    const input = document.getElementById('add-contact-search');
    if (input) { input.value = ''; input.focus(); }
    const results = document.getElementById('add-contact-results');
    if (results) results.innerHTML = '';
}

// ══════════════════════════════════════════════════════════════════════════════
// 12. Sidebar menus (hamburger + compose)
// ══════════════════════════════════════════════════════════════════════════════

function toggleSidebarMenu() {
    const menu = document.getElementById('cs-sidebar-menu');
    if (!menu) return;
    const open = menu.style.display !== 'none';
    menu.style.display = open ? 'none' : 'block';
    if (!open) {
        closeComposeMenu();
        const dismiss = (e) => { if (!menu.contains(e.target)) { menu.style.display = 'none'; document.removeEventListener('click', dismiss); } };
        setTimeout(() => document.addEventListener('click', dismiss), 10);
    }
    Haptic.light();
}

function closeSidebarMenu() {
    const menu = document.getElementById('cs-sidebar-menu');
    if (menu) menu.style.display = 'none';
}

function showCreateMenu(event) {
    event.stopPropagation();
    const menu = document.getElementById('cs-compose-menu');
    if (!menu) return;
    const open = menu.style.display !== 'none';
    menu.style.display = open ? 'none' : 'block';
    if (!open) {
        closeSidebarMenu();
        const dismiss = (e) => { if (!menu.contains(e.target)) { menu.style.display = 'none'; document.removeEventListener('click', dismiss); } };
        setTimeout(() => document.addEventListener('click', dismiss), 10);
    }
    Haptic.light();
}

function closeComposeMenu() {
    const menu = document.getElementById('cs-compose-menu');
    if (menu) menu.style.display = 'none';
}

var _globalSearchTimer = null;

function filterChats(query) {
    // 1. Filter local rooms immediately
    if (window.filterRoomList) window.filterRoomList(query);

    // 2. Global search with debounce (channels, groups, bots, users not in your chats)
    clearTimeout(_globalSearchTimer);
    var resultsEl = document.getElementById('global-search-results');
    if (!query || query.trim().length < 2) {
        if (resultsEl) { resultsEl.style.display = 'none'; resultsEl.innerHTML = ''; }
        return;
    }
    _globalSearchTimer = setTimeout(function() {
        if (window.globalSearch) window.globalSearch(query.trim());
    }, 400);
}

function switchFolder(folder) {
    document.querySelectorAll('.cs-folder-tab').forEach(b => {
        b.classList.toggle('active', b.dataset.folder === folder);
    });
    if (window.filterRoomsByFolder) window.filterRoomsByFolder(folder);
    Haptic.selection();
}

window.toggleSidebarMenu = toggleSidebarMenu;
window.closeSidebarMenu = closeSidebarMenu;
window.showCreateMenu = showCreateMenu;
window.closeComposeMenu = closeComposeMenu;
window.filterChats = filterChats;
window.switchFolder = switchFolder;

window.loadContacts = loadContacts;
window.searchContacts = searchContacts;
window.searchUsersForAdd = searchUsersForAdd;
window.addContactById = addContactById;
window.openContactDM = openContactDM;
window.callContact = callContact;
window.showContactMenu = showContactMenu;
window.renameContact = renameContact;
window.deleteContact = deleteContact;
window.blockContact = blockContact;
window.openAddContactModal = openAddContactModal;

window.loadRecentCalls = loadRecentCalls;
window.filterCalls = filterCalls;
window.clearCallHistory = clearCallHistory;
window.callUser = callUser;

// ══════════════════════════════════════════════════════════════════════════════
// Header popovers: call picker & three-dots menu
// ══════════════════════════════════════════════════════════════════════════════

function toggleCallPicker(e) {
    e && e.stopPropagation();
    const popup = document.getElementById('call-picker-popup');
    const dotsPopup = document.getElementById('header-dots-menu');
    if (!popup) return;
    const opening = !popup.classList.contains('open');
    // Close other popup first
    if (dotsPopup) dotsPopup.classList.remove('open');
    popup.classList.toggle('open', opening);
    if (opening) {
        const close = (ev) => {
            if (!document.getElementById('call-picker-wrap')?.contains(ev.target)) {
                popup.classList.remove('open');
                document.removeEventListener('click', close);
            }
        };
        setTimeout(() => document.addEventListener('click', close), 0);
    }
}
function closeCallPicker() {
    document.getElementById('call-picker-popup')?.classList.remove('open');
}

function toggleHeaderMenu(e) {
    e && e.stopPropagation();
    const popup = document.getElementById('header-dots-menu');
    const callPopup = document.getElementById('call-picker-popup');
    if (!popup) return;
    const opening = !popup.classList.contains('open');
    if (callPopup) callPopup.classList.remove('open');
    popup.classList.toggle('open', opening);
    if (opening) {
        const close = (ev) => {
            if (!document.getElementById('header-dots-wrap')?.contains(ev.target)) {
                popup.classList.remove('open');
                document.removeEventListener('click', close);
            }
        };
        setTimeout(() => document.addEventListener('click', close), 0);
    }
}
function closeHeaderMenu() {
    document.getElementById('header-dots-menu')?.classList.remove('open');
}

window.toggleCallPicker = toggleCallPicker;
window.closeCallPicker  = closeCallPicker;
window.toggleHeaderMenu = toggleHeaderMenu;
window.closeHeaderMenu  = closeHeaderMenu;

// ── Room Settings Screen — полный экран внутри #main ──────────────────────────
function openRoomSettingsScreen() {
    const screen = document.getElementById('room-settings-screen');
    const chat   = document.getElementById('chat-screen');
    const welcome = document.getElementById('welcome-screen');
    if (!screen) return;
    // Закрываем info панель если открыта
    if (typeof window.closeRoomInfo === 'function') window.closeRoomInfo();
    if (typeof window.closeModal === 'function') window.closeModal('room-info-modal');
    if (chat)    chat.style.display    = 'none';
    if (welcome) welcome.style.display = 'none';
    screen.style.display = 'flex';
    screen.classList.add('rss-entering');
    screen.addEventListener('animationend', () => screen.classList.remove('rss-entering'), { once: true });
}

function closeRoomSettingsScreen() {
    const screen = document.getElementById('room-settings-screen');
    const chat   = document.getElementById('chat-screen');
    if (screen) screen.style.display = 'none';
    if (chat)   chat.style.display   = '';
}

window.openRoomSettingsScreen  = openRoomSettingsScreen;
window.closeRoomSettingsScreen = closeRoomSettingsScreen;

// openRoomSettings — opens the full-screen settings panel.
// The screen is shown FIRST (no async blocking), then data is populated.
window.openRoomSettings = function() {
    // Always open the screen — never block on AppState state
    openRoomSettingsScreen();

    const S = window.AppState;
    const room = S && S.currentRoom;
    if (!room) return;

    // Initialize per-room theme UI (works for all room types including DMs)
    if (typeof window._initRoomThemeUI === 'function') {
        window._initRoomThemeUI();
    }

    if (room.is_dm) {
        // For DMs: populate minimal info and show only theme section
        const nameEl = document.getElementById('room-info-name');
        const descEl = document.getElementById('room-info-desc');
        if (nameEl) nameEl.textContent = room.dm_user?.display_name || room.dm_user?.username || 'DM';
        if (descEl) descEl.textContent = '';
        return;
    }

    // Populate basic fields instantly from the in-memory room object
    const avatarEl = document.getElementById('room-info-avatar');
    if (avatarEl) {
        if (room.avatar_url) {
            avatarEl.innerHTML = `<img src="${room.avatar_url}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
        } else {
            avatarEl.innerHTML = '';
            avatarEl.textContent = room.avatar_emoji || '\u{1F4AC}';
        }
    }
    const isChannel = !!room.is_channel;
    const nameEl   = document.getElementById('room-info-name');
    const descEl   = document.getElementById('room-info-desc');
    const metaEl   = document.getElementById('room-info-meta');
    const inviteEl = document.getElementById('room-info-invite');
    const inviteSec = document.getElementById('rss-invite-section');
    const topTitle  = document.getElementById('rss-topbar-title');
    if (nameEl)   nameEl.textContent   = room.name        || '';
    if (descEl)   descEl.textContent   = room.description || '';
    if (isChannel) {
        const count = room.subscriber_count || room.member_count || 0;
        if (metaEl) metaEl.textContent = `${count} ${t('rooms.subscribers')}`;
        if (inviteSec) inviteSec.style.display = 'none';
        if (topTitle) topTitle.textContent = t('channel.settings');
    } else {
        if (metaEl) metaEl.textContent = `${room.member_count || 0} ${t('roomMedia.members')}`;
        if (inviteEl) inviteEl.textContent = room.invite_code || '';
        if (inviteSec) inviteSec.style.display = '';
        if (topTitle) topTitle.textContent = t('room.settings');
    }

    // Load media section for this room
    window._loadRssMedia(room.id, 'photo');

    // Asynchronously load full/fresh data (fills admin-only settings fields)
    // openRoomInfo from rooms/info.js is saved as _roomsOpenRoomInfo in core.js,
    // but we access it via window since it's not in our import scope.
    const _infoFn = window._roomsOpenRoomInfo || window.openRoomInfo;
    if (typeof _infoFn === 'function') {
        _infoFn();
    }
};

// ── Inline media grid for room info screen ────────────────────────────────────
let _rssMediaFiles = [];

window._renderRssMedia = function(tab) {
    const grid = document.getElementById('rss-media-grid');
    if (!grid) return;
    let filtered;
    if (tab === 'photo')       filtered = _rssMediaFiles.filter(f => f.mime_type?.startsWith('image/'));
    else if (tab === 'video')  filtered = _rssMediaFiles.filter(f => f.mime_type?.startsWith('video/'));
    else                       filtered = _rssMediaFiles.filter(f => !f.mime_type?.startsWith('image/') && !f.mime_type?.startsWith('video/'));

    if (!filtered.length) {
        const labels = { photo: t('roomMedia.noPhotos'), video: t('roomMedia.noVideos'), files: t('roomMedia.noFiles') };
        grid.className = 'rss-media-grid';
        grid.innerHTML = `<div class="gallery-empty">${labels[tab] || t('rooms.empty')}</div>`; // labels contain only i18n strings
        return;
    }
    if (tab === 'photo') {
        grid.className = 'rss-media-grid rss-media-grid-photos';
        grid.innerHTML = filtered.map(f => {
            const n = (f.file_name || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
            return `<div class="gallery-thumb" onclick="window.openImageViewer('${f.download_url}','${n}')"><img src="${f.download_url}" alt="${n}" loading="lazy"></div>`;
        }).join('');
    } else if (tab === 'video') {
        grid.className = 'rss-media-grid rss-media-grid-photos';
        grid.innerHTML = filtered.map(f => {
            const n = (f.file_name || '').replace(/'/g, "\\'");
            return `<div class="gallery-thumb gallery-thumb-video" onclick="window.openGalleryVideo && window.openGalleryVideo('${f.download_url}','${n}')"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>`;
        }).join('');
    } else {
        grid.className = 'rss-media-grid';
        grid.innerHTML = filtered.map(f => {
            const name = f.file_name || t('roomMedia.file');
            return `<a class="rss-file-item" href="${f.download_url}" target="_blank" rel="noopener"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11z"/></svg><span>${name}</span></a>`;
        }).join('');
    }
};

window._loadRssMedia = async function(roomId, tab) {
    const grid = document.getElementById('rss-media-grid');
    if (!grid) return;
    grid.className = 'rss-media-grid';
    grid.innerHTML = `<div class="gallery-empty">${t('roomMedia.loading')}</div>`;
    try {
        const data = await window.api('GET', `/api/files/room/${roomId}`);
        _rssMediaFiles = data.files || [];
        window._renderRssMedia(tab || 'photo');
    } catch {
        grid.innerHTML = `<div class="gallery-empty">${t('roomMedia.loadError')}</div>`;
    }
};

window._switchRssTab = function(btn, tab) {
    document.querySelectorAll('.rss-media-tab').forEach(t => t.classList.toggle('active', t === btn));
    window._renderRssMedia(tab);
};




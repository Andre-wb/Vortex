// static/js/spaces.js
// ============================================================================
// Spaces (Discord-like servers): icon bar, space view, create/join/settings
// ============================================================================

import { $, api, esc, openModal, closeModal, showAlert } from './utils.js';
import { renderRoomsList } from './rooms.js';

// ── State ────────────────────────────────────────────────────────────────────
let _activeSpaceId = null;   // null = home (DMs + standalone rooms)
let _mySpaces = [];          // [{id, name, avatar_emoji, avatar_url, member_count, ...}]
let _activeSpaceData = null; // full space detail with categories
let _collapsedCategories = new Set(); // category IDs collapsed in sidebar

export function getActiveSpaceId() { return _activeSpaceId; }
export function getMySpaces() { return _mySpaces; }

// ── Load spaces list ─────────────────────────────────────────────────────────
export async function loadMySpaces() {
    try {
        const data = await api('GET', '/api/spaces');
        _mySpaces = data.spaces || data || [];
    } catch {
        _mySpaces = [];
    }
    renderSpaceIconBar();
}

// ── Select a space ───────────────────────────────────────────────────────────
export async function selectSpace(id) {
    if (id === null) {
        // Go home
        _activeSpaceId = null;
        _activeSpaceData = null;
        _applySpaceTheme({});  // reset space theme
        _showHomeView();
        renderSpaceIconBar();
        renderRoomsList();
        return;
    }
    _activeSpaceId = id;
    renderSpaceIconBar();
    _showSpaceView();
    await _loadSpaceDetail(id);
}

async function _loadSpaceDetail(id) {
    const loader = document.getElementById('space-rooms-list');
    if (loader) loader.innerHTML = `<div style="padding:16px;color:var(--text2);font-size:12px;">${t('app.loading')}</div>`;
    try {
        const data = await api('GET', `/api/spaces/${id}`);
        _activeSpaceData = data;
        renderSpaceRooms(data);
        // Update space name in header
        const nameEl = document.getElementById('space-view-name');
        if (nameEl) nameEl.textContent = data.name || '';
        // Apply space theme to sidebar
        _applySpaceTheme(data);
    } catch (e) {
        if (loader) loader.innerHTML = `<div style="padding:16px;color:var(--red);font-size:12px;">${esc(e.message || t('rooms.loadError'))}</div>`;
    }
}

// ── Render space icon bar ────────────────────────────────────────────────────
export function renderSpaceIconBar() {
    const bar = document.getElementById('space-icon-bar');
    if (!bar) return;

    let html = '';

    // Home button
    html += `<div class="space-icon ${_activeSpaceId === null ? 'active' : ''}"
                  onclick="window.selectSpace(null)" title="${t('spaces.home')}">
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12.71 2.29a.996.996 0 0 0-1.41 0l-8.01 8A1 1 0 0 0 3 11v9c0 1.1.9 2 2 2h4c.55 0 1-.45 1-1v-6h4v6c0 .55.45 1 1 1h4c1.1 0 2-.9 2-2v-9c0-.27-.11-.52-.29-.71z"/>
        </svg>
    </div>`;

    html += '<div class="space-separator"></div>';

    // Space icons
    for (const sp of _mySpaces) {
        const isActive = _activeSpaceId === sp.id;
        const avatarContent = sp.avatar_url
            ? `<img src="${esc(sp.avatar_url)}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
            : esc(sp.avatar_emoji || sp.name?.charAt(0)?.toUpperCase() || 'S');
        html += `<div class="space-icon ${isActive ? 'active' : ''}"
                      onclick="window.selectSpace(${sp.id})"
                      title="${esc(sp.name || '')}">
            ${avatarContent}
        </div>`;
    }

    html += '<div class="space-separator"></div>';

    // Add/Join button
    html += `<div class="space-icon space-icon-add" onclick="window.showCreateSpaceModal()" title="${t('spaces.createOrJoin')}">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
            <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
        </svg>
    </div>`;

    bar.innerHTML = html;
}

// ── Show/hide views ──────────────────────────────────────────────────────────
function _showHomeView() {
    const homeContent = document.getElementById('sidebar-home-content');
    const spaceContent = document.getElementById('sidebar-space-content');
    if (homeContent) homeContent.style.display = '';
    if (spaceContent) spaceContent.style.display = 'none';
}

function _applySpaceTheme(spaceData) {
    const sidebar = document.getElementById('sidebar-space-content');
    if (!sidebar) return;
    let theme = null;
    try {
        const raw = spaceData.theme_json;
        theme = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw) : null;
    } catch(e) {}
    if (!theme) {
        sidebar.style.backgroundImage = '';
        sidebar.style.removeProperty('--accent');
        return;
    }
    if (theme.wallpaper && theme.wallpaper !== 'none' && typeof _chatBgPresets !== 'undefined' && _chatBgPresets[theme.wallpaper]) {
        sidebar.style.backgroundImage = _chatBgPresets[theme.wallpaper];
    } else {
        sidebar.style.backgroundImage = '';
    }
    if (theme.accent) {
        sidebar.style.setProperty('--accent', theme.accent);
    }
}

function _showSpaceView() {
    const homeContent = document.getElementById('sidebar-home-content');
    const spaceContent = document.getElementById('sidebar-space-content');
    if (homeContent) homeContent.style.display = 'none';
    if (spaceContent) spaceContent.style.display = '';
}

// ── Render categorized rooms for a space ─────────────────────────────────────
export function renderSpaceRooms(space) {
    const el = document.getElementById('space-rooms-list');
    if (!el || !space) return;

    const S = window.AppState;
    const categories = space.categories || [];
    let html = '';

    if (!categories.length) {
        html = `<div style="padding:16px;color:var(--text3);font-size:12px;font-family:var(--mono);">${t('spaces.noCategories')}</div>`;
        el.innerHTML = html;
        return;
    }

    for (const cat of categories) {
        const isCollapsed = _collapsedCategories.has(cat.id);
        const rooms = cat.rooms || [];

        html += `<div class="space-category">
            <div class="space-category-header" onclick="window._toggleSpaceCategory(${cat.id})">
                <svg class="space-category-arrow ${isCollapsed ? 'collapsed' : ''}" xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M7 10l5 5 5-5z"/>
                </svg>
                <span class="space-category-name">${esc(cat.name)}</span>
                <button class="space-category-add" onclick="event.stopPropagation();window._showCreateRoomInSpace(${space.id},${cat.id})" title="${t('spaces.addRoom')}">+</button>
            </div>`;

        if (!isCollapsed) {
            html += '<div class="space-category-rooms">';
            for (const r of rooms) {
                const isActive = S.currentRoom?.id === r.id;
                const icon = _spaceRoomIcon(r);
                const meta = r.is_voice
                    ? `${(r.voice_participants || []).length || 0} ${t('spaces.inVoice')}`
                    : (r.is_channel ? `${r.subscriber_count || r.member_count || 0} ${t('spaces.subs')}` : '');

                html += `<div class="space-room-item ${isActive ? 'active' : ''}"
                              onclick="${r.is_voice ? `window.joinVoiceChannel(${r.id})` : `window._openSpaceRoom(${r.id})`}"
                              data-room="${r.id}">
                    <span class="space-room-icon">${icon}</span>
                    <span class="space-room-name">${esc(r.name)}</span>
                    ${meta ? `<span class="space-room-meta">${meta}</span>` : ''}
                </div>`;
            }
            html += '</div>';
        }

        html += '</div>';
    }

    el.innerHTML = html;
}

function _spaceRoomIcon(r) {
    if (r.is_voice) {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z"/><path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z"/></svg>';
    }
    if (r.is_channel) {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>';
    }
    // Text room - hash icon
    return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M5.41 21L6.12 17H2.12L2.47 15H6.47L7.53 9H3.53L3.88 7H7.88L8.59 3H10.59L9.88 7H15.88L16.59 3H18.59L17.88 7H21.88L21.53 9H17.53L16.47 15H20.47L20.12 17H16.12L15.41 21H13.41L14.12 17H8.12L7.41 21H5.41ZM9.53 9L8.47 15H14.47L15.53 9H9.53Z"/></svg>';
}

// ── Toggle category collapse ─────────────────────────────────────────────────
window._toggleSpaceCategory = function(catId) {
    if (_collapsedCategories.has(catId)) {
        _collapsedCategories.delete(catId);
    } else {
        _collapsedCategories.add(catId);
    }
    if (_activeSpaceData) renderSpaceRooms(_activeSpaceData);
};

// ── Create Space Modal ───────────────────────────────────────────────────────
export function showCreateSpaceModal() {
    openModal('create-space-modal');
    setTimeout(() => {
        const nameEl = document.getElementById('cs-name');
        if (nameEl) nameEl.focus();
    }, 50);
}

export async function createSpace() {
    const name = (document.getElementById('cs-name')?.value || '').trim();
    const desc = (document.getElementById('cs-desc')?.value || '').trim();
    const isPublic = document.getElementById('cs-public')?.checked || false;

    if (!name) {
        showAlert('cs-alert', t('rooms.enterName'));
        return;
    }

    try {
        const data = await api('POST', '/api/spaces', {
            name,
            description: desc,
            is_public: isPublic,
        });

        closeModal('create-space-modal');
        // Clear form
        const nameEl = document.getElementById('cs-name');
        const descEl = document.getElementById('cs-desc');
        const pubEl = document.getElementById('cs-public');
        if (nameEl) nameEl.value = '';
        if (descEl) descEl.value = '';
        if (pubEl) pubEl.checked = false;

        // Add to list and select
        _mySpaces.push(data);
        await selectSpace(data.id);
    } catch (e) {
        showAlert('cs-alert', e.message || t('spaces.createError'));
    }
}

// ── Join Space by code ───────────────────────────────────────────────────────
export async function joinSpaceByCode() {
    const code = (document.getElementById('cs-join-code')?.value || '').trim().toUpperCase();
    if (!code) {
        showAlert('cs-alert', t('spaces.enterInvite'));
        return;
    }

    try {
        const data = await api('POST', `/api/spaces/join/${code}`);
        closeModal('create-space-modal');
        const joinCodeEl = document.getElementById('cs-join-code');
        if (joinCodeEl) joinCodeEl.value = '';

        // Reload spaces and select
        await loadMySpaces();
        const spaceId = data.id || data.space_id;
        if (spaceId) await selectSpace(spaceId);
    } catch (e) {
        showAlert('cs-alert', e.message || t('spaces.joinError'));
    }
}

// ── Space Settings Modal ─────────────────────────────────────────────────────
export function showSpaceSettings() {
    if (!_activeSpaceData) return;
    const sp = _activeSpaceData;

    // Fill form fields
    const nameEl = document.getElementById('ss-name');
    const descEl = document.getElementById('ss-desc');
    const codeEl = document.getElementById('ss-invite-code');
    const membersEl = document.getElementById('ss-member-count');

    if (nameEl) nameEl.value = sp.name || '';
    if (descEl) descEl.value = sp.description || '';
    if (codeEl) codeEl.textContent = sp.invite_code || '---';
    if (membersEl) membersEl.textContent = `${sp.member_count || 0} ${t('spaces.members')}`;

    openModal('space-settings-modal');
    _loadSpaceMembers(sp.id);
}

async function _loadSpaceMembers(spaceId) {
    const el = document.getElementById('ss-members-list');
    if (!el) return;
    el.innerHTML = `<div style="padding:8px;color:var(--text2);font-size:12px;">${t('app.loading')}</div>`;
    try {
        const data = await api('GET', `/api/spaces/${spaceId}/members`);
        const members = data.members || data || [];
        if (!members.length) {
            el.innerHTML = `<div style="padding:8px;color:var(--text3);font-size:12px;">${t('spaces.noMembers')}</div>`;
            return;
        }
        el.innerHTML = members.map(m => {
            const av = m.avatar_url
                ? `<img src="${esc(m.avatar_url)}" style="width:28px;height:28px;border-radius:50%;object-fit:cover;">`
                : `<div style="width:28px;height:28px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;">${m.avatar_emoji ? esc(m.avatar_emoji) : '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>'}</div>`;
            const roleBadge = m.role === 'owner' ? `<span class="ss-role-badge ss-owner">${t('rooms.owner')}</span>`
                : m.role === 'admin' ? `<span class="ss-role-badge ss-admin">${t('rooms.admin')}</span>` : '';
            return `<div class="ss-member-row">
                ${av}
                <div style="flex:1;min-width:0;">
                    <div style="font-weight:700;font-size:13px;">${esc(m.display_name || m.username || '')}</div>
                    <div style="font-size:11px;color:var(--text2);">@${esc(m.username || '')}</div>
                </div>
                ${roleBadge}
            </div>`;
        }).join('');
    } catch (e) {
        el.innerHTML = `<div style="padding:8px;color:var(--red);font-size:12px;">${esc(e.message)}</div>`;
    }
}

export async function saveSpaceSettings() {
    if (!_activeSpaceData) return;
    const name = (document.getElementById('ss-name')?.value || '').trim();
    const desc = (document.getElementById('ss-desc')?.value || '').trim();

    if (!name) {
        showAlert('ss-alert', t('spaces.nameCantBeEmpty'));
        return;
    }

    try {
        await api('PUT', `/api/spaces/${_activeSpaceData.id}`, { name, description: desc });
        showAlert('ss-alert', t('spaces.saved'), 'success');
        _activeSpaceData.name = name;
        _activeSpaceData.description = desc;
        // Update header
        const nameEl = document.getElementById('space-view-name');
        if (nameEl) nameEl.textContent = name;
        // Update icon bar
        const sp = _mySpaces.find(s => s.id === _activeSpaceData.id);
        if (sp) sp.name = name;
        renderSpaceIconBar();
    } catch (e) {
        showAlert('ss-alert', e.message || t('app.error'));
    }
}

export async function leaveSpace() {
    if (!_activeSpaceData) return;
    if (!confirm(t('spaces.leaveSpace') + ' "' + (_activeSpaceData.name || '') + '"?')) return;
    try {
        await api('POST', `/api/spaces/${_activeSpaceData.id}/leave`);
        _mySpaces = _mySpaces.filter(s => s.id !== _activeSpaceData.id);
        closeModal('space-settings-modal');
        selectSpace(null);
    } catch (e) {
        alert(e.message || t('app.error'));
    }
}

export async function deleteSpace() {
    if (!_activeSpaceData) return;
    if (!confirm(t('spaces.deleteSpace') + ' "' + (_activeSpaceData.name || '') + '"? ' + t('spaces.irreversible'))) return;
    try {
        await api('DELETE', `/api/spaces/${_activeSpaceData.id}`);
        _mySpaces = _mySpaces.filter(s => s.id !== _activeSpaceData.id);
        closeModal('space-settings-modal');
        selectSpace(null);
    } catch (e) {
        alert(e.message || t('app.error'));
    }
}

// ── Copy invite code ─────────────────────────────────────────────────────────
export function copySpaceInvite() {
    if (!_activeSpaceData?.invite_code) return;
    navigator.clipboard.writeText(_activeSpaceData.invite_code).then(() => {
        const btn = document.getElementById('ss-copy-btn');
        if (btn) {
            btn.textContent = t('app.copied');
            setTimeout(() => { btn.textContent = t('app.copy'); }, 1500);
        }
    });
}

// ── Create room in space ─────────────────────────────────────────────────────
window._showCreateRoomInSpace = function(spaceId, categoryId) {
    const el = document.getElementById('crs-space-id');
    const catEl = document.getElementById('crs-category-id');
    if (el) el.value = spaceId;
    if (catEl) catEl.value = categoryId || '';
    openModal('create-room-in-space-modal');
    setTimeout(() => {
        const nameEl = document.getElementById('crs-name');
        if (nameEl) nameEl.focus();
    }, 50);
};

export async function createRoomInSpace() {
    const spaceId = parseInt(document.getElementById('crs-space-id')?.value);
    const categoryId = parseInt(document.getElementById('crs-category-id')?.value) || undefined;
    const name = (document.getElementById('crs-name')?.value || '').trim();
    const type = document.getElementById('crs-type')?.value || 'text';

    if (!name) {
        showAlert('crs-alert', t('rooms.enterName'));
        return;
    }

    try {
        await api('POST', `/api/spaces/${spaceId}/rooms`, {
            name,
            category_id: categoryId,
            is_channel: type === 'channel',
            is_voice: type === 'voice',
        });

        closeModal('create-room-in-space-modal');
        const nameEl = document.getElementById('crs-name');
        if (nameEl) nameEl.value = '';

        // Reload space detail
        await _loadSpaceDetail(spaceId);
    } catch (e) {
        showAlert('crs-alert', e.message || t('app.error'));
    }
}

// ── Create category in space ─────────────────────────────────────────────────
export async function createCategory() {
    if (!_activeSpaceData) return;
    const name = prompt(t('spaces.categoryName'));
    if (!name?.trim()) return;

    try {
        await api('POST', `/api/spaces/${_activeSpaceData.id}/categories`, { name: name.trim() });
        await _loadSpaceDetail(_activeSpaceData.id);
    } catch (e) {
        alert(e.message || t('app.error'));
    }
}

// ── Helper: re-render space rooms when renderRoomsList triggers ──────────────
window._refreshSpaceRoomsIfActive = function() {
    if (_activeSpaceId && _activeSpaceData) {
        renderSpaceRooms(_activeSpaceData);
    }
};

// ── Open a space room (ensure it's in S.rooms first) ────────────────────────
window._openSpaceRoom = function(roomId) {
    const S = window.AppState;
    // If the room is already in the global rooms list, just open it
    if (S.rooms.find(r => r.id === roomId)) {
        if (typeof window.openRoom === 'function') window.openRoom(roomId);
        return;
    }
    // Otherwise, find the room data from the active space detail and inject it
    if (_activeSpaceData) {
        for (const cat of (_activeSpaceData.categories || [])) {
            const room = (cat.rooms || []).find(r => r.id === roomId);
            if (room) {
                S.rooms.unshift(room);
                if (typeof window.openRoom === 'function') window.openRoom(roomId);
                return;
            }
        }
    }
    // Last resort: try opening anyway (will silently fail if room not found)
    if (typeof window.openRoom === 'function') window.openRoom(roomId);
};

// ── Global exports ───────────────────────────────────────────────────────────
window.selectSpace = selectSpace;
window.showCreateSpaceModal = showCreateSpaceModal;
window.createSpace = createSpace;
window.joinSpaceByCode = joinSpaceByCode;
window.showSpaceSettings = showSpaceSettings;
window.saveSpaceSettings = saveSpaceSettings;
window.leaveSpace = leaveSpace;
window.deleteSpace = deleteSpace;
window.copySpaceInvite = copySpaceInvite;
window.createRoomInSpace = createRoomInSpace;
window.createSpaceCategory = createCategory;

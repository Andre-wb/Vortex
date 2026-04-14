// static/js/contacts.js
// ============================================================================
// Управление контактами: поиск пользователей, добавление/удаление контактов,
// открытие личных сообщений (DM), группы контактов (client-side).
// ============================================================================

import { $, api, esc, openModal, closeModal, showAlert, vxPrompt, vxConfirm, vxAlert } from './utils.js';
import { eciesEncrypt, getRoomKey, setRoomKey } from './crypto.js';

function _avatarEl(obj) {
    const presence = obj.presence || 'online';
    let inner;
    if (obj.avatar_url) {
        inner = `<div class="avatar"><img src="${esc(obj.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;"></div>`;
    } else {
        inner = `<div class="avatar">${esc(obj.avatar_emoji || '\u{1F464}')}</div>`;
    }
    return `<div class="avatar-status-wrap">${inner}<div class="status-dot ${esc(presence)}"></div></div>`;
}

// ── Состояние ────────────────────────────────────────────────────────────────
let _contacts = [];
let _searchTimeout = null;

// ── Contact Groups (localStorage) ───────────────────────────────────────────
const CG_STORAGE_KEY = 'vortex_contact_groups';
const CG_MAX_GROUPS = 10;
let _contactGroups = [];
let _activeGroupId = null;   // null = "All"

function _loadGroups() {
    try {
        const raw = localStorage.getItem(CG_STORAGE_KEY);
        _contactGroups = raw ? JSON.parse(raw) : [];
    } catch { _contactGroups = []; }
}

function _saveGroups() {
    localStorage.setItem(CG_STORAGE_KEY, JSON.stringify(_contactGroups));
}

function _nextGroupId() {
    return _contactGroups.length ? Math.max(..._contactGroups.map(g => g.id)) + 1 : 1;
}

export async function _addContactFolder() {
    const name = await vxPrompt(t('contacts.newFolderName'));
    if (name?.trim()) createGroup(name.trim());
}
window._addContactFolder = _addContactFolder;

export function createGroup(name) {
    if (_contactGroups.length >= CG_MAX_GROUPS) {
        vxAlert(t('contacts.maxGroupsReached'));
        return null;
    }
    name = (name || '').trim();
    if (!name) return null;
    const group = { id: _nextGroupId(), name, contactIds: [] };
    _contactGroups.push(group);
    _saveGroups();
    renderGroupTabs();
    return group;
}

export function deleteGroup(id) {
    _contactGroups = _contactGroups.filter(g => g.id !== id);
    if (_activeGroupId === id) _activeGroupId = null;
    _saveGroups();
    renderGroupTabs();
    renderContactsList();
}

export function renameGroup(id, name) {
    name = (name || '').trim();
    if (!name) return;
    const g = _contactGroups.find(g => g.id === id);
    if (g) {
        g.name = name;
        _saveGroups();
        renderGroupTabs();
    }
}

export function addToGroup(groupId, contactId) {
    const g = _contactGroups.find(g => g.id === groupId);
    if (!g) return;
    contactId = Number(contactId);
    if (!g.contactIds.includes(contactId)) {
        g.contactIds.push(contactId);
        _saveGroups();
        renderGroupTabs();
        renderContactsList();
    }
}

export function removeFromGroup(groupId, contactId) {
    const g = _contactGroups.find(g => g.id === groupId);
    if (!g) return;
    contactId = Number(contactId);
    g.contactIds = g.contactIds.filter(cid => cid !== contactId);
    _saveGroups();
    renderGroupTabs();
    renderContactsList();
}

// ── Render group tabs ───────────────────────────────────────────────────────

export function renderGroupTabs() {
    const el = $('contact-group-tabs');
    if (!el) return;

    let html = '';

    // "All" tab
    const allActive = _activeGroupId === null ? ' active' : '';
    html += `<div class="contact-group-tab${allActive}" data-cg-id="all">${t('contacts.allGroup')}<span class="cg-count">${_contacts.length}</span></div>`;

    // Custom groups
    for (const g of _contactGroups) {
        const active = _activeGroupId === g.id ? ' active' : '';
        const count = g.contactIds.filter(cid => _contacts.some(c => c.contact_id === cid)).length;
        html += `<div class="contact-group-tab${active}" data-cg-id="${g.id}" oncontextmenu="event.preventDefault();showGroupTabCtx(event,${g.id})">${esc(g.name)}<span class="cg-count">${count}</span></div>`;
    }

    el.innerHTML = html;
    if (!el.classList.contains('contact-group-tabs')) el.classList.add('contact-group-tabs');

    // Click handlers
    el.querySelectorAll('.contact-group-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const gid = tab.dataset.cgId;
            _activeGroupId = gid === 'all' ? null : Number(gid);
            renderGroupTabs();
            renderContactsList();
        });
    });
}

// ── Group tab right-click context menu ──────────────────────────────────────

export function showGroupTabCtx(e, groupId) {
    document.querySelectorAll('.contact-ctx-menu,.cg-ctx-submenu').forEach(m => m.remove());

    const menu = document.createElement('div');
    menu.className = 'contact-ctx-menu';
    menu.style.cssText = `position:fixed;left:${e.clientX}px;top:${e.clientY}px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:4px 0;z-index:10000;min-width:140px;box-shadow:0 4px 16px rgba(0,0,0,.3);`;
    menu.innerHTML = `
        <div style="padding:6px 12px;cursor:pointer;font-size:12px;color:var(--text);" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background=''" data-action="rename">${t('folders.rename')}</div>
        <div style="padding:6px 12px;cursor:pointer;font-size:12px;color:var(--red);" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background=''" data-action="delete">${t('app.delete')}</div>
    `;
    document.body.appendChild(menu);

    menu.querySelector('[data-action="rename"]').addEventListener('click', async () => {
        menu.remove();
        const g = _contactGroups.find(g => g.id === groupId);
        const newName = await vxPrompt(t('folders.rename'), g?.name || '');
        if (newName) renameGroup(groupId, newName);
    });
    menu.querySelector('[data-action="delete"]').addEventListener('click', () => {
        menu.remove();
        deleteGroup(groupId);
    });

    const closeMenu = (ev) => {
        if (!menu.contains(ev.target)) {
            menu.remove();
            document.removeEventListener('click', closeMenu);
        }
    };
    setTimeout(() => document.addEventListener('click', closeMenu), 10);
}

// ── Manage Groups Modal ─────────────────────────────────────────────────────

export function showManageGroupsModal() {
    // Build modal content dynamically using the existing openModal infrastructure
    let overlay = $('cg-manage-modal');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.id = 'cg-manage-modal';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.innerHTML = `
            <div class="modal" style="width:380px;">
                <div class="modal-title">${t('contacts.manageGroups')}</div>
                <div id="cg-manage-body"></div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" onclick="closeModal('cg-manage-modal')">${t('app.close')}</button>
                </div>
            </div>`;  // eslint-disable-line no-unsanitized/property -- template uses only t() keys, no user input
        document.body.appendChild(overlay);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeModal('cg-manage-modal');
        });
    }

    _renderManageGroupsBody();
    openModal('cg-manage-modal');
}

function _renderManageGroupsBody() {
    const body = $('cg-manage-body');
    if (!body) return;

    let html = '<div class="cg-manage-list">';

    if (!_contactGroups.length) {
        html += `<div style="padding:12px;color:var(--text2);font-size:12px;font-family:var(--mono);">${t('contacts.noGroupsYet')}</div>`;
    } else {
        for (const g of _contactGroups) {
            const count = g.contactIds.filter(cid => _contacts.some(c => c.contact_id === cid)).length;
            html += `
            <div class="cg-manage-row" data-cg-manage-id="${g.id}">
                <span class="cg-manage-name">${esc(g.name)}</span>
                <span style="font-size:11px;color:var(--text3);">${count}</span>
                <button class="btn btn-secondary" data-action="rename">${t('folders.rename')}</button>
                <button class="btn btn-secondary" data-action="delete" style="color:var(--red);">${t('app.delete')}</button>
            </div>`;
        }
    }

    html += '</div>';

    // Add new group input
    html += `
    <div style="display:flex;gap:6px;margin-top:10px;">
        <input id="cg-new-group-input" class="input" type="text" placeholder="${t('contacts.newGroupName')}" maxlength="40" style="flex:1;font-size:13px;padding:6px 10px;">
        <button class="btn btn-primary btn-sm" id="cg-new-group-btn">${t('app.create')}</button>
    </div>`;

    if (_contactGroups.length >= CG_MAX_GROUPS) {
        html += `<div style="font-size:11px;color:var(--text3);margin-top:4px;">${t('contacts.maxGroupsNote').replace('{n}', CG_MAX_GROUPS)}</div>`;
    }

    body.innerHTML = html;

    // Bind events
    const createBtn = $('cg-new-group-btn');
    const createInput = $('cg-new-group-input');
    if (createBtn && createInput) {
        createBtn.addEventListener('click', () => {
            const name = createInput.value.trim();
            if (name) {
                createGroup(name);
                _renderManageGroupsBody();
            }
        });
        createInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                createBtn.click();
            }
        });
    }

    body.querySelectorAll('[data-action="rename"]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const row = btn.closest('[data-cg-manage-id]');
            const id = Number(row.dataset.cgManageId);
            const g = _contactGroups.find(g => g.id === id);
            const newName = await vxPrompt(t('contacts.renameGroup'), g?.name || '');
            if (newName && newName.trim()) {
                renameGroup(id, newName.trim());
                _renderManageGroupsBody();
            }
        });
    });

    body.querySelectorAll('[data-action="delete"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const row = btn.closest('[data-cg-manage-id]');
            const id = Number(row.dataset.cgManageId);
            if (confirm(t('contacts.deleteGroupConfirm'))) {
                deleteGroup(id);
                _renderManageGroupsBody();
            }
        });
    });
}

// ── Загрузка контактов ───────────────────────────────────────────────────────

export async function loadContacts() {
    try {
        const data = await api('GET', '/api/contacts');
        _contacts = data.contacts || [];
        window.AppState.contacts = _contacts;
        // Кэшируем pubkey контактов для шифрования ключей DM
        if (!window._cachedUserPubkeys) window._cachedUserPubkeys = {};
        for (const c of _contacts) {
            if (c.x25519_public_key) window._cachedUserPubkeys[c.user_id] = c.x25519_public_key;
        }
        const badge = $('contacts-badge');
        if (badge) badge.textContent = _contacts.length;
        _loadGroups();
        renderGroupTabs();
        renderContactsList();
    } catch (e) {
        console.warn('loadContacts:', e.message);
    }
}

// ── Рендеринг списка контактов ───────────────────────────────────────────────

function _renderContactCard(c) {
    const name = c.nickname || c.display_name || c.username || t('rooms.member');
    const phone = c.phone || '';
    const statusLine = (c.status_emoji || c.custom_status)
        ? `<div class="contact-status-line">${esc((c.status_emoji || '') + (c.status_emoji && c.custom_status ? ' ' : '') + (c.custom_status || ''))}</div>`
        : '';
    return `
    <div class="contact-item" data-contact-id="${c.contact_id}">
        ${_avatarEl(c)}
        <div class="contact-info">
            <div class="contact-name">${esc(name)}</div>
            ${statusLine}
            <div class="contact-meta">@${esc(c.username || '')}${phone ? ' · ' + esc(phone) : ''}</div>
        </div>
        <div class="contact-actions">
            <button class="btn-icon" onclick="event.stopPropagation();openDM(${c.user_id})" title="${t('contacts.write')}">
                <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>
            </button>
            <button class="btn-icon" onclick="event.stopPropagation();startCall(${c.user_id},false)" title="${t('contacts.call')}">
                <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M20.01 15.38c-1.23 0-2.42-.2-3.53-.56-.35-.12-.74-.03-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z"/></svg>
            </button>
            <button class="btn-icon" onclick="event.stopPropagation();startCall(${c.user_id},true)" title="${t('notifications.videoCall')}">
                <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>
            </button>
            <button class="btn-icon danger" onclick="event.stopPropagation();toggleContactMenu(this,${c.contact_id})" title="...">
                <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>
            </button>
        </div>
    </div>`;
}

export function renderContactsList() {
    const el = $('contacts-list');
    if (!el) return;

    // If a specific group tab is selected — show only that group
    if (_activeGroupId !== null) {
        const g = _contactGroups.find(g => g.id === _activeGroupId);
        const idSet = g ? new Set(g.contactIds) : new Set();
        const visible = _contacts.filter(c => idSet.has(c.contact_id));
        if (!visible.length) {
            el.innerHTML = `<div style="padding:16px;color:var(--text2);font-size:12px;">${t('contacts.noContactsInGroup')}</div>`;
            return;
        }
        el.innerHTML = visible.map(c => _renderContactCard(c)).join('');
        return;
    }

    // "All" view — show folders with contacts inside
    if (!_contacts.length) {
        el.innerHTML = `<div style="padding:16px;color:var(--text2);font-size:12px;">${t('contacts.noContacts')}</div>`;
        return;
    }

    let html = '';

    // Render each folder
    const assigned = new Set();
    for (const g of _contactGroups) {
        const folderContacts = _contacts.filter(c => g.contactIds.includes(c.contact_id));
        if (!folderContacts.length) continue;
        folderContacts.forEach(c => assigned.add(c.contact_id));

        const collapsed = localStorage.getItem(`vortex_cf_${g.id}`) === '1';
        html += `
        <div class="cf-folder" data-folder-id="${g.id}">
            <div class="cf-folder-header" onclick="window._toggleContactFolder(${g.id})">
                <svg class="cf-folder-arrow${collapsed ? '' : ' cf-open'}" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6z"/></svg>
                <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="color:var(--accent);"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
                <span class="cf-folder-name">${esc(g.name)}</span>
                <span class="cf-folder-count">${folderContacts.length}</span>
            </div>
            <div class="cf-folder-body${collapsed ? ' cf-collapsed' : ''}">
                ${folderContacts.map(c => _renderContactCard(c)).join('')}
            </div>
        </div>`;
    }

    // Ungrouped contacts
    const ungrouped = _contacts.filter(c => !assigned.has(c.contact_id));
    if (ungrouped.length) {
        if (_contactGroups.length) {
            html += `
            <div class="cf-folder">
                <div class="cf-folder-header cf-ungrouped">
                    <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="color:var(--text3);"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
                    <span class="cf-folder-name">${t('contacts.ungrouped')}</span>
                    <span class="cf-folder-count">${ungrouped.length}</span>
                </div>
                <div class="cf-folder-body">
                    ${ungrouped.map(c => _renderContactCard(c)).join('')}
                </div>
            </div>`;
        } else {
            html += ungrouped.map(c => _renderContactCard(c)).join('');
        }
    }

    el.innerHTML = html;
}

window._toggleContactFolder = function(folderId) {
    const key = `vortex_cf_${folderId}`;
    const collapsed = localStorage.getItem(key) === '1';
    localStorage.setItem(key, collapsed ? '0' : '1');
    renderContactsList();
};

// ── Поиск пользователей ──────────────────────────────────────────────────────

export async function searchUsers(query) {
    const resultsEl = $('search-results');
    if (!resultsEl) return;

    resultsEl.innerHTML = `<div style="padding:16px;color:var(--text2);font-size:12px;">${t('app.search')}</div>`;

    try {
        const data = await api('GET', `/api/users/search?q=${encodeURIComponent(query)}`);
        const users = data.users || [];

        if (!users.length) {
            resultsEl.innerHTML = `<div style="padding:16px;color:var(--text2);font-size:12px;font-family:var(--mono);">${t('app.nothingFound')}</div>`;
            return;
        }

        const myId = window.AppState.user?.id;
        const contactIds = new Set(_contacts.map(c => c.user_id));

        // Кэшируем pubkey для быстрой передачи ключа при создании DM
        if (!window._cachedUserPubkeys) window._cachedUserPubkeys = {};
        for (const u of users) {
            if (u.x25519_public_key) window._cachedUserPubkeys[u.user_id] = u.x25519_public_key;
        }

        resultsEl.innerHTML = users.map(u => {
            const phone = u.phone ? u.phone.replace(/(\d{2})\d{5}(\d{2})/, '$1*****$2') : '';

            if (u.is_self) {
                return `
                <div class="search-result" style="opacity:0.6;">
                    ${_avatarEl(u)}
                    <div class="search-result-info">
                        <div class="search-result-name">${esc(u.display_name || u.username)}</div>
                        <div class="search-result-meta">@${esc(u.username)}${phone ? ' · ' + esc(phone) : ''}</div>
                    </div>
                    <span style="font-size:11px;color:var(--text3);font-family:var(--mono);">${t('contacts.itsYou')}</span>
                </div>`;
            }

            const isContact = contactIds.has(u.user_id);
            const actionBtn = isContact
                ? `<button class="btn btn-primary btn-sm" onclick="openDM(${u.user_id})">${t('contacts.write')}</button>`
                : `<button class="btn btn-primary btn-sm" data-add-contact="${u.user_id}" onclick="addContact(${u.user_id})">${t('contacts.add')}</button>`;

            return `
            <div class="search-result">
                ${_avatarEl(u)}
                <div class="search-result-info">
                    <div class="search-result-name">${esc(u.display_name || u.username)}</div>
                    <div class="search-result-meta">@${esc(u.username)}${phone ? ' · ' + esc(phone) : ''}</div>
                </div>
                ${actionBtn}
            </div>`;
        }).join('');
    } catch (e) {
        resultsEl.innerHTML = `<div style="padding:16px;color:var(--red);font-size:12px;font-family:var(--mono);">${esc(e.message)}</div>`;
    }
}

export function debounceSearch(value) {
    clearTimeout(_searchTimeout);
    const resultsEl = $('search-results');
    if (!value.trim()) {
        if (resultsEl) resultsEl.innerHTML = '';
        return;
    }
    _searchTimeout = setTimeout(() => searchUsers(value.trim()), 400);
}

// ── Операции с контактами ────────────────────────────────────────────────────

export async function addContact(userId) {
    try {
        await api('POST', '/api/contacts', { user_id: userId });
        await loadContacts();
        // Обновляем кнопку в результатах поиска
        const btn = document.querySelector(`[data-add-contact="${userId}"]`);
        if (btn) {
            btn.textContent = t('contacts.added');
            btn.style.background = 'var(--green)';
            btn.style.borderColor = 'var(--green)';
            btn.style.color = '#fff';
            btn.disabled = true;
        }
    } catch (e) {
        vxAlert(e.message);
    }
}

export async function renameContact(contactId) {
    const name = await vxPrompt(t('contacts.newName'));
    if (!name) return;
    try {
        await api('PUT', `/api/contacts/${contactId}`, { nickname: name });
        await loadContacts();
    } catch (e) {
        vxAlert(e.message);
    }
}

export async function deleteContact(contactId) {
    if (!await vxConfirm(t('contacts.deleteConfirm'), { danger: true })) return;
    try {
        await api('DELETE', `/api/contacts/${contactId}`);
        // Also remove from all groups
        for (const g of _contactGroups) {
            g.contactIds = g.contactIds.filter(cid => cid !== contactId);
        }
        _saveGroups();
        await loadContacts();
    } catch (e) {
        vxAlert(e.message);
    }
}

// ── Контекстное меню контакта ────────────────────────────────────────────────

export function toggleContactMenu(btn, contactId) {
    // Удаляем старое меню, если есть
    document.querySelectorAll('.contact-ctx-menu').forEach(m => m.remove());

    const menu = document.createElement('div');
    menu.className = 'contact-ctx-menu';
    menu.style.cssText = 'position:absolute;right:0;top:100%;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:4px 0;z-index:100;min-width:140px;';

    // Build "Add to group" submenu items
    let groupSubmenuHtml = '';
    if (_contactGroups.length) {
        groupSubmenuHtml = `
        <div style="padding:6px 12px;cursor:pointer;font-size:12px;color:var(--text2);position:relative;border-radius:6px;transition:background .15s,color .15s;" class="cg-submenu-trigger" onmouseover="this.style.background='rgba(124,58,237,0.15)';this.style.color='var(--accent)'" onmouseout="this.style.background='';this.style.color='var(--text2)'">
            Groups &#9656;
            <div class="cg-ctx-submenu" style="display:none;">
                ${_contactGroups.map(g => {
                    const inGroup = g.contactIds.includes(contactId);
                    return `<div class="cg-ctx-submenu-item${inGroup ? ' in-group' : ''}" data-cg-toggle="${g.id}" data-contact-toggle="${contactId}">${esc(g.name)}</div>`;
                }).join('')}
            </div>
        </div>`;
    }

    menu.innerHTML = `
        ${groupSubmenuHtml}
        <div style="padding:6px 12px;cursor:pointer;font-size:12px;color:var(--text2);border-radius:6px;transition:background .15s,color .15s;" onmouseover="this.style.background='rgba(124,58,237,0.15)';this.style.color='var(--accent)'" onmouseout="this.style.background='';this.style.color='var(--text2)'" onclick="renameContact(${contactId});this.closest('.contact-ctx-menu').remove()">${t('folders.rename')}</div>
        <div style="padding:6px 12px;cursor:pointer;font-size:12px;color:var(--red);border-radius:6px;transition:background .15s;" onmouseover="this.style.background='rgba(239,68,68,0.15)'" onmouseout="this.style.background=''" onclick="deleteContact(${contactId});this.closest('.contact-ctx-menu').remove()">${t('app.delete')}</div>
    `;

    const parent = btn.parentElement;
    parent.style.position = 'relative';
    parent.appendChild(menu);

    // Show/hide group submenu on hover
    const trigger = menu.querySelector('.cg-submenu-trigger');
    if (trigger) {
        const submenu = trigger.querySelector('.cg-ctx-submenu');
        trigger.addEventListener('mouseenter', () => { submenu.style.display = 'block'; });
        trigger.addEventListener('mouseleave', () => { submenu.style.display = 'none'; });

        // Toggle group membership on click
        submenu.querySelectorAll('[data-cg-toggle]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const gId = Number(item.dataset.cgToggle);
                const cId = Number(item.dataset.contactToggle);
                const g = _contactGroups.find(g => g.id === gId);
                if (!g) return;
                if (g.contactIds.includes(cId)) {
                    removeFromGroup(gId, cId);
                    item.classList.remove('in-group');
                } else {
                    addToGroup(gId, cId);
                    item.classList.add('in-group');
                }
            });
        });
    }

    const closeMenu = (e) => {
        if (!menu.contains(e.target)) {
            menu.remove();
            document.removeEventListener('click', closeMenu);
        }
    };
    setTimeout(() => document.addEventListener('click', closeMenu), 10);
}

// ── Открытие личного сообщения (DM) ─────────────────────────────────────────

export async function openDM(targetUserId) {
    try {
        const S = window.AppState;

        // Проверяем есть ли уже DM с этим пользователем
        const existingDm = S.rooms.find(r => r.is_dm && r.dm_user?.user_id === targetUserId);
        if (existingDm) {
            // DM уже существует — просто открываем, не создаём новый ключ
            if (typeof window.renderRoomsList === 'function') window.renderRoomsList();
            if (typeof window.openRoom === 'function') window.openRoom(existingDm.id);
            closeModal('contacts-modal');
            closeModal('search-modal');
            return;
        }

        // Генерируем ключ только для НОВОГО DM
        const roomKeyBytes = crypto.getRandomValues(new Uint8Array(32));

        let myPubkey = S.user?.x25519_public_key;
        if (!myPubkey) {
            const privJwkStr = S.x25519PrivateKey || localStorage.getItem('vortex_x25519_priv');
            if (privJwkStr) {
                try {
                    const jwk = JSON.parse(privJwkStr);
                    if (jwk.x) {
                        const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
                        const binary = atob(b64);
                        myPubkey = Array.from(binary, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                    }
                } catch {}
            }
        }

        let encryptedKey = null;
        if (myPubkey) {
            encryptedKey = await eciesEncrypt(roomKeyBytes, myPubkey);
        }

        // Пытаемся получить pubkey получателя заранее (из кэша поиска)
        let encryptedKeyForTarget = null;
        const cachedPubkey = window._cachedUserPubkeys?.[targetUserId];
        if (cachedPubkey) {
            try {
                encryptedKeyForTarget = await eciesEncrypt(roomKeyBytes, cachedPubkey);
            } catch {}
        }

        // Создаём DM — передаём оба ключа если есть
        const data = await api('POST', `/api/dm/${targetUserId}`, {
            encrypted_room_key: encryptedKey,
            encrypted_key_for_target: encryptedKeyForTarget,
        });

        // Если не передали ключ для получателя — шифруем по pubkey из ответа
        if (!encryptedKeyForTarget && data.other_user?.x25519_public_key) {
            try {
                const encForTarget = await eciesEncrypt(roomKeyBytes, data.other_user.x25519_public_key);
                const roomId = (data.room || data).id;
                await api('POST', `/api/dm/store-key/${roomId}`, {
                    user_id: targetUserId,
                    ephemeral_pub: encForTarget.ephemeral_pub,
                    ciphertext: encForTarget.ciphertext,
                });
            } catch (e) { console.warn('Не удалось сохранить ключ для получателя:', e); }
        }

        const room = data.room || data;
        // Устанавливаем ключ для нового DM и сохраняем в sessionStorage,
        // чтобы создатель мог отправлять сообщения сразу (не дожидаясь WS-доставки)
        if (encryptedKey && room.id) {
            setRoomKey(room.id, roomKeyBytes);
            if (window.registerRoomSecret) window.registerRoomSecret(room.id);
            // Upload sealed prekeys for offline key distribution
            if (window._uploadSealedPrekeys) {
                window._uploadSealedPrekeys(room.id, roomKeyBytes).catch(() => {});
            }
            try {
                const hex = Array.from(roomKeyBytes, b => b.toString(16).padStart(2, '0')).join('');
                sessionStorage.setItem(`vortex_rk_${room.id}`, hex);
                localStorage.setItem(`vortex_rk_${room.id}`, hex);
            } catch {}
        }

        // Добавляем комнату в список, если её ещё нет
        if (!S.rooms.find(r => r.id === room.id)) {
            room.is_dm = true;
            room.dm_user = data.other_user || {};
            S.rooms.unshift(room);
        }

        // Перерисовываем и открываем
        if (typeof window.renderRoomsList === 'function') window.renderRoomsList();
        if (typeof window.openRoom === 'function') window.openRoom(room.id);

        // Закрываем модалки
        closeModal('contacts-modal');
        closeModal('search-modal');
    } catch (e) {
        vxAlert(e.message);
    }
}

// ── Модальные окна ───────────────────────────────────────────────────────────

export function showSearchModal() {
    openModal('search-modal');
    setTimeout(() => $('search-input')?.focus(), 50);
}

export function showContactsPanel() {
    openModal('contacts-modal');
    loadContacts();
}

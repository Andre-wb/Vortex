// static/js/rooms/state.js — pure localStorage helpers for folders, hidden, pinned, archived chats

export const FOLDER_COLORS = ['#7c3aed', '#2563eb', '#16a34a', '#ea580c', '#dc2626', '#d946ef'];
export const MAX_FOLDERS   = 10;

// ── Folders ──────────────────────────────────────────────────────────────────

export function _getFolders() {
    try { return JSON.parse(localStorage.getItem('vortex_chat_folders') || '[]'); }
    catch { return []; }
}

export function _setFolders(folders) {
    localStorage.setItem('vortex_chat_folders', JSON.stringify(folders));
}

export function _getFolderRooms() {
    try { return JSON.parse(localStorage.getItem('vortex_folder_rooms') || '{}'); }
    catch { return {}; }
}

export function _setFolderRooms(map) {
    localStorage.setItem('vortex_folder_rooms', JSON.stringify(map));
}

export function _nextFolderId() {
    const folders = _getFolders();
    return folders.length ? Math.max(...folders.map(f => f.id)) + 1 : 1;
}

export function assignRoomToFolder(roomId, folderId) {
    const map = _getFolderRooms();
    // remove from all folders first
    for (const key of Object.keys(map)) {
        map[key] = (map[key] || []).filter(id => id !== roomId);
        if (!map[key].length) delete map[key];
    }
    // add to target folder
    if (folderId !== null && folderId !== undefined) {
        if (!map[folderId]) map[folderId] = [];
        map[folderId].push(roomId);
    }
    _setFolderRooms(map);
}

export function _getRoomFolderId(roomId) {
    const map = _getFolderRooms();
    for (const [fid, ids] of Object.entries(map)) {
        if ((ids || []).includes(roomId)) return parseInt(fid, 10);
    }
    return null;
}

export function _getActiveFilterRoomIds(activeFolder) {
    if (activeFolder === null) return null; // show all
    const map = _getFolderRooms();
    return map[activeFolder] || [];
}

// ── Hidden rooms ─────────────────────────────────────────────────────────────

export function _getHiddenRoomIds() {
    try { return JSON.parse(localStorage.getItem('vortex_hidden_rooms') || '[]'); }
    catch { return []; }
}

export function _setHiddenRoomIds(ids) {
    localStorage.setItem('vortex_hidden_rooms', JSON.stringify(ids));
}

// ── Pinned rooms ─────────────────────────────────────────────────────────────

export function _getPinnedRoomIds() {
    try { return JSON.parse(localStorage.getItem('vortex_pinned_rooms') || '[]'); }
    catch { return []; }
}

export function _setPinnedRoomIds(ids) {
    localStorage.setItem('vortex_pinned_rooms', JSON.stringify(ids));
}

// ── Archived rooms ───────────────────────────────────────────────────────────

export function _getArchivedRoomIds() {
    try { return JSON.parse(localStorage.getItem('vortex_archived_rooms') || '[]'); }
    catch { return []; }
}

export function _setArchivedRoomIds(ids) {
    localStorage.setItem('vortex_archived_rooms', JSON.stringify(ids));
}

// ── Hidden-chat password ─────────────────────────────────────────────────────

export function _getHiddenHash() {
    return localStorage.getItem('vortex_hidden_hash') || null;
}

export async function _hashPassword(password) {
    const enc = new TextEncoder().encode(password);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

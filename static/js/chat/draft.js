// static/js/chat/draft.js — save/load draft to localStorage

let _draftTimer = null;

export function saveDraft(roomId, text) {
    if (!roomId) return;
    const key = `vortex_draft_${roomId}`;
    if (text) {
        localStorage.setItem(key, text);
    } else {
        localStorage.removeItem(key);
    }
}

export function loadDraft(roomId) {
    if (!roomId) return '';
    return localStorage.getItem(`vortex_draft_${roomId}`) || '';
}

export function _clearDraft(roomId) {
    if (!roomId) return;
    localStorage.removeItem(`vortex_draft_${roomId}`);
}

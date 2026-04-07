// static/js/chat/messages/shared.js — shared mutable state maps
export const _msgElements = new Map();
export const _msgTexts    = new Map();
// chat.js accesses _msgTexts via window
window._msgTexts = _msgTexts;

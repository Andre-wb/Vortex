// static/js/chat/messages.js — barrel (split into messages/ subfolder)
// Rendering helpers → messages/helpers.js
// Public API + voice/polls/reactions/selection → messages/core.js

export { extractMentions } from './messages/helpers.js';
export * from './messages/core.js';

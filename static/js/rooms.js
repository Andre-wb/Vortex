// static/js/rooms.js — barrel (split into rooms/ subfolder)
// State helpers (localStorage)      → rooms/state.js
// Folders, panels, CRUD, members    → rooms/core.js
// Room info panel, global search    → rooms/info.js
// Channel autoposting (RSS/webhooks)→ rooms/channels.js

export * from './rooms/state.js';
export * from './rooms/core.js';
export * from './rooms/info.js';
import './rooms/channels.js';

/**
 * UX Enhancements — entry point (barrel).
 * Logic split into ux-enhancements/ subfolder by domain:
 *   core.js      — haptic, swipe, themes, ripple, PiP, init, tabs, room-info
 *   contacts.js  — contacts tab, sidebar menus, header popovers
 *   settings.js  — bot store, settings panel, mini-app viewer
 */

export * from './ux-enhancements/core.js';
import './ux-enhancements/contacts.js';
import './ux-enhancements/settings.js';

/**
 * tauri-bridge.js — Vortex Tauri native API bridge
 *
 * Provides a unified interface for native features when running inside the
 * Tauri desktop shell, with graceful fallbacks to standard Web APIs when
 * running in a browser.
 *
 * All public symbols are exported to window.VortexNative for easy access.
 */

(function (global) {
    'use strict';

    // ------------------------------------------------------------------
    // Detection
    // ------------------------------------------------------------------

    /**
     * Returns true when the app is running inside the Tauri desktop shell.
     * @returns {boolean}
     */
    function isTauri() {
        return (
            typeof global.__TAURI__ !== 'undefined' &&
            typeof global.__TAURI__.core !== 'undefined'
        );
    }

    /**
     * Shorthand for invoking a Tauri command.
     * @param {string} cmd
     * @param {object} [args]
     * @returns {Promise<any>}
     */
    async function invoke(cmd, args) {
        return global.__TAURI__.core.invoke(cmd, args || {});
    }

    // ------------------------------------------------------------------
    // File picker
    // ------------------------------------------------------------------

    /**
     * Opens a native file picker (Tauri) or a hidden <input type="file">
     * (browser fallback).
     *
     * @param {object} [options]
     * @param {boolean} [options.multiple=true]  allow multiple selection
     * @param {string[]} [options.accept]        MIME types for browser fallback
     * @returns {Promise<string[]>}  array of file paths (Tauri) or data-URLs (browser)
     */
    async function nativeFilePicker(options) {
        options = options || {};
        const multiple = options.multiple !== false;

        if (isTauri()) {
            try {
                const paths = await invoke('pick_files');
                return Array.isArray(paths) ? paths : [];
            } catch (err) {
                console.error('[tauri-bridge] pick_files failed:', err);
                return [];
            }
        }

        // Browser fallback — resolve when the user closes the picker
        return new Promise((resolve) => {
            const input = document.createElement('input');
            input.type = 'file';
            input.multiple = multiple;
            if (options.accept && options.accept.length) {
                input.accept = options.accept.join(',');
            }
            input.style.display = 'none';
            document.body.appendChild(input);

            input.addEventListener('change', () => {
                const files = Array.from(input.files || []);
                document.body.removeChild(input);
                // Return object-URLs so callers can preview / upload
                resolve(files.map((f) => URL.createObjectURL(f)));
            });

            // Cancelled — user closed without selecting
            input.addEventListener('cancel', () => {
                document.body.removeChild(input);
                resolve([]);
            });

            input.click();
        });
    }

    // ------------------------------------------------------------------
    // Clipboard
    // ------------------------------------------------------------------

    /**
     * Writes text to the system clipboard.
     * @param {string} text
     * @returns {Promise<void>}
     */
    async function nativeCopy(text) {
        if (isTauri()) {
            try {
                await invoke('write_clipboard', { text });
                return;
            } catch (err) {
                console.warn('[tauri-bridge] write_clipboard failed, trying web API:', err);
            }
        }

        // Browser fallback
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            // Legacy execCommand fallback
            const el = document.createElement('textarea');
            el.value = text;
            el.style.cssText = 'position:fixed;left:-9999px;top:-9999px';
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }
    }

    /**
     * Reads text from the system clipboard.
     * @returns {Promise<string>}
     */
    async function nativePaste() {
        if (isTauri()) {
            try {
                return await invoke('read_clipboard');
            } catch (err) {
                console.warn('[tauri-bridge] read_clipboard failed, trying web API:', err);
            }
        }

        if (navigator.clipboard && navigator.clipboard.readText) {
            return navigator.clipboard.readText();
        }

        return '';
    }

    // ------------------------------------------------------------------
    // Window controls
    // ------------------------------------------------------------------

    /** Minimise the native window. No-op in browser. */
    async function minimizeWindow() {
        if (!isTauri()) return;
        await invoke('minimize_window');
    }

    /** Toggle maximise / restore for the native window. No-op in browser. */
    async function maximizeWindow() {
        if (!isTauri()) return;
        await invoke('maximize_window');
    }

    /** Close the native window. Falls back to window.close() in browser. */
    async function closeWindow() {
        if (isTauri()) {
            await invoke('close_window');
        } else {
            global.close();
        }
    }

    // ------------------------------------------------------------------
    // Badge count
    // ------------------------------------------------------------------

    /**
     * Set the dock / taskbar badge counter.
     * @param {number} count  0 to clear
     * @returns {Promise<void>}
     */
    async function setBadge(count) {
        if (isTauri()) {
            try {
                await invoke('set_badge', { count: Math.max(0, count | 0) });
            } catch (err) {
                console.warn('[tauri-bridge] set_badge failed:', err);
            }
        } else if ('setAppBadge' in navigator) {
            // Progressive Web App badge API
            if (count === 0) {
                await navigator.clearAppBadge();
            } else {
                await navigator.setAppBadge(count);
            }
        }
    }

    // ------------------------------------------------------------------
    // Deep-link listener
    // ------------------------------------------------------------------

    /**
     * Register a handler called when the app is opened via vortex:// URL.
     * @param {function(string): void} callback
     */
    function onDeepLink(callback) {
        if (!isTauri()) return;

        global.__TAURI__.event
            .listen('vortex-deep-link', (event) => {
                const url = typeof event.payload === 'string'
                    ? event.payload
                    : JSON.stringify(event.payload);
                callback(url);
            })
            .catch((err) => {
                console.error('[tauri-bridge] deep-link listener error:', err);
            });
    }

    // ------------------------------------------------------------------
    // Theme detection
    // ------------------------------------------------------------------

    /**
     * Register a handler called when the OS theme changes.
     * Also fires immediately with the current theme.
     * @param {function('dark'|'light'): void} callback
     */
    function onThemeChange(callback) {
        // Immediate value via CSS media query (works in both environments)
        const initial = global.matchMedia('(prefers-color-scheme: dark)').matches
            ? 'dark'
            : 'light';
        callback(initial);

        if (isTauri()) {
            // Backend emits 'theme-changed' every time OS preference flips
            global.__TAURI__.event
                .listen('theme-changed', (event) => {
                    callback(event.payload);
                })
                .catch((err) => {
                    console.error('[tauri-bridge] theme-changed listener error:', err);
                });
        } else {
            // Browser fallback via matchMedia
            global
                .matchMedia('(prefers-color-scheme: dark)')
                .addEventListener('change', (e) => {
                    callback(e.matches ? 'dark' : 'light');
                });
        }
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    const VortexNative = {
        isTauri,
        nativeFilePicker,
        nativeCopy,
        nativePaste,
        minimizeWindow,
        maximizeWindow,
        closeWindow,
        setBadge,
        onDeepLink,
        onThemeChange,
    };

    // Make available globally
    global.VortexNative = VortexNative;

    // Also export as ES module when supported (bundlers, modern scripts)
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = VortexNative;
    }
})(typeof window !== 'undefined' ? window : globalThis);

// static/js/chat/liquid-glass.js
// =============================================================================
// Wrapper around Liquid-Glass-PRO with performance-safe defaults.
// No live refraction, no caustics, no cursor tracking, no grain.
// Mirror variant by default, switchable at runtime.
// =============================================================================

import {
    initLiquidGlass   as _proInit,
    destroyLiquidGlass as _proDestroy,
    createReplyQuote  as _proCreateReplyQuote,
    wrapWithDistortion as _proWrap,
    setGlassVariant   as _proSetVariant,
    getGlassVariants  as _proGetVariants,
    getOptions        as _proGetOptions,
} from '../lib/liquid-glass-pro.js';

const _savedVariant = localStorage.getItem('lg-variant') || 'mirror';

let _initialized = false;

/**
 * Initialise Liquid-Glass-PRO in ultra-light mode.
 */
export function initLiquidGlass() {
    if (_initialized) return;
    _initialized = true;

    _proInit({
        // ── Performance: disable heavy features ────────────────────────────
        caustics:            false,   // no WebGL caustic pass
        grain:               false,   // no grain noise overlay
        refractionStrength:  0,       // disables html2canvas background capture
        aberrationStrength:  0,       // no SVG chromatic aberration filter
        breathe:             false,   // no idle breathing animation
        bgCaptureInterval:   999999,  // effectively never (safety net)
        bgCaptureScale:      0.1,     // minimal if somehow triggered

        // ── Visuals ────────────────────────────────────────────────────────
        glassVariant:        _savedVariant,
        glassType:           'BK7',
        iridescence:         false,   // disabled — no spinning overlay
        glassOpacity:        0.10,
        glassSaturation:     160,
    });

    // Inject CSS overrides: no cursor tracking, no iridescence spin,
    // no specular spot, mirror style everywhere.
    _injectOverrides();
}

/**
 * Freeze highlight position on all .lg elements so cursor tracking has no effect.
 * Also inject a CSS rule that blocks PRO from updating --lg-mx/--lg-my.
 */
function _injectOverrides() {
    if (document.getElementById('lg-vortex-overrides')) return;
    const style = document.createElement('style');
    style.id = 'lg-vortex-overrides';
    style.textContent = `
/* No cursor tracking */
.lg { --lg-mx: 50% !important; --lg-my: 28% !important; }

/* All .lg elements use mirror style — no radial-gradient spot, no purple */
.lg {
    backdrop-filter:         blur(3px) saturate(125%) brightness(1.18) !important;
    -webkit-backdrop-filter: blur(3px) saturate(125%) brightness(1.18) !important;
    background: rgba(220,228,240,0.08) !important;
    box-shadow:
        inset  0   2px  0  rgba(255,255,255,0.60),
        inset  1px  0   0  rgba(255,255,255,0.28),
        inset  0  -1px  0  rgba(0,0,0,0.12),
        0  5px 20px  -4px  rgba(0,0,0,0.30),
        0 16px 48px -12px  rgba(0,0,0,0.20),
        0  1px  4px  0     rgba(0,0,0,0.16) !important;
}

/* Kill specular ::before (the bright spot in the center) */
.lg::before {
    display: none !important;
}

/* Kill iridescence spin animation */
.lg::after {
    display: none !important;
}

/* Own messages — same mirror, very subtle warm tint */
.lg.lg-own {
    background: rgba(210,218,235,0.10) !important;
}

/* Message bubbles: solid Telegram-style, no glass effect */
.msg-bubble.lg,
.vb-wrap.lg {
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
    box-shadow: none !important;
}
.msg-bubble.lg > .lg-grain,
.vb-wrap.lg > .lg-grain {
    display: none !important;
}
/* Own messages — Telegram-style green-blue */
.msg-bubble.lg.own,
.vb-wrap.lg.own {
    background: #2b5278 !important;
    color: #fff !important;
    border-bottom-right-radius: 4px !important;
}
.msg-bubble.lg.own .msg-time {
    color: rgba(255,255,255,0.5) !important;
}
/* Incoming messages — neutral solid */
.msg-bubble.lg:not(.own),
.vb-wrap.lg:not(.own) {
    background: var(--bg3) !important;
    color: var(--text) !important;
    border-bottom-left-radius: 4px !important;
}

/* ── Glass on specific UI elements ──────────────────────── */

/* Toggle switches — Apple-style glass track */
.toggle-slider,
.poll-toggle-slider {
    backdrop-filter: blur(8px) saturate(140%) brightness(1.15) !important;
    -webkit-backdrop-filter: blur(8px) saturate(140%) brightness(1.15) !important;
    background: rgba(255,255,255,0.06) !important;
    border-color: rgba(255,255,255,0.12) !important;
}
input:checked + .toggle-slider,
input:checked + .poll-toggle-slider {
    background: var(--accent) !important;
}

/* Context menus — glass dropdown */
.ctx-menu {
    backdrop-filter: blur(16px) saturate(140%) brightness(1.12) !important;
    -webkit-backdrop-filter: blur(16px) saturate(140%) brightness(1.12) !important;
    background: rgba(22,22,30,0.72) !important;
    border: 1px solid rgba(255,255,255,0.10) !important;
}

/* Sidebar burger dropdown */
.cs-dropdown-menu {
    backdrop-filter: blur(16px) saturate(140%) brightness(1.12) !important;
    -webkit-backdrop-filter: blur(16px) saturate(140%) brightness(1.12) !important;
    background: rgba(22,22,30,0.72) !important;
}

/* Modal overlay — frosted glass backdrop */
.modal {
    backdrop-filter: blur(20px) saturate(130%) brightness(1.08) !important;
    -webkit-backdrop-filter: blur(20px) saturate(130%) brightness(1.08) !important;
    background: rgba(22,22,30,0.78) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
}

/* Folder tabs — glass pills */
.folder-tab, .cs-folder-tab {
    backdrop-filter: blur(6px) saturate(130%) !important;
    -webkit-backdrop-filter: blur(6px) saturate(130%) !important;
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid rgba(255,255,255,0.06) !important;
}
.folder-tab.active, .cs-folder-tab.active {
    background: var(--accent) !important;
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
}

/* Pomodoro overlay ring — glass circle */
.ide-pom-ring {
    backdrop-filter: blur(12px) saturate(140%) brightness(1.1) !important;
    -webkit-backdrop-filter: blur(12px) saturate(140%) brightness(1.1) !important;
    background: rgba(22,22,30,0.6) !important;
    border-radius: 50% !important;
    border: 1px solid rgba(255,255,255,0.10) !important;
}
`;
    document.head.appendChild(style);
}

export function destroyLiquidGlass() {
    _initialized = false;
    document.getElementById('lg-vortex-overrides')?.remove();
    _proDestroy();
}

/**
 * Switch glass variant at runtime.
 * @param {string} variant
 */
export function setGlassVariant(variant) {
    localStorage.setItem('lg-variant', variant);
    _proSetVariant(variant);
}

/** @returns {string} */
export function getGlassVariant() {
    return _proGetOptions().glassVariant || _savedVariant;
}

/** @returns {string[]} */
export function getGlassVariants() {
    return _proGetVariants();
}

export { _proWrap as wrapWithDistortion };

export function createGrainLayer() {
    // Grain disabled — return empty div for API compat
    return document.createElement('div');
}

// ── Reply quote (extends PRO with msgType icon support) ─────────────────────

function _replyIcon(text, msgType) {
    if (msgType === 'voice' || (text && text.startsWith('voice_')))
        return '\u{1F3A4} ';
    if (msgType === 'image' || /\.(jpg|jpeg|png|gif|webp)/i.test(text || ''))
        return '\u{1F5BC} ';
    if (msgType === 'file' || text === '\u0444\u0430\u0439\u043b')
        return '\u{1F4CE} ';
    return '';
}

/**
 * Create a reply quote element using Liquid-Glass-PRO styling.
 */
export function createReplyQuote(sender, text, isOwn = false, onClick = null, msgType = '') {
    const icon = _replyIcon(text, msgType);
    const displayText = icon + (text || '');
    const el = _proCreateReplyQuote(sender, displayText, isOwn, onClick);

    // Fix static highlight position (no cursor follow)
    el.style.setProperty('--lg-mx', '50%');
    el.style.setProperty('--lg-my', '28%');

    return el;
}

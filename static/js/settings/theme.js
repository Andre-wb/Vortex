// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 2: Chat Themes & Accent Colors
// ══════════════════════════════════════════════════════════════════════════════

var _chatThemes = {
    default:  { bg: '#09090b', bg2: '#111115', bg3: '#18181d', border: '#202027', text: '#e4e4e7', text2: '#71717a', text3: '#52525b' },
    midnight: { bg: '#0d1117', bg2: '#161b22', bg3: '#21262d', border: '#30363d', text: '#c9d1d9', text2: '#8b949e', text3: '#484f58' },
    ocean:    { bg: '#0a192f', bg2: '#112240', bg3: '#1a365d', border: '#234681', text: '#ccd6f6', text2: '#8892b0', text3: '#495670' },
    forest:   { bg: '#0a1a0a', bg2: '#112211', bg3: '#1a331a', border: '#2a4a2a', text: '#d4e8d4', text2: '#8aaa8a', text3: '#4a6a4a' },
    wine:     { bg: '#1a0a0a', bg2: '#221111', bg3: '#331a1a', border: '#4a2a2a', text: '#e8d4d4', text2: '#aa8a8a', text3: '#6a4a4a' },
    purple:   { bg: '#150a1a', bg2: '#1c1122', bg3: '#261a33', border: '#3a2a4a', text: '#e0d4e8', text2: '#a08aaa', text3: '#604a6a' },
    light:    { bg: '#ffffff', bg2: '#f4f4f5', bg3: '#e4e4e7', border: '#d4d4d8', text: '#18181b', text2: '#52525b', text3: '#a1a1aa' },
};

// ── Theme Mode: dark / light / auto ──────────────────────────────────────────
window.setThemeMode = function(mode) {
    localStorage.setItem('vortex_theme_mode', mode);
    _applyThemeMode(mode);
    // Update toggle buttons
    document.querySelectorAll('.theme-mode-btn').forEach(function(btn) {
        btn.classList.toggle('active', btn.id === 'tm-' + mode);
    });
};

function _applyThemeMode(mode) {
    if (mode === 'auto') {
        var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        setChatTheme(prefersDark ? 'default' : 'light');
    } else if (mode === 'light') {
        setChatTheme('light');
    } else {
        // Dark mode: restore saved dark theme or use default
        var savedDark = localStorage.getItem('vortex_dark_variant') || 'default';
        setChatTheme(savedDark);
    }
}

// Listen for system theme changes (for auto mode)
try {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
        if (localStorage.getItem('vortex_theme_mode') === 'auto') {
            setChatTheme(e.matches ? 'default' : 'light');
        }
    });
} catch(e) {}

window.setChatTheme = function(theme) {
    var t = _chatThemes[theme] || _chatThemes['default'];
    var root = document.documentElement;
    root.style.setProperty('--bg', t.bg);
    root.style.setProperty('--bg2', t.bg2);
    root.style.setProperty('--bg3', t.bg3);
    root.style.setProperty('--border', t.border);
    root.style.setProperty('--text', t.text);
    root.style.setProperty('--text2', t.text2);
    root.style.setProperty('--text3', t.text3);
    localStorage.setItem('vortex_theme', theme);
    // Remember dark variant for "dark" mode toggle
    if (theme !== 'light') {
        localStorage.setItem('vortex_dark_variant', theme);
    }
    if (theme === 'light') {
        document.body.setAttribute('data-theme', 'light');
    } else {
        document.body.removeAttribute('data-theme');
    }
    // Show/hide background grids based on theme
    var darkGrid = document.getElementById('dark-bg-grid');
    var lightGrid = document.getElementById('light-bg-grid');
    if (darkGrid) darkGrid.style.display = theme === 'light' ? 'none' : '';
    if (lightGrid) lightGrid.style.display = theme === 'light' ? '' : 'none';

    document.querySelectorAll('.theme-option').forEach(function(el) {
        el.classList.toggle('active', el.dataset.theme === theme);
    });
};

window.setAccentColor = function(color) {
    document.documentElement.style.setProperty('--accent', color);
    var accent2 = _lightenColor(color, 0.3);
    document.documentElement.style.setProperty('--accent2', accent2);
    localStorage.setItem('vortex_accent', color);
    document.querySelectorAll('.accent-option').forEach(function(el) {
        el.classList.toggle('active', el.dataset.accent === color);
    });
};

function _lightenColor(hex, amount) {
    hex = hex.replace('#', '');
    var r = parseInt(hex.substring(0,2), 16);
    var g = parseInt(hex.substring(2,4), 16);
    var b = parseInt(hex.substring(4,6), 16);
    r = Math.min(255, Math.round(r + (255 - r) * amount));
    g = Math.min(255, Math.round(g + (255 - g) * amount));
    b = Math.min(255, Math.round(b + (255 - b) * amount));
    return '#' + [r,g,b].map(function(c){ return c.toString(16).padStart(2,'0'); }).join('');
}

function _highlightActiveTheme() {
    var saved = localStorage.getItem('vortex_theme') || 'default';
    document.querySelectorAll('.theme-option').forEach(function(el) {
        el.classList.toggle('active', el.dataset.theme === saved);
    });
    // Highlight active mode button
    var mode = localStorage.getItem('vortex_theme_mode') || 'dark';
    document.querySelectorAll('.theme-mode-btn').forEach(function(btn) {
        btn.classList.toggle('active', btn.id === 'tm-' + mode);
    });
}

window._highlightLang = function() {
    var lang = localStorage.getItem('vortex_locale') || 'ru';
    document.querySelectorAll('.lang-btn').forEach(function(btn) {
        btn.classList.toggle('active', btn.dataset.lang === lang);
    });
};

function _highlightActiveAccent() {
    var saved = localStorage.getItem('vortex_accent') || '#7C3AED';
    document.querySelectorAll('.accent-option').forEach(function(el) {
        el.classList.toggle('active', el.dataset.accent === saved);
    });
}

// -- Chat Background Presets --
var _chatBgPresets = {
    none: 'none',
    stars: 'radial-gradient(ellipse at 20% 50%,rgba(124,58,237,0.15) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(59,130,246,0.1) 0%,transparent 50%),radial-gradient(1px 1px at 10% 10%,rgba(255,255,255,0.3) 50%,transparent 50%),radial-gradient(1px 1px at 20% 40%,rgba(255,255,255,0.15) 50%,transparent 50%),radial-gradient(1px 1px at 30% 70%,rgba(255,255,255,0.2) 50%,transparent 50%),radial-gradient(1px 1px at 45% 15%,rgba(255,255,255,0.1) 50%,transparent 50%),radial-gradient(1px 1px at 55% 55%,rgba(255,255,255,0.2) 50%,transparent 50%),radial-gradient(1px 1px at 60% 30%,rgba(255,255,255,0.25) 50%,transparent 50%),radial-gradient(1px 1px at 75% 65%,rgba(255,255,255,0.12) 50%,transparent 50%),radial-gradient(1px 1px at 80% 80%,rgba(255,255,255,0.15) 50%,transparent 50%),radial-gradient(1px 1px at 90% 45%,rgba(255,255,255,0.18) 50%,transparent 50%)',
    aurora: 'linear-gradient(160deg,rgba(10,10,18,0) 0%,rgba(26,10,46,0.6) 30%,rgba(10,25,47,0.6) 60%,rgba(10,26,26,0.4) 100%)',
    sunset: 'linear-gradient(180deg,rgba(26,10,46,0.6) 0%,rgba(46,26,26,0.6) 50%,rgba(26,16,8,0.5) 100%)',
    'ocean-wave': 'linear-gradient(180deg,rgba(10,25,47,0.5) 0%,rgba(13,40,71,0.5) 40%,rgba(10,58,94,0.4) 70%,rgba(10,25,47,0.5) 100%)',
    mesh: 'repeating-linear-gradient(0deg,transparent,transparent 19px,rgba(255,255,255,0.03) 19px,rgba(255,255,255,0.03) 20px),repeating-linear-gradient(90deg,transparent,transparent 19px,rgba(255,255,255,0.03) 19px,rgba(255,255,255,0.03) 20px)',
    'deep-space': 'radial-gradient(ellipse at 50% 0%,rgba(88,28,135,0.2) 0%,transparent 60%),radial-gradient(ellipse at 80% 100%,rgba(30,64,175,0.15) 0%,transparent 50%)',
    // Light theme backgrounds
    'light-clean': 'none',
    'light-lavender': 'linear-gradient(180deg,#f0e6ff 0%,#e8d5ff 50%,#f5eeff 100%)',
    'light-sky': 'linear-gradient(180deg,#dbeafe 0%,#bfdbfe 50%,#e0f2fe 100%)',
    'light-mint': 'linear-gradient(180deg,#d1fae5 0%,#a7f3d0 50%,#ecfdf5 100%)',
    'light-peach': 'linear-gradient(180deg,#fef3c7 0%,#fde68a 50%,#fffbeb 100%)',
    'light-rose': 'linear-gradient(180deg,#ffe4e6 0%,#fecdd3 50%,#fff1f2 100%)',
    'light-dots': 'radial-gradient(circle,rgba(124,58,237,0.08) 1px,transparent 1px)',
    'light-grid': 'repeating-linear-gradient(0deg,transparent,transparent 19px,rgba(0,0,0,0.04) 19px,rgba(0,0,0,0.04) 20px),repeating-linear-gradient(90deg,transparent,transparent 19px,rgba(0,0,0,0.04) 19px,rgba(0,0,0,0.04) 20px)',
};

var _lightBgColors = {
    'light-clean': '#f8f9fa', 'light-lavender': '#f5eeff', 'light-sky': '#e0f2fe',
    'light-mint': '#ecfdf5', 'light-peach': '#fffbeb', 'light-rose': '#fff1f2',
    'light-dots': '#fafafa', 'light-grid': '#fafafa',
};

window.setChatBackground = function(bgKey) {
    var mc = document.getElementById('messages-container');
    if (!mc) return;
    if (bgKey === 'none' || bgKey === 'light-clean') {
        mc.style.backgroundImage = 'none';
        mc.style.backgroundSize = '';
        mc.style.backgroundPosition = '';
        mc.style.backgroundRepeat = '';
        mc.style.backgroundColor = _lightBgColors[bgKey] || '';
    } else if (bgKey === 'custom') {
        return;
    } else {
        var preset = _chatBgPresets[bgKey];
        if (!preset) return;
        mc.style.backgroundImage = preset;
        mc.style.backgroundColor = _lightBgColors[bgKey] || '';
        mc.style.backgroundSize = bgKey === 'light-dots' ? '16px 16px' : '';
        mc.style.backgroundPosition = '';
        mc.style.backgroundRepeat = '';
    }
    localStorage.setItem('vortex_chat_bg', bgKey);
    if (bgKey !== 'custom') {
        localStorage.removeItem('vortex_chat_bg_custom');
    }
    document.querySelectorAll('.bg-preview').forEach(function(el) {
        el.classList.toggle('active', el.dataset.bg === bgKey);
    });
};

window.uploadChatBackground = function(input) {
    if (!input.files || !input.files[0]) return;
    var file = input.files[0];
    if (file.size > 2 * 1024 * 1024) {
        alert(t('settings.fileTooLarge'));
        input.value = '';
        return;
    }
    var reader = new FileReader();
    reader.onload = function(e) {
        var dataUrl = e.target.result;
        var mc = document.getElementById('messages-container');
        if (!mc) return;
        mc.style.backgroundImage = 'url(' + dataUrl + ')';
        mc.style.backgroundSize = 'cover';
        mc.style.backgroundPosition = 'center';
        mc.style.backgroundRepeat = 'no-repeat';
        localStorage.setItem('vortex_chat_bg', 'custom');
        localStorage.setItem('vortex_chat_bg_custom', dataUrl);
        document.querySelectorAll('.bg-preview').forEach(function(el) {
            el.classList.toggle('active', el.dataset.bg === 'custom');
        });
    };
    reader.readAsDataURL(file);
    input.value = '';
};

// Restore saved theme/accent/background on page load
(function() {
    // Check theme mode first (auto respects system preference)
    var themeMode = localStorage.getItem('vortex_theme_mode');
    if (themeMode === 'auto') {
        var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        var autoTheme = prefersDark ? (localStorage.getItem('vortex_dark_variant') || 'default') : 'light';
        var t = _chatThemes[autoTheme] || _chatThemes['default'];
        var root = document.documentElement;
        root.style.setProperty('--bg', t.bg);
        root.style.setProperty('--bg2', t.bg2);
        root.style.setProperty('--bg3', t.bg3);
        root.style.setProperty('--border', t.border);
        root.style.setProperty('--text', t.text);
        root.style.setProperty('--text2', t.text2);
        root.style.setProperty('--text3', t.text3);
        if (autoTheme === 'light') document.body.setAttribute('data-theme', 'light');
        else document.body.removeAttribute('data-theme');
    } else {
        var savedTheme = localStorage.getItem('vortex_theme');
        if (savedTheme && _chatThemes[savedTheme]) {
            var t = _chatThemes[savedTheme];
            var root = document.documentElement;
            root.style.setProperty('--bg', t.bg);
            root.style.setProperty('--bg2', t.bg2);
            root.style.setProperty('--bg3', t.bg3);
            root.style.setProperty('--border', t.border);
            root.style.setProperty('--text', t.text);
            root.style.setProperty('--text2', t.text2);
            root.style.setProperty('--text3', t.text3);
            if (savedTheme === 'light') {
                document.body.setAttribute('data-theme', 'light');
            }
        }
    }
    var savedAccent = localStorage.getItem('vortex_accent');
    if (savedAccent) {
        document.documentElement.style.setProperty('--accent', savedAccent);
        document.documentElement.style.setProperty('--accent2', _lightenColor(savedAccent, 0.3));
    }
    function _restoreChatBg() {
        var savedBg = localStorage.getItem('vortex_chat_bg');
        if (!savedBg || savedBg === 'none') return;
        var mc = document.getElementById('messages-container');
        if (!mc) return;
        if (savedBg === 'custom') {
            var customData = localStorage.getItem('vortex_chat_bg_custom');
            if (customData) {
                mc.style.backgroundImage = 'url(' + customData + ')';
                mc.style.backgroundSize = 'cover';
                mc.style.backgroundPosition = 'center';
                mc.style.backgroundRepeat = 'no-repeat';
            }
        } else if (_chatBgPresets[savedBg]) {
            mc.style.backgroundImage = _chatBgPresets[savedBg];
        }
        document.querySelectorAll('.bg-preview').forEach(function(el) {
            el.classList.toggle('active', el.dataset.bg === savedBg);
        });
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _restoreChatBg);
    } else {
        _restoreChatBg();
    }
})();


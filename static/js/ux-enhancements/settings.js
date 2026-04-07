import { Haptic } from './core.js';

// ══════════════════════════════════════════════════════════════════════════════
// 13. Bot Store — load, render, search, categories
// ══════════════════════════════════════════════════════════════════════════════

let _botCategory = '';
let _botSearchDebounce = null;

async function loadBotStore() {
    const grid = document.getElementById('bot-store-grid');
    const featured = document.getElementById('bot-featured-grid');
    const empty = document.getElementById('bot-store-empty');
    if (!grid) return;

    try {
        const params = new URLSearchParams();
        if (_botCategory) params.set('category', _botCategory);
        params.set('sort', 'popular');
        const resp = await fetch(`/api/bots/store?${params}`, { credentials: 'include' });
        let bots = [];
        if (resp.ok) bots = (await resp.json()).bots || [];

        if (!bots.length) {
            grid.innerHTML = '';
            if (featured) featured.innerHTML = '';
            if (empty) empty.style.display = 'flex';
            return;
        }
        if (empty) empty.style.display = 'none';

        if (featured && !_botCategory) {
            featured.innerHTML = bots.slice(0, 3).map(b => _renderBotCard(b)).join('');
            const fs = document.getElementById('bot-featured-section');
            if (fs) fs.style.display = '';
        } else {
            const fs = document.getElementById('bot-featured-section');
            if (fs) fs.style.display = 'none';
        }
        grid.innerHTML = bots.map(b => _renderBotCard(b)).join('');
    } catch (e) {
        console.warn('Bot store error:', e);
    }
}

function _renderBotCard(bot) {
    const botSvg = '<svg width="24" height="24" fill="#fff" viewBox="0 0 24 24"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1v3h-1.07A7 7 0 0 1 7.07 19H6v-3h1a7 7 0 0 1 7-7h-1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2M7.5 13A2.5 2.5 0 0 0 5 15.5 2.5 2.5 0 0 0 7.5 18a2.5 2.5 0 0 0 2.5-2.5A2.5 2.5 0 0 0 7.5 13m9 0a2.5 2.5 0 0 0-2.5 2.5 2.5 2.5 0 0 0 2.5 2.5 2.5 2.5 0 0 0 2.5-2.5 2.5 2.5 0 0 0-2.5-2.5"/></svg>';
    const avatar = bot.avatar_url ? `<img src="${_esc(bot.avatar_url)}" style="width:100%;height:100%;border-radius:12px;object-fit:cover;">` : botSvg;
    const starSvg = '<svg width="12" height="12" fill="currentColor" viewBox="0 0 24 24"><path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/></svg>';
    const rating = bot.rating ? starSvg + ' ' + bot.rating.toFixed(1) : '';
    const installs = bot.installs || 0;
    let badges = '';
    if (bot.has_inline) badges += '<span class="bot-badge inline">INLINE</span>';
    if (bot.has_commands) badges += '<span class="bot-badge commands">COMMANDS</span>';
    if (bot.has_mini_app) badges += '<span class="bot-badge miniapp">MINI APP</span>';

    return `<div class="bot-card" onclick="openBotDetail(${bot.id})">
        <div class="bot-card-header">
            <div class="bot-card-avatar">${avatar}</div>
            <div><div class="bot-card-name">${_esc(bot.name)}</div><div class="bot-card-category">${_esc(bot.category || 'other')}</div></div>
        </div>
        <div class="bot-card-desc">${_esc(bot.description || '')}</div>
        ${badges ? '<div class="bot-card-badges">' + badges + '</div>' : ''}
        <div class="bot-card-footer">
            <div class="bot-card-stats">${rating ? '<span>' + rating + '</span>' : ''}<span><svg width="12" height="12" fill="currentColor" viewBox="0 0 24 24"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg> ${installs}</span></div>
            <button class="bot-card-install" onclick="event.stopPropagation();installBot(${bot.id})">${window.t ? window.t('bots.install') : 'Install'}</button>
        </div>
    </div>`;
}

function searchBotStore(query) {
    clearTimeout(_botSearchDebounce);
    _botSearchDebounce = setTimeout(async () => {
        const grid = document.getElementById('bot-store-grid');
        if (!grid) return;
        if (!query || query.length < 2) { loadBotStore(); return; }
        try {
            const resp = await fetch(`/api/bots/store?q=${encodeURIComponent(query)}`, { credentials: 'include' });
            if (!resp.ok) return;
            const bots = (await resp.json()).bots || [];
            grid.innerHTML = bots.length ? bots.map(b => _renderBotCard(b)).join('') : `<div style="padding:20px;text-align:center;color:var(--text3);">${window.t ? window.t('bots.noBotsFound') : 'No bots found'}</div>`;
            const fs = document.getElementById('bot-featured-section');
            if (fs) fs.style.display = 'none';
        } catch {}
    }, 300);
}

function filterBotCategory(cat) {
    _botCategory = cat;
    document.querySelectorAll('#bot-categories .cs-folder-tab').forEach(b => b.classList.toggle('active', (b.dataset.cat || '') === cat));
    loadBotStore();
    Haptic.selection();
}

async function installBot(botId) { Haptic.success(); alert(window.t ? window.t('bots.installSuccess') : 'Bot installed! Add it to a room from room settings.'); }
function openBotDetail(botId) {
    Haptic.light();
    const allBots = [
        ...(document.getElementById('bot-featured-grid')?.querySelectorAll('.bot-card') || []),
        ...(document.getElementById('bot-store-grid')?.querySelectorAll('.bot-card') || []),
    ];
    // Find the card that was clicked and install from it
    installBot(botId);
}

window.loadBotStore = loadBotStore;
window.searchBotStore = searchBotStore;
window.filterBotCategory = filterBotCategory;
window.installBot = installBot;
window.openBotDetail = openBotDetail;


// ══════════════════════════════════════════════════════════════════════════════
// 14. Settings fullscreen view — sections, language picker
// ══════════════════════════════════════════════════════════════════════════════

const ALL_LANGUAGES = [
    {code:"af",name:"Afrikaans"},{code:"am",name:"አማርኛ"},{code:"ar",name:"العربية"},
    {code:"az",name:"Azərbaycan"},{code:"be",name:"Беларуская"},{code:"bg",name:"Български"},
    {code:"bn",name:"বাংলা"},{code:"ca",name:"Català"},{code:"cs",name:"Čeština"},
    {code:"cy",name:"Cymraeg"},{code:"da",name:"Dansk"},{code:"de",name:"Deutsch"},
    {code:"el",name:"Ελληνικά"},{code:"en",name:"English"},{code:"eo",name:"Esperanto"},
    {code:"es",name:"Español"},{code:"et",name:"Eesti"},{code:"eu",name:"Euskara"},
    {code:"fa",name:"فارسی"},{code:"fi",name:"Suomi"},{code:"fr",name:"Français"},
    {code:"ga",name:"Gaeilge"},{code:"gl",name:"Galego"},{code:"gu",name:"ગુજરાતી"},
    {code:"ha",name:"Hausa"},{code:"he",name:"עברית"},{code:"hi",name:"हिन्दी"},
    {code:"hr",name:"Hrvatski"},{code:"hu",name:"Magyar"},{code:"hy",name:"Հայերեն"},
    {code:"id",name:"Bahasa Indonesia"},{code:"is",name:"Íslenska"},{code:"it",name:"Italiano"},
    {code:"ja",name:"日本語"},{code:"ka",name:"ქართული"},{code:"kk",name:"Қазақша"},
    {code:"km",name:"ភាសាខ្មែរ"},{code:"kn",name:"ಕನ್ನಡ"},{code:"ko",name:"한국어"},
    {code:"ku",name:"Kurdî"},{code:"ky",name:"Кыргызча"},{code:"lt",name:"Lietuvių"},
    {code:"lv",name:"Latviešu"},{code:"mk",name:"Македонски"},{code:"ml",name:"മലയാളം"},
    {code:"mn",name:"Монгол"},{code:"mr",name:"मराठी"},{code:"ms",name:"Bahasa Melayu"},
    {code:"my",name:"မြန်မာ"},{code:"ne",name:"नेपाली"},{code:"nl",name:"Nederlands"},
    {code:"no",name:"Norsk"},{code:"pa",name:"ਪੰਜਾਬੀ"},{code:"pl",name:"Polski"},
    {code:"pt",name:"Português"},{code:"ro",name:"Română"},{code:"ru",name:"Русский"},
    {code:"si",name:"සිංහල"},{code:"sk",name:"Slovenčina"},{code:"sl",name:"Slovenščina"},
    {code:"so",name:"Soomaali"},{code:"sr",name:"Српски"},{code:"sv",name:"Svenska"},
    {code:"sw",name:"Kiswahili"},{code:"ta",name:"தமிழ்"},{code:"te",name:"తెలుగు"},
    {code:"th",name:"ไทย"},{code:"tl",name:"Filipino"},{code:"tr",name:"Türkçe"},
    {code:"uk",name:"Українська"},{code:"ur",name:"اردو"},{code:"uz",name:"Oʻzbek"},
    {code:"vi",name:"Tiếng Việt"},{code:"zh",name:"中文"},{code:"zh-TW",name:"繁體中文"},
    {code:"zu",name:"isiZulu"},
].sort((a,b) => a.name.localeCompare(b.name));

function openSettingsView() {
    // Populate profile card
    const S = window.AppState;
    if (S && S.user) {
        const av = document.getElementById('set-avatar');
        const nm = document.getElementById('set-name');
        const ph = document.getElementById('set-phone');
        if (av) {
            if (S.user.avatar_emoji) { av.textContent = S.user.avatar_emoji; }
            else { av.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>'; }
        }
        if (nm) nm.textContent = S.user.display_name || S.user.username || '—';
        if (ph) ph.textContent = S.user.phone || S.user.username || '—';
    }
    // Show current language
    const langVal = document.getElementById('set-current-lang');
    const currentLang = window.getLocale ? window.getLocale() : 'en';
    const langObj = ALL_LANGUAGES.find(l => l.code === currentLang);
    if (langVal) langVal.textContent = langObj ? langObj.name : currentLang;

    // Show main list, hide sub-pages
    const main = document.getElementById('settings-main-list');
    const sub = document.getElementById('settings-sub-page');
    const lang = document.getElementById('settings-lang-page');
    if (main) main.style.display = '';
    if (sub) sub.style.display = 'none';
    if (lang) lang.style.display = 'none';
}

function openSettingsSection(section) {
    if (section === 'language') {
        document.getElementById('settings-main-list').style.display = 'none';
        document.getElementById('settings-lang-page').style.display = 'flex';
        renderLanguageList('');
        const input = document.getElementById('lang-search-input');
        if (input) { input.value = ''; input.focus(); }
        Haptic.light();
        return;
    }

    const sectionEl = document.getElementById('settings-' + section);
    const content   = document.getElementById('settings-sub-content');
    const sub       = document.getElementById('settings-sub-page');
    const main      = document.getElementById('settings-main-list');
    const titleEl   = document.getElementById('settings-sub-title');
    const pool      = document.getElementById('settings-sections-pool');

    if (!sectionEl || !content || !sub || !pool) return;

    // Return any previously open section back to the pool
    while (content.firstChild) pool.appendChild(content.firstChild);

    // Move section into sub-page and make it visible
    sectionEl.classList.add('active');
    content.appendChild(sectionEl);

    // Set localised title
    const titles = {
        profile:       window.t ? window.t('settings.profile')       : 'Profile',
        security:      window.t ? window.t('settings.security')      : 'Security',
        appearance:    window.t ? window.t('settings.appearance')    : 'Appearance',
        notifications: window.t ? window.t('settings.notifications') : 'Notifications',
        storage:       window.t ? window.t('settings.storage')       : 'Storage',
        calls:         window.t ? window.t('settings.calls')         : 'Calls',
        stickers:      window.t ? window.t('settings.stickers')      : 'Stickers',
        bots:          window.t ? window.t('settings.bots')          : 'Bots',
        about:         window.t ? window.t('settings.about')         : 'About',
        privacy:       window.t ? window.t('settings.privacy')       : 'Privacy',
        dev:           window.t ? window.t('settings.devSettings')   : 'Dev Settings',
        panic:         window.t ? window.t('settings.panic')         : 'Panic',
    };
    if (titleEl) titleEl.textContent = titles[section] || section;

    if (main) main.style.display = 'none';
    sub.style.display = 'flex';
    Haptic.light();

    // Section-specific initialization
    const S = window.AppState;
    if (section === 'profile' && S?.user) {
        const dn = document.getElementById('set-display-name');
        const em = document.getElementById('set-email');
        if (dn) dn.value = S.user.display_name || '';
        if (em) em.value = S.user.email || '';
        const av = document.getElementById('settings-avatar');
        if (av) {
            if (S.user.avatar_url) {
                av.innerHTML = `<img src="${S.user.avatar_url}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
            } else {
                if (S.user.avatar_emoji) { av.textContent = S.user.avatar_emoji; }
                else { av.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>'; }
            }
        }
        window._settingsSelectedEmoji = null;
        document.querySelectorAll('#settings-emoji-picker .emoji-btn').forEach(b => {
            b.classList.remove('emoji-selected');
            if (b.dataset.emoji === S.user.avatar_emoji) b.classList.add('emoji-selected');
        });

        // Bio
        const bioEl = document.getElementById('set-bio');
        if (bioEl) {
            bioEl.value = S.user.bio || '';
            const counter = document.getElementById('set-bio-count');
            if (counter) counter.textContent = bioEl.value.length;
            bioEl.oninput = () => { if (counter) counter.textContent = bioEl.value.length; };
        }

        // Birthday
        const bdBtn  = document.getElementById('set-birthday-btn');
        const bdText = document.getElementById('set-birthday-text');
        if (bdBtn && bdText) {
            const bd = S.user.birth_date || '';
            bdBtn.dataset.value = bd;
            if (bd) {
                const MONTHS_GEN = window.t ? window.t('time.monthsGen') : ['января','февраля','марта','апреля','мая','июня','июля','августа','сентября','октября','ноября','декабря'];
                try {
                    if (bd.startsWith('--')) {
                        const [m, d] = bd.slice(2).split('-').map(Number);
                        bdText.textContent = d + ' ' + (Array.isArray(MONTHS_GEN) ? MONTHS_GEN[m - 1] : bd);
                    } else {
                        const [y, m, d] = bd.split('-').map(Number);
                        bdText.textContent = d + '.' + String(m).padStart(2,'0') + '.' + y;
                    }
                } catch { bdText.textContent = bd; }
            } else {
                bdText.textContent = window.t ? window.t('settings.birthdayNotSet') : 'Not set';
            }
        }

        // Profile background
        const currentBg = S.user.profile_bg || 'linear-gradient(135deg,#0f0c29,#302b63,#24243e)';
        window._settingsProfileBg = currentBg;
        document.querySelectorAll('.pbg-swatch').forEach(b => {
            const match = b.dataset.bg === currentBg;
            b.classList.toggle('active', match);
        });
        const bgPreview = document.getElementById('set-profile-bg-preview');
        if (bgPreview) bgPreview.style.background = currentBg;

        // Profile icon
        const currentIcon = S.user.profile_icon || '';
        window._settingsProfileIcon = currentIcon || undefined;
        document.querySelectorAll('.pi-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.icon === currentIcon);
        });
        // Sync mini preview
        const piSvg  = document.getElementById('pi-preview-svg');
        const piHero = document.getElementById('pi-preview-hero');
        if (piSvg && window._PROFILE_ICONS) {
            const paths = window._PROFILE_ICONS[currentIcon] || '';
            piSvg.innerHTML    = paths;
            piSvg.style.display = paths ? '' : 'none';
        }
        if (piHero) {
            const bg = S.user.profile_bg || 'linear-gradient(135deg,#0f0c29,#302b63,#24243e)';
            piHero.style.background = bg;
        }
    }
    if (section === 'security' && S?.user) {
        const pk = document.getElementById('settings-pubkey');
        if (pk) pk.textContent = S.user.x25519_public_key || '-';
        if (typeof window._loadPinStatus === 'function') window._loadPinStatus();
        if (typeof window._load2FAStatus === 'function') window._load2FAStatus();
    }
    if (section === 'appearance') {
        if (typeof window._highlightActiveTheme === 'function') window._highlightActiveTheme();
        if (typeof window._highlightActiveAccent === 'function') window._highlightActiveAccent();
        if (typeof window._highlightLang === 'function') window._highlightLang();
    }
    if (section === 'calls') {
        if (typeof window._loadCallSettings === 'function') window._loadCallSettings();
    }
    if (section === 'stickers') {
        if (typeof window.loadStickerManager === 'function') window.loadStickerManager();
    }
    if (section === 'bots') {
        if (typeof window.loadMyBots === 'function') window.loadMyBots();
    }
    if (section === 'privacy') {
        if (typeof window._loadPrivacySettings === 'function') window._loadPrivacySettings();
    }
    if (section === 'dev') {
        if (typeof window.DevSettings?.renderDevSettings === 'function') {
            window.DevSettings.renderDevSettings();
            // update theme count badge
            const badge = document.getElementById('dev-theme-count');
            if (badge && window.DevSettings.themes) badge.textContent = window.DevSettings.themes.length + ' themes';
        }
    }
}

function closeSettingsLangPage() {
    document.getElementById('settings-lang-page').style.display = 'none';
    document.getElementById('settings-main-list').style.display = '';
}

function closeSettingsSubPage() {
    const sub     = document.getElementById('settings-sub-page');
    const main    = document.getElementById('settings-main-list');
    const content = document.getElementById('settings-sub-content');
    const pool    = document.getElementById('settings-sections-pool');

    // Return section back to pool
    if (content && pool) {
        while (content.firstChild) {
            const el = content.firstChild;
            el.classList.remove('active');
            pool.appendChild(el);
        }
    }

    if (sub) sub.style.display = 'none';
    if (main) main.style.display = '';
}

function renderLanguageList(query) {
    const list = document.getElementById('lang-list');
    if (!list) return;
    const currentLang = window.getLocale ? window.getLocale() : 'en';
    const q = (query || '').toLowerCase();

    const filtered = q
        ? ALL_LANGUAGES.filter(l => l.name.toLowerCase().includes(q) || l.code.toLowerCase().includes(q))
        : ALL_LANGUAGES;

    list.innerHTML = filtered.map(l => {
        const isActive = l.code === currentLang;
        return `<div class="lang-item${isActive ? ' active' : ''}" onclick="selectLanguage('${l.code}')">
            <div class="lang-check"></div>
            <span class="lang-native">${l.name}</span>
            <span class="lang-code">${l.code}</span>
        </div>`;
    }).join('');
}

function filterLanguages(query) {
    renderLanguageList(query);
}

async function selectLanguage(code) {
    if (window.setLocale) await window.setLocale(code);
    Haptic.medium();
    renderLanguageList('');
    // Update label
    const langVal = document.getElementById('set-current-lang');
    const langObj = ALL_LANGUAGES.find(l => l.code === code);
    if (langVal) langVal.textContent = langObj ? langObj.name : code;
    // Update select in old settings modal too
    const sel = document.getElementById('lang-select');
    if (sel) sel.value = code;
}

window.openSettingsView = openSettingsView;
window.openSettingsSection = openSettingsSection;
window.closeSettingsLangPage = closeSettingsLangPage;
window.closeSettingsSubPage = closeSettingsSubPage;
window.filterLanguages = filterLanguages;
window.selectLanguage = selectLanguage;

// ══════════════════════════════════════════════════════════════════════════════
// Mini App fullscreen viewer
// ══════════════════════════════════════════════════════════════════════════════

window.openMiniApp = function(botId, url, title) {
    const S      = window.AppState;
    const screen = document.getElementById('mini-app-screen');
    const body   = document.getElementById('mini-app-panel-body');
    const nameEl = document.getElementById('mini-app-panel-name');
    const subEl  = document.getElementById('mini-app-header-sub');
    if (!screen || !body) return;

    // Resolve bot info from current room when called from the chat button
    const bot    = S?.currentRoom?.dm_user;
    const name   = title || bot?.display_name || bot?.username || 'Mini App';
    const appUrl = url   || bot?.mini_app_url  || null;

    if (nameEl) nameEl.textContent = name;
    if (subEl)  subEl.textContent  = bot?.username ? '@' + bot.username : (window.t ? window.t('tabs.bots') : 'Bot').toLowerCase();

    if (appUrl) {
        body.innerHTML = `<iframe class="mini-app-iframe" src="${appUrl}"
            allow="camera; microphone; payment"
            sandbox="allow-scripts allow-same-origin allow-forms allow-popups"></iframe>`;
    } else {
        body.innerHTML = `
        <div class="mini-app-placeholder">
            <div class="mini-app-placeholder-icon">
                <svg width="32" height="32" fill="#a78bfa" viewBox="0 0 24 24">
                    <path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/>
                </svg>
            </div>
            <p class="mini-app-placeholder-title">${name}</p>
            <p class="mini-app-placeholder-sub">${window.t ? window.t('bots.noMiniAppUrl') : 'No Mini App URL configured for this bot.'}</p>
        </div>`;
    }

    screen.classList.add('mini-app-open');
    Haptic?.light?.();
};

window.closeMiniApp = function() {
    const screen = document.getElementById('mini-app-screen');
    const body   = document.getElementById('mini-app-panel-body');
    if (!screen) return;
    screen.classList.remove('mini-app-open');
    setTimeout(() => { if (body) body.innerHTML = ''; }, 350);
};


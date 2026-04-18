/* Vortex Wizard i18n — same engine as controller website, scoped to the
 * wizard/admin locales. 130 languages shipped, same extended list.
 */
(() => {
    'use strict';

    const STORAGE_KEY = 'vortex_wizard_locale';
    const DEFAULT_LOCALE = 'en';

    const SUPPORTED = [
        'en','ru','uk','es','fr','de','it','pt','zh','zh-TW','ja','ko','ar','hi',
        'tr','pl','nl','th','vi','id','cs','sv','ro','hu','el','da','fi','no','he',
        'fa','bg','hr','sr','sk','sl','lt','lv','et','ka','hy','az','kk','uz','bn',
        'ms','af','sw','ca','eu','gl','is','mk','be','mn','ky','ur','ta','te','mr',
        'gu','kn','ml','pa','ne','si','km','my','tl','zu','eo','ga','cy','so','ku',
        'am','ha','sq','bs','tg','tk','ti','yi','ny','st','gd','fy','co','sm','ay',
        'ee','ak',
        'as','bho','bm','ceb','ckb','doi','dv','gn','haw','hmn','ht','ig','ilo','jv',
        'kri','la','lb','lg','ln','lo','lus','mai','mg','mi','mt','nso','om','or',
        'ps','qu','rw','sa','sd','sn','su','tt','ug','xh','yo',
        // Cloud-only locales — now supported in wizard too
        'ba','bo','bua','ce','crh','cv','ff','kv','mhr','oc','os','sah','tn','tyv','udm','wo',
    ];

    const NAMES = {
        en:'English', ru:'Русский', uk:'Українська', es:'Español', fr:'Français',
        de:'Deutsch', it:'Italiano', pt:'Português', zh:'中文', 'zh-TW':'繁體中文',
        ja:'日本語', ko:'한국어', ar:'العربية', hi:'हिन्दी', tr:'Türkçe',
        pl:'Polski', nl:'Nederlands', th:'ไทย', vi:'Tiếng Việt', id:'Bahasa Indonesia',
        cs:'Čeština', sv:'Svenska', ro:'Română', hu:'Magyar', el:'Ελληνικά',
        da:'Dansk', fi:'Suomi', no:'Norsk', he:'עברית', fa:'فارسی',
        bg:'Български', hr:'Hrvatski', sr:'Српски', sk:'Slovenčina', sl:'Slovenščina',
        lt:'Lietuvių', lv:'Latviešu', et:'Eesti', ka:'ქართული', hy:'Հայերեն',
        az:'Azərbaycan', kk:'Қазақша', uz:'Oʻzbek', bn:'বাংলা', ms:'Bahasa Melayu',
        af:'Afrikaans', sw:'Kiswahili', ca:'Català', eu:'Euskara', gl:'Galego',
        is:'Íslenska', mk:'Македонски', be:'Беларуская', mn:'Монгол', ky:'Кыргызча',
        ur:'اردو', ta:'தமிழ்', te:'తెలుగు', mr:'मराठी', gu:'ગુજરાતી',
        kn:'ಕನ್ನಡ', ml:'മലയാളം', pa:'ਪੰਜਾਬੀ', ne:'नेपाली', si:'සිංහල',
        km:'ភាសាខ្មែរ', my:'မြန်မာ', tl:'Filipino', zu:'isiZulu', eo:'Esperanto',
        ga:'Gaeilge', cy:'Cymraeg', so:'Soomaali', ku:'Kurdî', am:'አማርኛ',
        ha:'Hausa', sq:'Shqip', bs:'Bosanski', tg:'Тоҷикӣ', tk:'Türkmen',
        ti:'ትግርኛ', yi:'ייִדיש', ny:'Chichewa', st:'Sesotho', gd:'Gàidhlig',
        fy:'Frysk', co:'Corsu', sm:'Gagana Sāmoa', ay:'Aymar aru', ee:'Eʋegbe',
        ak:'Akan',
    };

    const RTL = new Set(['ar','fa','he','ur','yi']);
    const ALLOWED_TAGS = new Set(['STRONG','EM','BR','B','I','CODE']);

    let _cur = DEFAULT_LOCALE;
    let _tr = {};
    let _fb = {};

    function resolve(obj, key) {
        const parts = key.split('.');
        let c = obj;
        for (const p of parts) {
            if (c && typeof c === 'object' && p in c) c = c[p];
            else return null;
        }
        return c;
    }
    function t(k) { return resolve(_tr, k) ?? resolve(_fb, k) ?? k; }

    function renderInline(el, txt) {
        while (el.firstChild) el.removeChild(el.firstChild);
        if (typeof txt !== 'string') return;
        if (!/[<>]/.test(txt)) { el.textContent = txt; return; }
        const doc = new DOMParser().parseFromString('<body>' + txt + '</body>', 'text/html');
        doc.body.childNodes.forEach(n => el.appendChild(sanitize(n)));
    }
    function sanitize(node) {
        if (node.nodeType === Node.TEXT_NODE) return document.createTextNode(node.textContent || '');
        if (node.nodeType !== Node.ELEMENT_NODE) return document.createTextNode(node.textContent || '');
        if (!ALLOWED_TAGS.has(node.tagName)) return document.createTextNode(node.textContent || '');
        const el = document.createElement(node.tagName.toLowerCase());
        node.childNodes.forEach(c => el.appendChild(sanitize(c)));
        return el;
    }

    function applyDom() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const val = t(el.dataset.i18n);
            if (typeof val !== 'string') return;
            if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                if (el.hasAttribute('data-i18n-placeholder-mode') || el.type !== 'button') el.placeholder = val;
                else el.value = val;
                return;
            }
            renderInline(el, val);
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const v = t(el.dataset.i18nPlaceholder);
            if (typeof v === 'string') el.placeholder = v;
        });
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const v = t(el.dataset.i18nTitle);
            if (typeof v === 'string') el.setAttribute('title', v);
        });
        document.documentElement.lang = _cur;
        document.documentElement.dir = RTL.has(_cur) ? 'rtl' : 'ltr';
    }

    async function load(code) {
        const r = await fetch('/locales/' + code + '.json', { cache: 'force-cache' });
        if (!r.ok) throw new Error('no locale');
        return r.json();
    }

    async function setLocale(code) {
        if (!SUPPORTED.includes(code)) code = DEFAULT_LOCALE;
        try { _tr = await load(code); } catch { _tr = {}; }
        if (code !== DEFAULT_LOCALE && Object.keys(_fb).length === 0) {
            try { _fb = await load(DEFAULT_LOCALE); } catch { _fb = {}; }
        } else if (code === DEFAULT_LOCALE) _fb = _tr;
        _cur = code;
        try { localStorage.setItem(STORAGE_KEY, code); } catch {}
        applyDom();
        window.dispatchEvent(new CustomEvent('i18n:loaded', { detail: { locale: code } }));
    }

    function pickInitial() {
        let s = null;
        try { s = localStorage.getItem(STORAGE_KEY); } catch {}
        if (s && SUPPORTED.includes(s)) return s;
        const nav = (navigator.language || 'en').toLowerCase();
        const short = nav.split('-')[0];
        if (SUPPORTED.includes(nav)) return nav;
        if (SUPPORTED.includes(short)) return short;
        return DEFAULT_LOCALE;
    }

    function buildPicker() {
        const menu = document.getElementById('lang-menu');
        const btn  = document.getElementById('lang-btn');
        const cur  = document.getElementById('lang-current');
        if (!menu || !btn || !cur) return;

        while (menu.firstChild) menu.removeChild(menu.firstChild);
        SUPPORTED.forEach(code => {
            const it = document.createElement('button');
            it.className = 'lang-item' + (code === _cur ? ' active' : '');
            it.type = 'button';
            const name = document.createElement('span');
            name.className = 'lang-item-name';
            name.textContent = NAMES[code] || code;
            const cd = document.createElement('span');
            cd.className = 'lang-item-code';
            cd.textContent = code.toUpperCase();
            it.append(name, cd);
            it.addEventListener('click', async () => {
                await setLocale(code);
                cur.textContent = code.toUpperCase();
                menu.classList.remove('open');
                menu.querySelectorAll('.lang-item.active').forEach(e => e.classList.remove('active'));
                it.classList.add('active');
            });
            menu.appendChild(it);
        });
        btn.addEventListener('click', e => { e.stopPropagation(); menu.classList.toggle('open'); });
        document.addEventListener('click', e => {
            if (!menu.contains(e.target) && !btn.contains(e.target)) menu.classList.remove('open');
        });
        cur.textContent = _cur.toUpperCase();
    }

    window.VortexI18n = { t, setLocale, applyDom, getLocale: () => _cur };

    (async () => {
        await setLocale(pickInitial());
        buildPicker();
    })();
})();

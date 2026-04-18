// node_setup/static/js/setup/step-lang.js — Step 0: Language selection + i18n
// Matches the registration language picker exactly (orbs, typewriter, purple theme)

const _WIZ_LANGS = [
    {code:"ru",name:"Русский",hint:"Выберите язык"},
    {code:"en",name:"English",hint:"Choose your language"},
    {code:"uk",name:"Українська",hint:"Оберіть мову"},
    {code:"es",name:"Español",hint:"Elige tu idioma"},
    {code:"fr",name:"Français",hint:"Choisissez votre langue"},
    {code:"de",name:"Deutsch",hint:"Wähle deine Sprache"},
    {code:"it",name:"Italiano",hint:"Scegli la tua lingua"},
    {code:"pt",name:"Português",hint:"Escolha seu idioma"},
    {code:"zh",name:"中文",hint:"选择语言"},
    {code:"ja",name:"日本語",hint:"言語を選択"},
    {code:"ko",name:"한국어",hint:"언어를 선택하세요"},
    {code:"ar",name:"العربية",hint:"اختر لغتك"},
    {code:"hi",name:"हिन्दी",hint:"अपनी भाषा चुनें"},
    {code:"tr",name:"Türkçe",hint:"Dilinizi seçin"},
    {code:"pl",name:"Polski",hint:"Wybierz język"},
    {code:"nl",name:"Nederlands",hint:"Kies je taal"},
    {code:"th",name:"ไทย",hint:"เลือกภาษา"},
    {code:"vi",name:"Tiếng Việt",hint:"Chọn ngôn ngữ"},
    {code:"id",name:"Bahasa Indonesia",hint:"Pilih bahasa"},
    {code:"cs",name:"Čeština",hint:"Vyberte jazyk"},
    {code:"sv",name:"Svenska",hint:"Välj språk"},
    {code:"ro",name:"Română",hint:"Alege limba"},
    {code:"hu",name:"Magyar",hint:"Válaszd ki a nyelvet"},
    {code:"el",name:"Ελληνικά",hint:"Επιλέξτε γλώσσα"},
    {code:"da",name:"Dansk",hint:"Vælg sprog"},
    {code:"fi",name:"Suomi",hint:"Valitse kieli"},
    {code:"no",name:"Norsk",hint:"Velg språk"},
    {code:"he",name:"עברית",hint:"בחר שפה"},
    {code:"fa",name:"فارسی",hint:"زبان خود را انتخاب کنید"},
    {code:"bg",name:"Български",hint:"Изберете език"},
    {code:"hr",name:"Hrvatski",hint:"Odaberite jezik"},
    {code:"sr",name:"Српски",hint:"Изаберите језик"},
    {code:"sk",name:"Slovenčina",hint:"Vyberte jazyk"},
    {code:"sl",name:"Slovenščina",hint:"Izberite jezik"},
    {code:"lt",name:"Lietuvių",hint:"Pasirinkite kalbą"},
    {code:"lv",name:"Latviešu",hint:"Izvēlieties valodu"},
    {code:"et",name:"Eesti",hint:"Vali keel"},
    {code:"ka",name:"ქართული",hint:"აირჩიეთ ენა"},
    {code:"hy",name:"Հայերեն",hint:"Ընտրեք լեdelays"},
    {code:"az",name:"Azərbaycan",hint:"Dili seçin"},
    {code:"kk",name:"Қазақша",hint:"Тілді таңдаңыз"},
    {code:"uz",name:"Oʻzbek",hint:"Tilni tanlang"},
    {code:"bn",name:"বাংলা",hint:"ভাষা নির্বাচন করুন"},
    {code:"ms",name:"Bahasa Melayu",hint:"Pilih bahasa"},
    {code:"af",name:"Afrikaans",hint:"Kies jou taal"},
    {code:"sw",name:"Kiswahili",hint:"Chagua lugha"},
    {code:"ca",name:"Català",hint:"Tria el teu idioma"},
    {code:"eu",name:"Euskara",hint:"Aukeratu hizkuntza"},
    {code:"gl",name:"Galego",hint:"Elixe o teu idioma"},
    {code:"is",name:"Íslenska",hint:"Veldu tungumál"},
    {code:"mk",name:"Македонски",hint:"Изберете јазик"},
    {code:"be",name:"Беларуская",hint:"Абярыце мову"},
    {code:"mn",name:"Монгол",hint:"Хэлээ сонго"},
    {code:"ky",name:"Кыргызча",hint:"Тилди тандаңыз"},
    {code:"ur",name:"اردو",hint:"اپنی زبان منتخب کریں"},
    {code:"ta",name:"தமிழ்",hint:"மொழியைத் தேர்வுசெய்"},
    {code:"te",name:"తెలుగు",hint:"భాషను ఎంచుకోండి"},
    {code:"mr",name:"मराठी",hint:"भाषा निवडा"},
    {code:"gu",name:"ગુજરાતી",hint:"ભાષા પસંદ કરો"},
    {code:"kn",name:"ಕನ್ನಡ",hint:"ಭಾಷೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ"},
    {code:"ml",name:"മലയാളം",hint:"ഭാഷ തിരഞ്ഞെടുക്കുക"},
    {code:"pa",name:"ਪੰਜਾਬੀ",hint:"ਭਾਸ਼ਾ ਚੁਣੋ"},
    {code:"ne",name:"नेपाली",hint:"भाषा छान्नुहोस्"},
    {code:"si",name:"සිංහල",hint:"භාෂාව තෝරන්න"},
    {code:"km",name:"ភាសាខ្មែរ",hint:"ជ្រើសរើសភាសា"},
    {code:"my",name:"မြန်မာ",hint:"ဘာသာစကားရွေးပါ"},
    {code:"zh-TW",name:"繁體中文",hint:"選擇語言"},
    {code:"tl",name:"Filipino",hint:"Pumili ng wika"},
    {code:"zu",name:"isiZulu",hint:"Khetha ulimi"},
    {code:"eo",name:"Esperanto",hint:"Elektu lingvon"},
    {code:"ga",name:"Gaeilge",hint:"Roghnaigh teanga"},
    {code:"cy",name:"Cymraeg",hint:"Dewiswch iaith"},
    {code:"so",name:"Soomaali",hint:"Dooro luuqadda"},
    {code:"ku",name:"Kurdî",hint:"Zimanê xwe hilbijêre"},
    {code:"am",name:"አማርኛ",hint:"ቋንቋ ይምረጡ"},
    {code:"ha",name:"Hausa",hint:"Zaɓi harshe"},
    {code:"sq",name:"Shqip",hint:"Zgjidhni gjuhën"},
    {code:"bs",name:"Bosanski",hint:"Odaberite jezik"},
    {code:"tg",name:"Тоҷикӣ",hint:"Забонро интихоб кунед"},
    {code:"tk",name:"Türkmen",hint:"Dili saýlaň"},
    {code:"ti",name:"ትግርኛ",hint:"ቋንቋ ምረጹ"},
    {code:"yi",name:"ייִדיש",hint:"קלייַבט אויס שפּראַך"},
    {code:"ny",name:"Chichewa",hint:"Sankhani chilankhulo"},
    {code:"st",name:"Sesotho",hint:"Khetha puo"},
    {code:"gd",name:"Gàidhlig",hint:"Tagh cànan"},
    {code:"fy",name:"Frysk",hint:"Kies jo taal"},
    {code:"co",name:"Corsu",hint:"Sceglie a lingua"},
    {code:"sm",name:"Gagana Sāmoa",hint:"Filifili gagana"},
    {code:"ay",name:"Aymar aru",hint:"Arunt'aña"},
    {code:"ee",name:"Eʋegbe",hint:"Tia gbe"},
    {code:"ak",name:"Akan",hint:"Yi kasa"},
    {code:"bho",name:"भोजपुरी",hint:"भाषा चुनीं"},
    {code:"doi",name:"डोगरी",hint:"बोली चुनो"},
    {code:"dv",name:"ދިވެހި",hint:"ބަސް ޚިޔާރުކުރައްވާ"},
    {code:"hmn",name:"Hmong",hint:"Xaiv lus"},
    {code:"ilo",name:"Ilokano",hint:"Pilien ti pagsasao"},
    {code:"kri",name:"Krio",hint:"Pik langwej"},
    {code:"lus",name:"Mizo ṭawng",hint:"Ṭawng thlang rawh"},
    {code:"nso",name:"Sepedi",hint:"Kgetha polelo"},
    {code:"ckb",name:"کوردیی ناوەندی",hint:"زمان هەڵبژێرە"},
];

let _wizLpSelected = null;
let _wizTranslations = {};

// ── Typewriter title rotation (same as registration) ──
const _WIZ_TITLE_HINTS = _WIZ_LANGS.map(l => l.hint).filter(Boolean);
let _wizTitleIdx = 0;
let _wizTitleRunning = false;

const _WIZ_TYPE_SPEED   = 45;
const _WIZ_DELETE_SPEED  = 30;
const _WIZ_PAUSE_AFTER   = 1800;

function _wizSleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function _wizTypewriterLoop() {
    var el = document.getElementById('wiz-lp-title');
    if (!el) return;
    _wizTitleRunning = true;

    while (_wizTitleRunning) {
        var text = _WIZ_TITLE_HINTS[_wizTitleIdx];

        // Type in
        for (var i = 0; i <= text.length && _wizTitleRunning; i++) {
            el.textContent = text.slice(0, i);
            await _wizSleep(_WIZ_TYPE_SPEED);
        }

        if (!_wizTitleRunning) break;
        await _wizSleep(_WIZ_PAUSE_AFTER);
        if (!_wizTitleRunning) break;

        // Delete
        var current = el.textContent;
        for (var j = current.length; j >= 0 && _wizTitleRunning; j--) {
            el.textContent = current.slice(0, j);
            await _wizSleep(_WIZ_DELETE_SPEED);
        }

        if (!_wizTitleRunning) break;
        await _wizSleep(200);

        _wizTitleIdx = (_wizTitleIdx + 1) % _WIZ_TITLE_HINTS.length;
    }
}

function _wizStartTitleRotation() {
    _wizTitleRunning = true;
    _wizTypewriterLoop();
}

function _wizStopTitleRotation() {
    _wizTitleRunning = false;
}

// ── Continue button text map ──
const _WIZ_CONTINUE_MAP = {
    ru:"Продолжить",en:"Continue",uk:"Продовжити",es:"Continuar",fr:"Continuer",
    de:"Weiter",it:"Continua",pt:"Continuar",zh:"继续","zh-TW":"繼續",ja:"続ける",
    ko:"계속",ar:"متابعة",hi:"जारी रखें",tr:"Devam",pl:"Kontynuuj",nl:"Doorgaan",
    th:"ดำเนินการต่อ",vi:"Tiếp tục",id:"Lanjutkan",cs:"Pokračovat",sv:"Fortsätt",
    ro:"Continuă",hu:"Folytatás",el:"Συνέχεια",da:"Fortsæt",fi:"Jatka",
    no:"Fortsett",he:"המשך",fa:"ادامه",bg:"Продължи",hr:"Nastavi",
    sr:"Настави",sk:"Pokračovať",sl:"Nadaljuj",lt:"Tęsti",lv:"Turpināt",
    et:"Jätka",ka:"გაგრძელება",hy:"Շարունակել",az:"Davam",kk:"Жалғастыру",
    uz:"Davom",bn:"চালিয়ে যান",ms:"Teruskan",
};

// ── Subtitle text map ──
const _WIZ_SUB_MAP = {
    ru:"Можно изменить позже в настройках",en:"You can change it later in settings",
    uk:"Можна змінити пізніше в налаштуваннях",es:"Puedes cambiarlo en ajustes",
    fr:"Modifiable dans les paramètres",de:"Kann in Einstellungen geändert werden",
    it:"Puoi cambiarlo nelle impostazioni",pt:"Pode alterar nas configurações",
    zh:"可以在设置中更改",ja:"設定で変更できます",ko:"설정에서 변경 가능",
    tr:"Ayarlardan değiştirebilirsiniz",pl:"Zmienisz w ustawieniach",
    ar:"يمكنك تغييرها في الإعدادات",hi:"सेटिंग्स में बदल सकते हैं",
};

// ── Render language list (safe DOM construction) ──
function _wizLpRender(query) {
    var list = document.getElementById('wiz-lp-list');
    if (!list) return;
    var q = (query || '').toLowerCase();
    var filtered = q
        ? _WIZ_LANGS.filter(function(l) {
            return l.name.toLowerCase().includes(q) || l.code.includes(q) || (l.hint && l.hint.toLowerCase().includes(q));
        })
        : _WIZ_LANGS;

    list.replaceChildren();
    filtered.forEach(function(lang) {
        var div = document.createElement('div');
        div.className = 'wiz-lp-item' + (_wizLpSelected === lang.code ? ' selected' : '');
        div.onclick = function() { _wizLpSelect(lang.code); };

        var radio = document.createElement('div');
        radio.className = 'wiz-lp-radio';

        var name = document.createElement('span');
        name.className = 'wiz-lp-name';
        name.textContent = lang.name;

        var code = document.createElement('span');
        code.className = 'wiz-lp-code';
        code.textContent = lang.code;

        div.append(radio, name, code);
        list.appendChild(div);
    });
}

// ── Select language (with typewriter re-type) ──
var _wizSelectVersion = 0;

function _wizLpSelect(code) {
    _wizLpSelected = code;
    _wizLpRender(document.getElementById('wiz-lp-search')?.value || '');

    var btn = document.getElementById('wiz-lp-continue');
    if (btn) btn.disabled = false;

    var lang = _WIZ_LANGS.find(function(l) { return l.code === code; });
    if (lang) {
        _wizStopTitleRotation();
        var el = document.getElementById('wiz-lp-title');
        if (el) {
            var ver = ++_wizSelectVersion;
            var oldText = el.textContent;
            (async function() {
                // Delete old text
                for (var i = oldText.length; i >= 0; i--) {
                    if (_wizSelectVersion !== ver) return;
                    el.textContent = oldText.slice(0, i);
                    await _wizSleep(_WIZ_DELETE_SPEED);
                }
                if (_wizSelectVersion !== ver) return;
                await _wizSleep(150);
                // Type new text
                var newText = lang.hint;
                for (var j = 0; j <= newText.length; j++) {
                    if (_wizSelectVersion !== ver) return;
                    el.textContent = newText.slice(0, j);
                    await _wizSleep(_WIZ_TYPE_SPEED);
                }
            })();
        }

        // Update button text
        var btnText = document.getElementById('wiz-lp-btn-text');
        if (btnText) btnText.textContent = _WIZ_CONTINUE_MAP[code] || 'Continue';

        // Update subtitle
        var sub = document.getElementById('wiz-lp-subtitle');
        if (sub) sub.textContent = _WIZ_SUB_MAP[code] || _WIZ_SUB_MAP.en;
    }

    // Scroll selected into view
    setTimeout(function() {
        var sel = document.querySelector('.wiz-lp-item.selected');
        if (sel) sel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }, 50);
}

window.wizLpFilter = function(q) { _wizLpRender(q); };

// ── Confirm + load translations ──
window.wizLpConfirm = async function() {
    if (!_wizLpSelected) return;
    _wizStopTitleRotation();

    // Load locale JSON from main app's static files
    try {
        var resp = await fetch('/static/locales/' + _wizLpSelected + '.json');
        if (resp.ok) {
            _wizTranslations = await resp.json();
            _applyWizTranslations();
        }
    } catch (e) {
        console.warn('Failed to load locale:', e);
    }

    _setStep(1);
};

// ── Simple i18n: translate all data-i18n elements ──
function _applyWizTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(function(el) {
        var key = el.dataset.i18n;
        var val = _resolveKey(_wizTranslations, key);
        if (val && typeof val === 'string') {
            if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                el.placeholder = val;
            } else {
                el.textContent = val;
            }
        }
    });
}

function _resolveKey(obj, keyPath) {
    var parts = keyPath.split('.');
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
        if (cur && typeof cur === 'object' && parts[i] in cur) {
            cur = cur[parts[i]];
        } else {
            return null;
        }
    }
    return cur;
}

// ── Init: render list, auto-detect browser language, start typewriter ──
window.addEventListener('DOMContentLoaded', function() {
    _wizLpRender();
    _wizStartTitleRotation();

    var browserLang = (navigator.language || '').slice(0, 2).toLowerCase();
    var match = _WIZ_LANGS.find(function(l) { return l.code === browserLang; });
    if (match) _wizLpSelect(match.code);
});

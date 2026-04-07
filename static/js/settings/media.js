// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 3: Location Sharing
// ══════════════════════════════════════════════════════════════════════════════

window.shareLocation = function() {
    if (!navigator.geolocation) {
        alert(window.t ? window.t('settings.geoNotSupported') : 'Геолокация не поддерживается вашим браузером');
        return;
    }
    var S = window.AppState;
    if (!S.currentRoom) {
        alert(window.t ? window.t('settings.openChatFirst') : 'Сначала откройте чат');
        return;
    }

    navigator.geolocation.getCurrentPosition(function(pos) {
        var lat = pos.coords.latitude.toFixed(6);
        var lng = pos.coords.longitude.toFixed(6);
        var text = '\ud83d\udccd Местоположение: ' + lat + ', ' + lng + '\nhttps://maps.google.com/maps?q=' + lat + ',' + lng;

        var input = document.getElementById('msg-input');
        if (input) {
            input.value = text;
            if (window.sendMessage) window.sendMessage();
        }
    }, function(err) {
        if (err.code === 1) {
            var isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
            var msg = 'Доступ к геолокации запрещён.\n\n';
            if (isMac) {
                msg += '1. macOS: Системные настройки → Конфиденциальность → Службы геолокации → включите для браузера\n';
                msg += '2. Браузер: нажмите на замок в адресной строке → Местоположение → Разрешить\n';
                msg += '3. Перезагрузите страницу';
            } else {
                msg += 'Нажмите на замок в адресной строке → Местоположение → Разрешить, затем перезагрузите страницу';
            }
            alert(msg);
        } else if (err.code === 2) {
            alert(window.t ? window.t('settings.geoFailed') : 'Не удалось определить местоположение.\nПроверьте что GPS/Wi-Fi включены.');
        } else {
            alert(window.t ? window.t('settings.geoTimeout') : 'Таймаут определения местоположения.\nПопробуйте на открытом пространстве.');
        }
    }, { enableHighAccuracy: false, timeout: 15000, maximumAge: 60000 });
};

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 4: GIF Search (Tenor API)
// ══════════════════════════════════════════════════════════════════════════════

var _gifSearchTimer = null;

window.openGifPicker = function() {
    if (!window.AppState.currentRoom) {
        alert(window.t ? window.t('settings.openChatFirst') : 'Сначала откройте чат');
        return;
    }
    window.openModal('gif-modal');
    var el = document.getElementById('gif-search-input');
    if (el) { el.value = ''; el.focus(); }
    var results = document.getElementById('gif-results');
    if (results) results.innerHTML = ("<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.enterQuery') : 'Введите запрос для поиска') + '</div>');
};

window.searchGifs = function(query) {
    clearTimeout(_gifSearchTimer);
    var el = document.getElementById('gif-results');
    if (!query || !query.trim()) {
        if (el) el.innerHTML = ("<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.enterQuery') : 'Введите запрос для поиска') + '</div>');
        return;
    }
    _gifSearchTimer = setTimeout(async function() {
        if (el) el.innerHTML = ("<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.searching') : 'Поиск...') + '</div>');
        try {
            var key = 'AIzaSyDvT6aTBbn1fJWEAqEz1Kht2xQN_pjUib0';
            var resp = await fetch('https://tenor.googleapis.com/v2/search?q=' + encodeURIComponent(query) + '&key=' + key + '&limit=20&media_filter=gif');
            var data = await resp.json();
            var results = data.results || [];
            if (results.length === 0) {
                el.innerHTML = "<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.nothingFound') : 'Ничего не найдено') + '</div>';
                return;
            }
            el.innerHTML = results.map(function(gif) {
                var preview = (gif.media_formats && (gif.media_formats.nanogif || gif.media_formats.tinygif || {}).url) || '';
                var full = (gif.media_formats && (gif.media_formats.gif || gif.media_formats.tinygif || {}).url) || preview;
                return '<img src="' + preview + '" data-full="' + full + '" onclick="sendGif(\'' + full.replace(/'/g, "\\'") + '\')" ' +
                       'style="width:calc(50% - 4px);cursor:pointer;border-radius:4px;object-fit:cover;max-height:150px;">';
            }).join('');
        } catch(e) {
            if (el) el.innerHTML = "<div style='padding:16px;color:var(--red);text-align:center;'>" + (window.t ? window.t('gif.searchError').replace('{error}', e.message) : 'Ошибка поиска: ' + e.message) + '</div>';
        }
    }, 500);
};

window.sendGif = function(url) {
    window.closeModal('gif-modal');
    var input = document.getElementById('msg-input');
    if (input) {
        input.value = '[GIF] ' + url;
        if (window.sendMessage) window.sendMessage();
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 5: Share Profile Link
// ══════════════════════════════════════════════════════════════════════════════

window.copyProfileLink = function() {
    var u = window.AppState.user;
    if (!u) return;
    var link = location.origin + '?contact=' + encodeURIComponent(u.username);
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(link).then(function() {
            alert((window.t ? window.t('settings.linkCopied') : 'Ссылка скопирована: {link}').replace('{link}', link));
        }).catch(function() {
            prompt('Скопируйте ссылку:', link);
        });
    } else {
        prompt('Скопируйте ссылку:', link);
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE: Sticker Picker
// ══════════════════════════════════════════════════════════════════════════════

// Animated sticker definitions (vortex pack)
var ANIMATED_STICKERS = [
    { name: 'wave',     emoji: '\u{1F44B}', label: 'Привет' },
    { name: 'heart',    emoji: '\u{2764}\u{FE0F}', label: 'Сердце' },
    { name: 'fire',     emoji: '\u{1F525}', label: 'Огонь' },
    { name: 'laugh',    emoji: '\u{1F602}', label: 'Смех' },
    { name: 'cry',      emoji: '\u{1F62D}', label: 'Плач' },
    { name: 'thumbsup', emoji: '\u{1F44D}', label: 'Класс' },
    { name: 'party',    emoji: '\u{1F389}', label: 'Праздник' },
    { name: 'rocket',   emoji: '\u{1F680}', label: 'Ракета' },
    { name: 'star',     emoji: '\u{2B50}',  label: 'Звезда' },
    { name: 'cool',     emoji: '\u{1F60E}', label: 'Круто' },
    { name: 'love',     emoji: '\u{1F970}', label: 'Любовь' },
    { name: 'clap',     emoji: '\u{1F44F}', label: 'Аплодисменты' },
    { name: 'think',    emoji: '\u{1F914}', label: 'Думаю' },
    { name: 'scared',   emoji: '\u{1F631}', label: 'Страх' },
    { name: 'angry',    emoji: '\u{1F621}', label: 'Злость' },
    { name: 'sleep',    emoji: '\u{1F634}', label: 'Сон' },
    { name: 'money',    emoji: '\u{1F911}', label: 'Деньги' },
    { name: 'ghost',    emoji: '\u{1F47B}', label: 'Призрак' },
    { name: 'hundred',  emoji: '\u{1F4AF}', label: '100' },
    { name: 'eyes',     emoji: '\u{1F440}', label: 'Глаза' }
];

// Classic emoji sticker packs
var STICKER_PACKS = {
    emotions: ['\u{1F600}','\u{1F602}','\u{1F923}','\u{1F60D}','\u{1F970}','\u{1F618}','\u{1F60E}','\u{1F929}','\u{1F624}','\u{1F621}','\u{1F622}','\u{1F62D}','\u{1F97A}','\u{1F631}','\u{1F92E}','\u{1F480}','\u{1F47B}','\u{1F921}','\u{1F608}','\u{1F47F}','\u{1F4A9}','\u{1F916}','\u{1F47D}','\u{1F383}'],
    animals: ['\u{1F436}','\u{1F431}','\u{1F42D}','\u{1F439}','\u{1F430}','\u{1F98A}','\u{1F43B}','\u{1F43C}','\u{1F428}','\u{1F42F}','\u{1F981}','\u{1F42E}','\u{1F437}','\u{1F438}','\u{1F435}','\u{1F984}','\u{1F41D}','\u{1F98B}','\u{1F422}','\u{1F40D}','\u{1F98E}','\u{1F988}','\u{1F419}','\u{1F980}'],
    food: ['\u{1F34E}','\u{1F355}','\u{1F354}','\u{1F32E}','\u{1F35F}','\u{1F37F}','\u{1F369}','\u{1F382}','\u{1F370}','\u{1F36B}','\u{1F36C}','\u{2615}','\u{1F37A}','\u{1F377}','\u{1F964}','\u{1F349}','\u{1F347}','\u{1F353}','\u{1F951}','\u{1F33D}','\u{1F955}','\u{1F346}','\u{1F966}','\u{1F9C0}'],
    activities: ['\u{26BD}','\u{1F3C0}','\u{1F3BE}','\u{1F3C8}','\u{1F3AF}','\u{1F3AE}','\u{1F3B2}','\u{1F3AD}','\u{1F3A8}','\u{1F3B5}','\u{1F3B8}','\u{1F3B9}','\u{1F3C6}','\u{1F947}','\u{1F3AA}','\u{1F3A0}','\u{1F3C4}','\u{1F6B4}','\u{26F7}','\u{1F3CA}','\u{1F9D7}','\u{1F938}','\u{1F3CB}','\u{1F93A}'],
    objects: ['\u{2764}','\u{1F494}','\u{1F495}','\u{1F496}','\u{2728}','\u{2B50}','\u{1F31F}','\u{1F4AB}','\u{1F525}','\u{1F4A7}','\u{1F308}','\u{2600}','\u{1F319}','\u{26A1}','\u{1F48E}','\u{1F381}','\u{1F388}','\u{1F380}','\u{1F3E0}','\u{1F680}','\u{2708}','\u{1F6F8}','\u{1F4BB}','\u{1F4F1}'],
};

window.openStickerPicker = function() {
    if (window.openModal) window.openModal('sticker-modal');
    window.showStickerCategory('animated', document.querySelector('#sticker-modal .settings-tab'));
};

window.showStickerCategory = function(cat, btn) {
    document.querySelectorAll('#sticker-modal .settings-tab').forEach(function(t) { t.classList.remove('active'); });
    if (btn) btn.classList.add('active');
    var grid = document.getElementById('sticker-grid');
    if (!grid) return;

    if (cat === 'animated') {
        // Render animated sticker grid (4 columns)
        grid.className = 'sticker-grid-animated';
        grid.style.cssText = '';
        grid.innerHTML = ANIMATED_STICKERS.map(function(s) {
            return '<button class="sticker-preview" onclick="sendAnimatedSticker(\'' + s.name + '\')" title="' + s.label + '">' +
                '<span class="animated-sticker sticker-' + s.name + '">' + s.emoji + '</span>' +
                '</button>';
        }).join('');
    } else {
        // Render classic emoji grid (5 columns)
        grid.className = '';
        grid.style.cssText = 'display:grid;grid-template-columns:repeat(5,1fr);gap:4px;max-height:250px;overflow-y:auto;';
        var stickers = STICKER_PACKS[cat] || [];
        grid.innerHTML = stickers.map(function(s) {
            return '<div style="font-size:36px;text-align:center;cursor:pointer;padding:8px;border-radius:8px;transition:background 0.1s;" ' +
                'onmouseover="this.style.background=\'var(--bg3)\'" onmouseout="this.style.background=\'\'" ' +
                'onclick="sendSticker(\'' + s + '\')">' + s + '</div>';
        }).join('');
    }
};

window.sendAnimatedSticker = function(name) {
    if (window.closeModal) window.closeModal('sticker-modal');
    if (window.sendStickerDirect) window.sendStickerDirect('[STICKER] vortex:' + name);
};

window.sendSticker = function(emoji) {
    if (window.closeModal) window.closeModal('sticker-modal');
    if (window.sendStickerDirect) window.sendStickerDirect('[STICKER] ' + emoji);
};


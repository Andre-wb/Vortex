// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 3: Location Sharing
// ══════════════════════════════════════════════════════════════════════════════

window.shareLocation = function() {
    if (!navigator.geolocation) {
        alert(window.t ? window.t('settings.geoNotSupported') : 'Geolocation is not supported by your browser');
        return;
    }
    var S = window.AppState;
    if (!S.currentRoom) {
        alert(window.t ? window.t('settings.openChatFirst') : 'Open a chat first');
        return;
    }

    navigator.geolocation.getCurrentPosition(function(pos) {
        var lat = pos.coords.latitude.toFixed(6);
        var lng = pos.coords.longitude.toFixed(6);
        var text = '\ud83d\udccd ' + (window.t ? window.t('settings.location') : 'Location') + ': ' + lat + ', ' + lng + '\nhttps://maps.google.com/maps?q=' + lat + ',' + lng;

        var input = document.getElementById('msg-input');
        if (input) {
            input.value = text;
            if (window.sendMessage) window.sendMessage();
        }
    }, function(err) {
        if (err.code === 1) {
            var isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
            if (isMac) {
                alert(window.t ? window.t('settings.geoDeniedMac') : 'Geolocation access denied.\n\n1. macOS: System Settings → Privacy → Location Services → enable for browser\n2. Browser: click the lock icon in the address bar → Location → Allow\n3. Reload the page');
            } else {
                alert(window.t ? window.t('settings.geoDeniedOther') : 'Geolocation access denied.\n\nClick the lock icon in the address bar → Location → Allow, then reload the page');
            }
        } else if (err.code === 2) {
            alert(window.t ? window.t('settings.geoFailed') : 'Could not determine location.\nMake sure GPS/Wi-Fi is enabled.');
        } else {
            alert(window.t ? window.t('settings.geoTimeout') : 'Location request timed out.\nTry in an open area.');
        }
    }, { enableHighAccuracy: false, timeout: 15000, maximumAge: 60000 });
};

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 4: GIF Search (Tenor API)
// ══════════════════════════════════════════════════════════════════════════════

var _gifSearchTimer = null;

// Don't overwrite — inline-handlers.js has the full version with saved GIFs
if (!window.openGifPicker) {
    window.openGifPicker = function() {
        if (!window.AppState.currentRoom) {
            alert(window.t ? window.t('settings.openChatFirst') : 'Open a chat first');
            return;
        }
        window.openModal('gif-modal');
        var el = document.getElementById('gif-search-input');
        if (el) { el.value = ''; el.focus(); }
    };
}

if (!window.searchGifs) window.searchGifs = function(query) {
    clearTimeout(_gifSearchTimer);
    var el = document.getElementById('gif-results');
    if (!query || !query.trim()) {
        if (el) el.innerHTML = ("<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.enterQuery') : 'Enter a search query') + '</div>');
        return;
    }
    _gifSearchTimer = setTimeout(async function() {
        if (el) el.innerHTML = ("<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.searching') : 'Searching...') + '</div>');
        try {
            var key = 'AIzaSyDvT6aTBbn1fJWEAqEz1Kht2xQN_pjUib0';
            var resp = await fetch('https://tenor.googleapis.com/v2/search?q=' + encodeURIComponent(query) + '&key=' + key + '&limit=20&media_filter=gif');
            var data = await resp.json();
            var results = data.results || [];
            if (results.length === 0) {
                el.innerHTML = "<div style='padding:16px;color:var(--text2);text-align:center;'>" + (window.t ? window.t('gif.nothingFound') : 'Nothing found') + '</div>';
                return;
            }
            el.innerHTML = results.map(function(gif) {
                var preview = (gif.media_formats && (gif.media_formats.nanogif || gif.media_formats.tinygif || {}).url) || '';
                var full = (gif.media_formats && (gif.media_formats.gif || gif.media_formats.tinygif || {}).url) || preview;
                return '<img src="' + preview + '" data-full="' + full + '" onclick="sendGif(\'' + full.replace(/'/g, "\\'") + '\')" ' +
                       'style="width:calc(50% - 4px);cursor:pointer;border-radius:4px;object-fit:cover;max-height:150px;">';
            }).join('');
        } catch(e) {
            if (el) el.innerHTML = "<div style='padding:16px;color:var(--red);text-align:center;'>" + (window.t ? window.t('gif.searchError').replace('{error}', e.message) : 'Search error: ' + e.message) + '</div>';
        }
    }, 500);
};

if (!window.sendGif) window.sendGif = function(url) {
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
            window.showToast?.(window.t ? window.t('settings.linkCopied') : 'Link copied', 'success');
        }).catch(function() {
            window.vxAlert(window.t ? window.t('settings.copyLink') : 'Copy link:', { token: link });
        });
    } else {
        window.vxAlert(window.t ? window.t('settings.copyLink') : 'Copy link:', { token: link });
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE: Sticker Picker
// ══════════════════════════════════════════════════════════════════════════════

// Animated sticker definitions (vortex pack)
var ANIMATED_STICKERS = [
    { name: 'wave',     emoji: '\u{1F44B}', label: (window.t ? window.t('stickers.wave') : 'Wave') },
    { name: 'heart',    emoji: '\u{2764}\u{FE0F}', label: (window.t ? window.t('stickers.heart') : 'Heart') },
    { name: 'fire',     emoji: '\u{1F525}', label: (window.t ? window.t('stickers.fire') : 'Fire') },
    { name: 'laugh',    emoji: '\u{1F602}', label: (window.t ? window.t('stickers.laugh') : 'Laugh') },
    { name: 'cry',      emoji: '\u{1F62D}', label: (window.t ? window.t('stickers.cry') : 'Cry') },
    { name: 'thumbsup', emoji: '\u{1F44D}', label: (window.t ? window.t('stickers.thumbsup') : 'Thumbs up') },
    { name: 'party',    emoji: '\u{1F389}', label: (window.t ? window.t('stickers.party') : 'Party') },
    { name: 'rocket',   emoji: '\u{1F680}', label: (window.t ? window.t('stickers.rocket') : 'Rocket') },
    { name: 'star',     emoji: '\u{2B50}',  label: (window.t ? window.t('stickers.star') : 'Star') },
    { name: 'cool',     emoji: '\u{1F60E}', label: (window.t ? window.t('stickers.cool') : 'Cool') },
    { name: 'love',     emoji: '\u{1F970}', label: (window.t ? window.t('stickers.love') : 'Love') },
    { name: 'clap',     emoji: '\u{1F44F}', label: (window.t ? window.t('stickers.clap') : 'Applause') },
    { name: 'think',    emoji: '\u{1F914}', label: (window.t ? window.t('stickers.think') : 'Thinking') },
    { name: 'scared',   emoji: '\u{1F631}', label: (window.t ? window.t('stickers.scared') : 'Scared') },
    { name: 'angry',    emoji: '\u{1F621}', label: (window.t ? window.t('stickers.angry') : 'Angry') },
    { name: 'sleep',    emoji: '\u{1F634}', label: (window.t ? window.t('stickers.sleep') : 'Sleep') },
    { name: 'money',    emoji: '\u{1F911}', label: (window.t ? window.t('stickers.money') : 'Money') },
    { name: 'ghost',    emoji: '\u{1F47B}', label: (window.t ? window.t('stickers.ghost') : 'Ghost') },
    { name: 'hundred',  emoji: '\u{1F4AF}', label: (window.t ? window.t('stickers.hundred') : '100') },
    { name: 'eyes',     emoji: '\u{1F440}', label: (window.t ? window.t('stickers.eyes') : 'Eyes') }
];

// Classic emoji sticker packs
var STICKER_PACKS = {
    emotions: ['\u{1F600}','\u{1F602}','\u{1F923}','\u{1F60D}','\u{1F970}','\u{1F618}','\u{1F60E}','\u{1F929}','\u{1F624}','\u{1F621}','\u{1F622}','\u{1F62D}','\u{1F97A}','\u{1F631}','\u{1F92E}','\u{1F480}','\u{1F47B}','\u{1F921}','\u{1F608}','\u{1F47F}','\u{1F4A9}','\u{1F916}','\u{1F47D}','\u{1F383}'],
    animals: ['\u{1F436}','\u{1F431}','\u{1F42D}','\u{1F439}','\u{1F430}','\u{1F98A}','\u{1F43B}','\u{1F43C}','\u{1F428}','\u{1F42F}','\u{1F981}','\u{1F42E}','\u{1F437}','\u{1F438}','\u{1F435}','\u{1F984}','\u{1F41D}','\u{1F98B}','\u{1F422}','\u{1F40D}','\u{1F98E}','\u{1F988}','\u{1F419}','\u{1F980}'],
    food: ['\u{1F34E}','\u{1F355}','\u{1F354}','\u{1F32E}','\u{1F35F}','\u{1F37F}','\u{1F369}','\u{1F382}','\u{1F370}','\u{1F36B}','\u{1F36C}','\u{2615}','\u{1F37A}','\u{1F377}','\u{1F964}','\u{1F349}','\u{1F347}','\u{1F353}','\u{1F951}','\u{1F33D}','\u{1F955}','\u{1F346}','\u{1F966}','\u{1F9C0}'],
    activities: ['\u{26BD}','\u{1F3C0}','\u{1F3BE}','\u{1F3C8}','\u{1F3AF}','\u{1F3AE}','\u{1F3B2}','\u{1F3AD}','\u{1F3A8}','\u{1F3B5}','\u{1F3B8}','\u{1F3B9}','\u{1F3C6}','\u{1F947}','\u{1F3AA}','\u{1F3A0}','\u{1F3C4}','\u{1F6B4}','\u{26F7}','\u{1F3CA}','\u{1F9D7}','\u{1F938}','\u{1F3CB}','\u{1F93A}'],
    objects: ['\u{2764}','\u{1F494}','\u{1F495}','\u{1F496}','\u{2728}','\u{2B50}','\u{1F31F}','\u{1F4AB}','\u{1F525}','\u{1F4A7}','\u{1F308}','\u{2600}','\u{1F319}','\u{26A1}','\u{1F48E}','\u{1F381}','\u{1F388}','\u{1F380}','\u{1F3E0}','\u{1F680}','\u{2708}','\u{1F6F8}','\u{1F4BB}','\u{1F4F1}'],
};

// openStickerPicker is defined in stickers.js (loaded after this file)
// Do NOT redefine it here to avoid wrapper recursion

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


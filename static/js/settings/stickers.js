// ══════════════════════════════════════════════════════════════════════════════
// FEATURE: Custom Sticker Packs (Manager + Enhanced Picker)
// ══════════════════════════════════════════════════════════════════════════════

// Cached custom packs for the picker
window._customStickerPacks = [];

// ── Sticker Manager tab switching ──
window.switchStickerMgrTab = function(tab, btn) {
    document.querySelectorAll('.sticker-mgr-tab').forEach(function(t) { t.classList.remove('active'); });
    document.querySelectorAll('.sticker-mgr-section').forEach(function(s) { s.classList.remove('active'); });
    if (btn) btn.classList.add('active');
    var el = document.getElementById('sticker-mgr-' + tab);
    if (el) el.classList.add('active');
    if (tab === 'my') loadMyPacks();
    if (tab === 'catalog') loadCatalogPacks();
};

window.toggleStickerCreateForm = function() {
    var form = document.getElementById('sticker-create-form');
    if (form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
};

// ── CSRF helper ──
function _stickerHeaders(isJSON) {
    var headers = {};
    var S = window.AppState;
    if (S && S.csrfToken) headers['X-CSRF-Token'] = S.csrfToken;
    if (isJSON) headers['Content-Type'] = 'application/json';
    return headers;
}

// ── HTML escape ──
function _sesc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}

// ── Load user's own + favorited packs ──
window.loadMyPacks = async function() {
    var list = document.getElementById('sticker-my-packs-list');
    if (!list) return;
    try {
        var resp = await fetch('/api/stickers/packs', { credentials: 'include', headers: _stickerHeaders(false) });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var data = await resp.json();
        var packs = Array.isArray(data) ? data : (data.own || []).concat(data.favorited || []);
        window._customStickerPacks = packs;
        _renderMyPacks(packs, list);
    } catch(e) {
        list.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">Не удалось загрузить паки</div>';
        console.warn('loadMyPacks error:', e);
    }
};

function _renderMyPacks(packs, container) {
    if (!packs || packs.length === 0) {
        container.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">У вас пока нет стикерпаков</div>';
        return;
    }
    var S = window.AppState;
    var myId = S && S.user ? S.user.id : null;
    container.innerHTML = packs.map(function(pack) {
        var isOwner = pack.creator_id === myId;
        var stickerCount = (pack.stickers && pack.stickers.length) || 0;
        var coverHtml = pack.cover_url
            ? '<img src="' + _sesc(pack.cover_url) + '" class="sticker-pack-cover">'
            : '<div class="sticker-pack-cover sticker-pack-cover--empty">📦</div>';
        var actions = '';
        if (isOwner) {
            actions = '<button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();deleteStickerPack(\'' + pack.id + '\')" title="Удалить" style="color:var(--red);padding:4px 8px;font-size:11px;">Удалить</button>';
        } else {
            actions = '<button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();unfavoritePack(\'' + pack.id + '\')" title="Убрать" style="padding:4px 8px;font-size:11px;">Убрать</button>';
        }
        return '<div class="sticker-pack-card" onclick="togglePackExpand(this,\'' + pack.id + '\',' + isOwner + ')">' +
            '<div class="sticker-pack-card-header">' +
                coverHtml +
                '<div class="sticker-pack-card-info">' +
                    '<div class="sticker-pack-card-name">' + _sesc(pack.name) + '</div>' +
                    '<div class="sticker-pack-card-meta">' + stickerCount + ' стикер' + _pluralRu(stickerCount) + '</div>' +
                '</div>' +
                '<div class="sticker-pack-card-actions">' + actions + '</div>' +
            '</div>' +
            '<div class="sticker-pack-expand" style="display:none;"></div>' +
        '</div>';
    }).join('');
}

function _pluralRu(n) {
    var m = n % 10, mm = n % 100;
    if (m === 1 && mm !== 11) return '';
    if (m >= 2 && m <= 4 && (mm < 12 || mm > 14)) return 'а';
    return 'ов';
}

// ── Expand pack to show stickers ──
window.togglePackExpand = async function(cardEl, packId, isOwner) {
    var expandEl = cardEl.querySelector('.sticker-pack-expand');
    if (!expandEl) return;
    if (expandEl.style.display !== 'none') {
        expandEl.style.display = 'none';
        return;
    }
    expandEl.style.display = 'block';
    expandEl.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:11px;padding:12px;">Загрузка...</div>';
    try {
        var resp = await fetch('/api/stickers/packs/' + packId, { credentials: 'include', headers: _stickerHeaders(false) });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var pack = await resp.json();
        _renderPackStickers(expandEl, pack, isOwner);
    } catch(e) {
        expandEl.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:11px;padding:12px;">Ошибка загрузки</div>';
    }
};

function _renderPackStickers(container, pack, isOwner) {
    var stickers = pack.stickers || [];
    var html = '<div class="sticker-pack-grid">';
    stickers.forEach(function(st) {
        html += '<div class="sticker-thumb-wrap">' +
            '<img src="' + _sesc(st.image_url) + '" class="sticker-thumb" alt="sticker">' +
            (isOwner ? '<button class="sticker-thumb-delete" onclick="event.stopPropagation();deleteStickerFromPack(\'' + pack.id + '\',\'' + st.id + '\')" title="Удалить">&times;</button>' : '') +
        '</div>';
    });
    if (isOwner) {
        html += '<div class="sticker-upload-btn" onclick="event.stopPropagation();triggerStickerUpload(\'' + pack.id + '\')" title="Добавить стикер">+</div>';
    }
    html += '</div>';
    container.innerHTML = html;
}

// ── Create pack ──
window.createStickerPack = async function() {
    var name = document.getElementById('sticker-pack-name')?.value?.trim();
    if (!name) return;
    var desc = document.getElementById('sticker-pack-desc')?.value?.trim() || '';
    try {
        var resp = await fetch('/api/stickers/packs', {
            method: 'POST',
            credentials: 'include',
            headers: _stickerHeaders(true),
            body: JSON.stringify({ name: name, description: desc, is_public: false })
        });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        document.getElementById('sticker-pack-name').value = '';
        document.getElementById('sticker-pack-desc').value = '';
        toggleStickerCreateForm();
        loadMyPacks();
    } catch(e) {
        console.warn('createStickerPack error:', e);
        alert(window.t ? window.t('settings.stickerPackFailed') : 'Не удалось создать пак');
    }
};

// ── Delete pack ──
window.deleteStickerPack = async function(packId) {
    if (!confirm('Удалить этот стикерпак?')) return;
    try {
        await fetch('/api/stickers/packs/' + packId, {
            method: 'DELETE',
            credentials: 'include',
            headers: _stickerHeaders(false)
        });
        loadMyPacks();
    } catch(e) { console.warn('deleteStickerPack error:', e); }
};

// ── Upload sticker to pack ──
window.triggerStickerUpload = function(packId) {
    var input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/png,image/webp,image/gif,image/jpeg';
    input.onchange = function() {
        if (!input.files || !input.files[0]) return;
        uploadStickerFile(packId, input.files[0]);
    };
    input.click();
};

window.uploadStickerFile = async function(packId, file) {
    var formData = new FormData();
    formData.append('file', file);
    try {
        var headers = {};
        var S = window.AppState;
        if (S && S.csrfToken) headers['X-CSRF-Token'] = S.csrfToken;
        var resp = await fetch('/api/stickers/packs/' + packId + '/stickers', {
            method: 'POST',
            credentials: 'include',
            headers: headers,
            body: formData
        });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        loadMyPacks();
    } catch(e) {
        console.warn('uploadStickerFile error:', e);
        alert(window.t ? window.t('settings.stickerUploadFailed') : 'Не удалось загрузить стикер');
    }
};

// ── Delete sticker from pack ──
window.deleteStickerFromPack = async function(packId, stickerId) {
    try {
        await fetch('/api/stickers/packs/' + packId + '/stickers/' + stickerId, {
            method: 'DELETE',
            credentials: 'include',
            headers: _stickerHeaders(false)
        });
        loadMyPacks();
    } catch(e) { console.warn('deleteStickerFromPack error:', e); }
};

// ── Favorite / unfavorite ──
window.favoritePack = async function(packId) {
    try {
        await fetch('/api/stickers/packs/' + packId + '/favorite', {
            method: 'POST',
            credentials: 'include',
            headers: _stickerHeaders(false)
        });
        loadCatalogPacks();
        loadMyPacks();
    } catch(e) { console.warn('favoritePack error:', e); }
};

window.unfavoritePack = async function(packId) {
    try {
        await fetch('/api/stickers/packs/' + packId + '/favorite', {
            method: 'DELETE',
            credentials: 'include',
            headers: _stickerHeaders(false)
        });
        loadMyPacks();
    } catch(e) { console.warn('unfavoritePack error:', e); }
};

// ── Catalog (public packs) ──
window.loadCatalogPacks = async function() {
    var list = document.getElementById('sticker-catalog-list');
    if (!list) return;
    try {
        var resp = await fetch('/api/stickers/packs/public', { credentials: 'include', headers: _stickerHeaders(false) });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var packs = await resp.json();
        _renderCatalogPacks(packs, list);
    } catch(e) {
        list.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">Не удалось загрузить каталог</div>';
        console.warn('loadCatalogPacks error:', e);
    }
};

function _renderCatalogPacks(packs, container) {
    if (!packs || packs.length === 0) {
        container.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">Каталог пуст</div>';
        return;
    }
    // Determine which packs user already has
    var ownedIds = {};
    (window._customStickerPacks || []).forEach(function(p) { ownedIds[p.id] = true; });

    container.innerHTML = packs.map(function(pack) {
        var stickerCount = (pack.stickers && pack.stickers.length) || 0;
        var coverHtml = pack.cover_url
            ? '<img src="' + _sesc(pack.cover_url) + '" class="sticker-pack-cover">'
            : '<div class="sticker-pack-cover sticker-pack-cover--empty">📦</div>';
        var addBtn = ownedIds[pack.id]
            ? '<span style="font-size:11px;color:var(--green);">Добавлен</span>'
            : '<button class="btn btn-primary btn-sm" onclick="event.stopPropagation();favoritePack(\'' + pack.id + '\')" style="padding:4px 10px;font-size:11px;">Добавить</button>';
        return '<div class="sticker-pack-card">' +
            '<div class="sticker-pack-card-header">' +
                coverHtml +
                '<div class="sticker-pack-card-info">' +
                    '<div class="sticker-pack-card-name">' + _sesc(pack.name) + '</div>' +
                    '<div class="sticker-pack-card-meta">' + stickerCount + ' стикер' + _pluralRu(stickerCount) +
                        (pack.description ? ' &mdash; ' + _sesc(pack.description) : '') + '</div>' +
                '</div>' +
                '<div class="sticker-pack-card-actions">' + addBtn + '</div>' +
            '</div>' +
        '</div>';
    }).join('');
}

// ── Enhanced sticker picker: inject custom pack tabs ──
window._loadCustomPackTabs = async function() {
    var tabsContainer = document.getElementById('custom-pack-tabs');
    if (!tabsContainer) return;
    try {
        var resp = await fetch('/api/stickers/packs', { credentials: 'include', headers: _stickerHeaders(false) });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var data = await resp.json();
        var packs = Array.isArray(data) ? data : (data.own || []).concat(data.favorited || []);
        window._customStickerPacks = packs;
        tabsContainer.innerHTML = packs.map(function(pack) {
            var icon = pack.cover_url
                ? '<img src="' + _sesc(pack.cover_url) + '" class="custom-sticker-tab-icon">'
                : '<span class="custom-sticker-tab-emoji">📦</span>';
            return '<button class="settings-tab custom-sticker-tab" onclick="showCustomPackInPicker(\'' + pack.id + '\',this)" title="' + _sesc(pack.name) + '">' +
                icon + '</button>';
        }).join('');
    } catch(e) {
        tabsContainer.innerHTML = '';
        console.warn('_loadCustomPackTabs error:', e);
    }
};

window.showCustomPackInPicker = async function(packId, btn) {
    document.querySelectorAll('#sticker-modal .settings-tab').forEach(function(t) { t.classList.remove('active'); });
    if (btn) btn.classList.add('active');
    var grid = document.getElementById('sticker-grid');
    if (!grid) return;
    grid.className = '';
    grid.style.cssText = 'max-height:280px;overflow-y:auto;padding:4px;';
    grid.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">Загрузка...</div>';
    try {
        var resp = await fetch('/api/stickers/packs/' + packId, { credentials: 'include', headers: _stickerHeaders(false) });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var pack = await resp.json();
        var stickers = pack.stickers || [];
        if (stickers.length === 0) {
            grid.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">Пак пуст</div>';
            return;
        }
        grid.innerHTML = '<div class="custom-sticker-picker-grid">' +
            stickers.map(function(st) {
                return '<div class="custom-sticker-preview" onclick="sendCustomSticker(\'' + _sesc(st.image_url) + '\')" title="' + _sesc(st.emoji || '') + '">' +
                    '<img src="' + _sesc(st.image_url) + '" alt="sticker">' +
                '</div>';
            }).join('') +
        '</div>';
    } catch(e) {
        grid.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:24px 0;">Ошибка загрузки</div>';
    }
};

// ── Send custom sticker ──
window.sendCustomSticker = function(imageUrl) {
    if (window.closeModal) window.closeModal('sticker-modal');
    if (window.sendStickerDirect) window.sendStickerDirect('[STICKER] img:' + imageUrl);
};

// ── Hook into sticker picker open to load custom tabs ──
var _origOpenStickerPicker = window.openStickerPicker;
window.openStickerPicker = function() {
    window._loadCustomPackTabs();
    if (_origOpenStickerPicker) _origOpenStickerPicker();
    else {
        if (window.openModal) window.openModal('sticker-modal');
        window.showStickerCategory('animated', document.querySelector('#sticker-modal .sticker-picker-tabs .settings-tab'));
    }
};

// Load packs when stickers tab is selected in settings
var _origSwitchSettingsTab = window.switchSettingsTab;
window.switchSettingsTab = function(tab) {
    _origSwitchSettingsTab(tab);
    if (tab === 'stickers') {
        loadMyPacks();
    }
    if (tab === 'bots') {
        loadMyBots();
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// FEATURE: Video Messages (circular video notes)
// ══════════════════════════════════════════════════════════════════════════════

var _videoRecorder = null;
var _videoStream = null;
var _videoChunks = [];

window.startVideoMessage = async function() {
    try {
        _videoStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'user', width: 320, height: 320 },
            audio: true
        });

        var overlay = document.createElement('div');
        overlay.id = 'video-record-overlay';
        overlay.innerHTML =
            '<div class="vr-overlay">' +
                '<div class="vr-top">' +
                    '<div class="vr-circle-wrap">' +
                        '<video id="video-preview" autoplay playsinline muted class="vr-preview"></video>' +
                        '<div class="vr-rec-badge"><span class="vr-rec-dot"></span> REC</div>' +
                    '</div>' +
                    '<div class="vr-timer" id="video-timer">0:00</div>' +
                '</div>' +
                '<div class="vr-controls">' +
                    '<button class="vr-btn" onclick="stopVideoMessage(false)">' +
                        '<span class="vr-btn-icon vr-btn-cancel">&#x2715;</span>' +
                        '<span class="vr-btn-label">Отмена</span>' +
                    '</button>' +
                    '<button class="vr-btn" onclick="stopVideoMessage(true)">' +
                        '<span class="vr-btn-icon vr-btn-send"><svg width="24" height="24" fill="#fff" viewBox="0 0 24 24"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg></span>' +
                        '<span class="vr-btn-label">Отправить</span>' +
                    '</button>' +
                '</div>' +
            '</div>';
        document.body.appendChild(overlay);

        document.getElementById('video-preview').srcObject = _videoStream;

        _videoChunks = [];
        var mimeType = 'video/webm;codecs=vp8,opus';
        if (!MediaRecorder.isTypeSupported(mimeType)) {
            mimeType = 'video/webm';
        }
        _videoRecorder = new MediaRecorder(_videoStream, { mimeType: mimeType });
        _videoRecorder.ondataavailable = function(e) {
            if (e.data.size > 0) _videoChunks.push(e.data);
        };
        _videoRecorder.start(100);

        var sec = 0;
        var timerEl = document.getElementById('video-timer');
        var tid = setInterval(function() {
            sec++;
            if (timerEl) timerEl.textContent = Math.floor(sec / 60) + ':' + (sec % 60).toString().padStart(2, '0');
            if (sec >= 60) window.stopVideoMessage(true);
        }, 1000);
        overlay._tid = tid;

    } catch(e) {
        alert((window.t ? window.t('settings.cameraNoAccess') : 'Нет доступа к камере: {error}').replace('{error}', e.message));
    }
};

window.stopVideoMessage = async function(send) {
    var overlay = document.getElementById('video-record-overlay');
    if (overlay && overlay._tid) clearInterval(overlay._tid);

    if (_videoRecorder && _videoRecorder.state !== 'inactive') {
        _videoRecorder.stop();
    }
    if (_videoStream) {
        _videoStream.getTracks().forEach(function(t) { t.stop(); });
    }

    if (send && _videoChunks.length > 0) {
        await new Promise(function(r) { setTimeout(r, 300); });
        var blob = new Blob(_videoChunks, { type: 'video/webm' });
        var file = new File([blob], 'video_' + Date.now() + '.webm', { type: 'video/webm' });

        var S = window.AppState;
        if (S && S.currentRoom) {
            var formData = new FormData();
            formData.append('file', file);
            try {
                var headers = {};
                if (S.csrfToken) headers['X-CSRF-Token'] = S.csrfToken;
                await fetch('/api/files/upload/' + S.currentRoom.id, {
                    method: 'POST',
                    body: formData,
                    credentials: 'include',
                    headers: headers,
                });
            } catch(e) { console.warn('Video upload failed:', e); }
        }
    }

    if (overlay) overlay.remove();
    _videoRecorder = null;
    _videoStream = null;
    _videoChunks = [];
};


// ── Space create/join tab switching ──
window._switchCsTab = function(tab) {
    var createPanel = document.getElementById('cs-panel-create');
    var joinPanel = document.getElementById('cs-panel-join');
    var tabs = document.querySelectorAll('#create-space-modal .cs-tab');
    tabs.forEach(function(t, i) {
        t.classList.toggle('active', (tab === 'create' && i === 0) || (tab === 'join' && i === 1));
    });
    if (createPanel) createPanel.classList.toggle('active', tab === 'create');
    if (joinPanel) joinPanel.classList.toggle('active', tab === 'join');
};

// ── Avatar tab switching (registration form) ──
window.switchAvatarTab = function(tab) {
    var emojiTab = document.getElementById('avatar-emoji-tab');
    var photoTab = document.getElementById('avatar-photo-tab');
    var emojiPanel = document.getElementById('avatar-emoji-panel');
    var photoPanel = document.getElementById('avatar-photo-panel');
    if (tab === 'emoji') {
        if (emojiTab) emojiTab.classList.add('active');
        if (photoTab) photoTab.classList.remove('active');
        if (emojiPanel) emojiPanel.style.display = '';
        if (photoPanel) photoPanel.style.display = 'none';
    } else {
        if (emojiTab) emojiTab.classList.remove('active');
        if (photoTab) photoTab.classList.add('active');
        if (emojiPanel) emojiPanel.style.display = 'none';
        if (photoPanel) photoPanel.style.display = '';
    }
};

window.previewAvatar = function(input) {
    if (!input.files || !input.files[0]) return;
    var reader = new FileReader();
    reader.onload = function(e) {
        var preview = document.getElementById('avatar-preview');
        if (preview) preview.innerHTML = '<img src="' + e.target.result + '" style="width:100%;height:100%;object-fit:cover;">';
    };
    reader.readAsDataURL(input.files[0]);
};

// ── Settings tab switching (legacy stub, sections now open full-screen) ──
window.switchSettingsTab = function(tab) {};

// ── Settings emoji picker ──
window._settingsSelectedEmoji = null;
window.selectSettingsEmoji = function(btn) {
    document.querySelectorAll('#settings-emoji-picker .emoji-btn').forEach(function(b) { b.classList.remove('emoji-selected'); });
    btn.classList.add('emoji-selected');
    window._settingsSelectedEmoji = btn.dataset.emoji;
};

// ── Save profile from settings ──
window.saveProfileSettings = async function() {
    var S = window.AppState;
    var body = {
        display_name: document.getElementById('set-display-name')?.value?.trim() || undefined,
        email: document.getElementById('set-email')?.value?.trim() || undefined,
        bio: document.getElementById('set-bio')?.value?.trim() ?? undefined,
    };
    if (window._settingsSelectedEmoji) {
        body.avatar_emoji = window._settingsSelectedEmoji;
    }
    // Birthday — only send if user actually changed it via the picker
    var bdBtn = document.getElementById('set-birthday-btn');
    if (bdBtn && bdBtn.dataset.dirty === '1') {
        body.birth_date = bdBtn.dataset.value;
    }
    // Profile background
    if (window._settingsProfileBg !== undefined) {
        body.profile_bg = window._settingsProfileBg;
    }
    // Profile icon
    if (window._settingsProfileIcon !== undefined) {
        body.profile_icon = window._settingsProfileIcon;
    }
    // Reply bubble color + icon
    if (window._settingsReplyColor !== undefined) {
        body.reply_color = window._settingsReplyColor;
    }
    if (window._settingsReplyIcon !== undefined) {
        body.reply_icon = window._settingsReplyIcon;
    }
    try {
        var resp = await window.api('PUT', '/api/authentication/profile', body);
        if (resp.display_name !== undefined) {
            S.user.display_name = resp.display_name;
            var sbName = document.getElementById('sb-name');
            if (sbName) sbName.textContent = resp.display_name;
        }
        if (resp.avatar_emoji !== undefined) {
            S.user.avatar_emoji = resp.avatar_emoji;
            if (!S.user.avatar_url) {
                var sbAv = document.getElementById('sb-avatar');
                if (sbAv) sbAv.textContent = resp.avatar_emoji;
            }
        }
        if (resp.email      !== undefined) S.user.email      = resp.email;
        if (resp.bio        !== undefined) S.user.bio        = resp.bio;
        if (resp.birth_date !== undefined) S.user.birth_date = resp.birth_date;
        if (resp.profile_bg  !== undefined) S.user.profile_bg  = resp.profile_bg;
        if (resp.profile_icon !== undefined) S.user.profile_icon = resp.profile_icon;
        if (resp.reply_color !== undefined) S.user.reply_color = resp.reply_color;
        if (resp.reply_icon !== undefined) S.user.reply_icon = resp.reply_icon;

        // Reset dirty flags
        window._settingsReplyColor = undefined;
        window._settingsReplyIcon = undefined;
        alert(window.t ? window.t('spaces.saved') : 'Saved');
    } catch(e) { alert(e.message); }
};

// ── Profile background picker ──
window._settingsProfileBg = undefined;
window._selectProfileBg = function(btn) {
    document.querySelectorAll('.pbg-swatch').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    window._settingsProfileBg = btn.dataset.bg;
    var preview = document.getElementById('set-profile-bg-preview');
    if (preview) preview.style.background = btn.dataset.bg;
    // Sync icon preview background
    var piHero = document.getElementById('pi-preview-hero');
    if (piHero) piHero.style.background = btn.dataset.bg;
};

// ── Reply bubble color picker ──
window._settingsReplyColor = undefined;
window._selectReplyColor = function(btn) {
    document.querySelectorAll('.rc-swatch').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    window._settingsReplyColor = btn.dataset.color || null;
};

// ── Reply icon picker ──
window._settingsReplyIcon = undefined;
window._selectReplyIcon = function(btn) {
    document.querySelectorAll('.ri-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    window._settingsReplyIcon = btn.dataset.icon || null;
};

// ── Profile icon registry (shared with user-profile.js) ──
window._PROFILE_ICONS = {
  bolt:     '<path d="M7 2v11h3v9l7-12h-4l4-8z"/>',
  diamond:  '<path d="M12 1l10 8-10 13L2 9z"/>',
  flame:    '<path d="M12 23c-3.87 0-7-3.13-7-7 0-4 2.5-7.5 7-14 4.5 6.5 7 10 7 14 0 3.87-3.13 7-7 7z"/>',
  moon:     '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  star:     '<path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z"/>',
  crown:    '<path d="M2 20v-2h20v2H2zm2-4 3-11 5 3 5-3 3 11H4z"/>',
  shield:   '<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5z"/>',
  eye:      '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zm0 12.5c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>',
  drop:     '<path d="M12 2C8.13 6 5 10 5 14c0 3.87 3.13 7 7 7s7-3.13 7-7c0-4-3.13-8-7-12z"/>',
  hexagon:  '<path d="M17.27 4H6.73L2 12l4.73 8h10.54L22 12z"/>',
  target:   '<path d="M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16zm0-12a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm0 6a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"/>',
  compass:  '<path d="M12 2L4.5 20.29l.71.71L12 18l6.79 3 .71-.71z"/>',
  crystal:  '<path d="M16.5 3h-9L3 9.5 12 21l9-11.5L16.5 3zM9.14 4.5h5.72L17.7 9H6.3l2.84-4.5zM12 18.5 5.63 10.5h12.74L12 18.5z"/>',
  infinity: '<path d="M18.6 6.62c-1.44 0-2.8.56-3.77 1.53L12 10.66l-2.83-2.51A5.37 5.37 0 0 0 5.4 6.62C2.42 6.62 0 9.04 0 12s2.42 5.38 5.4 5.38c1.44 0 2.8-.56 3.77-1.53L12 13.34l2.83 2.51a5.37 5.37 0 0 0 3.77 1.53C21.58 17.38 24 14.96 24 12s-2.42-5.38-5.4-5.38zm-13.2 8.76c-1.87 0-3.39-1.52-3.39-3.38s1.52-3.38 3.39-3.38c.9 0 1.76.35 2.44 1.03L8.87 12l-1.43 1.27c-.68.68-1.54 1.11-2.44 1.11zm13.2 0c-.9 0-1.76-.43-2.44-1.11L15.13 12l1.43-1.27c.68-.68 1.54-1.03 2.44-1.03 1.87 0 3.39 1.52 3.39 3.38s-1.52 3.38-3.39 3.38z"/>',
  wave:     '<path d="M21 12.5c-1.5 0-2.5-1-4-1s-2.5 1-4 1-2.5-1-4-1-2.5 1-4 1V15c1.5 0 2.5-1 4-1s2.5 1 4 1 2.5-1 4-1 2.5 1 4 1v-2.5zm0-5c-1.5 0-2.5-1-4-1s-2.5 1-4 1-2.5-1-4-1-2.5 1-4 1V10c1.5 0 2.5-1 4-1s2.5 1 4 1 2.5-1 4-1 2.5 1 4 1V7.5z"/>',
  vortex:   '<path d="M12 6v3l4-4-4-4v3c-4.42 0-8 3.58-8 8 0 1.57.46 3.03 1.24 4.26L6.7 14.8A5.87 5.87 0 0 1 6 12c0-3.31 2.69-6 6-6zm6.76 1.74L17.3 9.2A5.9 5.9 0 0 1 18 12c0 3.31-2.69 6-6 6v-3l-4 4 4 4v-3c4.42 0 8-3.58 8-8 0-1.57-.46-3.03-1.24-4.26z"/>',
  mountain: '<path d="M14 6.5L12 3 2 21h20L14 6.5zm-2 2.6L18.9 19H9.5l2.5-9.9z"/>',
  anchor:   '<path d="M12 2a3 3 0 0 0 0 6v2H8v2h4v7.93A8 8 0 0 1 4 12H2a10 10 0 0 0 10 10 10 10 0 0 0 10-10h-2a8 8 0 0 1-7 7.93V12h4v-2h-4V8a3 3 0 0 0 3-3 3 3 0 0 0-3-3z"/>',
  key:      '<path d="M12.65 10A6 6 0 1 0 10 12.65l6.65 6.65 2.12-2.12-1.41-1.41 1.41-1.42-1.41-1.41-1.42 1.41-1.41-1.41 1.41-1.42zm-6.65 0a4 4 0 1 1 4 4 4 4 0 0 1-4-4z"/>',
};

// ── Profile icon picker ──
window._settingsProfileIcon = undefined;
window._selectProfileIcon = function(btn) {
    document.querySelectorAll('.pi-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    window._settingsProfileIcon = btn.dataset.icon;
    // Update mini preview
    var svg = document.getElementById('pi-preview-svg');
    if (svg) {
        var paths = window._PROFILE_ICONS[btn.dataset.icon] || '';
        svg.innerHTML = paths;
        svg.style.display = paths ? '' : 'none';
    }
    var hero = document.getElementById('pi-preview-hero');
    if (hero && window._settingsProfileBg) {
        hero.style.background = window._settingsProfileBg;
    }
};

// ══════════════════════════════════════════════════
// BIRTHDAY CALENDAR PICKER
// ══════════════════════════════════════════════════
(function() {
    var _calMonth = 0;
    var _calYear  = new Date().getFullYear() - 20;
    var _calSelDay   = null;
    var _calSelMonth = null;
    var _calSelYear  = null;
    var _calWithYear = false;
    var _calAnimating = false;

    var _monthsArr = t('time.months');
    var MONTHS = Array.isArray(_monthsArr) ? _monthsArr : ['January','February','March','April','May','June','July','August','September','October','November','December'];
    var _monthsGenArr = t('time.monthsGen');
    var MONTHS_GEN = Array.isArray(_monthsGenArr) ? _monthsGenArr : MONTHS;

    window.openBirthdayPicker = function() {
        var S = window.AppState;
        var bd = S && S.user && S.user.birth_date ? S.user.birth_date : '';
        _calSelDay = null; _calSelMonth = null; _calSelYear = null;
        _calWithYear = false;
        _calMonth = 0;
        _calYear  = new Date().getFullYear() - 20;

        if (bd) {
            try {
                if (bd.startsWith('--')) {
                    var p = bd.slice(2).split('-');
                    _calSelMonth = parseInt(p[0]) - 1;
                    _calSelDay   = parseInt(p[1]);
                    _calMonth    = _calSelMonth;
                } else {
                    var parts = bd.split('-');
                    _calSelYear  = parseInt(parts[0]);
                    _calSelMonth = parseInt(parts[1]) - 1;
                    _calSelDay   = parseInt(parts[2]);
                    _calWithYear = true;
                    _calMonth    = _calSelMonth;
                    _calYear     = _calSelYear;
                }
            } catch(e) {}
        }

        var toggle = document.getElementById('bp-year-toggle');
        if (toggle) toggle.checked = _calWithYear;
        var strip = document.getElementById('bp-year-strip');
        if (strip) strip.style.display = _calWithYear ? '' : 'none';

        document.getElementById('birthday-picker').style.display = 'flex';
        requestAnimationFrame(function() {
            document.querySelector('#birthday-picker .bp-sheet').style.transform = 'translateY(0)';
        });
        _calRenderYearStrip();
        _calRender();
        _calUpdatePreview();
    };

    window.closeBirthdayPicker = function() {
        var sheet = document.querySelector('#birthday-picker .bp-sheet');
        if (sheet) sheet.style.transform = 'translateY(100%)';
        setTimeout(function() {
            document.getElementById('birthday-picker').style.display = 'none';
            if (sheet) sheet.style.transform = '';
        }, 300);
    };

    window._calToggleYear = function(on) {
        _calWithYear = on;
        var strip = document.getElementById('bp-year-strip');
        if (strip) strip.style.display = on ? '' : 'none';
        if (on) {
            if (!_calSelYear) { _calSelYear = _calYear; }
            _calRenderYearStrip();
        }
        _calUpdatePreview();
    };

    function _calRenderYearStrip() {
        var track = document.getElementById('bp-year-track');
        if (!track) return;
        var maxY = new Date().getFullYear() - 3;
        var minY = maxY - 100;
        var html = '';
        for (var y = maxY; y >= minY; y--) {
            var act = y === _calSelYear ? ' active' : '';
            html += '<button class="bp-year-chip' + act + '" onclick="window._calSelectYear(' + y + ')">' + y + '</button>';
        }
        track.innerHTML = html;
        setTimeout(function() {
            var active = track.querySelector('.active');
            if (active) active.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' });
        }, 60);
    }

    window._calSelectYear = function(y) {
        _calSelYear = y;
        _calYear = y;
        document.querySelectorAll('#bp-year-track .bp-year-chip').forEach(function(b) {
            b.classList.toggle('active', parseInt(b.textContent) === y);
        });
        _calUpdatePreview();
    };

    window._calPrevMonth = function() {
        if (_calAnimating) return;
        _calAnimateSlide('right', function() {
            if (--_calMonth < 0) _calMonth = 11;
            _calRender();
        });
    };

    window._calNextMonth = function() {
        if (_calAnimating) return;
        _calAnimateSlide('left', function() {
            if (++_calMonth > 11) _calMonth = 0;
            _calRender();
        });
    };

    function _calAnimateSlide(dir, cb) {
        _calAnimating = true;
        var grid = document.getElementById('bp-grid');
        if (!grid) { cb(); _calAnimating = false; return; }
        var out = dir === 'left' ? 'bp-slide-out-left' : 'bp-slide-out-right';
        var inn = dir === 'left' ? 'bp-slide-in-right' : 'bp-slide-in-left';
        grid.classList.add(out);
        setTimeout(function() {
            grid.classList.remove(out);
            cb();
            grid.classList.add(inn);
            setTimeout(function() { grid.classList.remove(inn); _calAnimating = false; }, 280);
        }, 180);
    }

    function _calRender() {
        var el = document.getElementById('bp-month-name');
        if (el) el.textContent = MONTHS[_calMonth];
        var grid = document.getElementById('bp-grid');
        if (!grid) return;

        var refYear = _calWithYear && _calSelYear ? _calSelYear : (_calYear || 2000);
        var firstDow = (new Date(refYear, _calMonth, 1).getDay() + 6) % 7; // Mon=0
        var daysInMon = new Date(refYear, _calMonth + 1, 0).getDate();
        var today = new Date();
        var isCurMon = today.getFullYear() === refYear && today.getMonth() === _calMonth;

        var html = '';
        for (var i = 0; i < firstDow; i++) html += '<div class="bp-cell bp-empty"></div>';
        for (var d = 1; d <= daysInMon; d++) {
            var cls = 'bp-cell bp-day';
            if (d === _calSelDay && _calMonth === _calSelMonth) cls += ' selected';
            if (isCurMon && d === today.getDate()) cls += ' today';
            var dow = (firstDow + d - 1) % 7;
            if (dow === 5 || dow === 6) cls += ' wknd';
            html += '<button class="' + cls + '" onclick="window._calSelectDay(' + d + ')">' + d + '</button>';
        }
        grid.innerHTML = html;
    }

    window._calSelectDay = function(d) {
        _calSelDay   = d;
        _calSelMonth = _calMonth;
        _calRender();
        _calUpdatePreview();
    };

    function _calUpdatePreview() {
        var el = document.getElementById('bp-selected-preview');
        if (!el) return;
        if (_calSelDay === null || _calSelMonth === null) { el.textContent = ''; return; }
        var text = _calSelDay + ' ' + MONTHS_GEN[_calSelMonth];
        if (_calWithYear && _calSelYear) text += ' ' + _calSelYear;
        el.textContent = text;
    }

    window._calApply = function() {
        if (_calSelDay === null || _calSelMonth === null) {
            window.closeBirthdayPicker();
            return;
        }
        var mm = String(_calSelMonth + 1).padStart(2, '0');
        var dd = String(_calSelDay).padStart(2, '0');
        var value, display;
        if (_calWithYear && _calSelYear) {
            value   = _calSelYear + '-' + mm + '-' + dd;
            display = dd + '.' + mm + '.' + _calSelYear;
        } else {
            value   = '--' + mm + '-' + dd;
            display = dd + '.' + mm;
        }
        var btn = document.getElementById('set-birthday-btn');
        var txt = document.getElementById('set-birthday-text');
        if (btn) {
            btn.dataset.value = value;
            btn.dataset.dirty = '1';
        }
        if (txt) txt.textContent = display;
        window.closeBirthdayPicker();
    };
})();

// ── Upload avatar from settings ──
window.uploadSettingsAvatar = async function(input) {
    if (!input.files || !input.files[0]) return;
    var formData = new FormData();
    formData.append('file', input.files[0]);
    try {
        var resp = await fetch('/api/authentication/avatar', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        });
        var data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Upload failed');
        window.AppState.user.avatar_url = data.avatar_url;
        var av = document.getElementById('settings-avatar');
        if (av) av.innerHTML = '<img src="' + data.avatar_url + '" style="width:100%;height:100%;object-fit:cover;">';
        var sbAv = document.getElementById('sb-avatar');
        if (sbAv) sbAv.innerHTML = '<img src="' + data.avatar_url + '" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">';
    } catch(e) { alert(e.message); }
};

// ── Import key from settings ──
window.importKey = function(input) {
    if (!input.files || !input.files[0]) return;
    if (window.importPrivateKey) window.importPrivateKey(input.files[0]);
};

// ── Toggle push setting ──
window.togglePushSetting = function(enabled) {
    if (enabled && window.requestNotificationPermission) {
        window.requestNotificationPermission();
    }
};

// ── Call settings (Force TCP / Relay / Traffic Masking) ──
window._saveCallSetting = function(key, value) {
    localStorage.setItem(key, value ? 'true' : 'false');
};
window._loadCallSettings = function() {
    var keys = ['vortex_call_force_relay', 'vortex_call_force_tcp', 'vortex_call_traffic_mask'];
    var ids  = ['set-call-force-relay',    'set-call-force-tcp',    'set-call-traffic-mask'];
    for (var i = 0; i < keys.length; i++) {
        var el = document.getElementById(ids[i]);
        if (el) el.checked = localStorage.getItem(keys[i]) === 'true';
    }
};

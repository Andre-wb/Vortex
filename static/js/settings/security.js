// ══════════════════════════════════════════════════════════════════════════════
// PIN-код: lock screen + settings
// ══════════════════════════════════════════════════════════════════════════════
async function _hashPIN(pin) {
    var enc = new TextEncoder();
    var buf = await crypto.subtle.digest('SHA-256', enc.encode(pin));
    return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
}
window._setPIN = async function(pin) {
    localStorage.setItem('vortex_pin_hash', await _hashPIN(pin));
};
window._removePIN = function() {
    localStorage.removeItem('vortex_pin_hash');
};
window._verifyPIN = async function(pin) {
    var stored = localStorage.getItem('vortex_pin_hash');
    if (!stored) return true;
    return (await _hashPIN(pin)) === stored;
};
function _loadPinStatus() {
    var hasPin = !!localStorage.getItem('vortex_pin_hash');
    var notSet = document.getElementById('pin-not-set');
    var isSet  = document.getElementById('pin-is-set');
    var form   = document.getElementById('pin-setup-form');
    if (notSet) notSet.style.display = hasPin ? 'none' : '';
    if (isSet)  isSet.style.display  = hasPin ? '' : 'none';
    if (form)   form.style.display   = 'none';
}
window._pinSettingsSetup = function() {
    document.getElementById('pin-not-set').style.display = 'none';
    document.getElementById('pin-is-set').style.display  = 'none';
    document.getElementById('pin-setup-form').style.display = '';
    document.getElementById('pin-input-1').value = '';
    document.getElementById('pin-input-2').value = '';
    document.getElementById('pin-input-1').focus();
};
window._pinSettingsChange = function() { window._pinSettingsSetup(); };
window._pinSettingsCancel = function() { _loadPinStatus(); };
window._pinSettingsSave = async function() {
    var p1 = document.getElementById('pin-input-1').value.trim();
    var p2 = document.getElementById('pin-input-2').value.trim();
    if (!/^\d{4}$/.test(p1)) { alert(window.t ? window.t('security.pinMustBe4Digits') : 'PIN must be 4 digits'); return; }
    if (p1 !== p2) { alert(window.t ? window.t('security.pinMismatch') : 'PINs do not match'); return; }
    await window._setPIN(p1);
    alert(window.t ? window.t('security.pinSet') : 'PIN set');
    _loadPinStatus();
};
window._pinSettingsRemove = function() {
    if (!confirm(window.t ? window.t('security.removePinConfirm') : 'Remove PIN?')) return;
    window._removePIN();
    _loadPinStatus();
};
var _pinBuffer = '';
var _pinAttempts = parseInt(sessionStorage.getItem('_va') || '0');
var _pinLocked   = Date.now() < parseInt(sessionStorage.getItem('_vlu') || '0');
var _pinResolve  = null;
function _pinUpdateDots() {
    var dots = document.querySelectorAll('#pin-dots .pin-dot');
    for (var i = 0; i < dots.length; i++) dots[i].classList.toggle('filled', i < _pinBuffer.length);
}
function _pinShake() {
    var el = document.getElementById('pin-dots');
    el.classList.add('shake');
    setTimeout(function(){ el.classList.remove('shake'); }, 500);
}
window._pinInput = function(digit) {
    if (_pinLocked || _pinBuffer.length >= 4) return;
    _pinBuffer += String(digit);
    _pinUpdateDots();
    if (_pinBuffer.length === 4) setTimeout(function(){ _pinCheckEntry(); }, 200);
};
window._pinBackspace = function() {
    if (_pinLocked || !_pinBuffer.length) return;
    _pinBuffer = _pinBuffer.slice(0, -1);
    _pinUpdateDots();
};
window._pinClear = function() {
    if (_pinLocked) return;
    _pinBuffer = '';
    _pinUpdateDots();
};
async function _pinCheckEntry() {
    var ok = await window._verifyPIN(_pinBuffer);
    if (ok) {
        _pinAttempts = 0;
        sessionStorage.removeItem('_va');
        sessionStorage.removeItem('_vlu');
        _pinBuffer = ''; _pinUpdateDots();
        document.getElementById('pin-lock-error').textContent = '';
        var scr = document.getElementById('pin-lock-screen');
        scr.classList.add('pin-unlock');
        setTimeout(function(){
            scr.classList.remove('show','pin-unlock');
            if (_pinResolve) { _pinResolve(); _pinResolve = null; }
        }, 300);
    } else {
        _pinAttempts++;
        sessionStorage.setItem('_va', _pinAttempts);
        _pinBuffer = '';
        _pinShake();
        setTimeout(function(){ _pinUpdateDots(); }, 300);
        if (_pinAttempts >= 5) {
            _pinLocked = true;
            sessionStorage.setItem('_vlu', Date.now() + 30000);
            sessionStorage.removeItem('_va');
            var errEl = document.getElementById('pin-lock-error');
            var sec = 30;
            errEl.textContent = window.t ? window.t('security.waitSeconds', {sec: sec}) : ('Please wait ' + sec + ' seconds');
            var iv = setInterval(function(){
                sec--;
                if (sec <= 0) {
                    clearInterval(iv);
                    _pinLocked = false; _pinAttempts = 0;
                    sessionStorage.removeItem('_va');
                    sessionStorage.removeItem('_vlu');
                    errEl.textContent = '';
                } else errEl.textContent = window.t ? window.t('security.waitSeconds', {sec: sec}) : ('Please wait ' + sec + ' seconds');
            }, 1000);
        } else {
            var e2 = document.getElementById('pin-lock-error');
            e2.textContent = window.t ? window.t('security.wrongPin') : 'Incorrect PIN';
            setTimeout(function(){ e2.textContent = ''; }, 2000);
        }
    }
}
window._checkPinLock = function() {
    if (!localStorage.getItem('vortex_pin_hash')) return Promise.resolve();
    _pinBuffer = '';
    _pinAttempts = parseInt(sessionStorage.getItem('_va') || '0');
    var lu = parseInt(sessionStorage.getItem('_vlu') || '0');
    _pinLocked = Date.now() < lu;
    _pinUpdateDots();
    var errEl = document.getElementById('pin-lock-error');
    if (_pinLocked) {
        errEl.textContent = window.t ? window.t('security.waitSeconds', {sec: Math.ceil((lu - Date.now()) / 1000)}) : ('Please wait ' + Math.ceil((lu - Date.now()) / 1000) + ' seconds');
    } else {
        errEl.textContent = '';
    }
    document.getElementById('pin-lock-screen').classList.add('show');
    return new Promise(function(resolve) { _pinResolve = resolve; });
};
document.addEventListener('keydown', function(e) {
    var scr = document.getElementById('pin-lock-screen');
    if (!scr || !scr.classList.contains('show')) return;
    if (e.key >= '0' && e.key <= '9') { window._pinInput(parseInt(e.key)); e.preventDefault(); }
    else if (e.key === 'Backspace') { window._pinBackspace(); e.preventDefault(); }
    else if (e.key === 'Escape') { window._pinClear(); e.preventDefault(); }
});
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible' && window.AppState && window.AppState.user) {
        if (localStorage.getItem('vortex_pin_hash')) {
            _pinBuffer = '';
            _pinAttempts = parseInt(sessionStorage.getItem('_va') || '0');
            var lu = parseInt(sessionStorage.getItem('_vlu') || '0');
            _pinLocked = Date.now() < lu;
            _pinUpdateDots();
            var errEl = document.getElementById('pin-lock-error');
            if (_pinLocked) {
                errEl.textContent = window.t ? window.t('security.waitSeconds', {sec: Math.ceil((lu - Date.now()) / 1000)}) : ('Please wait ' + Math.ceil((lu - Date.now()) / 1000) + ' seconds');
            } else {
                errEl.textContent = '';
            }
            document.getElementById('pin-lock-screen').classList.add('show');
        }
    }
});

// _loadPinStatus, _load2FAStatus, _highlightActiveTheme, _highlightActiveAccent
// are function declarations defined below — they are automatically on window
// and called by openSettingsSection in ux-enhancements.js.

// ══════════════════════════════════════════════════════════════════════════════
// Developer Mode
// ══════════════════════════════════════════════════════════════════════════════

(function initDevMode() {
    var enabled = localStorage.getItem('vortex_dev_mode') === '1';
    _applyDevMode(enabled);
})();

function _applyDevMode(enabled) {
    var toggle  = document.getElementById('dev-mode-toggle');
    var ideBtn  = document.getElementById('tab-btn-ide');
    if (toggle) toggle.classList.toggle('on', enabled);
    if (ideBtn) ideBtn.style.display = enabled ? '' : 'none';
    // If dev mode was disabled while IDE was open — go back to settings
    if (!enabled && typeof window.switchBottomTab === 'function') {
        var active = document.querySelector('.tab-item.active');
        if (active && active.dataset.tab === 'ide') {
            window.switchBottomTab('settings');
        }
    }
}

window.toggleDevMode = function() {
    var enabled = localStorage.getItem('vortex_dev_mode') === '1';
    enabled = !enabled;
    localStorage.setItem('vortex_dev_mode', enabled ? '1' : '0');
    _applyDevMode(enabled);
};


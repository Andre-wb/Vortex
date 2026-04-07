// ══════════════════════════════════════════════════════════════════════════════
// FEATURE 1: 2FA Setup / Enable / Disable (settings)
// ══════════════════════════════════════════════════════════════════════════════

async function _load2FAStatus() {
    try {
        var resp = await window.api('GET', '/api/authentication/2fa/status');
        var setupArea   = document.getElementById('2fa-setup-area');
        var disableArea = document.getElementById('2fa-disable-area');
        var statusArea  = document.getElementById('2fa-status-area');
        if (resp.enabled) {
            if (statusArea) statusArea.style.display = 'none';
            if (setupArea)  setupArea.style.display  = 'none';
            if (disableArea) disableArea.style.display = '';
        } else {
            if (statusArea) statusArea.style.display = '';
            if (setupArea)  setupArea.style.display  = 'none';
            if (disableArea) disableArea.style.display = 'none';
        }
    } catch(e) { console.warn('2FA status check failed:', e); }
}

window.setup2FA = async function() {
    try {
        var resp = await window.api('POST', '/api/authentication/2fa/setup');
        var setupArea  = document.getElementById('2fa-setup-area');
        var statusArea = document.getElementById('2fa-status-area');
        if (statusArea) statusArea.style.display = 'none';
        if (setupArea)  setupArea.style.display  = '';

        // Show secret
        var secretEl = document.getElementById('2fa-secret-display');
        if (secretEl) secretEl.textContent = resp.secret;

        // Show QR via external API
        var qrContainer = document.getElementById('2fa-qr-container');
        if (qrContainer) {
            var qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(resp.uri);
            qrContainer.innerHTML = '<img src="' + qrUrl + '" alt="QR" style="border-radius:8px;background:white;padding:8px;">';
        }
    } catch(e) { alert(e.message); }
};

window.confirm2FA = async function() {
    var code = document.getElementById('2fa-verify-code')?.value?.trim();
    if (!code || code.length !== 6) { alert(window.t ? window.t('security.enter6DigitCode') : 'Enter 6-digit code'); return; }
    try {
        await window.api('POST', '/api/authentication/2fa/enable', { code: code });
        alert(window.t ? window.t('security.twoFAEnabledSuccess') : '2FA enabled successfully!');
        _load2FAStatus();
    } catch(e) { alert(e.message); }
};

window.disable2FA = async function() {
    var code = document.getElementById('2fa-disable-code')?.value?.trim();
    if (!code || code.length !== 6) { alert(window.t ? window.t('security.enter6DigitCode') : 'Enter 6-digit code'); return; }
    try {
        await window.api('POST', '/api/authentication/2fa/disable', { code: code });
        alert(window.t ? window.t('security.twoFADisabled') : '2FA disabled');
        _load2FAStatus();
    } catch(e) { alert(e.message); }
};


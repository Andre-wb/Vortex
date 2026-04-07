// static/js/fingerprint.js
// =============================================================================
// Fingerprint verification — compute, display, verify key fingerprints
// =============================================================================

import { api } from './utils.js';
import QR from './vendor/qrcode.js';

// ── Emoji set (64 visually distinct, non-confusable) ────────────────────────
// 6 emojis from 64 = 36 bits entropy → 1 in ~69 billion collision chance

const _VERIFY_EMOJI = [
    '🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼',
    '🐨','🐯','🦁','🐸','🐵','🐔','🐧','🐦',
    '🦅','🦉','🐺','🐗','🐴','🦄','🐝','🐛',
    '🦋','🐌','🐞','🐙','🦑','🐠','🐳','🐋',
    '🌵','🌲','🌻','🌹','🍄','🍀','🍁','🌸',
    '🍎','🍊','🍋','🍇','🍉','🍓','🥝','🍒',
    '🌍','🌙','⭐','🔥','💧','❄️','⚡','🌈',
    '💎','🔑','🎵','🎯','🚀','⚓','🏔️','🎲',
];

// ── Fingerprint computation ─────────────────────────────────────────────────

/**
 * Compute raw SHA-256 hash bytes from two X25519 public keys.
 * Keys are sorted so both sides get the same result.
 */
async function _computeRawHash(pubkeyA, pubkeyB) {
    const sorted = [pubkeyA.toLowerCase(), pubkeyB.toLowerCase()].sort();
    const combined = sorted[0] + ':' + sorted[1];
    const data = new TextEncoder().encode(combined);
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

/**
 * Compute a fingerprint from two X25519 public keys (hex strings).
 * Both users will see the same fingerprint because keys are sorted.
 * Returns an uppercase hex string formatted as "XXXX XXXX XXXX ..." (16 groups).
 */
export async function computeFingerprint(pubkeyA, pubkeyB) {
    if (!pubkeyA || !pubkeyB) return null;
    const bytes = await _computeRawHash(pubkeyA, pubkeyB);
    const hex = Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0').toUpperCase())
        .join('');
    return hex.match(/.{1,4}/g).join(' ');
}

/**
 * Compute 6 emoji from two X25519 public keys.
 * Each emoji is derived from one byte of the SHA-256 hash mod 64.
 * 6 × 6 bits = 36 bits entropy → collision ~1 in 69 billion.
 */
export async function computeEmojiFingerprint(pubkeyA, pubkeyB) {
    if (!pubkeyA || !pubkeyB) return null;
    const bytes = await _computeRawHash(pubkeyA, pubkeyB);
    const emojis = [];
    for (let i = 0; i < 6; i++) {
        emojis.push(_VERIFY_EMOJI[bytes[i] % 64]);
    }
    return emojis;
}

/**
 * SHA-256 hash of a single pubkey hex string — used to detect key changes.
 */
export async function hashPubkey(pubkeyHex) {
    if (!pubkeyHex) return null;
    const data = new TextEncoder().encode(pubkeyHex.toLowerCase());
    const hashBuf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// ── Key change detection (localStorage) ─────────────────────────────────────

const _KNOWN_KEYS_STORAGE = 'vortex_known_pubkeys';

function _loadKnownKeys() {
    try {
        return JSON.parse(localStorage.getItem(_KNOWN_KEYS_STORAGE) || '{}');
    } catch { return {}; }
}

function _saveKnownKeys(keys) {
    localStorage.setItem(_KNOWN_KEYS_STORAGE, JSON.stringify(keys));
}

/**
 * Check if a contact's pubkey has changed since we last saw it.
 * Returns: 'new' | 'unchanged' | 'changed'
 */
export function checkKeyChange(userId, currentPubkey) {
    if (!currentPubkey) return 'new';
    const known = _loadKnownKeys();
    const prev = known[String(userId)];
    if (!prev) return 'new';
    return prev === currentPubkey.toLowerCase() ? 'unchanged' : 'changed';
}

/**
 * Store a contact's pubkey as "known".
 */
export function markKeyKnown(userId, pubkey) {
    if (!pubkey) return;
    const known = _loadKnownKeys();
    known[String(userId)] = pubkey.toLowerCase();
    _saveKnownKeys(known);
}

// ── Fingerprint modal ───────────────────────────────────────────────────────

let _currentFpData = null;

/**
 * Open the fingerprint verification modal for a user.
 * @param {Object} opts - { userId, username, displayName, contactId, pubkey, verified }
 */
export async function openFingerprintModal(opts) {
    const overlay = document.getElementById('fingerprint-modal');
    if (!overlay) return;

    const S = window.AppState;
    const myPubkey = S?.user?.x25519_public_key;
    if (!myPubkey || !opts.pubkey) {
        console.warn('[fingerprint] Missing pubkey(s)');
        return;
    }

    _currentFpData = { ...opts, myPubkey };

    // Compute fingerprint + emojis
    const fp = await computeFingerprint(myPubkey, opts.pubkey);
    const emojis = await computeEmojiFingerprint(myPubkey, opts.pubkey);
    const pubkeyHash = await hashPubkey(opts.pubkey);
    _currentFpData.fingerprint = fp;
    _currentFpData.emojis = emojis;
    _currentFpData.pubkeyHash = pubkeyHash;

    // Check key change
    const keyStatus = checkKeyChange(opts.userId, opts.pubkey);
    markKeyKnown(opts.userId, opts.pubkey);

    // Populate DOM
    const nameEl = document.getElementById('fp-contact-name');
    if (nameEl) nameEl.textContent = opts.displayName || opts.username;

    const usernameEl = document.getElementById('fp-contact-username');
    if (usernameEl) usernameEl.textContent = '@' + opts.username;

    // Emoji display (primary)
    const emojiContainer = document.getElementById('fp-emoji-container');
    if (emojiContainer && emojis) {
        emojiContainer.textContent = '';
        emojis.forEach(e => {
            const span = document.createElement('span');
            span.className = 'fp-emoji-cell';
            span.textContent = e;
            emojiContainer.appendChild(span);
        });
    }

    // Hex fingerprint (secondary, hidden by default)
    const fpBlock = document.getElementById('fp-fingerprint-block');
    if (fpBlock) fpBlock.textContent = fp;

    const fpExpanded = document.getElementById('fp-hex-section');
    if (fpExpanded) fpExpanded.style.display = 'none';

    const toggleBtn = document.getElementById('fp-toggle-hex');
    if (toggleBtn) {
        toggleBtn.dataset.expanded = '0';
        const label = toggleBtn.querySelector('.fp-btn-label');
        if (label) label.textContent = 'Посмотреть ключ';
    }

    // Verified state
    const verifyBtn = document.getElementById('fp-verify-btn');
    const verifiedBadge = document.getElementById('fp-verified-badge');
    const unverifyBtn = document.getElementById('fp-unverify-btn');

    if (opts.verified) {
        if (verifyBtn) verifyBtn.style.display = 'none';
        if (verifiedBadge) verifiedBadge.style.display = 'flex';
        if (unverifyBtn) unverifyBtn.style.display = '';
    } else {
        if (verifyBtn) verifyBtn.style.display = '';
        if (verifiedBadge) verifiedBadge.style.display = 'none';
        if (unverifyBtn) unverifyBtn.style.display = 'none';
    }

    // Key change warning
    const warningEl = document.getElementById('fp-key-warning');
    if (warningEl) {
        warningEl.style.display = keyStatus === 'changed' ? '' : 'none';
    }

    // Show modal
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('fp-visible'));
}

export function closeFingerprintModal() {
    const overlay = document.getElementById('fingerprint-modal');
    if (!overlay) return;
    overlay.classList.remove('fp-visible');
    setTimeout(() => { overlay.style.display = 'none'; }, 240);
}

export async function verifyCurrentFingerprint() {
    if (!_currentFpData?.contactId || !_currentFpData?.pubkeyHash) return;
    try {
        await api('POST', `/api/contacts/${_currentFpData.contactId}/verify-fingerprint`, {
            pubkey_hash: _currentFpData.pubkeyHash,
        });
        _currentFpData.verified = true;

        const verifyBtn = document.getElementById('fp-verify-btn');
        const verifiedBadge = document.getElementById('fp-verified-badge');
        const unverifyBtn = document.getElementById('fp-unverify-btn');
        if (verifyBtn) verifyBtn.style.display = 'none';
        if (verifiedBadge) verifiedBadge.style.display = 'flex';
        if (unverifyBtn) unverifyBtn.style.display = '';

        // Update shield in chat header if visible
        _updateChatShield(true);
    } catch (e) {
        console.error('[fingerprint] verify error:', e);
    }
}

export async function unverifyCurrentFingerprint() {
    if (!_currentFpData?.contactId) return;
    try {
        await api('DELETE', `/api/contacts/${_currentFpData.contactId}/verify-fingerprint`);
        _currentFpData.verified = false;

        const verifyBtn = document.getElementById('fp-verify-btn');
        const verifiedBadge = document.getElementById('fp-verified-badge');
        const unverifyBtn = document.getElementById('fp-unverify-btn');
        if (verifyBtn) verifyBtn.style.display = '';
        if (verifiedBadge) verifiedBadge.style.display = 'none';
        if (unverifyBtn) unverifyBtn.style.display = 'none';

        _updateChatShield(false);
    } catch (e) {
        console.error('[fingerprint] unverify error:', e);
    }
}

export function toggleHexFingerprint() {
    const section = document.getElementById('fp-hex-section');
    const btn = document.getElementById('fp-toggle-hex');
    if (!section || !btn) return;
    const expanded = btn.dataset.expanded === '1';
    section.style.display = expanded ? 'none' : '';
    btn.dataset.expanded = expanded ? '0' : '1';
    const label = btn.querySelector('.fp-btn-label');
    if (label) label.textContent = expanded ? 'Посмотреть ключ' : 'Скрыть ключ';
}

export async function copyFingerprint() {
    if (!_currentFpData?.fingerprint) return;
    try {
        await navigator.clipboard.writeText(_currentFpData.fingerprint);
        const btn = document.getElementById('fp-copy-btn');
        if (btn) {
            const label = btn.querySelector('.fp-btn-label');
            if (label) {
                const orig = label.textContent;
                label.textContent = 'Скопировано';
                setTimeout(() => { label.textContent = orig; }, 2000);
            }
        }
    } catch {}
}

// ── Chat header shield ──────────────────────────────────────────────────────

function _updateChatShield(verified) {
    const shield = document.getElementById('chat-fp-shield');
    if (!shield) return;
    shield.classList.toggle('fp-shield-verified', verified);
    shield.classList.toggle('fp-shield-unverified', !verified);
    shield.title = verified ? 'Ключ проверен' : 'Ключ не проверен';
}

/**
 * Called when a DM room is opened — shows/hides the shield icon and sets its state.
 */
export async function updateShieldForRoom(room, otherUser) {
    const shield = document.getElementById('chat-fp-shield');
    if (!shield) return;

    if (!room?.is_dm || !otherUser?.x25519_public_key) {
        shield.style.display = 'none';
        return;
    }

    shield.style.display = '';

    // Check if this contact is verified
    const S = window.AppState;
    const contacts = S?.contacts || [];
    const contact = contacts.find(c => c.user_id === otherUser.id);
    const verified = contact?.fingerprint_verified || false;

    _updateChatShield(verified);

    // Check for key change
    const keyStatus = checkKeyChange(otherUser.id, otherUser.x25519_public_key);
    if (keyStatus === 'changed') {
        shield.classList.add('fp-shield-warning');
        shield.title = 'Ключ безопасности изменился!';
    } else {
        shield.classList.remove('fp-shield-warning');
    }

    // Store click handler data
    shield.dataset.userId = otherUser.id;
    shield.dataset.username = otherUser.username;
    shield.dataset.displayName = otherUser.display_name || otherUser.username;
    shield.dataset.pubkey = otherUser.x25519_public_key;
    shield.dataset.contactId = contact?.contact_id || '';
    shield.dataset.verified = verified ? '1' : '0';
}

/**
 * Click handler for the shield icon in the chat header.
 */
export function onShieldClick() {
    const shield = document.getElementById('chat-fp-shield');
    if (!shield) return;
    openFingerprintModal({
        userId:      parseInt(shield.dataset.userId),
        username:    shield.dataset.username,
        displayName: shield.dataset.displayName,
        contactId:   parseInt(shield.dataset.contactId) || null,
        pubkey:      shield.dataset.pubkey,
        verified:    shield.dataset.verified === '1',
    });
}

// ── QR Code generation ──────────────────────────────────────────────────────

/**
 * Show the QR code panel in the fingerprint modal.
 * Encodes fingerprint as "VORTEX-FP:<hex>" for scanning.
 */
export function showFingerprintQR() {
    if (!_currentFpData?.fingerprint) return;
    const container = document.getElementById('fp-qr-canvas-wrap');
    const panel = document.getElementById('fp-qr-panel');
    if (!container || !panel) return;

    const payload = 'VORTEX-FP:' + _currentFpData.fingerprint.replace(/\s/g, '');
    try {
        const matrix = QR.encode(payload);
        const canvas = QR.toCanvas(matrix, 5, 3);
        canvas.style.cssText = 'border-radius:12px;display:block;margin:0 auto;';
        container.textContent = '';
        container.appendChild(canvas);
        panel.style.display = '';
    } catch (e) {
        console.error('[fingerprint] QR encode error:', e);
    }
}

export function hideFingerprintQR() {
    const panel = document.getElementById('fp-qr-panel');
    if (panel) panel.style.display = 'none';
}

// ── QR Camera scanning ──────────────────────────────────────────────────────

let _scanStream = null;
let _scanInterval = null;

export async function startQRScan() {
    const overlay = document.getElementById('fp-scan-overlay');
    const video = document.getElementById('fp-scan-video');
    const status = document.getElementById('fp-scan-status');
    if (!overlay || !video) return;

    // Check BarcodeDetector support
    if (typeof BarcodeDetector === 'undefined') {
        if (status) status.textContent = 'Сканирование не поддерживается в этом браузере. Сравните эмодзи вручную.';
        overlay.style.display = 'flex';
        return;
    }

    try {
        _scanStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }
        });
        video.srcObject = _scanStream;
        await video.play();
        overlay.style.display = 'flex';
        if (status) status.textContent = 'Наведите камеру на QR-код собеседника';

        const detector = new BarcodeDetector({ formats: ['qr_code'] });

        _scanInterval = setInterval(async () => {
            try {
                const codes = await detector.detect(video);
                for (const code of codes) {
                    if (code.rawValue && code.rawValue.startsWith('VORTEX-FP:')) {
                        const scannedHex = code.rawValue.slice(10);
                        const localHex = _currentFpData?.fingerprint?.replace(/\s/g, '') || '';
                        stopQRScan();
                        if (scannedHex === localHex) {
                            // Match! Auto-verify
                            if (status) {
                                status.textContent = 'Ключи совпадают!';
                                status.classList.add('fp-scan-success');
                            }
                            await verifyCurrentFingerprint();
                            setTimeout(stopQRScan, 1500);
                        } else {
                            if (status) {
                                status.textContent = 'Ключи НЕ совпадают! Возможен MITM.';
                                status.classList.add('fp-scan-fail');
                            }
                            setTimeout(stopQRScan, 3000);
                        }
                        return;
                    }
                }
            } catch {}
        }, 300);
    } catch (e) {
        console.error('[fingerprint] camera error:', e);
        if (status) status.textContent = 'Нет доступа к камере';
        overlay.style.display = 'flex';
    }
}

export function stopQRScan() {
    if (_scanInterval) { clearInterval(_scanInterval); _scanInterval = null; }
    if (_scanStream) { _scanStream.getTracks().forEach(t => t.stop()); _scanStream = null; }
    const overlay = document.getElementById('fp-scan-overlay');
    const video = document.getElementById('fp-scan-video');
    const status = document.getElementById('fp-scan-status');
    if (video) video.srcObject = null;
    if (overlay) overlay.style.display = 'none';
    if (status) { status.classList.remove('fp-scan-success', 'fp-scan-fail'); }
}

// ── Cross-device verification ───────────────────────────────────────────────

/**
 * Open device verification modal showing all user's devices with fingerprints.
 */
export async function openDeviceVerification() {
    const panel = document.getElementById('fp-devices-panel');
    if (!panel) return;

    panel.style.display = '';
    const list = document.getElementById('fp-devices-list');
    if (list) list.textContent = 'Загрузка...';

    try {
        const data = await api('GET', '/api/authentication/devices');
        const devices = data.devices || [];
        if (!list) return;
        list.textContent = '';

        if (devices.length === 0) {
            list.textContent = 'Нет устройств';
            return;
        }

        const S = window.AppState;
        for (const dev of devices) {
            const row = document.createElement('div');
            row.className = 'fp-device-row';

            const icon = document.createElement('div');
            icon.className = 'fp-device-icon';
            const iconType = dev.device_type === 'mobile' ? 'M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z' : 'M20 16V7a2 2 0 00-2-2H6a2 2 0 00-2 2v9m16 0H4m16 0l1 3H3l1-3';
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', '18');
            svg.setAttribute('height', '18');
            svg.setAttribute('fill', 'none');
            svg.setAttribute('stroke', 'currentColor');
            svg.setAttribute('stroke-width', '2');
            svg.setAttribute('viewBox', '0 0 24 24');
            const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path.setAttribute('d', iconType);
            path.setAttribute('stroke-linecap', 'round');
            path.setAttribute('stroke-linejoin', 'round');
            svg.appendChild(path);
            icon.appendChild(svg);
            row.appendChild(icon);

            const info = document.createElement('div');
            info.className = 'fp-device-info';
            const name = document.createElement('div');
            name.className = 'fp-device-name';
            name.textContent = dev.device_name || 'Unknown';
            if (dev.is_current) {
                const badge = document.createElement('span');
                badge.className = 'fp-device-current';
                badge.textContent = 'это устройство';
                name.appendChild(badge);
            }
            info.appendChild(name);

            const meta = document.createElement('div');
            meta.className = 'fp-device-meta';
            meta.textContent = dev.last_active ? new Date(dev.last_active).toLocaleDateString('ru-RU') : '';
            info.appendChild(meta);
            row.appendChild(info);

            list.appendChild(row);
        }
    } catch (e) {
        console.error('[fingerprint] devices error:', e);
        if (list) list.textContent = 'Ошибка загрузки';
    }
}

export function closeDeviceVerification() {
    const panel = document.getElementById('fp-devices-panel');
    if (panel) panel.style.display = 'none';
}

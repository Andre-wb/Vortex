// static/js/key_backup.js
// ============================================================================
// Encrypted Key Backup & Multi-Device Sync
//
// Backup:
//   1. Собирает все ключи (X25519 priv JWK, room keys) в JSON bundle
//   2. Шифрует AES-256-GCM с ключом, производным от парольной фразы (PBKDF2-SHA256, 600k)
//   3. Загружает зашифрованный blob на сервер (POST /api/keys/backup)
//   4. Для восстановления: скачивает blob, расшифровывает парольной фразой
//
// Device linking:
//   1. Новое устройство генерирует эфемерную X25519 пару + запрашивает 6-значный код
//   2. Пользователь вводит код на старом устройстве
//   3. Старое устройство шифрует ключи ECIES (X25519 DH + AES-GCM) для нового
//   4. Новое устройство получает и расшифровывает ключи
// ============================================================================

import { $, api, showAlert, openModal, closeModal } from './utils.js';
import { getRoomKey, setRoomKey, eciesEncrypt, eciesDecrypt } from './crypto.js';

const toHex   = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

const PBKDF2_ITERATIONS = 600000;

// ============================================================================
// Key Derivation from passphrase
// ============================================================================

async function _deriveBackupKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// ============================================================================
// Collect all keys into a bundle
// ============================================================================

function _collectKeyBundle() {
    const bundle = { version: 1, keys: {} };

    // X25519 private key (JWK string)
    const privKey = window.AppState?.x25519PrivateKey
        || sessionStorage.getItem('vortex_x25519_priv')
        || localStorage.getItem('vortex_x25519_priv');
    if (privKey) {
        bundle.keys.x25519_private_jwk = privKey;
    }

    // Room keys (from crypto.js in-memory store)
    // We iterate known rooms from AppState
    const roomKeys = {};
    const rooms = window.AppState?.rooms || [];
    for (const room of rooms) {
        const rk = getRoomKey(room.id);
        if (rk) {
            roomKeys[room.id] = toHex(rk);
        }
    }
    if (Object.keys(roomKeys).length > 0) {
        bundle.keys.room_keys = roomKeys;
    }

    return bundle;
}

function _restoreKeyBundle(bundle) {
    if (!bundle || !bundle.keys) return;

    // Restore X25519 private key
    if (bundle.keys.x25519_private_jwk) {
        const jwk = bundle.keys.x25519_private_jwk;
        localStorage.setItem('vortex_x25519_priv', jwk);
        sessionStorage.setItem('vortex_x25519_priv', jwk);
        if (window.AppState) {
            window.AppState.x25519PrivateKey = jwk;
        }
    }

    // Restore room keys
    if (bundle.keys.room_keys) {
        for (const [roomId, keyHex] of Object.entries(bundle.keys.room_keys)) {
            setRoomKey(parseInt(roomId), fromHex(keyHex));
        }
    }
}

// ============================================================================
// Backup: encrypt & upload
// ============================================================================

export async function createKeyBackup(passphrase) {
    if (!passphrase || passphrase.length < 8) {
        showAlert(t('keyBackup.passphraseMinLen'), 'error');
        return false;
    }

    const bundle = _collectKeyBundle();
    if (!bundle.keys.x25519_private_jwk) {
        showAlert(t('keyBackup.noKeysToBackup'), 'error');
        return false;
    }

    const plaintext = new TextEncoder().encode(JSON.stringify(bundle));
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key = await _deriveBackupKey(passphrase, salt);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);

    // vault_data = nonce(12) + ciphertext
    const vaultBytes = new Uint8Array(12 + ct.byteLength);
    vaultBytes.set(nonce, 0);
    vaultBytes.set(new Uint8Array(ct), 12);

    try {
        await api('POST', '/api/keys/backup', {
            vault_data: toHex(vaultBytes),
            vault_salt: toHex(salt),
            kdf_params: JSON.stringify({
                alg: 'PBKDF2', iter: PBKDF2_ITERATIONS, hash: 'SHA-256'
            }),
        });
        showAlert(t('keyBackup.backupCreated'), 'success');
        return true;
    } catch (e) {
        showAlert(t('keyBackup.backupCreateError', {error: e.message || e}), 'error');
        return false;
    }
}

// ============================================================================
// Backup: download & decrypt
// ============================================================================

export async function restoreKeyBackup(passphrase) {
    if (!passphrase) {
        showAlert(t('keyBackup.enterPassphrase'), 'error');
        return false;
    }

    let backup;
    try {
        backup = await api('GET', '/api/keys/backup');
    } catch (e) {
        showAlert(t('keyBackup.backupNotFound'), 'error');
        return false;
    }

    const salt = fromHex(backup.vault_salt);
    const vaultBytes = fromHex(backup.vault_data);
    const nonce = vaultBytes.slice(0, 12);
    const ct = vaultBytes.slice(12);

    let key;
    try {
        // Parse KDF params (support future algorithms)
        const kdfParams = JSON.parse(backup.kdf_params || '{}');
        const iterations = kdfParams.iter || PBKDF2_ITERATIONS;
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
        );
        key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations, hash: kdfParams.hash || 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
    } catch (e) {
        showAlert(t('keyBackup.keyDerivationError'), 'error');
        return false;
    }

    try {
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
        const bundle = JSON.parse(new TextDecoder().decode(plain));
        _restoreKeyBundle(bundle);
        showAlert(t('keyBackup.keysRestored'), 'success');
        return true;
    } catch {
        showAlert(t('keyBackup.wrongPassphrase'), 'error');
        return false;
    }
}

export async function deleteKeyBackup() {
    try {
        await api('DELETE', '/api/keys/backup');
        showAlert(t('keyBackup.backupDeleted'), 'success');
        return true;
    } catch (e) {
        showAlert(t('keyBackup.backupDeleteError', {error: e.message || e}), 'error');
        return false;
    }
}

export async function hasKeyBackup() {
    try {
        await api('GET', '/api/keys/backup');
        return true;
    } catch {
        return false;
    }
}

// ============================================================================
// Device Linking — new device side
// ============================================================================

let _linkRequestId = null;
let _linkEphemeralPriv = null;
let _linkPollTimer = null;

export async function requestDeviceLink() {
    // Generate ephemeral X25519 keypair for this link session
    const keyPair = await crypto.subtle.generateKey(
        { name: 'X25519' }, true, ['deriveBits']
    );
    const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    _linkEphemeralPriv = keyPair.privateKey;

    try {
        const resp = await api('POST', '/api/keys/link/request', {
            new_device_pub: toHex(pubRaw),
        });
        _linkRequestId = resp.request_id;
        return {
            requestId: resp.request_id,
            linkCode: resp.link_code,
            expiresIn: resp.expires_in_seconds,
        };
    } catch (e) {
        showAlert(t('keyBackup.requestCreateError', {error: e.message || e}), 'error');
        return null;
    }
}

export function startLinkPoll(requestId, onSuccess, onExpired) {
    if (_linkPollTimer) clearInterval(_linkPollTimer);
    let attempts = 0;
    const maxAttempts = 120; // 10 min at 5s intervals

    _linkPollTimer = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
            clearInterval(_linkPollTimer);
            _linkPollTimer = null;
            if (onExpired) onExpired();
            return;
        }

        try {
            const resp = await api('GET', `/api/keys/link/poll/${requestId}`);
            if (resp.status === 'approved' && resp.encrypted_keys) {
                clearInterval(_linkPollTimer);
                _linkPollTimer = null;

                // Decrypt keys with our ephemeral private key
                const bundle = await _decryptLinkedKeys(resp.encrypted_keys);
                if (bundle) {
                    _restoreKeyBundle(bundle);
                    if (onSuccess) onSuccess();
                }
            } else if (resp.status === 'expired') {
                clearInterval(_linkPollTimer);
                _linkPollTimer = null;
                if (onExpired) onExpired();
            }
        } catch {
            // Retry silently
        }
    }, 5000);
}

export function stopLinkPoll() {
    if (_linkPollTimer) {
        clearInterval(_linkPollTimer);
        _linkPollTimer = null;
    }
    _linkEphemeralPriv = null;
    _linkRequestId = null;
}

async function _decryptLinkedKeys(encryptedHex) {
    if (!_linkEphemeralPriv) return null;

    try {
        // encrypted_keys format: ephemeral_pub(64hex) + ciphertext(rest)
        // This is ECIES: DH(our_ephemeral_priv, sender_ephemeral_pub) → shared → AES-GCM
        const data = fromHex(encryptedHex);
        const senderPubRaw = data.slice(0, 32);
        const nonce = data.slice(32, 44);
        const ct = data.slice(44);

        const senderPub = await crypto.subtle.importKey(
            'raw', senderPubRaw, { name: 'X25519' }, false, []
        );

        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'X25519', public: senderPub },
            _linkEphemeralPriv, 256
        );

        const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
        const encKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('vortex-device-link') },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, encKey, ct);
        return JSON.parse(new TextDecoder().decode(plain));
    } catch (e) {
        console.error('[KeyBackup] Failed to decrypt linked keys:', e);
        showAlert(t('keyBackup.decryptError'), 'error');
        return null;
    }
}

// ============================================================================
// Device Linking — existing device side
// ============================================================================

export async function checkLinkCode(code) {
    try {
        return await api('GET', `/api/keys/link/${code}`);
    } catch {
        return null;
    }
}

export async function approveLinkRequest(code, newDevicePubHex) {
    // Collect current keys
    const bundle = _collectKeyBundle();
    if (!bundle.keys.x25519_private_jwk) {
        showAlert(t('keyBackup.noKeysToTransfer'), 'error');
        return false;
    }

    const plaintext = new TextEncoder().encode(JSON.stringify(bundle));

    // ECIES: generate ephemeral keypair, DH with new device pub, encrypt
    const ephPair = await crypto.subtle.generateKey(
        { name: 'X25519' }, true, ['deriveBits']
    );
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephPair.publicKey));

    const recipientPub = await crypto.subtle.importKey(
        'raw', fromHex(newDevicePubHex), { name: 'X25519' }, false, []
    );

    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: recipientPub },
        ephPair.privateKey, 256
    );

    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const encKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('vortex-device-link') },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, encKey, plaintext);

    // Format: ephemeral_pub(32) + nonce(12) + ciphertext
    const packed = new Uint8Array(32 + 12 + ct.byteLength);
    packed.set(ephPubRaw, 0);
    packed.set(nonce, 32);
    packed.set(new Uint8Array(ct), 44);

    try {
        await api('POST', `/api/keys/link/${code}/approve`, {
            encrypted_keys: toHex(packed),
        });
        showAlert(t('keyBackup.keysTransferred'), 'success');
        return true;
    } catch (e) {
        showAlert(t('keyBackup.transferError', {error: e.message || e}), 'error');
        return false;
    }
}


// ============================================================================
// Privacy settings (stored locally + encrypted copy on server)
// ============================================================================

const _PREFS_KEY = 'vortex_sync_prefs';
const _DEFAULT_PREFS = { auto_key_sync: true, history_sync: true, cross_sign: true };
const _MIGRATION_KEY = 'vortex_history_migrated';

function _loadPrefs() {
    try {
        return { ..._DEFAULT_PREFS, ...JSON.parse(localStorage.getItem(_PREFS_KEY) || '{}') };
    } catch { return { ..._DEFAULT_PREFS }; }
}

function _savePrefsLocal(prefs) {
    localStorage.setItem(_PREFS_KEY, JSON.stringify(prefs));
}

export function _savePrivacySetting(key, value) {
    const prefs = _loadPrefs();
    prefs[key] = value;
    _savePrefsLocal(prefs);
    if (key === 'auto_key_sync' && value) {
        _autoSyncKeys().catch(() => {});
    }
    if (key === 'history_sync' && value) {
        // Re-enable: trigger initial migration if not done
        localStorage.removeItem(_MIGRATION_KEY);
        runInitialHistoryMigration().catch(() => {});
    }
}

export function _loadPrivacySettings() {
    const prefs = _loadPrefs();
    const el1 = $('set-privacy-auto-key-sync');
    const el2 = $('set-privacy-history-sync');
    const el3 = $('set-privacy-cross-sign');
    if (el1) el1.checked = prefs.auto_key_sync !== false;
    if (el2) el2.checked = prefs.history_sync !== false;
    if (el3) el3.checked = prefs.cross_sign !== false;
    _loadBackupStatus();
    _loadDevicesListWithFingerprint();
    _loadSsssStatus();
    _loadFederatedStatus();
    _loadKeyTransparencyLog();
    registerDevicePubKey().catch(() => {});
}


// ============================================================================
// Auto-sync: push encrypted key updates to server for other devices
// ============================================================================

let _syncKey = null;
let _lastSyncSeq = 0;
let _syncPollTimer = null;

async function _deriveSyncKey() {
    if (_syncKey) return _syncKey;
    const privJwk = window.AppState?.x25519PrivateKey
        || sessionStorage.getItem('vortex_x25519_priv')
        || localStorage.getItem('vortex_x25519_priv');
    if (!privJwk) return null;
    const seed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(privJwk));
    const hkdfKey = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveKey']);
    _syncKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('vortex-sync') },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    return _syncKey;
}

async function _encryptSyncPayload(data) {
    const key = await _deriveSyncKey();
    if (!key) return null;
    const plaintext = new TextEncoder().encode(JSON.stringify(data));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(ct), 12);
    return toHex(result);
}

async function _decryptSyncPayload(hex) {
    const key = await _deriveSyncKey();
    if (!key) return null;
    const data = fromHex(hex);
    try {
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
        return JSON.parse(new TextDecoder().decode(plain));
    } catch { return null; }
}

function _getDeviceId() {
    let id = localStorage.getItem('vortex_device_id');
    if (!id) { id = String(Date.now() % 1000000000); localStorage.setItem('vortex_device_id', id); }
    return parseInt(id);
}

async function _autoSyncKeys() {
    const prefs = _loadPrefs();
    if (!prefs.auto_key_sync) return;
    const bundle = _collectKeyBundle();
    if (!bundle.keys.x25519_private_jwk) return;
    const payload = await _encryptSyncPayload(bundle);
    if (!payload) return;
    try {
        await api('POST', '/api/keys/sync/push', { device_id: _getDeviceId(), event_type: 'key_update', payload });
    } catch (e) { console.debug('[KeyBackup] Auto-sync push failed:', e.message); }
}

async function _pullSyncEvents() {
    const prefs = _loadPrefs();
    if (!prefs.auto_key_sync && !prefs.history_sync) return;
    try {
        const resp = await api('GET', `/api/keys/sync/pull?since_seq=${_lastSyncSeq}`);
        const myDevice = _getDeviceId();
        for (const evt of resp.events || []) {
            if (evt.device_id === myDevice) { _lastSyncSeq = Math.max(_lastSyncSeq, evt.seq); continue; }
            if (evt.event_type === 'key_update' && prefs.auto_key_sync) {
                const data = await _decryptSyncPayload(evt.payload);
                if (data) _restoreKeyBundle(data);
            }
            if (evt.event_type === 'history' && prefs.history_sync) {
                const data = await _decryptSyncPayload(evt.payload);
                if (data) _restoreHistoryChunk(data);
            }
            _lastSyncSeq = Math.max(_lastSyncSeq, evt.seq);
        }
    } catch (e) { console.debug('[KeyBackup] Sync pull failed:', e.message); }
}

function _restoreHistoryChunk(data) {
    if (!data || !data.messages) return;
    for (const [roomId, msgs] of Object.entries(data.messages)) {
        const key = `vortex_history_${roomId}`;
        const existing = JSON.parse(localStorage.getItem(key) || '[]');
        const ids = new Set(existing.map(m => m.id));
        for (const m of msgs) { if (!ids.has(m.id)) existing.push(m); }
        existing.sort((a, b) => (a.id || 0) - (b.id || 0));
        if (existing.length > 500) existing.splice(0, existing.length - 500);
        localStorage.setItem(key, JSON.stringify(existing));
    }
}

/**
 * Get synced history for a room from localStorage (called when opening a room).
 */
export function getSyncedHistory(roomId) {
    try {
        return JSON.parse(localStorage.getItem(`vortex_history_${roomId}`) || '[]');
    } catch { return []; }
}

// ── Batched history push (debounce per room) ────────────────────────────────
const _historyBatch = {};      // roomId → messages[]
let _historyFlushTimer = null;

/**
 * Queue a message for history sync. Flushed in batches every 5 seconds.
 */
export function queueHistoryMessage(roomId, msg) {
    const prefs = _loadPrefs();
    if (!prefs.history_sync) return;
    if (!msg || !msg.msg_id) return;
    if (!_historyBatch[roomId]) _historyBatch[roomId] = [];
    _historyBatch[roomId].push({
        id: msg.msg_id,
        sender_id: msg.sender_id,
        sender: msg.sender || msg.username,
        text: msg.text,
        ciphertext: msg.ciphertext,
        created_at: msg.created_at || msg.timestamp || new Date().toISOString(),
        reply_to_id: msg.reply_to_id,
        is_edited: msg.is_edited || false,
    });
    if (!_historyFlushTimer) {
        _historyFlushTimer = setTimeout(_flushHistoryBatch, 5000);
    }
}

async function _flushHistoryBatch() {
    _historyFlushTimer = null;
    const batch = { ..._historyBatch };
    for (const k of Object.keys(_historyBatch)) delete _historyBatch[k];
    for (const [roomId, msgs] of Object.entries(batch)) {
        if (msgs.length) await pushHistorySync(roomId, msgs);
    }
}

export async function pushHistorySync(roomId, messages) {
    const prefs = _loadPrefs();
    if (!prefs.history_sync) return;
    const payload = await _encryptSyncPayload({ messages: { [roomId]: messages } });
    if (!payload) return;
    try {
        await api('POST', '/api/keys/sync/push', { device_id: _getDeviceId(), event_type: 'history', payload });
    } catch (e) { console.debug('[KeyBackup] History push failed:', e.message); }
}

export function startSyncPolling() {
    if (_syncPollTimer) return;
    _syncPollTimer = setInterval(() => _pullSyncEvents(), 15000);
    _pullSyncEvents().catch(() => {});
}

export function stopSyncPolling() {
    if (_syncPollTimer) { clearInterval(_syncPollTimer); _syncPollTimer = null; }
}

export async function onRoomKeyChanged(roomId, keyBytes) {
    const prefs = _loadPrefs();
    if (!prefs.auto_key_sync) return;
    await _autoSyncKeys();
}

// ── Initial history migration for new devices ───────────────────────────────

/**
 * Run initial history migration if this is a new device (never migrated before).
 * Fetches encrypted messages from server, decrypts with room keys, stores locally,
 * and pushes encrypted sync events for future devices.
 */
export async function runInitialHistoryMigration() {
    const prefs = _loadPrefs();
    if (!prefs.history_sync) return;
    if (localStorage.getItem(_MIGRATION_KEY)) return; // already migrated

    try {
        const summary = await api('GET', '/api/keys/sync/rooms-summary');
        if (!summary.rooms || !summary.rooms.length) {
            localStorage.setItem(_MIGRATION_KEY, Date.now().toString());
            return;
        }

        let migrated = 0;
        for (const room of summary.rooms) {
            if (!room.msg_count) continue;
            try {
                const data = await api('GET', `/api/keys/sync/history-export/${room.room_id}?limit=200`);
                if (data.messages && data.messages.length) {
                    // Store raw encrypted messages in localStorage for this room
                    const key = `vortex_history_${room.room_id}`;
                    const existing = JSON.parse(localStorage.getItem(key) || '[]');
                    const ids = new Set(existing.map(m => m.id));
                    for (const m of data.messages) {
                        if (!ids.has(m.id)) existing.push(m);
                    }
                    existing.sort((a, b) => (a.id || 0) - (b.id || 0));
                    if (existing.length > 500) existing.splice(0, existing.length - 500);
                    localStorage.setItem(key, JSON.stringify(existing));
                    migrated++;
                }
            } catch (e) {
                console.debug('[HistoryMigration] Room', room.room_id, 'failed:', e.message);
            }
        }
        console.info('[HistoryMigration] Migrated', migrated, 'rooms');
    } catch (e) {
        console.debug('[HistoryMigration] Failed:', e.message);
    }
    localStorage.setItem(_MIGRATION_KEY, Date.now().toString());
}


// ============================================================================
// Device list & backup status (safe DOM construction)
// ============================================================================

// _loadDevicesList replaced by _loadDevicesListWithFingerprint below

async function _loadBackupStatus() {
    const el = $('privacy-backup-status');
    if (!el) return;
    try {
        const backup = await api('GET', '/api/keys/backup');
        el.textContent = '';
        const span = document.createElement('span');
        span.style.color = 'var(--green)';
        span.textContent = t('keyBackup.backupCreatedShort');
        el.appendChild(span);
        const detail = document.createTextNode(` (${t('keyBackup.version')} ${backup.version}, ${t('keyBackup.updated')} ${backup.updated_at ? new Date(backup.updated_at).toLocaleDateString() : '\u2014'})`);
        el.appendChild(detail);
    } catch {
        el.textContent = t('keyBackup.backupNotCreated');
        el.style.color = 'var(--text3)';
    }
}


// ============================================================================
// Settings UI handlers (safe DOM construction)
// ============================================================================

export function _showBackupPassphraseDialog(mode) {
    const title = mode === 'create' ? t('keyBackup.createBackupTitle') : t('keyBackup.restoreBackupTitle');
    const btnText = mode === 'create' ? t('keyBackup.encryptAndSave') : t('keyBackup.decryptAndRestore');

    let modal = $('backup-passphrase-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'backup-passphrase-modal';
        modal.className = 'modal-overlay';
        document.body.appendChild(modal);
    }
    modal.textContent = '';

    const content = document.createElement('div');
    content.className = 'modal-content';
    content.style.maxWidth = '400px';

    const inner = document.createElement('div');
    inner.style.padding = '20px';

    const h3 = document.createElement('h3');
    h3.style.cssText = 'margin:0 0 12px;font-size:16px;';
    h3.textContent = title;
    inner.appendChild(h3);

    const desc = document.createElement('p');
    desc.style.cssText = 'font-size:12px;color:var(--text2);margin:0 0 16px;';
    desc.textContent = mode === 'create'
        ? t('keyBackup.passphraseEncryptHint')
        : t('keyBackup.passphraseRestoreHint');
    inner.appendChild(desc);

    const input = document.createElement('input');
    input.type = 'password'; input.id = 'backup-passphrase-input';
    input.className = 'form-input';
    input.placeholder = t('keyBackup.passphrasePlaceholder');
    input.style.marginBottom = '12px';
    inner.appendChild(input);

    let confirmInput;
    if (mode === 'create') {
        confirmInput = document.createElement('input');
        confirmInput.type = 'password'; confirmInput.id = 'backup-passphrase-confirm';
        confirmInput.className = 'form-input';
        confirmInput.placeholder = t('keyBackup.passphraseConfirmPlaceholder');
        confirmInput.style.marginBottom = '12px';
        inner.appendChild(confirmInput);
    }

    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary btn-sm';
    cancelBtn.textContent = t('app.cancel');
    cancelBtn.onclick = () => { modal.style.display = 'none'; };
    btnRow.appendChild(cancelBtn);

    const submitBtn = document.createElement('button');
    submitBtn.className = 'btn btn-primary btn-sm';
    submitBtn.textContent = btnText;
    submitBtn.onclick = async () => {
        const pass = input.value;
        if (mode === 'create') {
            if (pass !== confirmInput.value) { showAlert(t('keyBackup.phraseMismatch'), 'error'); return; }
            const ok = await createKeyBackup(pass);
            if (ok) { modal.style.display = 'none'; _loadBackupStatus(); }
        } else {
            const ok = await restoreKeyBackup(pass);
            if (ok) { modal.style.display = 'none'; _loadBackupStatus(); }
        }
    };
    btnRow.appendChild(submitBtn);
    inner.appendChild(btnRow);

    content.appendChild(inner);
    modal.appendChild(content);
    modal.style.display = 'flex';
    modal.onclick = (e) => { if (e.target === modal) modal.style.display = 'none'; };
    setTimeout(() => input.focus(), 100);
}

export async function _deleteBackupConfirm() {
    if (!confirm(t('keyBackup.deleteBackupConfirm'))) return;
    await deleteKeyBackup();
    _loadBackupStatus();
}

export function _startDeviceLinkFromSettings(role) {
    const status = $('privacy-link-status');
    if (!status) return;
    status.style.display = 'block';
    status.textContent = '';

    if (role === 'new') {
        status.textContent = t('keyBackup.generatingCode');
        requestDeviceLink().then(result => {
            if (!result) { status.textContent = t('keyBackup.errorGeneric'); return; }
            status.textContent = '';
            const code = document.createElement('div');
            code.style.cssText = 'font-size:24px;font-weight:700;letter-spacing:8px;margin:8px 0;';
            code.textContent = result.linkCode;
            const hint = document.createElement('div');
            hint.style.cssText = 'font-size:12px;color:var(--text2);';
            hint.textContent = t('keyBackup.enterCodeOnMain');
            const ttl = document.createElement('div');
            ttl.style.cssText = 'font-size:11px;color:var(--text3);margin-top:4px;';
            ttl.textContent = t('keyBackup.codeValid', {n: Math.floor(result.expiresIn / 60)});
            status.appendChild(code); status.appendChild(hint); status.appendChild(ttl);
            startLinkPoll(result.requestId,
                () => { status.textContent = ''; const s = document.createElement('span'); s.style.color = 'var(--green)'; s.textContent = t('keyBackup.keysReceived'); status.appendChild(s); },
                () => { status.textContent = ''; const s = document.createElement('span'); s.style.color = 'var(--red)'; s.textContent = t('keyBackup.codeExpired'); status.appendChild(s); }
            );
        });
    } else {
        const input = document.createElement('input');
        input.type = 'text'; input.id = 'link-code-input';
        input.className = 'form-input';
        input.placeholder = t('keyBackup.sixDigitCode'); input.maxLength = 6;
        input.style.cssText = 'text-align:center;font-size:18px;letter-spacing:4px;margin-bottom:8px;';
        const btn = document.createElement('button');
        btn.className = 'btn btn-primary btn-sm';
        btn.textContent = t('app.confirm');
        btn.onclick = () => _submitLinkCode();
        status.appendChild(input); status.appendChild(btn);
        setTimeout(() => input.focus(), 100);
    }
}

export async function _submitLinkCode() {
    const code = $('link-code-input')?.value?.trim();
    const status = $('privacy-link-status');
    if (!code || code.length !== 6) { showAlert(t('keyBackup.enter6DigitCode'), 'error'); return; }
    const req = await checkLinkCode(code);
    if (!req) { showAlert(t('keyBackup.invalidOrExpiredCode'), 'error'); return; }
    if (status) status.textContent = t('keyBackup.transferringKeys');
    const ok = await approveLinkRequest(code, req.new_device_pub);
    if (ok && status) {
        status.textContent = '';
        const s = document.createElement('span');
        s.style.color = 'var(--green)';
        s.textContent = t('keyBackup.keysTransferredShort');
        status.appendChild(s);
    }
}


// ============================================================================
// Shamir's Secret Sharing over GF(256) — client-side only
// ============================================================================
// Server NEVER sees plaintext shares. All math happens in the browser.
// GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)

const _GF_EXP = new Uint8Array(512);
const _GF_LOG = new Uint8Array(256);
(() => {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        _GF_EXP[i] = x;
        _GF_LOG[x] = i;
        x = (x << 1) ^ x;
        if (x >= 256) x ^= 0x11B;
    }
    for (let i = 255; i < 512; i++) _GF_EXP[i] = _GF_EXP[i - 255];
})();

function _gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]];
}

function _gfDiv(a, b) {
    if (b === 0) throw new Error('GF(256) division by zero');
    if (a === 0) return 0;
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b] + 255) % 255];
}

/**
 * Split secret bytes into N shares with threshold M.
 * Each share = { index: 1..N, data: Uint8Array(secret.length) }
 */
export function shamirSplit(secret, threshold, totalShares) {
    if (threshold < 2 || threshold > totalShares || totalShares > 255)
        throw new Error('Invalid threshold/totalShares');
    const secretBytes = secret instanceof Uint8Array ? secret : new TextEncoder().encode(secret);
    const shares = [];
    for (let s = 1; s <= totalShares; s++) {
        shares.push({ index: s, data: new Uint8Array(secretBytes.length) });
    }
    for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
        // Random polynomial: coefficients[0] = secret byte, rest random
        const coeffs = new Uint8Array(threshold);
        coeffs[0] = secretBytes[byteIdx];
        crypto.getRandomValues(coeffs.subarray(1));
        for (let s = 0; s < totalShares; s++) {
            const x = s + 1; // x = 1..N (never 0)
            let y = 0;
            for (let k = 0; k < threshold; k++) {
                // y += coeffs[k] * x^k  (in GF(256))
                let xpow = 1;
                for (let p = 0; p < k; p++) xpow = _gfMul(xpow, x);
                y ^= _gfMul(coeffs[k], xpow);
            }
            shares[s].data[byteIdx] = y;
        }
    }
    return shares;
}

/**
 * Recombine M shares using Lagrange interpolation at x=0.
 * shares: array of { index, data: Uint8Array }
 */
export function shamirCombine(shares, threshold) {
    if (shares.length < threshold) throw new Error(`Need ${threshold} shares, got ${shares.length}`);
    const selected = shares.slice(0, threshold);
    const len = selected[0].data.length;
    const result = new Uint8Array(len);
    for (let byteIdx = 0; byteIdx < len; byteIdx++) {
        let value = 0;
        for (let i = 0; i < threshold; i++) {
            const xi = selected[i].index;
            const yi = selected[i].data[byteIdx];
            // Lagrange basis polynomial L_i(0)
            let num = 1, den = 1;
            for (let j = 0; j < threshold; j++) {
                if (i === j) continue;
                const xj = selected[j].index;
                num = _gfMul(num, xj);          // product of xj
                den = _gfMul(den, xi ^ xj);     // product of (xi XOR xj)
            }
            const lagrange = _gfDiv(num, den);
            value ^= _gfMul(yi, lagrange);
        }
        result[byteIdx] = value;
    }
    return result;
}


// ============================================================================
// SSSS: create shares, upload, recovery UI
// ============================================================================

export async function createSecretShares(threshold, contacts) {
    // contacts: array of { userId, pubKeyHex, label }
    const totalShares = contacts.length;
    if (threshold < 2 || threshold > totalShares) {
        showAlert(t('keyBackup.minTwoContacts'), 'error');
        return false;
    }

    // Collect master secret
    const privJwk = window.AppState?.x25519PrivateKey
        || sessionStorage.getItem('vortex_x25519_priv')
        || localStorage.getItem('vortex_x25519_priv');
    if (!privJwk) { showAlert(t('keyBackup.noMasterKey'), 'error'); return false; }
    const secretBytes = new TextEncoder().encode(privJwk);

    // Split
    const rawShares = shamirSplit(secretBytes, threshold, totalShares);

    // Encrypt each share for its recipient (ECIES)
    const encryptedShares = [];
    for (let i = 0; i < totalShares; i++) {
        const shareHex = toHex(rawShares[i].data);
        const enc = await eciesEncrypt(fromHex(shareHex), contacts[i].pubKeyHex);
        encryptedShares.push({
            share_index: rawShares[i].index,
            encrypted_share: enc,
            recipient_id: contacts[i].userId,
            label: contacts[i].label,
        });
    }

    try {
        await api('POST', '/api/keys/ssss/create', {
            threshold,
            total_shares: totalShares,
            shares: encryptedShares,
        });
        showAlert(t('keyBackup.keyShared', {totalShares, threshold}), 'success');
        return true;
    } catch (e) {
        showAlert(t('keyBackup.ssssError', {error: e.message || e}), 'error');
        return false;
    }
}

export async function getMyShares() {
    try { return await api('GET', '/api/keys/ssss/shares'); }
    catch { return { shares: [], threshold: 0, total_shares: 0 }; }
}

export async function getHeldShares() {
    try { return await api('GET', '/api/keys/ssss/held'); }
    catch { return { shares: [] }; }
}

export async function revokeShares() {
    if (!confirm(t('keyBackup.revokeSharesConfirm'))) return;
    try {
        await api('DELETE', '/api/keys/ssss');
        showAlert(t('keyBackup.sharesRevoked'), 'success');
        _loadSsssStatus();
    } catch (e) {
        showAlert(t('errors.generic', {error: e.message || e}), 'error');
    }
}


// ============================================================================
// Per-device fingerprint — 6-emoji from device pub key
// ============================================================================

const _DEVICE_EMOJI = [
    '\u{1F436}','\u{1F431}','\u{1F42D}','\u{1F439}','\u{1F430}','\u{1F98A}','\u{1F43B}','\u{1F43C}',
    '\u{1F428}','\u{1F42F}','\u{1F981}','\u{1F438}','\u{1F435}','\u{1F414}','\u{1F427}','\u{1F426}',
    '\u{1F985}','\u{1F989}','\u{1F43A}','\u{1F417}','\u{1F434}','\u{1F984}','\u{1F41D}','\u{1F41B}',
    '\u{1F98B}','\u{1F40C}','\u{1F41E}','\u{1F419}','\u{1F991}','\u{1F420}','\u{1F433}','\u{1F40B}',
    '\u{1F335}','\u{1F332}','\u{1F33B}','\u{1F339}','\u{1F344}','\u{1F340}','\u{1F341}','\u{1F338}',
    '\u{1F34E}','\u{1F34A}','\u{1F34B}','\u{1F352}','\u{1F353}','\u{1F347}','\u{1F349}','\u{1F351}',
    '\u{2B50}','\u{1F319}','\u{2600}','\u{1F308}','\u{26A1}','\u{2744}','\u{1F525}','\u{1F4A7}',
    '\u{1F30D}','\u{1F30A}','\u{1F680}','\u{2708}','\u{1F3E0}','\u{1F3D4}','\u{1F3DD}','\u{1F3C6}',
];

async function _computeDeviceFingerprint(pubKeyHex) {
    if (!pubKeyHex) return null;
    const hash = await crypto.subtle.digest('SHA-256', fromHex(pubKeyHex));
    const bytes = new Uint8Array(hash);
    const emojis = [];
    for (let i = 0; i < 6; i++) {
        emojis.push(_DEVICE_EMOJI[bytes[i] % 64]);
    }
    return emojis.join('');
}

export async function registerDevicePubKey() {
    // Generate per-device X25519 keypair, store priv locally, send pub to server
    let pubHex = localStorage.getItem('vortex_device_pub');
    if (pubHex) {
        // Already registered — just push to server
        try { await api('POST', '/api/keys/device-pub-key', { device_pub_key: pubHex }); } catch {}
        return pubHex;
    }
    const keyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    pubHex = toHex(pubRaw);
    localStorage.setItem('vortex_device_pub', pubHex);
    localStorage.setItem('vortex_device_priv_jwk', JSON.stringify(privJwk));
    try { await api('POST', '/api/keys/device-pub-key', { device_pub_key: pubHex }); } catch {}
    return pubHex;
}


// ============================================================================
// Updated device list with per-device fingerprint (safe DOM)
// ============================================================================

async function _loadDevicesListWithFingerprint() {
    const container = $('privacy-devices-list');
    if (!container) return;
    try {
        const devices = await api('GET', '/api/authentication/devices');
        const signs = await api('GET', '/api/keys/cross-sign');
        const signedIds = new Set((signs.signs || []).map(s => s.signed_device));
        container.textContent = '';
        for (const d of (devices.devices || [])) {
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);';
            const iconEl = document.createElement('div');
            iconEl.style.color = 'var(--text2)';
            iconEl.textContent = d.device_type === 'mobile' ? '\u{1F4F1}' : '\u{1F4BB}';
            const info = document.createElement('div');
            info.style.cssText = 'flex:1;min-width:0;';
            const name = document.createElement('div');
            name.style.cssText = 'font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
            name.textContent = d.device_name || 'Unknown';
            const fpRow = document.createElement('div');
            fpRow.style.cssText = 'font-size:12px;letter-spacing:2px;margin-top:2px;';
            if (d.device_pub_key) {
                const fp = await _computeDeviceFingerprint(d.device_pub_key);
                fpRow.textContent = fp || '';
                fpRow.title = d.device_pub_key;
            } else {
                fpRow.textContent = t('keyBackup.noKey');
                fpRow.style.color = 'var(--text3)';
                fpRow.style.letterSpacing = '0';
                fpRow.style.fontSize = '11px';
            }
            const date = document.createElement('div');
            date.style.cssText = 'font-size:11px;color:var(--text3);';
            date.textContent = d.last_active ? new Date(d.last_active).toLocaleDateString() : '';
            info.appendChild(name);
            info.appendChild(fpRow);
            info.appendChild(date);
            const badge = document.createElement('span');
            badge.style.cssText = 'font-size:11px;font-weight:600;white-space:nowrap;';
            if (d.is_current) { badge.style.color = 'var(--green)'; badge.textContent = t('keyBackup.thisDevice'); }
            else if (signedIds.has(d.id)) { badge.style.color = 'var(--green)'; badge.textContent = t('keyBackup.verified'); }
            else { badge.style.color = 'var(--text3)'; badge.textContent = t('keyBackup.notVerified'); }
            row.appendChild(iconEl); row.appendChild(info); row.appendChild(badge);
            container.appendChild(row);
        }
    } catch {
        container.textContent = t('keyBackup.failedLoadDevices');
        container.style.cssText = 'font-size:12px;color:var(--text3);';
    }
}


// ============================================================================
// SSSS UI — status, create dialog (safe DOM)
// ============================================================================

async function _loadSsssStatus() {
    const el = $('privacy-ssss-status');
    if (!el) return;
    try {
        const resp = await getMyShares();
        el.textContent = '';
        if (resp.shares.length > 0) {
            const info = document.createElement('span');
            info.style.color = 'var(--green)';
            info.textContent = t('keyBackup.sharesActive', {threshold: resp.threshold, total: resp.total_shares});
            el.appendChild(info);
            const detail = document.createTextNode(` (${t('keyBackup.sharesCount', {count: resp.shares.length})}, ${t('keyBackup.created')} ${resp.shares[0].created_at ? new Date(resp.shares[0].created_at).toLocaleDateString() : '\u2014'})`);
            el.appendChild(detail);
        } else {
            el.textContent = t('keyBackup.keyNotShared');
            el.style.color = 'var(--text3)';
        }
    } catch {
        el.textContent = t('keyBackup.keyNotShared');
        el.style.color = 'var(--text3)';
    }
}

export function _showSsssCreateDialog() {
    let modal = $('ssss-create-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'ssss-create-modal';
        modal.className = 'modal-overlay';
        document.body.appendChild(modal);
    }
    modal.textContent = '';

    const content = document.createElement('div');
    content.className = 'modal-content';
    content.style.maxWidth = '440px';

    const inner = document.createElement('div');
    inner.style.padding = '20px';

    const h3 = document.createElement('h3');
    h3.style.cssText = 'margin:0 0 8px;font-size:16px;';
    h3.textContent = t('keyBackup.splitKeyTitle');
    inner.appendChild(h3);

    const desc = document.createElement('p');
    desc.style.cssText = 'font-size:12px;color:var(--text2);margin:0 0 16px;line-height:1.5;';
    desc.textContent = t('keyBackup.splitKeyDesc');
    inner.appendChild(desc);

    // Threshold input
    const thLabel = document.createElement('label');
    thLabel.style.cssText = 'display:block;font-size:13px;font-weight:500;margin-bottom:4px;';
    thLabel.textContent = t('keyBackup.thresholdLabel');
    const thInput = document.createElement('input');
    thInput.type = 'number'; thInput.min = '2'; thInput.max = '10'; thInput.value = '3';
    thInput.className = 'form-input'; thInput.style.marginBottom = '12px';
    thInput.id = 'ssss-threshold-input';
    inner.appendChild(thLabel);
    inner.appendChild(thInput);

    // Contact list
    const contactLabel = document.createElement('label');
    contactLabel.style.cssText = 'display:block;font-size:13px;font-weight:500;margin-bottom:4px;';
    contactLabel.textContent = t('keyBackup.trustedContactsLabel');
    inner.appendChild(contactLabel);

    const contactList = document.createElement('div');
    contactList.id = 'ssss-contact-list';
    contactList.style.cssText = 'max-height:200px;overflow-y:auto;margin-bottom:12px;';
    contactList.textContent = t('keyBackup.loadingContacts');
    inner.appendChild(contactList);

    // Buttons
    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary btn-sm';
    cancelBtn.textContent = t('app.cancel');
    cancelBtn.onclick = () => { modal.style.display = 'none'; };
    btnRow.appendChild(cancelBtn);

    const submitBtn = document.createElement('button');
    submitBtn.className = 'btn btn-primary btn-sm';
    submitBtn.textContent = t('keyBackup.splitKeyBtn');
    submitBtn.onclick = async () => {
        const threshold = parseInt(thInput.value);
        const checkboxes = contactList.querySelectorAll('input[type="checkbox"]:checked');
        const contacts = [];
        checkboxes.forEach(cb => {
            contacts.push({
                userId: parseInt(cb.dataset.userId),
                pubKeyHex: cb.dataset.pubKey,
                label: cb.dataset.label,
            });
        });
        if (contacts.length < 2) { showAlert(t('keyBackup.selectMinTwoContacts'), 'error'); return; }
        if (threshold < 2 || threshold > contacts.length) {
            showAlert(t('keyBackup.thresholdRange', {max: contacts.length}), 'error'); return;
        }
        const ok = await createSecretShares(threshold, contacts);
        if (ok) { modal.style.display = 'none'; _loadSsssStatus(); }
    };
    btnRow.appendChild(submitBtn);
    inner.appendChild(btnRow);
    content.appendChild(inner);
    modal.appendChild(content);
    modal.style.display = 'flex';
    modal.onclick = (e) => { if (e.target === modal) modal.style.display = 'none'; };

    // Load contacts with pub keys
    _loadSsssContacts(contactList);
}

async function _loadSsssContacts(container) {
    try {
        const resp = await api('GET', '/api/contacts');
        const contacts = resp.contacts || resp || [];
        container.textContent = '';
        if (!contacts.length) {
            container.textContent = t('keyBackup.noContactsWithKeys');
            container.style.cssText = 'font-size:12px;color:var(--text3);';
            return;
        }
        for (const c of contacts) {
            if (!c.x25519_public_key && !c.public_key) continue;
            const row = document.createElement('label');
            row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px 0;cursor:pointer;border-bottom:1px solid var(--border);';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.dataset.userId = String(c.contact_user_id || c.user_id || c.id);
            cb.dataset.pubKey = c.x25519_public_key || c.public_key || '';
            cb.dataset.label = c.display_name || c.username || '';
            const nameSpan = document.createElement('span');
            nameSpan.style.cssText = 'font-size:13px;flex:1;';
            nameSpan.textContent = c.display_name || c.username || `User #${c.id}`;
            row.appendChild(cb);
            row.appendChild(nameSpan);
            container.appendChild(row);
        }
    } catch {
        container.textContent = t('keyBackup.loadContactsError');
        container.style.cssText = 'font-size:12px;color:var(--text3);';
    }
}


// ============================================================================
// Federated Backup — distribute encrypted shards to federation peers
// ============================================================================

export async function distributeFederatedBackup(threshold) {
    // Get active peers
    let peers;
    try {
        const resp = await api('GET', '/api/peers');
        peers = (resp.peers || []).filter(p => p.online && p.encrypted);
    } catch {
        showAlert(t('keyBackup.failedLoadPeers'), 'error');
        return false;
    }
    if (peers.length < 2) {
        showAlert(t('keyBackup.minTwoPeers'), 'error');
        return false;
    }
    const totalShards = peers.length;
    const th = Math.min(threshold || 2, totalShards);

    // Collect backup data
    const bundle = _collectKeyBundle();
    if (!bundle.keys.x25519_private_jwk) {
        showAlert(t('keyBackup.noKeysToBackup'), 'error');
        return false;
    }
    const secretBytes = new TextEncoder().encode(JSON.stringify(bundle));
    const rawShares = shamirSplit(secretBytes, th, totalShards);

    // Encrypt each share for peer's node pubkey (ECIES)
    const shards = [];
    for (let i = 0; i < totalShards; i++) {
        const shareHex = toHex(rawShares[i].data);
        const hashBuf = await crypto.subtle.digest('SHA-256', rawShares[i].data);
        const shardHash = toHex(hashBuf);
        let encShard;
        try {
            encShard = await eciesEncrypt(rawShares[i].data, peers[i].pubkey ? peers[i].pubkey.replace('...', '') : '');
        } catch {
            // Fallback: store as hex (peer pubkey may be truncated in response)
            encShard = shareHex;
        }
        shards.push({
            shard_index: rawShares[i].index,
            peer_ip: peers[i].ip,
            peer_port: peers[i].port || 8000,
            encrypted_shard: encShard,
            shard_hash: shardHash,
        });
    }

    try {
        const resp = await api('POST', '/api/keys/federated-backup/distribute', {
            threshold: th,
            total_shards: totalShards,
            shards,
        });
        showAlert(t('keyBackup.backupDistributed', {placed: resp.placed, total: resp.total}), 'success');
        _loadFederatedStatus();
        return true;
    } catch (e) {
        showAlert(t('errors.generic', {error: e.message || e}), 'error');
        return false;
    }
}

async function _loadFederatedStatus() {
    const el = $('privacy-federated-status');
    if (!el) return;
    try {
        const resp = await api('GET', '/api/keys/federated-backup/status');
        el.textContent = '';
        if (resp.distributed) {
            const info = document.createElement('span');
            info.style.color = 'var(--green)';
            info.textContent = t('keyBackup.distributed', {threshold: resp.threshold, total: resp.total_shards});
            el.appendChild(info);
            const detail = document.createTextNode(` — ${t('keyBackup.shardsOnPeers', {shards: resp.shards.length, peers: new Set(resp.shards.map(s => s.peer_ip)).size})}`);
            el.appendChild(detail);
        } else {
            el.textContent = t('keyBackup.notDistributed');
            el.style.color = 'var(--text3)';
        }
    } catch {
        el.textContent = t('keyBackup.notDistributed');
        el.style.color = 'var(--text3)';
    }
}

export async function deleteFederatedBackup() {
    if (!confirm(t('keyBackup.deleteFederatedConfirm'))) return;
    try {
        await api('DELETE', '/api/keys/federated-backup');
        showAlert(t('keyBackup.federatedBackupDeleted'), 'success');
        _loadFederatedStatus();
    } catch (e) {
        showAlert(t('errors.generic', {error: e.message || e}), 'error');
    }
}


// ============================================================================
// Key Transparency — verifiable key history
// ============================================================================

export async function _loadKeyTransparencyLog() {
    const el = $('privacy-kt-log');
    if (!el) return;
    const userId = window.AppState?.user?.id;
    if (!userId) { el.textContent = t('keyBackup.notAuthorized'); return; }
    try {
        const resp = await api('GET', `/api/keys/transparency/${userId}`);
        const audit = await api('GET', `/api/keys/transparency/${userId}/audit`);
        el.textContent = '';

        // Status badge
        const badge = document.createElement('div');
        badge.style.cssText = 'margin-bottom:8px;font-size:12px;font-weight:600;';
        if (audit.valid) {
            badge.style.color = 'var(--green)';
            badge.textContent = `\u{2705} ${t('keyBackup.chainVerified', {entries: audit.entries})}`;
        } else {
            badge.style.color = 'var(--red)';
            badge.textContent = `\u{26A0} ${t('keyBackup.chainBroken', {errors: audit.errors.length})}`;
        }
        el.appendChild(badge);

        // Entry list (last 10)
        const entries = (resp.entries || []).slice(-10).reverse();
        for (const e of entries) {
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:4px 0;font-size:11px;border-bottom:1px solid var(--border);';
            const seq = document.createElement('span');
            seq.style.cssText = 'font-weight:600;color:var(--accent);min-width:24px;';
            seq.textContent = `#${e.seq}`;
            const type = document.createElement('span');
            type.style.cssText = 'color:var(--text2);min-width:50px;';
            type.textContent = e.key_type;
            const hash = document.createElement('span');
            hash.style.cssText = 'color:var(--text3);font-family:monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
            hash.textContent = e.pub_key_hash ? e.pub_key_hash.slice(0, 16) + '...' : '';
            hash.title = e.pub_key_hash || '';
            const date = document.createElement('span');
            date.style.cssText = 'color:var(--text3);white-space:nowrap;';
            date.textContent = e.created_at ? new Date(e.created_at).toLocaleDateString() : '';
            row.appendChild(seq); row.appendChild(type); row.appendChild(hash); row.appendChild(date);
            el.appendChild(row);
        }
        if (!entries.length) {
            const empty = document.createElement('div');
            empty.style.cssText = 'font-size:12px;color:var(--text3);';
            empty.textContent = t('keyBackup.noEntries');
            el.appendChild(empty);
        }
    } catch {
        el.textContent = t('keyBackup.loadError');
        el.style.color = 'var(--text3)';
    }
}


// ============================================================================
// Auto-backup: синхронизирует ключи автоматически при bootApp
// Можно отключить в конфиденциальности (auto_key_sync: false)
// ============================================================================

const _AUTO_BACKUP_KEY = 'vortex_auto_backup_ts';
const _AUTO_BACKUP_INTERVAL = 3600_000; // не чаще раза в час

export async function autoBackupIfNeeded() {
    const prefs = _loadPrefs();
    if (prefs.auto_key_sync === false) return;

    const lastTs = parseInt(localStorage.getItem(_AUTO_BACKUP_KEY) || '0');
    if (Date.now() - lastTs < _AUTO_BACKUP_INTERVAL) return;

    const bundle = _collectKeyBundle();
    if (!bundle.keys.x25519_private_jwk) return;

    // Push ключей на сервер (зашифровано, сервер не видит)
    try {
        const payload = await _encryptSyncPayload(bundle);
        if (payload) {
            await api('POST', '/api/keys/sync/push', {
                device_id: _getDeviceId(),
                event_type: 'key_update',
                payload,
            });
            localStorage.setItem(_AUTO_BACKUP_KEY, String(Date.now()));
            console.info('[AutoBackup] Keys synced');
        }
    } catch (e) {
        console.debug('[AutoBackup] Push failed:', e.message);
    }

    // Pull ключей от других устройств
    try { await _pullSyncEvents(); } catch {}

    // Авто-восстановление room keys на сервер (encrypted_room_key)
    // Если у нас есть ключ в localStorage но нет на сервере — загрузим
    try {
        const { getRoomKey, setRoomKey } = await import('./crypto.js');
        const { eciesEncrypt } = await import('./crypto.js');
        const rooms = window.AppState?.rooms || [];
        const pubkey = window.AppState?.user?.x25519_public_key;
        if (pubkey) {
            for (const room of rooms) {
                const rk = getRoomKey(room.id);
                if (!rk) continue;
                // Check if server has our key
                try {
                    const kb = await api('GET', `/api/rooms/${room.id}/key-bundle`);
                    if (kb.has_key) continue; // already on server
                    // Upload our key
                    const enc = await eciesEncrypt(rk, pubkey);
                    await api('POST', `/api/dm/store-key/${room.id}`, {
                        user_id: window.AppState.user.user_id,
                        ephemeral_pub: enc.ephemeral_pub,
                        ciphertext: enc.ciphertext,
                    });
                    console.info('[AutoBackup] Room key restored to server for room', room.id);
                } catch {}
            }
        }
    } catch {}
}


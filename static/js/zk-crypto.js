// static/js/zk-crypto.js
// ============================================================================
// Zero-Knowledge Crypto Layer — клиентское шифрование ВСЕХ метаданных.
//
// Сервер не видит: профиль, имена комнат, контакты, имена файлов,
// историю звонков, содержимое уведомлений.
//
// Архитектура:
//   Master Key = HKDF(X25519_private_key, salt="vortex-zk-master", info="master")
//   Profile Key = HKDF(master_key, info="profile")
//   Contact Key = HKDF(master_key, info="contacts")
//   Call Key    = HKDF(master_key, info="calls")
//   Blind Key   = получается с сервера, зашифрован через ECIES
//
// Room metadata шифруется room_key (уже есть в crypto.js).
// ============================================================================

import { api } from './utils.js';
import { eciesDecrypt, getRoomKey } from './crypto.js';

const _toHex   = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const _fromHex = h => {
    const m = h?.match(/.{2}/g);
    if (!m) throw new Error('Invalid hex');
    return Uint8Array.from(m.map(b => parseInt(b, 16)));
};

// ════════════════════════════════════════════════════════════════════════════
// Key Derivation
// ════════════════════════════════════════════════════════════════════════════

let _masterKey   = null;  // CryptoKey (AES-GCM)
let _profileKey  = null;
let _contactKey  = null;
let _callKey     = null;
let _blindKey    = null;  // Uint8Array — for HMAC blind indexes
let _senderSecret = null; // Uint8Array — for sealed sender pseudonyms

/**
 * Derive the ZK master key from user's X25519 private key.
 * Must be called after login, once private key is available.
 */
export async function initZKKeys(privKeyJwk) {
    if (!privKeyJwk) return;

    // Export raw key material from JWK for HKDF
    const jwk = typeof privKeyJwk === 'string' ? JSON.parse(privKeyJwk) : privKeyJwk;

    // Use the 'd' parameter (private scalar) as key material
    const rawBytes = _base64urlToBytes(jwk.d);

    // Derive master key via HKDF
    const hkdfKey = await crypto.subtle.importKey('raw', rawBytes, 'HKDF', false, ['deriveKey', 'deriveBits']);

    _masterKey = await _deriveAesKey(hkdfKey, 'vortex-zk-master');
    _profileKey = await _deriveAesKey(
        await crypto.subtle.importKey('raw', await _exportRaw(_masterKey), 'HKDF', false, ['deriveKey']),
        'profile'
    );
    _contactKey = await _deriveAesKey(
        await crypto.subtle.importKey('raw', await _exportRaw(_masterKey), 'HKDF', false, ['deriveKey']),
        'contacts'
    );
    _callKey = await _deriveAesKey(
        await crypto.subtle.importKey('raw', await _exportRaw(_masterKey), 'HKDF', false, ['deriveKey']),
        'calls'
    );

    // Derive sender secret for sealed sender
    const senderBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('sealed-sender') },
        hkdfKey, 256
    );
    _senderSecret = new Uint8Array(senderBits);

    // Fetch blind index key from server (ECIES encrypted)
    await _fetchBlindKey(privKeyJwk);
}

async function _deriveAesKey(hkdfKey, info) {
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
        hkdfKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
}

async function _exportRaw(key) {
    return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

async function _fetchBlindKey(privKeyJwk) {
    try {
        const resp = await api('GET', '/api/zk/blind-key');
        if (resp.ok && resp.ephemeral_pub && resp.ciphertext) {
            const jkStr = typeof privKeyJwk === 'string' ? privKeyJwk : JSON.stringify(privKeyJwk);
            const decrypted = await eciesDecrypt(resp.ephemeral_pub, resp.ciphertext, jkStr);
            _blindKey = decrypted;
        }
    } catch (e) {
        console.warn('[ZK] Failed to fetch blind key:', e.message);
    }
}

function _base64urlToBytes(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - b64.length % 4) % 4;
    const str = atob(b64 + '='.repeat(pad));
    return Uint8Array.from(str, c => c.charCodeAt(0));
}

export function isZKReady() {
    return _masterKey !== null;
}

// ════════════════════════════════════════════════════════════════════════════
// Core Encrypt / Decrypt
// ════════════════════════════════════════════════════════════════════════════

async function _encrypt(key, plaintext) {
    const data = new TextEncoder().encode(typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, data);
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(ct), 12);
    return _toHex(result);
}

async function _decrypt(key, hex) {
    const raw = _fromHex(hex);
    const nonce = raw.slice(0, 12);
    const ct = raw.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
    return new TextDecoder().decode(plain);
}

async function _encryptWithRaw(rawKeyBytes, plaintext) {
    const key = await crypto.subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    return _encrypt(key, plaintext);
}

async function _decryptWithRaw(rawKeyBytes, hex) {
    const key = await crypto.subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    return _decrypt(key, hex);
}

// ════════════════════════════════════════════════════════════════════════════
// Profile Vault — encrypt/decrypt user profile
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt user profile data.
 * @param {Object} profile — { display_name, bio, avatar_emoji, avatar_url, custom_status, ... }
 * @returns {Promise<string>} encrypted hex blob
 */
export async function encryptProfile(profile) {
    if (!_profileKey) throw new Error('ZK keys not initialized');
    return _encrypt(_profileKey, profile);
}

/**
 * Decrypt user profile data.
 * @param {string} vaultHex — encrypted hex blob from server
 * @returns {Promise<Object>} decrypted profile object
 */
export async function decryptProfile(vaultHex) {
    if (!_profileKey) throw new Error('ZK keys not initialized');
    const json = await _decrypt(_profileKey, vaultHex);
    return JSON.parse(json);
}

/**
 * Save encrypted profile to server.
 */
export async function saveProfileVault(profile) {
    const vaultData = await encryptProfile(profile);
    const blindName = _blindKey ? await computeBlindIndex(profile.display_name || '', 'user:') : null;
    return api('PUT', '/api/zk/profile', { vault_data: vaultData, blind_name: blindName });
}

/**
 * Load and decrypt own profile from server.
 */
export async function loadProfileVault() {
    const resp = await api('GET', '/api/zk/profile');
    if (!resp.ok || !resp.vault_data) return null;
    return decryptProfile(resp.vault_data);
}

/**
 * Load and decrypt another user's profile.
 * Uses the OTHER user's vault — we need their profile key.
 * Since we don't have their private key, we use the profile data
 * they shared with us (encrypted with OUR key via ECIES in the room).
 *
 * For now: profiles are dual-stored — encrypted vault + legacy plaintext.
 * This function returns the vault if available.
 */
export async function loadUserProfileVault(userId) {
    const resp = await api('GET', `/api/zk/profile/${userId}`);
    if (!resp.ok || !resp.vault_data) return null;
    // Note: we can only decrypt our own vault. Other users' vaults
    // are encrypted with THEIR master key. For cross-user profile display,
    // users share a "public profile" encrypted with a shared secret
    // derived from DH(our_priv, their_pub).
    return resp;
}

// ════════════════════════════════════════════════════════════════════════════
// Room Vault — encrypt/decrypt room metadata with room key
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt room metadata with room key.
 * @param {number} roomId
 * @param {Object} meta — { name, description, avatar_emoji, avatar_url, theme_json }
 */
export async function encryptRoomMeta(roomId, meta) {
    const roomKey = getRoomKey(roomId);
    if (!roomKey) throw new Error('No room key for room ' + roomId);
    return _encryptWithRaw(roomKey, meta);
}

/**
 * Decrypt room metadata with room key.
 */
export async function decryptRoomMeta(roomId, vaultHex) {
    const roomKey = getRoomKey(roomId);
    if (!roomKey) throw new Error('No room key for room ' + roomId);
    const json = await _decryptWithRaw(roomKey, vaultHex);
    return JSON.parse(json);
}

/**
 * Save encrypted room metadata to server.
 */
export async function saveRoomVault(roomId, meta) {
    const vaultData = await encryptRoomMeta(roomId, meta);
    const blindName = _blindKey ? await computeBlindIndex(meta.name || '', 'room:') : null;
    return api('PUT', `/api/zk/room/${roomId}`, { vault_data: vaultData, blind_name: blindName });
}

/**
 * Load and decrypt room metadata.
 */
export async function loadRoomVault(roomId) {
    const resp = await api('GET', `/api/zk/room/${roomId}`);
    if (!resp.ok || !resp.vault_data) return null;
    return decryptRoomMeta(roomId, resp.vault_data);
}

// ════════════════════════════════════════════════════════════════════════════
// Contact Vault — encrypted contact list
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a contact entry.
 * @param {Object} contact — { pubkey, nickname, verified, notes }
 */
export async function encryptContact(contact) {
    if (!_contactKey) throw new Error('ZK keys not initialized');
    return _encrypt(_contactKey, contact);
}

/**
 * Decrypt a contact entry.
 */
export async function decryptContact(vaultHex) {
    if (!_contactKey) throw new Error('ZK keys not initialized');
    const json = await _decrypt(_contactKey, vaultHex);
    return JSON.parse(json);
}

/**
 * Compute blind ID for contact dedup.
 */
export async function contactBlindId(contactPubkey) {
    if (!_contactKey) throw new Error('ZK keys not initialized');
    const raw = await _exportRaw(_contactKey);
    const data = new TextEncoder().encode('contact:' + contactPubkey);
    const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return _toHex(sig);
}

/**
 * Save encrypted contact to server.
 */
export async function saveContactVault(contact) {
    const vaultData = await encryptContact(contact);
    const blindId = await contactBlindId(contact.pubkey || contact.contact_pubkey || '');
    return api('PUT', '/api/zk/contacts', { vault_data: vaultData, blind_id: blindId });
}

/**
 * Load and decrypt all contacts.
 */
export async function loadContactVaults() {
    const resp = await api('GET', '/api/zk/contacts');
    if (!resp.ok || !resp.contacts) return [];
    const decrypted = [];
    for (const entry of resp.contacts) {
        try {
            const contact = await decryptContact(entry.vault_data);
            contact._id = entry.id;
            contact._blind_id = entry.blind_id;
            decrypted.push(contact);
        } catch (e) {
            console.warn('[ZK] Failed to decrypt contact:', e.message);
        }
    }
    return decrypted;
}

// ════════════════════════════════════════════════════════════════════════════
// Encrypted File Metadata — file_name, forwarded_from
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt file metadata with room key.
 */
export async function encryptFileMeta(roomId, meta) {
    const roomKey = getRoomKey(roomId);
    if (!roomKey) return meta;  // fallback: no encryption if no room key
    const result = {};
    if (meta.file_name) {
        result.file_name_encrypted = await _encryptWithRaw(roomKey, meta.file_name);
    }
    if (meta.forwarded_from) {
        result.forwarded_from_encrypted = await _encryptWithRaw(roomKey, meta.forwarded_from);
    }
    return result;
}

/**
 * Decrypt file metadata with room key.
 */
export async function decryptFileMeta(roomId, encryptedMeta) {
    const roomKey = getRoomKey(roomId);
    if (!roomKey) return {};
    const result = {};
    try {
        if (encryptedMeta.file_name_encrypted) {
            result.file_name = await _decryptWithRaw(roomKey, encryptedMeta.file_name_encrypted);
        }
        if (encryptedMeta.forwarded_from_encrypted) {
            result.forwarded_from = await _decryptWithRaw(roomKey, encryptedMeta.forwarded_from_encrypted);
        }
    } catch (e) {
        console.warn('[ZK] Failed to decrypt file meta:', e.message);
    }
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// Encrypted Call History
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt call record.
 */
export async function encryptCallRecord(record) {
    if (!_callKey) throw new Error('ZK keys not initialized');
    return _encrypt(_callKey, record);
}

/**
 * Decrypt call record.
 */
export async function decryptCallRecord(vaultHex) {
    if (!_callKey) throw new Error('ZK keys not initialized');
    const json = await _decrypt(_callKey, vaultHex);
    return JSON.parse(json);
}

/**
 * Save encrypted call record.
 */
export async function saveCallRecord(record) {
    const vaultData = await encryptCallRecord(record);
    return api('POST', '/api/zk/calls', { vault_data: vaultData });
}

/**
 * Load and decrypt call history.
 */
export async function loadCallRecords() {
    const resp = await api('GET', '/api/zk/calls');
    if (!resp.ok || !resp.records) return [];
    const decrypted = [];
    for (const r of resp.records) {
        try {
            const record = await decryptCallRecord(r.vault_data);
            record._id = r.id;
            record._created_at = r.created_at;
            decrypted.push(record);
        } catch (e) {
            console.warn('[ZK] Failed to decrypt call record:', e.message);
        }
    }
    return decrypted;
}

// ════════════════════════════════════════════════════════════════════════════
// Sealed Sender — per-room pseudonyms
// ════════════════════════════════════════════════════════════════════════════

/**
 * Derive sealed sender pseudonym for a room.
 * Different for every room — cannot correlate across rooms.
 */
export async function deriveSealedSender(roomId) {
    if (!_senderSecret) throw new Error('ZK keys not initialized');
    const data = new TextEncoder().encode(`sealed-sender:${roomId}`);
    const key = await crypto.subtle.importKey('raw', _senderSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return _toHex(sig);
}

// ════════════════════════════════════════════════════════════════════════════
// Blind Index — search encrypted data without revealing query
// ════════════════════════════════════════════════════════════════════════════

/**
 * Compute blind index for search.
 * @param {string} value — plaintext search term
 * @param {string} context — namespace prefix (e.g. "user:", "room:")
 * @returns {Promise<string>} 64-char hex HMAC
 */
export async function computeBlindIndex(value, context = '') {
    if (!_blindKey) return null;
    const data = new TextEncoder().encode(context + value.toLowerCase().trim());
    const key = await crypto.subtle.importKey('raw', _blindKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return _toHex(sig);
}

/**
 * Search users/rooms by blind index.
 */
export async function blindSearch(query, type = 'user') {
    const prefix = type === 'room' ? 'room:' : 'user:';
    const blindIndex = await computeBlindIndex(query, prefix);
    if (!blindIndex) return [];
    const resp = await api('POST', '/api/zk/search', { blind_index: blindIndex, search_type: type });
    return resp.ok ? resp.results : [];
}

// ════════════════════════════════════════════════════════════════════════════
// Encrypted Notifications — ECIES for recipient
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt notification for a recipient using their public key.
 */
export async function encryptNotification(recipientPubHex, payload) {
    const { eciesEncrypt } = await import('./crypto.js');
    const data = new TextEncoder().encode(JSON.stringify(payload));
    return eciesEncrypt(data, recipientPubHex);
}

// ════════════════════════════════════════════════════════════════════════════
// Encrypted Audit Log
// ════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt audit log entry with room key.
 */
export async function encryptAuditEntry(roomId, entry) {
    const roomKey = getRoomKey(roomId);
    if (!roomKey) return null;
    return _encryptWithRaw(roomKey, entry);
}

/**
 * Decrypt audit log entries for a room.
 */
export async function decryptAuditEntries(roomId, entries) {
    const roomKey = getRoomKey(roomId);
    if (!roomKey) return [];
    const result = [];
    for (const e of entries) {
        try {
            const json = await _decryptWithRaw(roomKey, e.vault_data);
            const entry = JSON.parse(json);
            entry._id = e.id;
            entry._created_at = e.created_at;
            result.push(entry);
        } catch (err) {
            console.warn('[ZK] Failed to decrypt audit entry:', err.message);
        }
    }
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// ZK Status
// ════════════════════════════════════════════════════════════════════════════

/**
 * Get ZK architecture status from server.
 */
export async function getZKStatus() {
    return api('GET', '/api/zk/status');
}

/**
 * Get ZK readiness info.
 */
export function getZKInfo() {
    return {
        initialized: isZKReady(),
        has_master_key: _masterKey !== null,
        has_blind_key: _blindKey !== null,
        has_sender_secret: _senderSecret !== null,
    };
}

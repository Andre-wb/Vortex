// static/js/chat/room-crypto.js — AES-256-GCM helpers + in-memory room key cache

export const toHex   = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
export const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

// Room keys: primary store in JS heap, backed by sessionStorage for page reload survival.
const _roomKeyCache = new Map();

export async function encryptText(text, roomKeyBytes) {
    const key = await crypto.subtle.importKey(
        'raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct    = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        new TextEncoder().encode(text)
    );
    return toHex(nonce) + toHex(ct);
}

export async function decryptText(ciphertextHex, roomKeyBytes) {
    const raw   = fromHex(ciphertextHex);
    const nonce = raw.slice(0, 12);
    const ct    = raw.slice(12);
    const key   = await crypto.subtle.importKey(
        'raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
    return new TextDecoder().decode(plain);
}

export function _saveRoomKeyToSession(roomId, keyBytes) {
    _roomKeyCache.set(String(roomId), keyBytes);
    // Backup to sessionStorage so key survives page reload
    try {
        sessionStorage.setItem(`vortex_rk_${roomId}`, toHex(keyBytes));
    } catch {}
}

export function _loadRoomKeyFromSession(roomId) {
    const cached = _roomKeyCache.get(String(roomId));
    if (cached) return cached;
    // Fallback: restore from sessionStorage after page reload
    try {
        const hex = sessionStorage.getItem(`vortex_rk_${roomId}`);
        if (hex) {
            const bytes = fromHex(hex);
            _roomKeyCache.set(String(roomId), bytes);
            return bytes;
        }
    } catch {}
    return null;
}

export function _clearRoomKeyFromSession(roomId) {
    _roomKeyCache.delete(String(roomId));
    try { sessionStorage.removeItem(`vortex_rk_${roomId}`); } catch {}
}

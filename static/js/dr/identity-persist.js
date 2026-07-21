// static/js/dr/identity-persist.js
// Пароль-шифрованная персистентность аккаунтного Ed25519-identity через logout.
//
// Ed25519 — долговременная подписывающая идентичность аккаунта. Она не должна
// теряться или подменяться на logout→login. Механизм: хранится зашифрованная
// паролем `_enc`-копия, переживающая logout (плейнтекст-слот при этом чистится —
// at-rest без пароля нечитаемо). На логине `_enc` расшифровывается паролем и
// восстанавливает плейнтекст-слот, чтобы дальнейший код нашёл ту же идентичность.
//
// ВНИМАНИЕ: `_enc`-блоб переживает logout, поэтому на общем/публичном терминале
// он доступен для оффлайн-подбора пароля — PBKDF2 600k снижает, но не устраняет
// риск для слабых паролей.
//
// Формат: PBKDF2-SHA256 600k + AES-256-GCM, salt(16)+iv(12)+ct, base64.

const _te = new TextEncoder();
const _td = new TextDecoder();

function _slot(userId) { return `vortex_ed25519_identity_${userId}`; }
function _encSlot(userId) { return `vortex_ed25519_identity_${userId}_enc`; }

async function _encrypt(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const km = await crypto.subtle.importKey('raw', _te.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, _te.encode(data));
    const out = new Uint8Array(16 + 12 + ct.byteLength);
    out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(ct), 28);
    return btoa(String.fromCharCode(...out));
}

async function _decrypt(b64, password) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const salt = raw.slice(0, 16), iv = raw.slice(16, 28), ct = raw.slice(28);
    const km = await crypto.subtle.importKey('raw', _te.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return _td.decode(plain);
}

/**
 * Создаёт `_enc`-копию аккаунтного Ed25519 из плейнтекст-слота (если тот есть
 * и дан пароль). Вызывать при регистрации и на логине. No-op без пароля/плейнтекста.
 */
export async function saveEd25519Enc(userId, password) {
    if (!userId || !password) return;
    const plain = localStorage.getItem(_slot(userId)) || sessionStorage.getItem(_slot(userId));
    if (!plain) return;
    try {
        localStorage.setItem(_encSlot(userId), await _encrypt(plain, password));
    } catch (e) {
        console.warn('[identity-persist] Ed25519 _enc save failed:', e?.message);
    }
}

/**
 * Восстанавливает плейнтекст-слот аккаунтного Ed25519 из `_enc` по паролю
 * (если плейнтекста нет, а `_enc` есть). Вызывать на логине. @returns {Promise<boolean>}
 */
export async function restoreEd25519Enc(userId, password) {
    if (!userId) return false;
    if (localStorage.getItem(_slot(userId)) || sessionStorage.getItem(_slot(userId))) return true;
    const enc = localStorage.getItem(_encSlot(userId));
    if (!enc || !password) return false;
    try {
        const jwk = await _decrypt(enc, password);
        JSON.parse(jwk);
        localStorage.setItem(_slot(userId), jwk);
        sessionStorage.setItem(_slot(userId), jwk);
        return true;
    } catch (e) {
        console.warn('[identity-persist] Ed25519 _enc restore failed:', e?.message);
        return false;
    }
}

// Аккаунтный ML-KEM-768 (Kyber) приватный — та же `_enc`-дисциплина (ADR-004 K2).
// Приватный — hex-строка (не JWK), поэтому валидация — hex, не JSON.parse.
function _kyberSlot(userId) { return `vortex_kyber_priv_${userId}`; }
function _kyberEncSlot(userId) { return `vortex_kyber_priv_${userId}_enc`; }

/** Создаёт `_enc`-копию Kyber-приватного из плейнтекст-слота. No-op без пароля/плейнтекста. */
export async function saveKyberEnc(userId, password) {
    if (!userId || !password) return;
    const plain = localStorage.getItem(_kyberSlot(userId)) || sessionStorage.getItem(_kyberSlot(userId));
    if (!plain) return;
    try {
        localStorage.setItem(_kyberEncSlot(userId), await _encrypt(plain, password));
    } catch (e) {
        console.warn('[identity-persist] Kyber _enc save failed:', e?.message);
    }
}

/** Восстанавливает Kyber-приватный из `_enc` по паролю. @returns {Promise<boolean>} */
export async function restoreKyberEnc(userId, password) {
    if (!userId) return false;
    if (localStorage.getItem(_kyberSlot(userId)) || sessionStorage.getItem(_kyberSlot(userId))) return true;
    const enc = localStorage.getItem(_kyberEncSlot(userId));
    if (!enc || !password) return false;
    try {
        const hex = await _decrypt(enc, password);
        if (!/^[0-9a-f]+$/i.test(hex)) throw new Error('not hex');
        localStorage.setItem(_kyberSlot(userId), hex);
        sessionStorage.setItem(_kyberSlot(userId), hex);
        return true;
    } catch (e) {
        console.warn('[identity-persist] Kyber _enc restore failed:', e?.message);
        return false;
    }
}

// static/js/dr/prekey-store.js
// Клиентское хранилище ПРИВАТНЫХ prekey-ключей.
//
// Чтобы Bob мог ответить на X3DH (входящее v2-prekey сообщение), ему нужны
// приватные Signed Pre-Key и One-Time Pre-Key, чьи ПУБЛИЧНЫЕ ключи он ранее
// опубликовал (dr/prekeys.js). Батч 4 публиковал только публичные — здесь
// добавляется персист приватных, привязанный к id и к аккаунту.
//
// Хранение: один JSON-объект в localStorage на аккаунт
//   vortex_dr_prekeys_<userId> = { spk: {id, jwk}, opks: { <opkId>: jwk } }
// Приватный Identity Key (X25519) отдельно не дублируем — это vortex_x25519_priv.
//
// Forward secrecy: использованный OPK-приватный УДАЛЯЕТСЯ (deleteOpk) сразу
// после успешного X3DH-respond.

const PREFIX = 'vortex_dr_prekeys';

function _key(userId) { return `${PREFIX}_${userId}`; }

function _load(userId) {
    try {
        const raw = localStorage.getItem(_key(userId));
        return raw ? JSON.parse(raw) : { spk: null, opks: {} };
    } catch {
        return { spk: null, opks: {} };
    }
}

function _save(userId, data) {
    localStorage.setItem(_key(userId), JSON.stringify(data));
}

function _currentUserId() {
    const uid = window.AppState?.user?.user_id;
    if (!uid) throw new Error('prekey-store requires a logged-in user');
    return uid;
}

/**
 * Сохраняет приватные ключи опубликованного бандла (перезаписывает SPK,
 * добавляет OPK). Вызывается из buildPrekeyBundle при (пере)публикации.
 * @param {{id:number, jwk:string}} spk
 * @param {Array<{id:number, jwk:string}>} opks
 */
export function storePrekeyPrivates(spk, opks) {
    const userId = _currentUserId();
    const data = _load(userId);
    data.spk = { id: spk.id, jwk: spk.jwk };
    for (const opk of opks) data.opks[opk.id] = opk.jwk;
    _save(userId, data);
}

/** @returns {boolean} есть ли локально приватный SPK (индикатор «умеет отвечать на v2»). */
export function hasPrekeyPrivates() {
    const userId = window.AppState?.user?.user_id;
    if (!userId) return false;
    return _load(userId).spk != null;
}

/**
 * Сохраняет приватный PQXDH Kyber pre-key (ML-KEM-768 secret, hex) — нужен, чтобы
 * decaps'ить входящий PQXDH-конверт (P4). Перезаписывает (одна активная пара).
 * @param {number} id — device_kyber_id
 * @param {string} skHex — ML-KEM-768 secret key (2400 байт = 4800 hex)
 */
export function storePqspkPrivate(id, skHex) {
    const userId = _currentUserId();
    const data = _load(userId);
    data.pqspk = { id, sk: skHex };
    _save(userId, data);
}

/** @returns {boolean} есть ли локально приватный PQSPK (умеет отвечать на PQXDH). */
export function hasPqspkPrivate() {
    const userId = window.AppState?.user?.user_id;
    if (!userId) return false;
    return _load(userId).pqspk != null;
}

/** @returns {{id:number, sk:string}|null} приватный PQSPK по id (или текущий, если id совпал). */
export function getPqspkPrivate(kyberId) {
    const data = _load(_currentUserId());
    if (!data.pqspk) return null;
    if (kyberId != null && data.pqspk.id !== kyberId) return null;   // запрошен другой (ротированный)
    return data.pqspk;
}

/**
 * Сохраняет приватные one-time Kyber pre-keys (PQXDH P6). Добавляет к пулу.
 * @param {Array<{id:number, sk:string}>} pqopks — ML-KEM-768 secret hex по id
 */
export function storePqopkPrivates(pqopks) {
    const userId = _currentUserId();
    const data = _load(userId);
    if (!data.pqopks) data.pqopks = {};
    for (const p of pqopks) data.pqopks[p.id] = p.sk;
    _save(userId, data);
}

/** @returns {string|null} приватный PQOPK (ML-KEM secret hex) по id, либо null. */
export function getPqopkPrivate(pqopkId) {
    if (pqopkId == null) return null;
    const data = _load(_currentUserId());
    return data.pqopks?.[pqopkId] || null;
}

/** Удаляет использованный PQOPK-приватный (KEM-forward-secrecy). Идемпотентно. */
export function deletePqopkPrivate(pqopkId) {
    if (pqopkId == null) return;
    const userId = _currentUserId();
    const data = _load(userId);
    if (data.pqopks && data.pqopks[pqopkId] !== undefined) {
        delete data.pqopks[pqopkId];
        _save(userId, data);
    }
}

/** @returns {{id:number, jwk:string}|null} приватный SPK по id (или текущий, если id совпал). */
export function getSpkPrivate(spkId) {
    const data = _load(_currentUserId());
    if (!data.spk) return null;
    if (spkId != null && data.spk.id !== spkId) return null;   // запрошен другой (ротированный) SPK
    return data.spk;
}

/** @returns {string|null} приватный OPK (JWK) по id, либо null если отсутствует/израсходован. */
export function getOpkPrivate(opkId) {
    if (opkId == null) return null;
    const data = _load(_currentUserId());
    return data.opks[opkId] || null;
}

/** Удаляет использованный OPK-приватный (forward secrecy). Идемпотентно. */
export function deleteOpkPrivate(opkId) {
    if (opkId == null) return;
    const userId = _currentUserId();
    const data = _load(userId);
    if (data.opks[opkId] !== undefined) {
        delete data.opks[opkId];
        _save(userId, data);
    }
}

/** Удаляет весь prekey-приватный стор аккаунта (logout/wipe). */
export function clearPrekeyPrivates(userId) {
    localStorage.removeItem(_key(userId));
}

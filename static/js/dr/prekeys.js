// static/js/dr/prekeys.js
// Ed25519-идентичность + публикация X3DH prekey-бандла (ADR-001, батч 4).
//
// Долговременная идентичность пользователя — ПАРА ключей:
//   • X25519 identity_key   — уже есть (генерируется при регистрации, auth.js),
//                             используется для DH в X3DH (батч 6);
//   • Ed25519 identity_key  — вводится здесь, подписывает Signed Pre-Key и
//                             (cross-signature) сам X25519 identity_key.
// XEdDSA не используется (ADR §2.4г), поэтому подписывающий ключ отдельный.
//
// ВНИМАНИЕ по угрозам (ADR §2.4г): серверная верификация подписей проверяет
// целостность бандла относительно ОПУБЛИКОВАННОГО Ed25519-ключа, но не даёт
// substitution-resistance — она появится только с внеполосной верификацией
// отпечатков по паре (identity_key, identity_key_ed).

import { api } from '../utils.js';
import { storePrekeyPrivates, hasPrekeyPrivates } from './prekey-store.js';

// Идентичность хранится ПЕР-АККАУНТ: слот `vortex_ed25519_identity_<userId>`.
// Общий слот использовать нельзя — на общем устройстве он мог бы принадлежать
// другому аккаунту (linkability + возможность выдать себя за другого). Это
// зеркалит per-user хранение X25519 (`vortex_x25519_priv_<id>`) в auth.js.
const ED_PRIV_PREFIX = 'vortex_ed25519_identity';     // + `_${userId}`
const DISABLE_FLAG = 'vortex_prekeys_disabled';       // rollback: не публиковать

function _edSlot(userId) { return `${ED_PRIV_PREFIX}_${userId}`; }

const OPK_BATCH = 20;             // сколько one-time prekeys публиковать за раз
const LOW_OPK_THRESHOLD = 10;     // ниже — пополняем пул

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

/** Восстанавливает hex публичного Ed25519 из JWK-строки (поле x — base64url pub). */
function _pubHexFromJwk(jwkString) {
    try {
        const jwk = JSON.parse(jwkString);
        if (!jwk.x) return null;
        const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(b64);
        return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    } catch { return null; }
}

// Ed25519 identity

/**
 * Загружает Ed25519-идентичность из хранилища или создаёт и сохраняет новую.
 * Приватный ключ хранится как JWK-строка (как X25519, auth.js), публичный — hex.
 * @returns {Promise<{privJwk: string, pubHex: string}>}
 */
export async function loadOrCreateEd25519Identity() {
    const userId = window.AppState?.user?.user_id;
    if (!userId) throw new Error('Ed25519 identity requires a logged-in user');
    const slot = _edSlot(userId);

    const existingPriv = localStorage.getItem(slot) || sessionStorage.getItem(slot);
    if (existingPriv) {
        // Публичный ключ всегда выводим из приватного JWK (поле x) — отдельно
        // не храним, что делает restore из vault (только priv) самодостаточным.
        const pubHex = _pubHexFromJwk(existingPriv);
        if (pubHex) {
            sessionStorage.setItem(slot, existingPriv);   // переживает reload вкладки
            return { privJwk: existingPriv, pubHex };
        }
    }

    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const pubRaw = await crypto.subtle.exportKey('raw', pair.publicKey);
    const privJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));

    // Незашифрованная копия (как X25519 в auth.js). Зашифрованную passphrase-копию
    // делает vault (key_backup.js) — сюда пароль не тянем, чтобы работал и путь
    // восстановления сессии без пароля.
    localStorage.setItem(slot, privJwk);
    sessionStorage.setItem(slot, privJwk);
    return { privJwk, pubHex: toHex(pubRaw) };
}

/**
 * Подписывает произвольные байты Ed25519-ключом идентичности (RFC 8032, не -ph).
 * @param {string} edPrivJwk — приватный Ed25519 как JWK-строка
 * @param {Uint8Array} messageBytes
 * @returns {Promise<string>} подпись в hex (64 байта = 128 hex)
 */
export async function edSign(edPrivJwk, messageBytes) {
    const key = await crypto.subtle.importKey(
        'jwk', JSON.parse(edPrivJwk), { name: 'Ed25519' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('Ed25519', key, messageBytes);
    return toHex(sig);
}

const _fromHexTop = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

/**
 * Проверяет Ed25519-подпись публичным ключом (hex). Возвращает false при любой
 * ошибке. Используется отправителем v2 для defense-in-depth проверки бандла
 * адресата (сервер верифицирует при publish, но в warn-only мог принять битый).
 * @param {string} pubHex — Ed25519 публичный (hex)
 * @param {Uint8Array} messageBytes
 * @param {string} sigHex — подпись (hex)
 * @returns {Promise<boolean>}
 */
export async function edVerify(pubHex, messageBytes, sigHex) {
    try {
        const key = await crypto.subtle.importKey('raw', _fromHexTop(pubHex), { name: 'Ed25519' }, false, ['verify']);
        return await crypto.subtle.verify('Ed25519', key, _fromHexTop(sigHex), messageBytes);
    } catch {
        return false;
    }
}

// Prekey bundle

const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

// SPK id фиксирован (одна активная пара на аккаунт); ротация SPK — вне скоупа 6a.
const SPK_ID = 1;

/** Генерирует X25519 пару. @returns {Promise<{pubHex, privJwk}>} */
async function _genX25519() {
    const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
    const privJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
    return { pubHex: toHex(raw), privJwk };
}

/** Монотонный per-account счётчик id для OPK (уникален между републикациями). */
function _nextOpkId(userId, count) {
    const k = `vortex_dr_opk_next_${userId}`;
    const start = parseInt(localStorage.getItem(k) || '1', 10);
    localStorage.setItem(k, String(start + count));
    return start;
}

/**
 * Собирает prekey-бандл: X25519 SPK + подпись Ed25519, cross-signature на
 * X25519 identity_key, и пачку one-time prekeys. Приватные ключи SPK/OPK
 * персистятся локально (prekey-store), чтобы отвечать на входящие X3DH (6a).
 * @param {string} identityKeyHex — X25519 публичный identity_key пользователя
 * @param {number} opkCount
 * @returns {Promise<object>} тело запроса для POST /api/keys/prekeys/publish
 */
export async function buildPrekeyBundle(identityKeyHex, opkCount = OPK_BATCH) {
    const { privJwk: edPriv, pubHex: edPub } = await loadOrCreateEd25519Identity();

    const spk = await _genX25519();
    const spkSig = await edSign(edPriv, fromHex(spk.pubHex));
    // Cross-signature: Ed25519 идентичность подписывает X25519 identity_key,
    // связывая два ключа (ADR §2.4г).
    const idSig = await edSign(edPriv, fromHex(identityKeyHex));

    const userId = window.AppState?.user?.user_id;
    const baseId = _nextOpkId(userId, opkCount);
    const oneTimePrekeys = [];
    const opkPrivates = [];
    for (let i = 0; i < opkCount; i++) {
        const opk = await _genX25519();
        const id = baseId + i;
        oneTimePrekeys.push({ key_id: id, public_key: opk.pubHex });
        opkPrivates.push({ id, jwk: opk.privJwk });
    }

    // Персистим приватные ДО возврата — публиковать публичные без сохранённых
    // приватных бессмысленно (не сможем ответить на X3DH).
    storePrekeyPrivates({ id: SPK_ID, jwk: spk.privJwk }, opkPrivates);

    return {
        identity_key:      identityKeyHex,
        signed_prekey:     spk.pubHex,
        signed_prekey_sig: spkSig,
        signed_prekey_id:  SPK_ID,
        identity_key_ed:   edPub,
        identity_key_sig:  idSig,
        supports_v2:       true,   // этот клиент умеет принимать v2 (ADR-001 6b)
        one_time_prekeys:  oneTimePrekeys,
    };
}

/**
 * Публикует prekey-бандл, если он ещё не опубликован или запас OPK иссяк.
 * Идемпотентно, неблокирующе; ошибки логируются, но не пробрасываются в boot.
 * Rollback: localStorage['vortex_prekeys_disabled'] = '1' отключает публикацию.
 * @returns {Promise<boolean>} true если бандл был опубликован в этот вызов
 */
export async function ensurePrekeysPublished() {
    if (localStorage.getItem(DISABLE_FLAG)) return false;

    const identityKeyHex = window.AppState?.user?.x25519_public_key;
    if (!identityKeyHex) return false;   // без X25519-идентичности публиковать нечего

    let status;
    try {
        status = await api('GET', '/api/keys/prekeys/status/me');
    } catch (e) {
        console.debug('[prekeys] status check failed:', e.message);
        return false;
    }

    const needsPublish = !status?.published
        || status.low_opk_warning
        || (status.available_opk_count ?? 0) < LOW_OPK_THRESHOLD
        // Пользователи батча 4 опубликовали публичные, но не имеют локальных
        // приватных SPK/OPK — форсируем один republish, чтобы уметь отвечать на v2.
        // Этот арм self-heal'ит устройство, потерявшее localStorage (гейт #3).
        || !hasPrekeyPrivates()
        // Опубликованный бандл ещё не заявляет v2-приём (пред-6b) — republish,
        // чтобы отправители знали, что нам можно слать v2.
        || status.supports_v2 !== true;
    if (!needsPublish) return false;

    try {
        const bundle = await buildPrekeyBundle(identityKeyHex);
        await api('POST', '/api/keys/prekeys/publish', bundle);
        console.info('[prekeys] bundle published (%d OPKs)', bundle.one_time_prekeys.length);
        return true;
    } catch (e) {
        console.warn('[prekeys] publish failed:', e.message);
        return false;
    }
}

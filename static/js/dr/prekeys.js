// static/js/dr/prekeys.js
// Ed25519-идентичность + публикация X3DH prekey-бандла.
//
// Долговременная идентичность пользователя — ПАРА ключей:
//   • X25519 identity_key   — уже есть (генерируется при регистрации, auth.js),
//                             используется для DH в X3DH;
//   • Ed25519 identity_key  — вводится здесь, подписывает Signed Pre-Key и
//                             (cross-signature) сам X25519 identity_key.
// XEdDSA не используется, поэтому подписывающий ключ отдельный.
//
// ВНИМАНИЕ по угрозам: серверная верификация подписей проверяет целостность
// бандла относительно ОПУБЛИКОВАННОГО Ed25519-ключа, но не даёт
// substitution-resistance — она появится только с внеполосной верификацией
// отпечатков по паре (identity_key, identity_key_ed).

import { api } from '../utils.js';
import { storePrekeyPrivates, hasPrekeyPrivates, storePqspkPrivate, hasPqspkPrivate, storePqopkPrivates } from './prekey-store.js';
import { loadOrCreateDeviceIdentity } from './device-identity.js';
import * as x25519 from './x25519-compat.js';

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

// Аккаунт-уровневый материал для публикации на устройстве БЕЗ аккаунтного
// Ed25519-приватного (свежелинкованное). `identity_key_sig` (= аккаунтный Ed25519
// подписал аккаунтный X25519 identity_key) и `account_ed_pub` — КОНСТАНТНЫ на
// аккаунт и ПУБЛИЧНЫ; одобряющее устройство передаёт их при линковке. Так
// линкованное устройство публикует полный бандл, не имея аккаунтного приватного.
const ACCT_LINK_PREFIX = 'vortex_account_link_material';   // + `_${userId}`
function _acctLinkSlot(userId) { return `${ACCT_LINK_PREFIX}_${userId}`; }

/** Сохраняет аккаунт-материал линковки (account_ed_pub + identity_key_sig). */
export function saveAccountLinkMaterial(userId, accountEdPub, identityKeySig) {
    localStorage.setItem(_acctLinkSlot(userId), JSON.stringify({ accountEdPub, identityKeySig }));
}

/** @returns {{accountEdPub:string, identityKeySig:string}|null} */
export function loadAccountLinkMaterial(userId) {
    try { return JSON.parse(localStorage.getItem(_acctLinkSlot(userId))); } catch { return null; }
}

// Ed25519 identity

/**
 * Загружает Ed25519-идентичность аккаунта из хранилища. Возвращает null, если
 * её нет — НЕ генерирует новую (иначе на logout→login без восстановления
 * молча появилась бы другая идентичность). Генерация — только при регистрации
 * (loadOrCreateEd25519Identity). Публичный ключ выводится из приватного JWK.
 * @returns {{privJwk: string, pubHex: string}|null}
 */
export function loadEd25519Identity() {
    const userId = window.AppState?.user?.user_id;
    if (!userId) return null;
    const slot = _edSlot(userId);
    const priv = localStorage.getItem(slot) || sessionStorage.getItem(slot);
    if (!priv) return null;
    const pubHex = _pubHexFromJwk(priv);
    if (!pubHex) return null;
    sessionStorage.setItem(slot, priv);
    return { privJwk: priv, pubHex };
}

/**
 * Возвращает Ed25519-идентичность аккаунта, СОЗДАВАЯ её, если отсутствует.
 * Вызывать только при регистрации — где создание новой идентичности корректно.
 * @returns {Promise<{privJwk: string, pubHex: string}>}
 */
export async function loadOrCreateEd25519Identity() {
    const existing = loadEd25519Identity();
    if (existing) return existing;
    const userId = window.AppState?.user?.user_id;
    if (!userId) throw new Error('Ed25519 identity requires a logged-in user');
    const slot = _edSlot(userId);
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const pubRaw = await crypto.subtle.exportKey('raw', pair.publicKey);
    const privJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
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

// SPK id фиксирован (одна активная пара на аккаунт); ротация SPK не поддерживается.
const SPK_ID = 1;
// PQXDH Kyber pre-key id — фиксирован (одна активная пара, как SPK).
const PQSPK_ID = 1;
// One-time Kyber pre-keys (PQXDH P6): малый батч (ML-KEM-ключи тяжелее X25519;
// значение out-of-scope под A1). Исчерпание → fallback на last-resort PQSPK.
const PQOPK_BATCH = 6;

/** Монотонный per-account счётчик id для PQOPK (отдельный от OPK namespace). */
function _nextPqopkId(userId, count) {
    const k = `vortex_dr_pqopk_next_${userId}`;
    const start = parseInt(localStorage.getItem(k) || '1', 10);
    localStorage.setItem(k, String(start + count));
    return start;
}

/** Генерирует X25519 пару. @returns {Promise<{pubHex, privJwk}>} */
async function _genX25519() {
    const pair = await x25519.generateKeyPair();
    const raw = await x25519.exportPublicRaw(pair.publicKey);
    const privJwk = JSON.stringify(await x25519.exportPrivateJwk(pair.privateKey));
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
 * персистятся локально (prekey-store), чтобы отвечать на входящие X3DH.
 * @param {string} identityKeyHex — X25519 публичный identity_key пользователя
 * @param {number} opkCount
 * @returns {Promise<object>} тело запроса для POST /api/keys/prekeys/publish
 */
export async function buildPrekeyBundle(identityKeyHex, opkCount = OPK_BATCH) {
    const userId = window.AppState?.user?.user_id;

    // Device-identity тройка: device X3DH-ключ, device signing-ключ и
    // authorization-cert аккаунта над ними. Цепочка доверия:
    //   account Ed25519 ──cert──▶ device signing key ──sign──▶ SPK.
    // SPK подписывает device signing-ключ; cert авторизует его.
    let device = null;
    try {
        device = await loadOrCreateDeviceIdentity();
    } catch (e) {
        console.debug('[prekeys] device identity unavailable:', e?.message);
    }

    // Аккаунт-уровневый материал (identity_key_ed + identity_key_sig) — два пути:
    //  • authorizer/primary: держит аккаунтный Ed25519-приватный → ВЫЧИСЛЯЕТ idSig;
    //  • linked (без аккаунтного Ed-приватного): берёт account_ed_pub + idSig из
    //    linking-payload (константны на аккаунт, публичны; переданы одобряющим).
    // idSig аккаунт-уровневый и НЕ опционален — это binding account-X25519↔account-Ed,
    // который проверяет sender-гейт; ослаблять его нельзя.
    const identity = loadEd25519Identity();
    let edPub, idSig;
    if (identity) {
        edPub = identity.pubHex;
        idSig = await edSign(identity.privJwk, fromHex(identityKeyHex));
    } else {
        const mat = loadAccountLinkMaterial(userId);
        if (!mat?.accountEdPub || !mat?.identityKeySig) {
            throw new Error('no account signing material — cannot publish prekeys');
        }
        edPub = mat.accountEdPub;
        idSig = mat.identityKeySig;
    }

    const spk = await _genX25519();
    // SPK подписан device signing-ключом (cert его авторизует). Fallback на
    // аккаунтный Ed — только если device-идентичности нет И есть аккаунтный Ed.
    const spkSigner = device ? device.signPriv : (identity ? identity.privJwk : null);
    if (!spkSigner) throw new Error('no signing key for SPK — cannot publish prekeys');
    const spkSig = await edSign(spkSigner, fromHex(spk.pubHex));

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

    const body = {
        identity_key:      identityKeyHex,
        signed_prekey:     spk.pubHex,
        signed_prekey_sig: spkSig,
        signed_prekey_id:  SPK_ID,
        identity_key_ed:   edPub,
        identity_key_sig:  idSig,
        supports_v2:       true,   // этот клиент умеет принимать v2
        one_time_prekeys:  oneTimePrekeys,
    };
    if (device) {
        body.device_x3dh_pub  = device.x3dhPub;
        body.device_sign_pub  = device.signPub;
        body.device_cert_sig  = device.certSig;   // null, если аккаунтный Ed25519 недоступен (свежелинкованное устройство)
    }

    // PQXDH Kyber pre-key (ML-KEM-768) — публикуем безусловно (receive-ready
    // везде, дормантно: отправку включит отдельный флаг). Подписан тем же
    // spkSigner, что и SPK (device signing-ключ). ML-KEM грузится лениво (~28КБ
    // вендор). All-or-nothing: сбой → публикуем классику, приватный НЕ храним
    // (без half-state); prekey-publish не ломаем.
    try {
        const { mlkemKeygen } = await import('./mlkem.js');
        const pqspk = mlkemKeygen();   // {publicKeyHex, secretKeyHex}
        const pqspkSig = await edSign(spkSigner, fromHex(pqspk.publicKeyHex));
        storePqspkPrivate(PQSPK_ID, pqspk.secretKeyHex);
        body.device_kyber_pub = pqspk.publicKeyHex;
        body.device_kyber_sig = pqspkSig;
        body.device_kyber_id  = PQSPK_ID;

        // One-time Kyber pre-keys (P6): опортунистический батч. Приватные хранятся
        // локально (удаляются у адресата после использования — KEM-FS). Публичные
        // НЕ подписываем: связывание идёт через km_pq (§3.2), а аутентичность
        // устройства — из cert-цепочки (device_sign_pub). Исчерпание → PQSPK.
        const pqopkBase = _nextPqopkId(userId, PQOPK_BATCH);
        const pqopks = [], pqopkPrivs = [];
        for (let i = 0; i < PQOPK_BATCH; i++) {
            const kp = mlkemKeygen();
            const id = pqopkBase + i;
            pqopks.push({ key_id: id, public_key: kp.publicKeyHex });
            pqopkPrivs.push({ id, sk: kp.secretKeyHex });
        }
        storePqopkPrivates(pqopkPrivs);
        body.one_time_kyber_prekeys = pqopks;
    } catch (e) {
        console.debug('[prekeys] Kyber pre-key skipped (classical bundle):', e?.message);
    }

    return body;
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
        // Клиент опубликовал публичные, но не имеет локальных
        // приватных SPK/OPK — форсируем один republish, чтобы уметь отвечать на v2.
        // Этот арм self-heal'ит устройство, потерявшее localStorage.
        || !hasPrekeyPrivates()
        // Нет локального PQXDH Kyber pre-key — один republish на бэкфилл
        // (receive-ready до включения отправки). Зеркало арма выше.
        || !hasPqspkPrivate()
        // Опубликованный бандл ещё не заявляет v2-приём — republish,
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

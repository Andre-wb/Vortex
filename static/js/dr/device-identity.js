// static/js/dr/device-identity.js
// Стабильная per-device идентичность для мультидевайсного Sesame.
//
// «device identity» — ТРОЙКА (все три переживают logout, per-account):
//   1. Device X3DH key    — X25519, DH-идентичность устройства в X3DH.
//   2. Device signing key — Ed25519, подписывает SPK этого устройства.
//   3. Authorization cert — подпись аккаунтного Ed25519 над
//        (client_device_id ‖ x3dh_pub ‖ sign_pub), связывает устройство с аккаунтом.
//
// Хранение: один JSON на аккаунт в localStorage `vortex_device_identity_<userId>`.
// НЕ чистится при logout (стабильность идентичности физического устройства для
// возврата пользователя). Аккаунтные СООБЩЕНЧЕСКИЕ данные (DR-сессии, history,
// room keys, identity-ключи) по-прежнему чистятся — это лишь device-DH/signing,
// не дающие доступа к аккаунту (device-ключ не auth-credential).
//
// Cert выпускается self-sign'ом, ЕСЛИ аккаунтный Ed25519 присутствует локально
// (первое/primary устройство, или после vault-restore). На свежелинкованном
// устройстве без аккаунтного Ed25519 cert откладывается — его подпишет
// одобряющее устройство при линковке. НЕ создаём аккаунтный Ed25519 здесь
// (это дало бы дивергентную идентичность на линкованном устройстве).

import { getClientDeviceId } from '../utils.js';
import { edSign, edVerify } from './prekeys.js';
import * as x25519 from './x25519-compat.js';

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

function _slot(userId) { return `vortex_device_identity_${userId}`; }

async function _genX25519() {
    const pair = await x25519.generateKeyPair();
    const raw = await x25519.exportPublicRaw(pair.publicKey);
    return { pubHex: toHex(raw), privJwk: JSON.stringify(await x25519.exportPrivateJwk(pair.privateKey)) };
}

async function _genEd25519() {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
    return { pubHex: toHex(raw), privJwk: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)) };
}

/** Аккаунтный Ed25519 приватный (JWK-строка), ТОЛЬКО если уже есть локально; иначе null. */
function _accountEdPrivIfPresent(userId) {
    return localStorage.getItem(`vortex_ed25519_identity_${userId}`)
        || sessionStorage.getItem(`vortex_ed25519_identity_${userId}`)
        || null;
}

/** Публичный ключ (hex) из Ed25519 JWK-строки (поле x — base64url pub). */
function _pubHexFromEdJwk(jwkString) {
    try {
        const jwk = JSON.parse(jwkString);
        if (!jwk.x) return null;
        const bin = atob(jwk.x.replace(/-/g, '+').replace(/_/g, '/'));
        return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    } catch { return null; }
}

/**
 * Каноническое сообщение authorization-cert'а: client_device_id(16) ‖ x3dh_pub(32) ‖ sign_pub(32).
 * @returns {Uint8Array} 80 байт
 */
export function certMessage(clientDeviceId, x3dhPubHex, signPubHex) {
    const out = new Uint8Array(80);
    out.set(fromHex(clientDeviceId), 0);
    out.set(fromHex(x3dhPubHex), 16);
    out.set(fromHex(signPubHex), 48);
    return out;
}

/**
 * Проверяет authorization-cert устройства: аккаунтный Ed25519 подписал
 * (client_device_id ‖ device_x3dh_pub ‖ device_sign_pub). Атомарный примитив на
 * СЫРЫХ полях — используется и на отправке (поля из fetch-бандла), и на приёме
 * (поля из прелюды сообщения). Возвращает false при любой нехватке/ошибке.
 * @param {string} clientDeviceId — 32 hex (16 байт)
 * @param {string} x3dhPubHex     — 64 hex (32 байта)
 * @param {string} signPubHex     — 64 hex (32 байта)
 * @param {string} certSigHex     — 128 hex (64 байта)
 * @param {string} accountEdPubHex — аккаунтный Ed25519 pub (корень доверия)
 * @returns {Promise<boolean>}
 */
export async function verifyDeviceCert(clientDeviceId, x3dhPubHex, signPubHex, certSigHex, accountEdPubHex) {
    if (!clientDeviceId || !x3dhPubHex || !signPubHex || !certSigHex || !accountEdPubHex) return false;
    try {
        return await edVerify(accountEdPubHex, certMessage(clientDeviceId, x3dhPubHex, signPubHex), certSigHex);
    } catch {
        return false;
    }
}

/**
 * Загружает стабильную device-идентичность аккаунта или создаёт её (тройка).
 * Выпускает cert, если аккаунтный Ed25519 доступен локально. Идемпотентно.
 * @returns {Promise<{deviceId, x3dhPub, x3dhPriv, signPub, signPriv, certSig: string|null}>}
 */
export async function loadOrCreateDeviceIdentity() {
    const userId = window.AppState?.user?.user_id;
    if (!userId) throw new Error('device identity requires a logged-in user');
    const slot = _slot(userId);

    let data;
    try { data = JSON.parse(localStorage.getItem(slot)); } catch { data = null; }
    if (!data || !data.x3dhPriv || !data.signPriv) {
        const x3dh = await _genX25519();
        const sign = await _genEd25519();
        data = {
            x3dhPub: x3dh.pubHex, x3dhPriv: x3dh.privJwk,
            signPub: sign.pubHex, signPriv: sign.privJwk,
            certSig: null,
        };
        localStorage.setItem(slot, JSON.stringify(data));
    }

    const deviceId = getClientDeviceId();

    // Cert выпускается/ПЕРЕВЫПУСКАЕТСЯ, если аккаунтный Ed25519 доступен и cert
    // ещё нет ИЛИ он подписан ДРУГИМ (устаревшим) аккаунтным ключом. Guard на
    // ВАЛИДНОСТЬ, не на наличие: аккаунтный Ed25519 может смениться (logout→login
    // без vault-restore регенерирует его), и stale
    // cert иначе навсегда исключил бы устройство из собственного fan-out.
    // Аккаунтный ключ здесь НЕ создаём (иначе дивергентная идентичность).
    const edPriv = _accountEdPrivIfPresent(userId);
    if (edPriv) {
        const curSignerPub = _pubHexFromEdJwk(edPriv);
        if (curSignerPub && (!data.certSig || data.certSignerPub !== curSignerPub)) {
            try {
                data.certSig = await edSign(edPriv, certMessage(deviceId, data.x3dhPub, data.signPub));
                data.certSignerPub = curSignerPub;
                localStorage.setItem(slot, JSON.stringify(data));
            } catch (e) {
                console.debug('[device-identity] cert (re)issue deferred:', e?.message);
            }
        }
    }
    // Если аккаунтного Ed25519 нет (свежелинкованное устройство) — cert
    // откладывается до подписи одобряющим устройством.

    return { deviceId, ...data };
}

/**
 * Записывает cert, ВЫДАННЫЙ одобряющим устройством при линковке, в device-identity
 * слот (устройство без аккаунтного Ed25519-приватного не может self-sign'ить —
 * cert подписывает одобряющий аккаунтным Ed25519). certSignerPub = аккаунтный
 * Ed25519 pub подписанта. Идемпотентно; возвращает false, если тройки ещё нет.
 * @param {string|number} userId
 * @param {string} certSigHex — 128 hex
 * @param {string} accountEdPubHex — 64 hex
 */
export function applyIssuedCert(userId, certSigHex, accountEdPubHex) {
    const slot = _slot(userId);
    let data;
    try { data = JSON.parse(localStorage.getItem(slot)); } catch { data = null; }
    if (!data || !data.x3dhPriv || !data.signPriv) return false;
    data.certSig = certSigHex;
    data.certSignerPub = accountEdPubHex;
    localStorage.setItem(slot, JSON.stringify(data));
    return true;
}

/** Удаляет device-идентичность аккаунта (removeAccount). */
export function clearDeviceIdentity(userId) {
    localStorage.removeItem(_slot(userId));
}

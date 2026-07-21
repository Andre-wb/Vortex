// static/js/dr/pq-capability.js
// Post-quantum отправка (X25519 + ML-KEM-768): решение «оборачивать ли room-key
// гибридно для пира». Приём — всегда-вкл (crypto.js decryptRoomKeyEnvelope);
// отправка — ПО УМОЛЧАНИЮ ВКЛ (активировано pre-launch: приложение не в сети, нет
// оператора; multi-device лок-аут K5 неактуален — каждое устройство с аккаунтным
// X25519-priv несёт и Kyber-priv, key_backup.js _collectKeyBundle портирует обе
// в тандеме, вне includeEd25519-гейта, и на линковке тоже). Kill-switch: '0'.
//
// Capability = у пира опубликован аккаунтный Kyber-pub, подписанный его аккаунтным
// Ed25519. Подпись проверяется против припиненного (TOFU) аккаунтного Ed25519 пира
// — того же корня доверия, что device-cert'ы v2-пути (identity-pin.js). Нет пина →
// fetch-and-pin по prekey-бандлу (как v2 _resolveSenderPin). Под честным сервером
// (A1) «pub есть» — функциональный флор; подпись добавляет Б2-аутентичность.

import { edVerify, loadEd25519Identity } from './prekeys.js';
import { pinnedPeerAccountEd, pinPeerAccountEd } from './identity-pin.js';
import { loadKyberIdentity } from './kyber-identity.js';
import { api } from '../utils.js';

const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

/** Гибрид-отправка включена? Дефолт ВЫКЛ — opt-in (флип на активации). */
export function pqSendEnabled() {
    try { return localStorage.getItem('vortex_pq_hybrid_enabled') !== '0'; } catch { return false; }
}

/**
 * Припиненный (или fetch-and-pin) аккаунтный Ed25519 пира — корень для проверки
 * подписи Kyber-pub. Своё устройство → локальный аккаунтный Ed25519.
 */
async function _peerAccountEd(peerUserId) {
    if (peerUserId != null && peerUserId === window.AppState?.user?.user_id) {
        return loadEd25519Identity()?.pubHex || null;
    }
    const pinned = pinnedPeerAccountEd(peerUserId);
    if (pinned) return pinned;
    try {
        const b = await api('GET', `/api/keys/prekeys/${peerUserId}`);
        const r = pinPeerAccountEd(peerUserId, b?.identity_key_ed);
        return r.trusted || null;
    } catch { return null; }
}

/**
 * Проверенный Kyber-pub пира (→ гибрид) или null (→ классика). null при: флаг ВЫКЛ,
 * нет pub/подписи, не удалось разрешить/запинить Ed пира, подпись не сошлась.
 * @param {number|string} peerUserId
 * @param {string|null} kyberPubHex
 * @param {string|null} kyberPubSig — Ed25519-подпись над сырыми байтами kyberPub
 * @returns {Promise<string|null>}
 */
export async function resolvePeerKyberPub(peerUserId, kyberPubHex, kyberPubSig) {
    if (!pqSendEnabled()) return null;
    if (!kyberPubHex || !kyberPubSig) return null;
    const peerEd = await _peerAccountEd(peerUserId);
    if (!peerEd) return null;
    try {
        const ok = await edVerify(peerEd, fromHex(kyberPubHex), kyberPubSig);
        return ok ? kyberPubHex : null;
    } catch { return null; }
}

/**
 * Свой аккаунтный Kyber-pub для self-обёртки room-key (локальное доверие, без
 * подписи), или null (флаг ВЫКЛ / нет локальной идентичности → классика).
 */
export function myKyberPub() {
    if (!pqSendEnabled()) return null;
    const uid = window.AppState?.user?.user_id;
    return uid ? (loadKyberIdentity(uid)?.pubHex || null) : null;
}

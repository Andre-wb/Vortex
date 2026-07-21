// static/js/dr/kyber-identity.js
// Аккаунтная ML-KEM-768 идентичность (post-quantum KEM, ADR-004 K2).
//
// Долговременная per-account идентичность как аккаунтный Ed25519: приватный
// переживает logout (`_enc`-персистенция, identity-persist.js), НЕ форкается на
// login (load-only + генерация ТОЛЬКО при регистрации), wipe на removeAccount.
// Публичный подписывается аккаунтным Ed25519 (аутентичность не слабее соседних
// ключей — sender фетчит pub с сервера, под A1 честно, но подпись обязательна).
//
// E2E: приватный генерится КЛИЕНТОМ и сервер его НЕ видит (в отличие от старой
// серверной keygen в password.py, которую K2 убирает). Слот
// vortex_kyber_priv_<userId> хранит приватный hex (2400 байт); публичный
// выводится из приватного (mlkemGetPublic) — не дублируем.

import { mlkemKeygen, mlkemGetPublic } from './mlkem.js';
import { edSign } from './prekeys.js';

const KYBER_PRIV_PREFIX = 'vortex_kyber_priv';   // + `_${userId}`
function _slot(userId) { return `${KYBER_PRIV_PREFIX}_${userId}`; }
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

/**
 * Загружает аккаунтную Kyber-идентичность (load-only, НЕ генерирует — иначе форк
 * на logout→login без восстановления). @returns {{privHex, pubHex}|null}
 */
export function loadKyberIdentity(userId) {
    if (!userId) return null;
    const slot = _slot(userId);
    const priv = localStorage.getItem(slot) || sessionStorage.getItem(slot);
    if (!priv) return null;
    let pubHex;
    try { pubHex = mlkemGetPublic(priv); } catch { return null; }
    sessionStorage.setItem(slot, priv);
    return { privHex: priv, pubHex };
}

/**
 * Возвращает Kyber-идентичность, СОЗДАВАЯ её при отсутствии. Вызывать только при
 * регистрации (где создание новой идентичности корректно). @returns {{privHex, pubHex}}
 */
export function loadOrCreateKyberIdentity(userId) {
    const existing = loadKyberIdentity(userId);
    if (existing) return existing;
    if (!userId) throw new Error('Kyber identity requires a logged-in user');
    const { publicKeyHex, secretKeyHex } = mlkemKeygen();
    localStorage.setItem(_slot(userId), secretKeyHex);
    sessionStorage.setItem(_slot(userId), secretKeyHex);
    return { privHex: secretKeyHex, pubHex: publicKeyHex };
}

/**
 * Подписывает Kyber-pub аккаунтным Ed25519. Sender проверяет
 * edVerify(accountEdPub, kyberPub, sig) — аутентичность корня перед hybrid-обёрткой.
 * @param {string} kyberPubHex
 * @param {string} edPrivJwk — приватный аккаунтный Ed25519 (JWK-строка)
 * @returns {Promise<string>} подпись hex (128)
 */
export async function signKyberPub(kyberPubHex, edPrivJwk) {
    return edSign(edPrivJwk, fromHex(kyberPubHex));
}

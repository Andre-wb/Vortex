// static/js/dr/mlkem.js
// KEM-примитив ML-KEM-768 (FIPS 203) для post-quantum гибрида (ADR-004).
//
// Web Crypto НЕ поддерживает ML-KEM — поэтому оборачиваем вендоренную pure-JS
// либу (@noble/post-quantum, static/js/vendor/mlkem768.js: self-contained ESM,
// без CDN/WASM → грузится под строгой CSP). Прод-код импортирует ТОЛЬКО этот
// wrapper, не вендорный файл напрямую.
//
// Дормантно (K1): примитив готов, но в путь обёртки ключей НЕ подключён —
// hybrid-обёртка (K3) и провязка (K4) идут отдельными батчами. Активация — K5.
//
// Размеры ML-KEM-768: public 1184, secret 2400, ciphertext 1088, shared 32 (байт).

import { ml_kem768 } from '../vendor/mlkem768.js';

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

/** Длины в байтах (FIPS 203 ML-KEM-768) — для валидации. */
export const MLKEM768 = { publicKey: 1184, secretKey: 2400, cipherText: 1088, sharedSecret: 32 };

/**
 * Генерирует ML-KEM-768 пару. Приватный — долговременная per-account идентичность
 * (персистится как аккаунтный Ed25519, K2).
 * @returns {{publicKeyHex: string, secretKeyHex: string}}
 */
export function mlkemKeygen() {
    const { publicKey, secretKey } = ml_kem768.keygen();
    return { publicKeyHex: toHex(publicKey), secretKeyHex: toHex(secretKey) };
}

/** Выводит публичный ключ из приватного (хранить достаточно приватный). */
export function mlkemGetPublic(secretKeyHex) {
    return toHex(ml_kem768.getPublicKey(fromHex(secretKeyHex)));
}

/**
 * Инкапсуляция к публичному ключу получателя: возвращает ciphertext (шлётся
 * получателю) и shared secret (для HKDF гибрида — K3).
 * @param {string} publicKeyHex — 1184 байта (2368 hex)
 * @returns {{cipherTextHex: string, sharedSecret: Uint8Array}} sharedSecret — 32 байта
 */
export function mlkemEncaps(publicKeyHex) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(fromHex(publicKeyHex));
    return { cipherTextHex: toHex(cipherText), sharedSecret: new Uint8Array(sharedSecret) };
}

/**
 * Декапсуляция: восстанавливает тот же shared secret из ciphertext своим приватным.
 * ML-KEM — implicit rejection (FIPS 203): при неверном приватном возвращает
 * ДЕТЕРМИНИРОВАННЫЙ, но ДРУГОЙ secret (не бросает) — расшифровка гибрида просто
 * не сойдётся (AEAD InvalidTag).
 * @param {string} cipherTextHex — 1088 байт (2176 hex)
 * @param {string} secretKeyHex — 2400 байт
 * @returns {Uint8Array} sharedSecret — 32 байта
 */
export function mlkemDecaps(cipherTextHex, secretKeyHex) {
    return new Uint8Array(ml_kem768.decapsulate(fromHex(cipherTextHex), fromHex(secretKeyHex)));
}

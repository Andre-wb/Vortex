// static/js/chat/message-cipher.js
// Единая точка шифрования/расшифровки текста сообщений (ADR-001, батч 3).
//
// Все чат-модули обязаны шифровать и расшифровывать сообщения ТОЛЬКО через
// эти две функции — прямые вызовы ratchetEncrypt/ratchetDecrypt вне данного
// модуля запрещены (проверяется static/js/__tests__/cipher-guard.test.js).
// Это единственное место, куда в батчах 5-6 подключится Double Ratchet (v2):
// добавление новой версии здесь не потребует правок в десятке call-sites.
//
// Проверка версии конверта (isKnownEncVersion) и обработка «нет ключа»
// остаются на стороне call-sites — у них разные тексты-заглушки. Эти
// функции лишь диспетчеризуют существующие форматы v0/v1 и бросают
// исключение, если расшифровать нечем.

import { ratchetEncrypt, ratchetDecrypt } from '../crypto.js';
import { decryptText } from './room-crypto.js';
import { ENC_V_CURRENT } from './enc-version.js';
import { createSessionStore, indexedDbBackend } from '../dr/session-store.js';
import { decryptV2 as _drDecryptV2, dmSessionId, importX25519PrivJwk } from '../dr/session.js';

/**
 * Шифрует текст сообщения текущей продовой схемой (v1, sender-chain).
 *
 * @param {string|number} roomId
 * @param {string|number} senderId
 * @param {string} text
 * @param {Uint8Array} roomKey — 32-байтный ключ комнаты
 * @returns {Promise<{enc_v: number, ciphertext: string}>}
 * @throws пробрасывает ошибку шифрования (например, при неверном roomKey) —
 *         call-site отвечает за пред-проверку наличия ключа.
 */
export async function encryptMessage(roomId, senderId, text, roomKey) {
    const ciphertext = await ratchetEncrypt(text, roomId, senderId, roomKey);
    return { enc_v: ENC_V_CURRENT, ciphertext };
}

/**
 * Расшифровывает текст сообщения существующих форматов v0/v1.
 *
 * Порядок: v1 sender-chain (ratchetDecrypt, у которого внутри есть фолбэк
 * на голый legacy v0) → padded-legacy (decryptText, magic 0x5678). Полностью
 * повторяет цепочку, которую до абстракции дублировал каждый call-site.
 *
 * @param {string} ciphertextHex
 * @param {string|number} roomId
 * @param {string|number} senderId
 * @param {Uint8Array} roomKey
 * @returns {Promise<string>} расшифрованный текст
 * @throws если ни v1, ни legacy расшифровать не смогли — call-site выбирает
 *         текст-заглушку.
 */
export async function decryptMessage(ciphertextHex, roomId, senderId, roomKey) {
    try {
        return await ratchetDecrypt(ciphertextHex, roomId, senderId, roomKey);
    } catch {
        return await decryptText(ciphertextHex, roomKey);
    }
}

// v2 — Double Ratchet (ADR-001, батч 6a). ТОЛЬКО ПРИЁМ: клиент умеет
// расшифровывать v2, но ничего в v2 не отправляет до батча 6b.

let _v2Store = null;
function _sessionStore() {
    // Ленивая инициализация — IndexedDB создаётся только при первом v2-сообщении.
    if (!_v2Store) _v2Store = createSessionStore(indexedDbBackend());
    return _v2Store;
}

/**
 * Расшифровывает v2-конверт (парная DR-сессия) для DM-комнаты. Бросает
 * SessionError при невозможности установить/расшифровать — call-site деградирует
 * в плейсхолдер.
 * @param {string} envelopeHex — v2-конверт
 * @param {string|number} roomId — id DM-комнаты (ключ сессии)
 * @param {string} senderIdentityPubHex — опубликованный x25519_public_key отправителя (TOFU)
 * @returns {Promise<string>} plaintext
 */
export async function decryptV2Message(envelopeHex, roomId, senderIdentityPubHex) {
    const privJwk = window.AppState?.x25519PrivateKey
        || sessionStorage.getItem('vortex_x25519_priv')
        || localStorage.getItem('vortex_x25519_priv');
    if (!privJwk) throw new Error('no identity private key for v2 decrypt');
    const myIkPriv = await importX25519PrivJwk(privJwk);
    return _drDecryptV2(
        _sessionStore(), dmSessionId(roomId),
        { myIkPriv, senderIdentityPubHex }, envelopeHex,
    );
}

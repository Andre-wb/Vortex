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

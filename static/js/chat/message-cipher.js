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
import { api } from '../utils.js';
import { createSessionStore, indexedDbBackend } from '../dr/session-store.js';
import { decryptV2 as _drDecryptV2, encryptV2 as _drEncryptV2, dmSessionId, importX25519PrivJwk } from '../dr/session.js';
import { edVerify } from '../dr/prekeys.js';

const _fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

// Фичефлаг v2-отправки в DM (ADR-001, батч 6b). ПО УМОЛЧАНИЮ ВЫКЛ.
// Включение — только после прохождения Playwright-гейта (IndexedDB/Web Locks).
// Это per-client opt-in; централизованный kill-switch — отдельный трек (ADR §2.6).
function _v2SendEnabled() {
    try { return localStorage.getItem('vortex_v2_dm_enabled') === '1'; } catch { return false; }
}

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

function _identityPrivJwk() {
    return window.AppState?.x25519PrivateKey
        || sessionStorage.getItem('vortex_x25519_priv')
        || localStorage.getItem('vortex_x25519_priv');
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
    const privJwk = _identityPrivJwk();
    if (!privJwk) throw new Error('no identity private key for v2 decrypt');
    const myIkPriv = await importX25519PrivJwk(privJwk);
    return _drDecryptV2(
        _sessionStore(), dmSessionId(roomId),
        { myIkPriv, senderIdentityPubHex }, envelopeHex,
    );
}

/** Проверяет подписи бандла адресата против его Ed25519 identity (defense-in-depth). */
async function _bundleWellSigned(bundle) {
    if (!bundle.identity_key_ed || !bundle.signed_prekey_sig || !bundle.identity_key_sig) return false;
    const spkOk = await edVerify(bundle.identity_key_ed, _fromHex(bundle.signed_prekey), bundle.signed_prekey_sig);
    const idOk  = await edVerify(bundle.identity_key_ed, _fromHex(bundle.identity_key), bundle.identity_key_sig);
    return spkOk && idOk;
}

/**
 * Пытается зашифровать сообщение в v2 для DM-комнаты. Возвращает
 * {enc_v:2, ciphertext} при успехе, либо null — тогда call-site шлёт v1.
 * Решение по комнате кэшируется на объекте room (`_v2`): 'no' — окончательно
 * не v2 (флаг/не-DM/адресат без v2/битый бандл), 'yes' — сессия установлена.
 * @param {object} room — S.currentRoom (нужны is_dm, id, dm_user)
 * @param {string} plaintext
 * @returns {Promise<{enc_v:number, ciphertext:string}|null>}
 */
export async function encryptV2ForDm(room, plaintext) {
    if (!_v2SendEnabled()) return null;                 // фичефлаг (kill-switch)
    if (!room?.is_dm || room._v2 === 'no') return null;
    const peer = room.dm_user;
    if (!peer?.user_id || !peer?.x25519_public_key) return null;

    const privJwk = _identityPrivJwk();
    const myIkPubHex = window.AppState?.user?.x25519_public_key;
    if (!privJwk || !myIkPubHex) return null;

    let myIkPriv;
    try { myIkPriv = await importX25519PrivJwk(privJwk); } catch { return null; }

    // getPeerBundle вызывается лишь при установлении (сессии ещё нет). Бросает
    // с _fallback=true для окончательных причин (кэшируем 'no'); транзиентные
    // ошибки (сеть) — без кэша, чтобы повторить на следующем сообщении.
    const getPeerBundle = async () => {
        const bundle = await api('GET', `/api/keys/prekeys/${peer.user_id}`);
        const reject = (msg) => { const e = new Error(msg); e._fallback = true; throw e; };
        if (!bundle) reject('no_bundle');
        if (bundle.supports_v2 !== true) reject('peer_no_v2');           // capability
        if (bundle.identity_key !== peer.x25519_public_key) reject('identity_mismatch'); // TOFU
        if (!await _bundleWellSigned(bundle)) reject('bad_signatures');  // defense-in-depth
        return bundle;
    };

    try {
        const hex = await _drEncryptV2(_sessionStore(), dmSessionId(room.id),
            { myIkPriv, myIkPubHex, getPeerBundle }, plaintext);
        room._v2 = 'yes';
        return { enc_v: 2, ciphertext: hex };
    } catch (e) {
        if (e && e._fallback) room._v2 = 'no';   // окончательно — далее шлём v1 без перезапросов
        else console.debug('[v2] transient establish failure, will retry:', e?.message);
        return null;
    }
}

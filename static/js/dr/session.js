// static/js/dr/session.js
// Установление и использование парных v2-сессий Double Ratchet (ADR-001, батч 6a).
//
// Связывает X3DH (x3dh.js) + ратчет (ratchet.js) + хранилище состояния
// (session-store.js) + приватные prekey (prekey-store.js) + провод (v2-envelope.js).
//
// Область: 1:1 DM. Сессия ключуется по roomId DM: `dm:<roomId>`.
//
// В батче 6a продовая проводка — ТОЛЬКО приём (decryptV2). encryptV2/установление
// инициатора написаны для тестов (нужны, чтобы создать v2-конверт), но из
// продового пути отправки не вызываются до батча 6b.
//
// БЕЗОПАСНОСТЬ: initiator IK не аутентифицирован криптографически — это TOFU
// (ADR §2.4г). decryptV2 требует, чтобы IK из прелюды совпал с опубликованным
// x25519_public_key отправителя, иначе отвергает. Но пока этот ключ не
// верифицирован внеполосно, злонамеренный сервер может подменить пару целиком.

import { x3dhInitiate, x3dhRespond } from './x3dh.js';
import {
    ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt,
} from './ratchet.js';
import { encodeV2, decodeV2 } from './v2-envelope.js';
import { getSpkPrivate, getOpkPrivate, deleteOpkPrivate } from './prekey-store.js';

/** Ошибка установления/использования сессии — caller деградирует в плейсхолдер. */
export class SessionError extends Error {
    constructor(code, message) { super(message || code); this.name = 'SessionError'; this.code = code; }
}

/** Идентификатор парной сессии для DM-комнаты. */
export function dmSessionId(roomId) { return `dm:${roomId}`; }

// Импорт X25519-приватных из JWK-строк (полный {d,x} JWK, как хранит prekey-store)

/** Импортирует X25519 приватный из JWK-строки → CryptoKey. */
export async function importX25519PrivJwk(jwkString) {
    return crypto.subtle.importKey('jwk', JSON.parse(jwkString), { name: 'X25519' }, false, ['deriveBits']);
}

/** Извлекает hex публичного ключа из X25519 JWK-строки (поле x). */
function _pubHexFromX25519Jwk(jwkString) {
    const jwk = JSON.parse(jwkString);
    const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

// Отправка (написано для тестов; НЕ подключено к продовой отправке в 6a)

async function _establishInitiator(myIkPriv, myIkPubHex, peerBundle, plaintextBytes) {
    const opkPub = peerBundle.one_time_prekey || null;
    const { sharedSecret, ekPubHex } = await x3dhInitiate(
        myIkPriv, peerBundle.identity_key, peerBundle.signed_prekey, opkPub,
    );
    const state = await ratchetInitAlice(sharedSecret, peerBundle.signed_prekey);
    const { header, ciphertext } = await ratchetEncrypt(state, plaintextBytes);
    const prelude = {
        ikPubHex: myIkPubHex,
        ekPubHex,
        spkId: peerBundle.signed_prekey_id,
        opkId: peerBundle.one_time_prekey_id ?? null,
    };
    return { state, hex: encodeV2({ prelude, header, aead: ciphertext }) };
}

/**
 * Шифрует сообщение в парную сессию. Если сессии нет — устанавливает её как
 * инициатор (X3DH initiate) и шлёт prekey-сообщение; иначе — normal-сообщение.
 * @param {object} store — session-store
 * @param {string} sessionId
 * @param {{myIkPriv:CryptoKey, myIkPubHex:string, peerBundle:object}} ctx
 * @param {string} plaintext
 * @returns {Promise<string>} v2-конверт (hex)
 */
export async function encryptV2(store, sessionId, ctx, plaintext) {
    const pt = new TextEncoder().encode(plaintext);
    return store.withSession(sessionId, async (state) => {
        if (state) {
            const { header, ciphertext } = await ratchetEncrypt(state, pt);
            return { state, result: encodeV2({ prelude: null, header, aead: ciphertext }) };
        }
        const { state: newState, hex } = await _establishInitiator(
            ctx.myIkPriv, ctx.myIkPubHex, ctx.peerBundle, pt,
        );
        return { state: newState, result: hex };
    });
}

// Приём (подключается к продовому приёму в 6a)

/**
 * Расшифровывает v2-конверт. Если сессии нет и конверт prekey — устанавливает
 * её как ответчик (X3DH respond). Атомарно под блокировкой сессии.
 * @param {object} store — session-store
 * @param {string} sessionId
 * @param {{myIkPriv:CryptoKey, senderIdentityPubHex:string}} ctx
 * @param {string} envelopeHex
 * @returns {Promise<string>} plaintext
 * @throws {SessionError} при невозможности установить/расшифровать — caller деградирует
 */
export async function decryptV2(store, sessionId, ctx, envelopeHex) {
    let env;
    try {
        env = decodeV2(envelopeHex);
    } catch (e) {
        throw new SessionError('bad_envelope', e.message);
    }

    return store.withSession(sessionId, async (state) => {
        // Существующая сессия — расшифровываем (prekey-ретрансмит тоже сюда).
        if (state) {
            try {
                const pt = await ratchetDecrypt(state, env.header, env.aead);
                return { state, result: new TextDecoder().decode(pt) };
            } catch (e) {
                throw new SessionError('decrypt_failed', e.message);
            }
        }

        // Сессии нет: установить можно только из prekey-сообщения.
        if (!env.isPrekey) throw new SessionError('no_session');

        // TOFU: IK инициатора обязан совпасть с опубликованным identity отправителя.
        if (!ctx.senderIdentityPubHex || env.prelude.ikPubHex !== ctx.senderIdentityPubHex) {
            throw new SessionError('identity_mismatch');
        }

        // Приватные наши prekey (батч-4 пользователи их не имеют → деградация).
        const spk = getSpkPrivate(env.prelude.spkId);
        if (!spk) throw new SessionError('no_prekey_privates');
        const spkPriv = await importX25519PrivJwk(spk.jwk);
        const spkPubHex = _pubHexFromX25519Jwk(spk.jwk);

        let opkPriv = null;
        if (env.prelude.opkId != null) {
            const opkJwk = getOpkPrivate(env.prelude.opkId);
            if (opkJwk) opkPriv = await importX25519PrivJwk(opkJwk);
            // opkJwk == null → OPK уже израсходован (дубликат): X3DH без OPK не
            // сойдётся → ratchetDecrypt бросит → SessionError('decrypt_failed').
        }

        let shared;
        try {
            shared = await x3dhRespond(ctx.myIkPriv, spkPriv, opkPriv, env.prelude.ikPubHex, env.prelude.ekPubHex);
        } catch (e) {
            throw new SessionError('x3dh_failed', e.message);
        }

        const newState = ratchetInitBob(shared, spkPriv, spkPubHex);
        let pt;
        try {
            pt = await ratchetDecrypt(newState, env.header, env.aead);
        } catch (e) {
            throw new SessionError('decrypt_failed', e.message);
        }

        // Использованный OPK удаляем — forward secrecy (не сохраняем на будущее).
        if (env.prelude.opkId != null) deleteOpkPrivate(env.prelude.opkId);

        return { state: newState, result: new TextDecoder().decode(pt) };
    });
}

// static/js/dr/session.js
// Установление и использование парных v2-сессий Double Ratchet.
//
// Связывает X3DH (x3dh.js) + ратчет (ratchet.js) + хранилище состояния
// (session-store.js) + приватные prekey (prekey-store.js) + провод (v2-envelope.js).
//
// Область: 1:1 DM, device-rooted (Sesame). Сессия ключуется по устройству
// пира: `dm:<roomId>:<peerClientDeviceId>` (см. dmSessionId).
//
// БЕЗОПАСНОСТЬ: инициатор — КОНКРЕТНОЕ УСТРОЙСТВО; его X3DH-ключ (IK) — device
// x3dh key, аутентифицированный device-cert'ом инициатора, который едет в
// прелюде. decryptV2 проверяет cert (verifyDeviceCert) против ПРИПИНЕННОГО
// аккаунтного Ed25519 отправителя — устройство без валидного cert (в т.ч.
// вставленное сервером) отвергается. Корень доверия — припиненный аккаунтный
// Ed25519 (TOFU по нему; внеполосная safety-number — ортогональный трек).

import { x3dhInitiate, x3dhInitiatePq, x3dhRespond, x3dhRespondPq } from './x3dh.js';
import {
    ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt,
} from './ratchet.js';
import { encodeV2, decodeV2 } from './v2-envelope.js';
import { getSpkPrivate, getOpkPrivate, deleteOpkPrivate, getPqspkPrivate, getPqopkPrivate, deletePqopkPrivate } from './prekey-store.js';
import { verifyDeviceCert } from './device-identity.js';

/** Ошибка установления/использования сессии — caller деградирует в плейсхолдер. */
export class SessionError extends Error {
    constructor(code, message) { super(message || code); this.name = 'SessionError'; this.code = code; }
}

/** Идентификатор парной сессии: DM-комната × устройство пира (client_device_id). */
export function dmSessionId(roomId, peerDeviceId) { return `dm:${roomId}:${peerDeviceId}`; }

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

// Отправка инициатором (X3DH-initiate)

async function _establishInitiator(ctx, peerBundle, plaintextBytes) {
    const opkPub = peerBundle.one_time_prekey || null;
    // PQXDH-путь, если бандл несёт (проверенный, за флагом — гейтит message-cipher)
    // per-device Kyber pre-key; иначе классический X3DH. X3DH против DEVICE-ключей
    // пира (device_x3dh_pub = IK_B), IK_A = свой device x3dh.
    const usePq = peerBundle.device_kyber_pub != null && peerBundle.device_kyber_id != null;
    // PQOPK (one-time, KEM-FS) предпочтительнее last-resort PQSPK, если claim его дал.
    // id — ЕДИНЫЙ источник истины (адресат ключует decaps по нему): инкапсулируем к
    // PQOPK-pub только когда есть и id, иначе к PQSPK — чтобы pub и wire-id не разошлись.
    const pqopkId = usePq ? (peerBundle.one_time_kyber_prekey_id ?? null) : null;
    const pqTargetPub = pqopkId != null ? peerBundle.one_time_kyber_prekey : peerBundle.device_kyber_pub;
    let sharedSecret, ekPubHex, ctHex = null;
    if (usePq) {
        ({ sharedSecret, ekPubHex, ctHex } = await x3dhInitiatePq(
            ctx.myDeviceX3dhPriv, peerBundle.device_x3dh_pub, peerBundle.signed_prekey,
            opkPub, pqTargetPub,
        ));
    } else {
        ({ sharedSecret, ekPubHex } = await x3dhInitiate(
            ctx.myDeviceX3dhPriv, peerBundle.device_x3dh_pub, peerBundle.signed_prekey, opkPub,
        ));
    }
    const state = await ratchetInitAlice(sharedSecret, peerBundle.signed_prekey);
    const { header, ciphertext } = await ratchetEncrypt(state, plaintextBytes);
    const prelude = {
        ikPubHex: ctx.myDeviceX3dhPubHex,
        ekPubHex,
        spkId: peerBundle.signed_prekey_id,
        opkId: peerBundle.one_time_prekey_id ?? null,
        // device-cert инициатора едет в прелюде (ответчик привяжет к аккаунту)
        clientDeviceId: ctx.myCert.clientDeviceId,
        deviceSignPub: ctx.myCert.deviceSignPub,
        deviceCertSig: ctx.myCert.deviceCertSig,
    };
    if (usePq) {
        // 0x03-конверт: kyber_ciphertext + pqspk_id в прелюде (encodeV2 роутит по kyberCtHex).
        // pqopk_id задан ⟹ инкапсуляция была к one-time PQOPK (адресат возьмёт его priv).
        prelude.pqspkId = peerBundle.device_kyber_id;
        prelude.pqopkId = pqopkId;
        prelude.kyberCtHex = ctHex;
    }
    return { state, hex: encodeV2({ prelude, header, aead: ciphertext }) };
}

/**
 * Шифрует сообщение в парную сессию с КОНКРЕТНЫМ устройством пира. Если сессии
 * нет — устанавливает её как инициатор (X3DH initiate) и шлёт prekey-сообщение
 * (с device-cert'ом инициатора в прелюде); иначе — normal-сообщение.
 *
 * @param {object} store — session-store
 * @param {string} sessionId — dmSessionId(roomId, peerClientDeviceId)
 * @param {{myDeviceX3dhPriv:CryptoKey, myDeviceX3dhPubHex:string,
 *          myCert:{clientDeviceId:string, deviceSignPub:string, deviceCertSig:string},
 *          getPeerBundle:()=>Promise<object>}} ctx
 *        getPeerBundle (device-бандл пира) вызывается ТОЛЬКО при установлении.
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
        const peerBundle = await ctx.getPeerBundle();
        const { state: newState, hex } = await _establishInitiator(ctx, peerBundle, pt);
        return { state: newState, result: hex };
    });
}

// Приём

/**
 * Расшифровывает v2-конверт. Если сессии нет и конверт prekey — проверяет
 * device-cert инициатора и устанавливает сессию как ответчик (X3DH respond).
 * Атомарно под блокировкой сессии.
 * @param {object} store — session-store
 * @param {string} sessionId — dmSessionId(roomId, senderClientDeviceId)
 * @param {{myDeviceX3dhPriv:CryptoKey, trustedSenderAccountEd:string}} ctx
 *        trustedSenderAccountEd — ПРИПИНЕННЫЙ аккаунтный Ed25519 отправителя.
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

        // Аутентичность инициатора: device-cert из прелюды против ПРИПИНЕННОГО
        // аккаунтного Ed25519 отправителя (НЕ против ключа из прелюды — было бы
        // циркулярно). Устройство без валидного cert отвергается.
        if (!ctx.trustedSenderAccountEd) throw new SessionError('no_sender_pin');
        const certOk = await verifyDeviceCert(
            env.prelude.clientDeviceId, env.prelude.ikPubHex, env.prelude.deviceSignPub,
            env.prelude.deviceCertSig, ctx.trustedSenderAccountEd);
        if (!certOk) throw new SessionError('cert_invalid');

        // Приватные наши prekey (могут отсутствовать → деградация).
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

        // X3DH respond своим DEVICE x3dh priv (IK_B) + своим SPK priv.
        // PQXDH-конверт (0x03) несёт kyber_ciphertext → PQ-путь; иначе классика.
        let shared;
        if (env.prelude.kyberCtHex != null) {
            // Нужен локальный Kyber-priv: one-time PQOPK по pqopk_id (если задан),
            // иначе last-resort PQSPK по pqspk_id. Отсутствие — единственный
            // fail-closed сигнал: mlkemDecaps НЕ бросает (ML-KEM implicit rejection —
            // чужой/битый ct даёт ДРУГОЙ ss, не ошибку). Поэтому проверяем null ДО
            // decaps → SessionError → плейсхолдер (как no_prekey_privates). После
            // decaps расхождение ss всплывёт как ratchetDecrypt InvalidTag.
            const usePqopk = env.prelude.pqopkId != null;
            const pqSk = usePqopk
                ? getPqopkPrivate(env.prelude.pqopkId)
                : (getPqspkPrivate(env.prelude.pqspkId)?.sk ?? null);
            if (!pqSk) throw new SessionError(usePqopk ? 'no_pqopk_privates' : 'no_pqspk_privates');
            try {
                const { mlkemDecaps, mlkemGetPublic } = await import('./mlkem.js');
                const ss = mlkemDecaps(env.prelude.kyberCtHex, pqSk);
                // Собственный PQPK-pub — из своего sk (то, к чему Alice инкапсулировала).
                const pqpkOwnPubHex = mlkemGetPublic(pqSk);
                shared = await x3dhRespondPq(
                    ctx.myDeviceX3dhPriv, spkPriv, opkPriv,
                    env.prelude.ikPubHex, env.prelude.ekPubHex,
                    pqpkOwnPubHex, env.prelude.kyberCtHex, ss);
            } catch (e) {
                throw new SessionError('x3dh_failed', e.message);
            }
        } else {
            try {
                shared = await x3dhRespond(ctx.myDeviceX3dhPriv, spkPriv, opkPriv, env.prelude.ikPubHex, env.prelude.ekPubHex);
            } catch (e) {
                throw new SessionError('x3dh_failed', e.message);
            }
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
        // Использованный one-time PQOPK удаляем — KEM-forward-secrecy (P6).
        if (env.prelude.pqopkId != null) deletePqopkPrivate(env.prelude.pqopkId);

        return { state: newState, result: new TextDecoder().decode(pt) };
    });
}

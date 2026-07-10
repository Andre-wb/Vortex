// static/js/dr/ratchet.js
// Double Ratchet — состояние и операции encrypt/decrypt (ADR-001, батч 5).
// Соответствует RatchetState / ratchet_* в app/security/double_ratchet.py.
// Не подключено к продовому коду.
//
// RatchetState — обычный объект (мутируется на месте, как в Python):
//   dhSendingPriv     CryptoKey (X25519 private, extractable)
//   dhSendingPubHex   string  — наш текущий ratchet-публичный (для заголовков)
//   dhReceivingPubHex string|null — ratchet-публичный собеседника
//   rootKey           Uint8Array(32)
//   sendingChainKey   Uint8Array(32)|null
//   receivingChainKey Uint8Array(32)|null
//   sendCount, recvCount, prevSendCount  number
//   skipped           Map<`${pubHex}:${n}`, Uint8Array>  — value-keyed строкой

import {
    generateX25519, importX25519Priv, exportX25519PrivHex,
    dh, kdfCk, kdfRk, aeadEncrypt, aeadDecrypt, serializeHeader, toHex, fromHex,
} from './primitives.js';

// Лимит пропущенных ключей (DoS-защита), как MAX_SKIP в double_ratchet.py.
export const MAX_SKIP = 1000;

// Инициализация

/**
 * Alice (инициатор): первый DH-шаг с ratchet-ключом Bob.
 * @param {Uint8Array} sharedSecret — 32 байта из X3DH
 * @param {string} bobRatchetPubHex — публичный ratchet Bob (обычно его SPK)
 */
export async function ratchetInitAlice(sharedSecret, bobRatchetPubHex) {
    const alice = await generateX25519();
    const dhOut = await dh(alice.priv, bobRatchetPubHex);
    const { rootKey, chainKey } = await kdfRk(sharedSecret, dhOut);
    return {
        dhSendingPriv: alice.priv,
        dhSendingPubHex: alice.pubHex,
        dhReceivingPubHex: bobRatchetPubHex,
        rootKey,
        sendingChainKey: chainKey,
        receivingChainKey: null,
        sendCount: 0, recvCount: 0, prevSendCount: 0,
        skipped: new Map(),
    };
}

/**
 * Bob (ответчик): receiving-ключа ещё нет, DH-шаг произойдёт на первом входящем.
 * @param {Uint8Array} sharedSecret — 32 байта из X3DH (начальный root_key)
 * @param {CryptoKey} bobSpkPriv — приватный ratchet Bob (обычно его SPK private)
 * @param {string} bobSpkPubHex — публичный ratchet Bob
 */
export function ratchetInitBob(sharedSecret, bobSpkPriv, bobSpkPubHex) {
    return {
        dhSendingPriv: bobSpkPriv,
        dhSendingPubHex: bobSpkPubHex,
        dhReceivingPubHex: null,
        rootKey: sharedSecret,
        sendingChainKey: null,
        receivingChainKey: null,
        sendCount: 0, recvCount: 0, prevSendCount: 0,
        skipped: new Map(),
    };
}

// Шифрование / дешифрование

/**
 * Шифрует plaintext. Возвращает { header, ciphertext } — header открытый,
 * но участвует как AAD. Мутирует state.
 * @returns {Promise<{header: {dhPublicHex,prevCount,msgNumber}, ciphertext: Uint8Array}>}
 */
export async function ratchetEncrypt(state, plaintextBytes) {
    if (state.sendingChainKey === null) {
        throw new Error('Sending chain key not initialized — cannot encrypt');
    }
    const { newCk, mk } = await kdfCk(state.sendingChainKey);
    state.sendingChainKey = newCk;

    const header = {
        dhPublicHex: state.dhSendingPubHex,
        prevCount: state.prevSendCount,
        msgNumber: state.sendCount,
    };
    state.sendCount += 1;

    const ciphertext = await aeadEncrypt(mk, plaintextBytes, serializeHeader(header));
    return { header, ciphertext };
}

async function _trySkippedKeys(state, header, ciphertextBytes) {
    const key = `${header.dhPublicHex}:${header.msgNumber}`;
    if (state.skipped.has(key)) {
        const mk = state.skipped.get(key);
        state.skipped.delete(key);
        return aeadDecrypt(mk, ciphertextBytes, serializeHeader(header));
    }
    return null;
}

async function _skipMessageKeys(state, until) {
    if (state.receivingChainKey === null) return;
    if (until - state.recvCount > MAX_SKIP) {
        throw new Error(`Too many skipped messages: ${until - state.recvCount} (max ${MAX_SKIP})`);
    }
    while (state.recvCount < until) {
        const { newCk, mk } = await kdfCk(state.receivingChainKey);
        state.receivingChainKey = newCk;
        state.skipped.set(`${state.dhReceivingPubHex}:${state.recvCount}`, mk);
        state.recvCount += 1;
    }
}

async function _dhRatchetStep(state, header) {
    state.prevSendCount = state.sendCount;
    state.sendCount = 0;
    state.recvCount = 0;

    state.dhReceivingPubHex = header.dhPublicHex;

    let dhOut = await dh(state.dhSendingPriv, state.dhReceivingPubHex);
    ({ rootKey: state.rootKey, chainKey: state.receivingChainKey } = await kdfRk(state.rootKey, dhOut));

    const fresh = await generateX25519();
    state.dhSendingPriv = fresh.priv;
    state.dhSendingPubHex = fresh.pubHex;

    dhOut = await dh(state.dhSendingPriv, state.dhReceivingPubHex);
    ({ rootKey: state.rootKey, chainKey: state.sendingChainKey } = await kdfRk(state.rootKey, dhOut));
}

/**
 * Дешифрует сообщение. Мутирует state. Бросает при повреждении/лимите пропусков.
 * @param {object} header — { dhPublicHex, prevCount, msgNumber }
 * @returns {Promise<Uint8Array>} plaintext
 */
export async function ratchetDecrypt(state, header, ciphertextBytes) {
    const skippedPlain = await _trySkippedKeys(state, header, ciphertextBytes);
    if (skippedPlain !== null) return skippedPlain;

    if (state.dhReceivingPubHex !== header.dhPublicHex) {
        await _skipMessageKeys(state, header.prevCount);
        await _dhRatchetStep(state, header);
    }

    await _skipMessageKeys(state, header.msgNumber);

    const { newCk, mk } = await kdfCk(state.receivingChainKey);
    state.receivingChainKey = newCk;
    state.recvCount += 1;

    return aeadDecrypt(mk, ciphertextBytes, serializeHeader(header));
}

// Сериализация состояния

/**
 * Сериализует state в JSON-совместимый объект. Формат совпадает с
 * double_ratchet.serialize_state ПЛЮС поле dh_sending_pub (нужно JS для
 * восстановления {d,x} JWK; Python лишнее поле игнорирует).
 */
export async function serializeState(state) {
    const skipped = {};
    for (const [k, mk] of state.skipped.entries()) skipped[k] = toHex(mk);
    return {
        dh_sending: await exportX25519PrivHex(state.dhSendingPriv),
        dh_sending_pub: state.dhSendingPubHex,
        dh_receiving: state.dhReceivingPubHex,
        root_key: toHex(state.rootKey),
        sending_chain_key: state.sendingChainKey ? toHex(state.sendingChainKey) : null,
        receiving_chain_key: state.receivingChainKey ? toHex(state.receivingChainKey) : null,
        send_count: state.sendCount,
        recv_count: state.recvCount,
        prev_send_count: state.prevSendCount,
        skipped_keys: skipped,
    };
}

/** Восстанавливает state из объекта serializeState / augmented Python-вектора. */
export async function deserializeState(data) {
    const skipped = new Map();
    for (const [k, hex] of Object.entries(data.skipped_keys || {})) {
        skipped.set(k, fromHex(hex));
    }
    if (!data.dh_sending_pub) {
        throw new Error('deserializeState requires dh_sending_pub (Web Crypto needs JWK.x)');
    }
    return {
        dhSendingPriv: await importX25519Priv(data.dh_sending, data.dh_sending_pub),
        dhSendingPubHex: data.dh_sending_pub,
        dhReceivingPubHex: data.dh_receiving ?? null,
        rootKey: fromHex(data.root_key),
        sendingChainKey: data.sending_chain_key ? fromHex(data.sending_chain_key) : null,
        receivingChainKey: data.receiving_chain_key ? fromHex(data.receiving_chain_key) : null,
        sendCount: data.send_count || 0,
        recvCount: data.recv_count || 0,
        prevSendCount: data.prev_send_count || 0,
        skipped,
    };
}

// static/js/dr/x3dh.js
// X3DH (Extended Triple Diffie-Hellman) — начальный обмен ключами.
// Соответствует x3dh_initiate/x3dh_respond в app/security/double_ratchet.py.
//
// Подпись Signed Pre-Key здесь НЕ проверяется — верификация идентичности
// делается отдельно (сервер при публикации, клиент при получении бандла).
// X3DH тут только выполняет DH-обмен.

import { generateX25519, dh, kdfX3dh, kdfX3dhPq, concatBytes, X3DH_F, fromHex } from './primitives.js';

/**
 * Сторона Alice (инициатор). Вычисляет shared secret из 3–4 DH.
 *   DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B),
 *   DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) [опц.]
 * km = 0xFF*32 + DH1 + DH2 + DH3 [+ DH4]; shared = HKDF(km).
 *
 * @param {CryptoKey} ikPriv — приватный Identity Key Alice (X25519)
 * @param {string} ikPeerPubHex — публичный Identity Key Bob
 * @param {string} spkPeerPubHex — публичный Signed Pre-Key Bob
 * @param {string|null} opkPeerPubHex — публичный One-Time Pre-Key Bob (или null)
 * @returns {Promise<{sharedSecret: Uint8Array, ekPriv: CryptoKey, ekPubHex: string}>}
 */
export async function x3dhInitiate(ikPriv, ikPeerPubHex, spkPeerPubHex, opkPeerPubHex = null) {
    const ek = await generateX25519();

    const dh1 = await dh(ikPriv, spkPeerPubHex);
    const dh2 = await dh(ek.priv, ikPeerPubHex);
    const dh3 = await dh(ek.priv, spkPeerPubHex);

    let km = concatBytes(X3DH_F, dh1, dh2, dh3);
    if (opkPeerPubHex) {
        const dh4 = await dh(ek.priv, opkPeerPubHex);
        km = concatBytes(km, dh4);
    }

    const sharedSecret = await kdfX3dh(km);
    return { sharedSecret, ekPriv: ek.priv, ekPubHex: ek.pubHex };
}

/**
 * Сторона Bob (ответчик). Зеркальные DH к initiate.
 *   DH1 = DH(SPK_B, IK_A), DH2 = DH(IK_B, EK_A),
 *   DH3 = DH(SPK_B, EK_A), DH4 = DH(OPK_B, EK_A) [если OPK использован]
 *
 * @param {CryptoKey} ikPriv — приватный Identity Key Bob
 * @param {CryptoKey} spkPriv — приватный Signed Pre-Key Bob
 * @param {CryptoKey|null} opkPriv — приватный One-Time Pre-Key Bob (или null)
 * @param {string} ikPeerPubHex — публичный Identity Key Alice
 * @param {string} ekPeerPubHex — публичный Ephemeral Key Alice
 * @returns {Promise<Uint8Array>} shared secret (32 байта) — тот же, что у Alice
 */
export async function x3dhRespond(ikPriv, spkPriv, opkPriv, ikPeerPubHex, ekPeerPubHex) {
    const dh1 = await dh(spkPriv, ikPeerPubHex);
    const dh2 = await dh(ikPriv, ekPeerPubHex);
    const dh3 = await dh(spkPriv, ekPeerPubHex);

    let km = concatBytes(X3DH_F, dh1, dh2, dh3);
    if (opkPriv) {
        const dh4 = await dh(opkPriv, ekPeerPubHex);
        km = concatBytes(km, dh4);
    }

    return kdfX3dh(km);
}

/**
 * PQXDH initiate (Alice). Классический X3DH km + KEM к device Kyber pre-key пира.
 * Инкапсулирует к PQPK_B (ML-KEM-768) → (CT, SS); привязка §3.2 ADR-006:
 *   km_pq = 0xFF*32 ‖ DH1‖DH2‖DH3[‖DH4] ‖ PQPK_B ‖ CT ‖ SS
 *   shared = HKDF(km_pq, info="vortex-pqxdh").
 * ML-KEM грузится лениво (вендор ~28КБ — только на PQXDH-инициацию).
 *
 * @param {CryptoKey} ikPriv — приватный device IK Alice (X25519)
 * @param {string} ikPeerPubHex — публичный device IK Bob
 * @param {string} spkPeerPubHex — публичный SPK Bob
 * @param {string|null} opkPeerPubHex — публичный OPK Bob (или null)
 * @param {string} pqpkPeerPubHex — публичный Kyber pre-key Bob (1184 байта hex)
 * @returns {Promise<{sharedSecret: Uint8Array, ekPriv: CryptoKey, ekPubHex: string, ctHex: string}>}
 *          ctHex — KEM ciphertext, едет в прелюде 0x03 (Bob декапсулирует).
 */
export async function x3dhInitiatePq(ikPriv, ikPeerPubHex, spkPeerPubHex, opkPeerPubHex, pqpkPeerPubHex) {
    const ek = await generateX25519();

    const dh1 = await dh(ikPriv, spkPeerPubHex);
    const dh2 = await dh(ek.priv, ikPeerPubHex);
    const dh3 = await dh(ek.priv, spkPeerPubHex);

    let km = concatBytes(X3DH_F, dh1, dh2, dh3);
    if (opkPeerPubHex) {
        const dh4 = await dh(ek.priv, opkPeerPubHex);
        km = concatBytes(km, dh4);
    }

    const { mlkemEncaps } = await import('./mlkem.js');
    const { cipherTextHex, sharedSecret: ss } = mlkemEncaps(pqpkPeerPubHex);
    const sharedSecret = await kdfX3dhPq(km, fromHex(pqpkPeerPubHex), fromHex(cipherTextHex), ss);
    return { sharedSecret, ekPriv: ek.priv, ekPubHex: ek.pubHex, ctHex: cipherTextHex };
}

/**
 * PQXDH respond (Bob). Зеркальные DH + km_pq с УЖЕ декапсулированным SS.
 *
 * decaps KEM выполняет ВЫЗЫВАЮЩИЙ (session.js) своим PQSPK-приватным (аналогично
 * тому, как он грузит SPK-priv) и передаёт сюда ssBytes + собственный PQPK-pub +
 * ct. Это делает функцию ЧИСТОЙ и детерминированной → прямо сверяемой с вектором
 * x3dh_pq через тот же путь kdfX3dhPq (без второго code-path, без drift).
 *
 * @param {CryptoKey} ikPriv — приватный device IK Bob
 * @param {CryptoKey} spkPriv — приватный SPK Bob
 * @param {CryptoKey|null} opkPriv — приватный OPK Bob (или null)
 * @param {string} ikPeerPubHex — публичный device IK Alice
 * @param {string} ekPeerPubHex — публичный EK Alice
 * @param {string} pqpkOwnPubHex — собственный Kyber pre-key pub Bob (тот, к которому инкапсулировала Alice)
 * @param {string} ctHex — KEM ciphertext из прелюды
 * @param {Uint8Array} ssBytes — KEM shared secret (Bob декапсулировал ctHex своим PQSPK-priv)
 * @returns {Promise<Uint8Array>} shared secret — тот же, что у Alice
 */
export async function x3dhRespondPq(ikPriv, spkPriv, opkPriv, ikPeerPubHex, ekPeerPubHex, pqpkOwnPubHex, ctHex, ssBytes) {
    const dh1 = await dh(spkPriv, ikPeerPubHex);
    const dh2 = await dh(ikPriv, ekPeerPubHex);
    const dh3 = await dh(spkPriv, ekPeerPubHex);

    let km = concatBytes(X3DH_F, dh1, dh2, dh3);
    if (opkPriv) {
        const dh4 = await dh(opkPriv, ekPeerPubHex);
        km = concatBytes(km, dh4);
    }

    return kdfX3dhPq(km, fromHex(pqpkOwnPubHex), fromHex(ctHex), ssBytes);
}

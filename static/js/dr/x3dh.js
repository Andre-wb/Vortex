// static/js/dr/x3dh.js
// X3DH (Extended Triple Diffie-Hellman) — начальный обмен ключами.
// Соответствует x3dh_initiate/x3dh_respond в app/security/double_ratchet.py.
// ADR-001, батч 5. Не подключено к продовому коду.
//
// Подпись Signed Pre-Key здесь НЕ проверяется — верификация идентичности
// делается отдельно (батч 4: серверная verify_spk_signature; клиентская
// проверка бандла — батч 6). X3DH тут только выполняет DH-обмен.

import { generateX25519, dh, kdfX3dh, concatBytes, X3DH_F } from './primitives.js';

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

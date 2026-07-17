// static/js/chat/enc-version.js
// Реестр версий шифрования конверта сообщений.
//
//   0 — legacy: прямой AES-256-GCM на roomKey (голый или padded 0x5678)
//   1 — sender-chain: симметричная HKDF-цепочка, seed = roomKey (текущий формат)
//   2 — pairwise Double Ratchet (зарезервировано)
//   3 — групповые sender-keys поверх DR (зарезервировано)
//
// enc_v — поле JSON-конверта. Отсутствие поля = до-версионное сообщение,
// расшифровка идёт по существующей эвристике (crypto.js:349, :356).

export const ENC_V_CURRENT = 1;

/**
 * Известна ли клиенту версия конверта. Отсутствие поля (null/undefined)
 * считается известным: это до-версионные сообщения v0/v1, которые
 * различаются эвристикой внутри ratchetDecrypt.
 */
export function isKnownEncVersion(v) {
    return v === undefined || v === null || v === 0 || v === ENC_V_CURRENT;
}

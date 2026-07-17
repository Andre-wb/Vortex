// static/js/dr/identity-pin.js
// TOFU-пиннинг аккаунтного Ed25519 пира — корня доверия device-cert'ов.
//
// Device-cert доказывает «устройство авторизовано аккаунтом X» только если
// аккаунтный Ed25519 X зафиксирован ВНЕ канала сервера. Если проверять cert
// против identity_key_ed, отданного сервером в том же бандле, — проверка
// декоративна: злонамеренный сервер подставит свой Ed25519 и cert под него
// (ADR-003 §4.1 «инъекция криптографически невозможна» верно ТОЛЬКО при пине).
//
// Поэтому: аккаунтный Ed25519 пира пиннится на ПЕРВЫЙ контакт (TOFU) и все
// device-cert'ы (и на отправке, и на приёме) проверяются против ПИНА. Смена
// ключа у известного пира — событие идентичности (block/warn), НЕ тихий апдейт.
//
// Стабильность пина обеспечена 0-bis (аккаунтный Ed25519 переживает logout и не
// форкается): рутинный логин восстанавливает тот же ключ; смена = реальная
// ре-регистрация/сброс. Внеполосная верификация пина (safety-number) —
// ортогональный трек поверх TOFU.

const _slot = (peerUserId) => `vortex_peer_acct_ed_${peerUserId}`;

/**
 * Пинит аккаунтный Ed25519 пира (TOFU) и возвращает статус:
 *   { trusted: edPubHex }      — совпал с пином (или впервые запинен);
 *   { changed: true, pinned }  — известный пир прислал ДРУГОЙ ключ (block/warn);
 *   { missing: true }          — edPubHex не передан.
 * На смене пин НЕ перезаписывается — это осознанное событие идентичности.
 * @param {string|number} peerUserId
 * @param {string} edPubHex — аккаунтный Ed25519 пира (identity_key_ed из бандла)
 */
export function pinPeerAccountEd(peerUserId, edPubHex) {
    if (!edPubHex) return { missing: true };
    const slot = _slot(peerUserId);
    let existing = null;
    try { existing = localStorage.getItem(slot); } catch { /* storage недоступен */ }
    if (!existing) {
        try { localStorage.setItem(slot, edPubHex); } catch { /* ignore */ }
        return { trusted: edPubHex };
    }
    if (existing !== edPubHex) return { changed: true, pinned: existing };
    return { trusted: existing };
}

/** Возвращает запиненный аккаунтный Ed25519 пира или null. */
export function pinnedPeerAccountEd(peerUserId) {
    try { return localStorage.getItem(_slot(peerUserId)); } catch { return null; }
}

/** Снимает пин (removeAccount / явный сброс доверия к пиру). */
export function clearPeerAccountEdPin(peerUserId) {
    try { localStorage.removeItem(_slot(peerUserId)); } catch { /* ignore */ }
}

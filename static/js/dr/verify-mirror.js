// static/js/dr/verify-mirror.js
// ADR-008 §4.2: кросс-девайсный мирор OOB-верификаций участников.
//
// Проблема: OOB-верификация («я сверил account-Ed пира вне канала») хранится
// локально (vortex_verified_ed_<peer>) → не переживает переход на другое устройство.
// Решение, НЕ ломающее «сервер недоверен»: устройство подписывает атестацию своим
// DEVICE-ключом (account-Ed приватного на линкованном устройстве нет — blast-radius),
// приложив device-cert (account-Ed подписал device-триплет). Сервер хранит и отдаёт
// владельцу его же записи, но подделать не может (нет приватных). Другое устройство
// владельца верифицирует device-cert→СВОЙ account-Ed + attest-sig и применяет.
//
// Мирор — лишь синхронизация локального hint. Заворачивание room-key (G3) НЕЗАВИСИМО
// ре-чекает живой ed против сохранённого верифицированного → подделка/откат мирора не
// даёт завернуть на подменённый ключ. Дормантно за флагом vortex_verify_mirror_enabled
// (дефолт ВЫКЛ, opt-in). Kill-switch — снять флаг.

import { edSign, edVerify, loadAccountLinkMaterial, loadEd25519Identity } from './prekeys.js';
import { loadOrCreateDeviceIdentity, verifyDeviceCert } from './device-identity.js';
import { markIdentityVerified, unmarkIdentityVerified } from './member-verify.js';
import { api } from '../utils.js';

function _mirrorEnabled() {
    try { return localStorage.getItem('vortex_verify_mirror_enabled') === '1'; } catch { return false; }
}

/**
 * Каноническая полезная нагрузка атестации (cross-impl ЗАФИКСИРОВАНА, §4.7 —
 * sort/регистр не при чём, но ed в LOWERCASE, разделитель ':').
 *   "vortex-verify-attest:v1:" + owner + ":" + peer + ":" + ed_lower + ":" + state + ":" + signed_at
 * @returns {Uint8Array}
 */
export function attestPayload(ownerUserId, peerUserId, verifiedEdHex, state, signedAt) {
    const s = `vortex-verify-attest:v1:${ownerUserId}:${peerUserId}:${String(verifiedEdHex).toLowerCase()}:${state}:${signedAt}`;
    return new TextEncoder().encode(s);
}

/** account-Ed pub (hex) этого аккаунта, из любого доступного источника. */
function _myAccountEdPub(userId) {
    return loadAccountLinkMaterial(userId)?.accountEdPub
        || loadEd25519Identity()?.pubHex
        || null;
}

/**
 * Подписать и опубликовать атестацию верификации (или её отзыв). No-op при
 * выключенном флаге или отсутствии device-cert (устройство ещё не авторизовано).
 * @param {number|string} peerUserId
 * @param {string} verifiedEdHex — account-Ed пира, который я сверил
 * @param {'verified'|'revoked'} state
 */
export async function publishAttestation(peerUserId, verifiedEdHex, state) {
    if (!_mirrorEnabled()) return;
    const owner = window.AppState?.user?.user_id;
    if (!owner || !verifiedEdHex) return;
    try {
        const dev = await loadOrCreateDeviceIdentity();
        if (!dev?.certSig || !dev.signPriv) return;      // cert не выпущен → нечем подтвердить авторство
        const signedAt = Math.floor(Date.now() / 1000);
        const attest_sig = await edSign(dev.signPriv, attestPayload(owner, peerUserId, verifiedEdHex, state, signedAt));
        await api('POST', '/api/verify/attestations', {
            peer_user_id:     Number(peerUserId),
            verified_ed:      String(verifiedEdHex).toLowerCase(),
            state,
            signed_at:        signedAt,
            client_device_id: dev.deviceId,
            device_x3dh_pub:  dev.x3dhPub,
            device_sign_pub:  dev.signPub,
            device_cert_sig:  dev.certSig,
            attest_sig,
        });
    } catch (e) {
        console.debug('[verify-mirror] publish skipped:', e?.message);
    }
}

/**
 * Синхронизировать OOB-верификации с сервера на это устройство. Для каждой записи:
 * device-cert должен вести к МОЕМУ account-Ed (подписант — авторизованное устройство
 * этого аккаунта) И attest-sig валиден под device-ключом. Только тогда применяем.
 * @returns {Promise<{applied:number, rejected:number}>}
 */
export async function syncAttestations() {
    const out = { applied: 0, rejected: 0 };
    if (!_mirrorEnabled()) return out;
    const owner = window.AppState?.user?.user_id;
    const myAccountEd = owner ? _myAccountEdPub(owner) : null;
    if (!owner || !myAccountEd) return out;

    let rows = [];
    try {
        const resp = await api('GET', '/api/verify/attestations');
        rows = resp?.attestations || [];
    } catch (e) {
        console.debug('[verify-mirror] sync fetch failed:', e?.message);
        return out;
    }

    for (const r of rows) {
        try {
            // 1. Подписант — авторизованное устройство МОЕГО аккаунта (cert→мой account-Ed).
            const certOk = await verifyDeviceCert(
                r.client_device_id, r.device_x3dh_pub, r.device_sign_pub, r.device_cert_sig, myAccountEd);
            if (!certOk) { out.rejected++; continue; }
            // 2. Атестацию реально подписал этот device-ключ.
            const sigOk = await edVerify(
                r.device_sign_pub,
                attestPayload(owner, r.peer_user_id, r.verified_ed, r.state, r.signed_at),
                r.attest_sig);
            if (!sigOk) { out.rejected++; continue; }

            if (r.state === 'verified') markIdentityVerified(r.peer_user_id, String(r.verified_ed).toLowerCase());
            else if (r.state === 'revoked') unmarkIdentityVerified(r.peer_user_id);
            out.applied++;
        } catch { out.rejected++; }
    }
    return out;
}

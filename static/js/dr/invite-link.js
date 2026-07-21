// static/js/dr/invite-link.js
// Offline-join по анонимной ссылке (ADR-005 O5b, клиент). Член генерит invite-
// keypair (X25519 + ML-KEM), оборачивает room key на invite-pub → escrow на сервер;
// приватные invite-ключи — ТОЛЬКО во фрагменте ссылки (`#…`, сервер не видит).
// re-wrap на ротации: после нового room key член заново оборачивает все активные
// invite'ы (identity персистит, O5a). Всё за флагом vortex_offline_invite_enabled.

import { getRoomKey, setRoomKey, hybridEciesEncrypt, hybridEciesDecrypt } from '../crypto.js';
import { mlkemKeygen } from './mlkem.js';
import { api } from '../utils.js';

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const b64url = s => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlDecode = s => atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4));

/** invite_pub (hex) из X25519 приватного JWK — поле `x` это публичный (base64url). */
function _invitePubFromJwk(jwkStr) {
    const jwk = JSON.parse(jwkStr);
    const bin = b64urlDecode(jwk.x);
    return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function offlineInviteEnabled() {
    try { return localStorage.getItem('vortex_offline_invite_enabled') === '1'; } catch { return false; }
}

/**
 * Создаёт invite-ссылку с escrow: генерит invite-пару (X25519+ML-KEM), оборачивает
 * room key на invite-pub, грузит escrow, возвращает ссылку с приватными во фрагменте.
 * @param {number} roomId
 * @param {string} inviteCode — короткий room invite_code (для вступления)
 * @returns {Promise<string|null>} полная ссылка или null (флаг ВЫКЛ / нет ключа)
 */
export async function createInviteLink(roomId, inviteCode) {
    if (!offlineInviteEnabled()) return null;
    const roomKey = getRoomKey(roomId);
    if (!roomKey) return null;

    const x = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const invitePub = toHex(await crypto.subtle.exportKey('raw', x.publicKey));
    const invitePrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', x.privateKey));
    const kyber = mlkemKeygen();   // {publicKeyHex, secretKeyHex}

    const env = await hybridEciesEncrypt(roomKey, invitePub, kyber.publicKeyHex);
    await api('POST', `/api/rooms/${roomId}/invite-escrow`, {
        invite_pub: invitePub, invite_kyber_pub: kyber.publicKeyHex, ...env,
    });

    // Фрагмент несёт ОБА приватных invite-ключа (X25519 JWK + ML-KEM hex)
    const secret = b64url(JSON.stringify({ x: invitePrivJwk, k: kyber.secretKeyHex }));
    return `${location.origin}/join/${inviteCode}#${secret}`;
}

/**
 * Re-wrap escrow'ов после ротации room key: identity инвайтов персистит (O5a), но
 * обёртки на старый ключ удалены → оборачиваем НОВЫЙ ключ для каждого invite_pub.
 * Цепляется в key_rotated-хендлер (клиент, сгенерировавший новый ключ). Идемпотентно
 * (upsert по invite_pub, last-wins).
 * @param {number} roomId
 * @param {Uint8Array} [roomKey] — новый ключ (иначе берётся из хранилища)
 */
export async function rewrapInvitesAfterRotation(roomId, roomKey) {
    if (!offlineInviteEnabled()) return;
    const rk = roomKey || getRoomKey(roomId);
    if (!rk) return;
    let invites = [];
    try { invites = (await api('GET', `/api/rooms/${roomId}/invites`))?.invites || []; }
    catch { return; }
    for (const iv of invites) {
        try {
            const env = await hybridEciesEncrypt(rk, iv.invite_pub, iv.invite_kyber_pub || null);
            await api('POST', `/api/rooms/${roomId}/invite-escrow`, {
                invite_pub: iv.invite_pub, invite_kyber_pub: iv.invite_kyber_pub, ...env,
            });
        } catch { /* один invite не должен ронять остальные */ }
    }
}

/**
 * Вступающий забирает room key из escrow по ссылке (ADR-005 O6). Извлекает
 * приватные invite-ключи из фрагмента, выводит invite_pub, фетчит escrow
 * (**membership-gated на сервере** — вступающий уже член), расшифровывает своими
 * приватными. Устаревший/отсутствующий escrow или decrypt-провал → null → caller
 * падает в key_request (self-heal §4.0, best-effort). За флагом.
 * @param {number} roomId
 * @param {string} fragment — часть ссылки после `#` (b64url({x,k})); можно с ведущим `#`
 * @returns {Promise<Uint8Array|null>} room key или null (fallback в key_request)
 */
export async function redeemInviteEscrow(roomId, fragment) {
    if (!offlineInviteEnabled()) return null;
    if (getRoomKey(roomId)) return null;              // ключ уже есть — escrow не нужен
    if (!fragment) return null;
    if (fragment[0] === '#') fragment = fragment.slice(1);
    let secret;
    try { secret = JSON.parse(b64urlDecode(fragment)); } catch { return null; }
    if (!secret || !secret.x) return null;

    let invitePub;
    try { invitePub = _invitePubFromJwk(secret.x); } catch { return null; }

    let resp;
    try { resp = await api('GET', `/api/rooms/${roomId}/invite-escrow?invite_pub=${invitePub}`); }
    catch { return null; }                            // не член / сеть → fallback
    if (!resp || !resp.has_escrow) return null;       // устаревший/отсутствует → key_request

    try {
        const roomKey = await hybridEciesDecrypt(resp, secret.x, secret.k || null);
        setRoomKey(roomId, roomKey);
        return roomKey;
    } catch { return null; }                          // мёртвый ключ (best-effort) → key_request
}

if (typeof window !== 'undefined') {
    window.createInviteLink = createInviteLink;
    window.rewrapInvitesAfterRotation = rewrapInvitesAfterRotation;
    window.redeemInviteEscrow = redeemInviteEscrow;
}

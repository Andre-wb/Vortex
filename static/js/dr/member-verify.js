// static/js/dr/member-verify.js
// ADR-008 G2: верификация личности участника группы + ядро wrap-гейта (G3).
//
// Composes: identity-pin (TOFU-пин account-Ed25519 пира — корень доверия) +
// edVerify цепочки (X25519/Kyber ← Ed через identity_key_sig / kyber_public_key_sig,
// ADR-008 §1) + локальная OOB-verified запись. Верификация account-Ed транзитивно
// покрывает X25519+Kyber.
//
// Несущий инвариант (ADR-008 §3): возвращает ПРОВЕРЕННЫЙ x25519/kyber — то, на что
// МОЖНО заворачивать room-key. Гейт (G3) обязан завернуть на verifiedX25519 и
// проверить, что серверный for_pubkey == verifiedX25519, иначе abort. Сервер
// недоверен — вся суть в клиентской сверке цепочки против ПИНА, не against данных сервера.

import { edVerify } from './prekeys.js';
import { pinPeerAccountEd } from './identity-pin.js';
import { resolvePeerKyberPub } from './pq-capability.js';
import { api } from '../utils.js';

const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));
const _vslot = (userId) => `vortex_verified_ed_${userId}`;

/**
 * Отмечает: я OOB-сверил account-Ed этого юзера вне канала. Хранится ЛОКАЛЬНО
 * (сервер недоверен → не источник «verified»). Верификация привязана к КОНКРЕТНОМУ
 * Ed: смена ключа → запись перестаёт совпадать → статус падает (через пин).
 * @param {number|string} userId
 * @param {string} edPubHex — account Ed25519, который я сверил
 */
export function markIdentityVerified(userId, edPubHex) {
    if (!edPubHex) return;
    try { localStorage.setItem(_vslot(userId), edPubHex); } catch { /* storage недоступен */ }
}

/** Снимает OOB-верификацию. */
export function unmarkIdentityVerified(userId) {
    try { localStorage.removeItem(_vslot(userId)); } catch { /* ignore */ }
}

/** Верифицирован ли ИМЕННО этот Ed (совпадает с локально OOB-подтверждённым)? */
export function isIdentityVerified(userId, edPubHex) {
    if (!edPubHex) return false;
    try { return localStorage.getItem(_vslot(userId)) === edPubHex; } catch { return false; }
}

const _fail = (ed) => ({ status: 'changed', verifiedX25519: null, verifiedKyber: null, verifiedKyberSig: null, ed });

/**
 * Проверяет личность участника по member-keys-цепочке (G1-эндпоинт).
 *
 * @param {number|string} userId
 * @param {{identity_key_ed?:string, x25519_public_key?:string, identity_key_sig?:string,
 *          kyber_public_key?:string, kyber_public_key_sig?:string}} entry — запись из /member-keys
 * @returns {Promise<{status:'self'|'verified'|'unverified'|'changed',
 *                    verifiedX25519:string|null, verifiedKyber:string|null,
 *                    verifiedKyberSig:string|null, ed:string|null}>}
 *          verifiedX25519 — ключ, НА КОТОРЫЙ можно заворачивать (null при changed).
 */
export async function verifyMemberIdentity(userId, entry) {
    const ed = entry?.identity_key_ed || null;
    const x25519 = entry?.x25519_public_key || null;
    const kyber = entry?.kyber_public_key || null;

    // Своё устройство — не верифицируем себя.
    if (userId != null && userId === window.AppState?.user?.user_id) {
        return { status: 'self', verifiedX25519: x25519, verifiedKyber: kyber,
                 verifiedKyberSig: entry?.kyber_public_key_sig || null, ed };
    }

    // 1. Пин account-Ed (TOFU). Смена известного Ed → changed (активная атака / сброс аккаунта).
    const pin = pinPeerAccountEd(userId, ed);
    if (pin.changed) return _fail(ed);
    if (pin.missing || !ed) {
        // Нет account-Ed (нет v2-идентичности) — нечем верифицировать цепочку.
        return { status: 'unverified', verifiedX25519: x25519, verifiedKyber: kyber,
                 verifiedKyberSig: entry?.kyber_public_key_sig || null, ed: null };
    }
    // pin.trusted — Ed консистентен с пином.

    // 2. X25519 ← Ed. Подпись ЕСТЬ и НЕ сходится → подмена X25519 сервером → changed.
    if (x25519 && entry.identity_key_sig) {
        if (!(await edVerify(ed, fromHex(x25519), entry.identity_key_sig))) return _fail(ed);
    } else {
        // Нет подписи над X25519 → неверифицируемо (не атака, но и не доверенно).
        return { status: 'unverified', verifiedX25519: x25519, verifiedKyber: null, verifiedKyberSig: null, ed };
    }

    // 3. Kyber ← Ed (опционально, PQ). Подпись есть и не сходится → changed.
    let vKyber = null, vKyberSig = null;
    if (kyber && entry.kyber_public_key_sig) {
        if (!(await edVerify(ed, fromHex(kyber), entry.kyber_public_key_sig))) return _fail(ed);
        vKyber = kyber; vKyberSig = entry.kyber_public_key_sig;
    }

    // 4. Цепочка валидна. verified iff я OOB-сверил ИМЕННО этот Ed; иначе unverified (TOFU).
    const status = isIdentityVerified(userId, ed) ? 'verified' : 'unverified';
    return { status, verifiedX25519: x25519, verifiedKyber: vKyber, verifiedKyberSig: vKyberSig, ed };
}

// Гейт обёртки room-key. Флаг vortex_member_verify_enabled: дефолт ВКЛ — фетч
// member-keys + верификация перед обёрткой. Kill-switch: явный '0' → passthrough
// (обёртка на серверный for_pubkey, как без верификации).
function _gateEnabled() {
    try { return localStorage.getItem('vortex_member_verify_enabled') !== '0'; } catch { return false; }
}

// Hard-mode (ADR-008 §4.4, opt-in, дефолт ВЫКЛ): allow ТОЛЬКО verified/self. Обычный
// гейт заворачивает на unverified (TOFU) с предупреждением; hard-mode блокирует его И
// неверифицируемые пути (no_chain/not_member) — иначе сервер индуцирует fetch-fail и
// через passthrough заворачивает на свой for_pubkey, обойдя весь гейт. Строгая posture
// (Signal-style): доступность в обмен на отказ доверять без ручной сверки. Kill-switch —
// снять флаг (мастер-выключатель — сам гейт vortex_member_verify_enabled='0').
export function isHardModeEnabled() {
    try { return localStorage.getItem('vortex_verify_hard_mode') === '1'; } catch { return false; }
}

/** Программно вкл/выкл hard-mode (для настроек UI). */
export function setHardMode(on) {
    try {
        if (on) localStorage.setItem('vortex_verify_hard_mode', '1');
        else localStorage.removeItem('vortex_verify_hard_mode');
    } catch { /* storage недоступен */ }
}

async function _passthrough(forPubkey, forUserId, forKyber, forKyberSig, status) {
    // Passthrough: kyber через resolvePeerKyberPub (проверяет kyber-sig против пина).
    const k = await resolvePeerKyberPub(forUserId, forKyber, forKyberSig);
    return { allow: true, wrapX25519: forPubkey, wrapKyber: k, status };
}

/**
 * Гейт: можно ли завернуть room-key на этого участника, и НА КАКОЙ ключ (ADR-008 G3 §3).
 *
 * Флаг ВЫКЛ → passthrough (обёртка на серверный for_pubkey, kyber через resolvePeerKyberPub).
 * Флаг ВКЛ → фетч member-keys (G1) → verifyMemberIdentity:
 *   - changed (пин-mismatch / sig-fail) → **BLOCK** (allow=false), fail-closed;
 *   - for_pubkey != проверенный x25519 → **BLOCK** (подмена сервером, инвариант §3);
 *   - unverified (TOFU) → warn + allow (в hard-mode → **BLOCK** `unverified_hardblock`);
 *   - обёртка ВСЕГДА на ПРОВЕРЕННЫЙ x25519/kyber (не на серверный for_pubkey).
 * Нет member-keys / не член (race/сеть) → passthrough (не блокируем легитимную обёртку).
 *
 * @returns {Promise<{allow:boolean, wrapX25519:string|null, wrapKyber:string|null, status:string}>}
 */
export async function verifyMemberForWrap(roomId, forUserId, forPubkey, forKyber, forKyberSig) {
    if (!_gateEnabled()) return _passthrough(forPubkey, forUserId, forKyber, forKyberSig, 'gate_off');

    // Hard-mode fail-CLOSED на неверифицируемых путях: сервер сам отдаёт /member-keys,
    // значит может индуцировать 500/пустой ответ и через passthrough завернуть на свой
    // for_pubkey (обойдя и changed-, и unverified-блок). Для strict-posture это
    // недопустимо — блокируем. Обычный гейт остаётся fail-open (availability для всех).
    const hard = isHardModeEnabled();
    let entry = null;
    try {
        const resp = await api('GET', `/api/rooms/${roomId}/member-keys`);
        entry = (resp?.members || []).find(m => String(m.user_id) === String(forUserId)) || null;
    } catch (e) {
        console.debug('[member-verify] member-keys fetch failed:', e?.message);
        if (hard) return { allow: false, wrapX25519: null, wrapKyber: null, status: 'no_chain_hardblock' };
        return _passthrough(forPubkey, forUserId, forKyber, forKyberSig, 'no_chain');
    }
    if (!entry) {
        if (hard) return { allow: false, wrapX25519: null, wrapKyber: null, status: 'not_member_hardblock' };
        return _passthrough(forPubkey, forUserId, forKyber, forKyberSig, 'not_member');
    }

    const v = await verifyMemberIdentity(forUserId, entry);
    if (v.status === 'changed') {
        console.warn('[member-verify] BLOCK wrap — участник', forUserId, 'сменил идентичность (changed)');
        return { allow: false, wrapX25519: null, wrapKyber: null, status: 'changed' };
    }
    // Инвариант §3: серверный for_pubkey ОБЯЗАН равняться проверенному, иначе подмена.
    if (v.verifiedX25519 && forPubkey && forPubkey.toLowerCase() !== v.verifiedX25519.toLowerCase()) {
        console.warn('[member-verify] BLOCK wrap — for_pubkey != проверенный x25519 (подмена сервером)');
        return { allow: false, wrapX25519: null, wrapKyber: null, status: 'pubkey_mismatch' };
    }
    if (v.status === 'unverified') {
        if (hard) {
            console.warn('[member-verify] BLOCK wrap — hard-mode: участник', forUserId, 'не OOB-верифицирован');
            return { allow: false, wrapX25519: null, wrapKyber: null, status: 'unverified_hardblock' };
        }
        console.warn('[member-verify] обёртка на НЕверифицированного участника', forUserId, '(TOFU)');
    }
    return { allow: true, wrapX25519: v.verifiedX25519 || forPubkey, wrapKyber: v.verifiedKyber, status: v.status };
}

/**
 * Статусы верификации всех участников комнаты (ADR-008 G4) — источник F1-бейджей,
 * F3-индикатора «N из M», F4-детекта changed. Фетчит member-keys (G1),
 * verifyMemberIdentity по каждому. Своё устройство ('self') в счётчики не идёт.
 * @returns {Promise<{statuses:Object, entries:Object, verified:number, total:number, changed:number}>}
 */
export async function getMemberStatuses(roomId) {
    const out = { statuses: {}, entries: {}, verified: 0, total: 0, changed: 0 };
    let members = [];
    try {
        const resp = await api('GET', `/api/rooms/${roomId}/member-keys`);
        members = resp?.members || [];
    } catch (e) {
        console.debug('[member-verify] statuses fetch failed:', e?.message);
        return out;
    }
    for (const entry of members) {
        const v = await verifyMemberIdentity(entry.user_id, entry);
        out.statuses[entry.user_id] = v.status;
        out.entries[entry.user_id] = entry;
        if (v.status === 'self') continue;
        out.total += 1;
        if (v.status === 'verified') out.verified += 1;
        else if (v.status === 'changed') out.changed += 1;
    }
    return out;
}

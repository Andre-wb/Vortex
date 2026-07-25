// static/js/dr/kt-evidence.js
// ADR-009 Фаза 2: удержание кросс-наблюдательной улики + аффорданс эскалации.
//
// Клиент СЕГОДНЯ выбрасывает нода-подписанную атестацию старого ключа пира (§2 ADR-009).
// Здесь мы её УДЕРЖИВАЕМ ЛОКАЛЬНО при принятии идентичности пира. Смысл несущий: злая
// нода может убрать старую запись из раздаваемого лога (withholding), но НЕ из моего
// локального стора. На смене ключа собираем пару «старая (локально) + новая (из лога)» —
// два нода-подписанных утверждения, связывающих ОДНОГО юзера с ДВУМЯ account-Ed.
//
// КРУКС (§4): это RESET-НЕОДНОЗНАЧНАЯ улика, НЕ fork-пруф. Phase 2 НЕ различает
// легитимный сброс от атаки (это Фаза 3 — STH/consistency). Поэтому — предупреждение
// человеку + экспорт для эскалации, НИКОГДА автоматическое действие/бан.
//
// Дормантно за vortex_kt_evidence_enabled (дефолт ВЫКЛ). Каждая атестация несёт СВОЙ
// node_pubkey → глобальный display-пин Фазы 1 не промоутится в реальный сигнал.

import { verifyKtLog, ktEntryMessage } from './kt-verify.js';
import { edVerify } from './prekeys.js';

function _enabled() {
    try { return localStorage.getItem('vortex_kt_evidence_enabled') === '1'; } catch { return false; }
}

const _slot = (peerId) => `vortex_kt_attest_${peerId}`;

/** SHA-256(utf8(hex-строка)) — ЗЕРКАЛО серверного pub_key_hash (sha256(pub_key_hex.encode())). */
export async function ktPubKeyHash(edHex) {
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(edHex)));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function _now() { return Math.floor(Date.now() / 1000); }

/** @returns {object|null} локально удержанная атестация account-Ed пира. */
export function getRetained(peerId) {
    try { return JSON.parse(localStorage.getItem(_slot(peerId))); } catch { return null; }
}

/** Сбрасывает удержанную атестацию (после того как человек пере-сверил новую личность). */
export function clearRetained(peerId) {
    try { localStorage.removeItem(_slot(peerId)); } catch { /* ignore */ }
}

/**
 * Находит нода-подписанную account_ed запись для конкретного ed в KT-логе пира.
 * @returns {Promise<{keyType,userId,pubKeyHash,prevHash,seq,nodeSig,nodePubkey,accountEdHex}|null>}
 */
async function _fetchAttestation(peerId, accountEdHex) {
    const wantHash = await ktPubKeyHash(accountEdHex);
    const kt = await verifyKtLog(peerId);
    if (!kt.nodePubkey) return null;
    const e = (kt.entries || []).find(
        x => x.key_type === 'account_ed' && x.pub_key_hash === wantHash && x.sig === 'ok');
    if (!e) return null;
    return {
        keyType: 'account_ed', userId: Number(peerId), pubKeyHash: e.pub_key_hash,
        prevHash: e.prev_hash || null, seq: e.seq, nodeSig: e.node_sig,
        nodePubkey: kt.nodePubkey, accountEdHex: String(accountEdHex).toLowerCase(),
    };
}

/**
 * Удержать нода-подписанную атестацию текущей (принятой) идентичности пира. No-op при
 * выключенном флаге или отсутствии нода-подписи. Зовётся при OOB-сверке пира.
 */
export async function retainAttestation(peerId, accountEdHex) {
    if (!_enabled() || !peerId || !accountEdHex) return null;
    // Дедуп: уже удержали эту же личность → не фетчим повторно (throttle KT-запроса).
    const cur = getRetained(peerId);
    if (cur && String(cur.accountEdHex).toLowerCase() === String(accountEdHex).toLowerCase()) return cur;
    try {
        const att = await _fetchAttestation(peerId, accountEdHex);
        if (!att) return null;
        const rec = { ...att, at: _now() };
        localStorage.setItem(_slot(peerId), JSON.stringify(rec));
        return rec;
    } catch (e) {
        console.debug('[kt-evidence] retain skipped:', e?.message);
        return null;
    }
}

/**
 * На смене account-Ed пира — собрать пару «старая (локально) + новая (из лога)».
 * @returns {Promise<{peerId, old, new, resetAmbiguous:true}|null>} null, если нет
 *   удержанной старой ИЛИ новая не нода-подписана ИЛИ ключ не изменился.
 */
export async function detectEquivocation(peerId, newAccountEdHex) {
    if (!_enabled() || !newAccountEdHex) return null;
    const old = getRetained(peerId);
    if (!old || !old.nodeSig) return null;
    if (String(old.accountEdHex).toLowerCase() === String(newAccountEdHex).toLowerCase()) return null;
    const fresh = await _fetchAttestation(peerId, newAccountEdHex);
    if (!fresh || !fresh.nodeSig) return null;
    return { peerId: Number(peerId), old, new: { ...fresh, at: _now() }, resetAmbiguous: true };
}

/**
 * Сериализует пару в самодостаточный, самопроверяемый блоб для эскалации (§2 ADR-009).
 * Получатель третьей стороной реконструирует ktEntryMessage и проверяет node_sig — без
 * доверия отправителю. Это НЕ fork-пруф (reset-неоднозначно) — эскалация человеку.
 */
export function exportEvidence(ev) {
    const stmt = (a) => ({
        key_type: a.keyType, user_id: a.userId, pub_key_hash: a.pubKeyHash,
        prev_hash: a.prevHash, seq: a.seq, node_sig: a.nodeSig,
        node_pubkey: a.nodePubkey, account_ed_hex: a.accountEdHex,
    });
    return JSON.stringify({
        vortex_kt_evidence: 'v1',
        peer_user_id: ev.peerId,
        reset_ambiguous: true,
        statements: [stmt(ev.old), stmt(ev.new)],
        note: 'Two node-signed statements bind THE SAME user to two account-Ed keys. '
            + 'Self-verifiable (reconstruct vortex-kt-entry:v1 message, check node_sig; '
            + 'confirm same user_id and node_pubkey). NOT a fork-proof — ambiguous between '
            + 'legitimate account reset, server substitution, and node migration (differing node_pubkey).',
    }, null, 2);
}

/**
 * Проверяет самодостаточность экспортированного блоба (то, что делает третья сторона
 * БЕЗ доверия отправителю): каждая statement нода-подписана, hash = sha256(ed), И обе
 * про ОДНОГО юзера (иначе — бессмысленная «улика» из ключей разных людей).
 *
 * `sameNode` различает случаи: разные node_pubkey = легитимная миграция ноды (§ Фаза 1),
 * НЕ эквивокация. Честная неоднозначность шире reset: reset-vs-attack-vs-migration.
 * @returns {Promise<{valid:boolean, distinctKeys:boolean, sameNode:boolean}>}
 */
export async function verifyEvidenceBlob(blob) {
    const bad = { valid: false, distinctKeys: false, sameNode: false };
    const o = typeof blob === 'string' ? JSON.parse(blob) : blob;
    const st = o?.statements || [];
    if (st.length !== 2) return bad;
    // Обе про одного юзера и совпадают с peer_user_id — иначе это не «пара про пира».
    if (st[0].user_id !== st[1].user_id) return bad;
    if (o.peer_user_id != null && st[0].user_id !== o.peer_user_id) return bad;
    // Улика = ДВА РАЗНЫХ ключа одного типа. Идентичные/разнотипные statements — не улика.
    if (st[0].key_type !== st[1].key_type) return bad;
    if (st[0].pub_key_hash === st[1].pub_key_hash) return bad;
    for (const s of st) {
        const sigOk = await edVerify(
            s.node_pubkey,
            ktEntryMessage(s.user_id, s.key_type, s.pub_key_hash, s.prev_hash, s.seq),
            s.node_sig);
        if (!sigOk) return bad;
        if ((await ktPubKeyHash(s.account_ed_hex)) !== s.pub_key_hash) return bad;
    }
    return {
        valid: true,
        distinctKeys: st[0].pub_key_hash !== st[1].pub_key_hash,
        sameNode: st[0].node_pubkey === st[1].node_pubkey,
    };
}

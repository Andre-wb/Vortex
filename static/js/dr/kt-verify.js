// static/js/dr/kt-verify.js
// ADR-009 Фаза 1: клиентская проверка нода-подписи записей прозрачного лога.
//
// КРУКС (§4): подпись ≠ детекция. Нода-подпись доказывает лишь «нода под ключом K
// заявила эту запись», НЕ «ключ честный» (противник — сама нода, она подпишет и
// подменённое). Поэтому результат здесь — ФАКТИЧЕСКАЯ улика (кто подписал, сошлось
// ли), НИКОГДА не зелёный «verified/безопасно». Детекцию (fork vs reset) даёт лишь
// Фаза 3 (кросс-юзерный STH + gossip). §7: не воспроизводить театр старого бейджа,
// который рисовал «verified» из серверного же audit.valid.

import { edVerify } from './prekeys.js';
import { api } from '../utils.js';

const _NODE_PIN = 'vortex_kt_node_pubkey';

/** Каноническая нагрузка нода-подписи — ЗЕРКАЛО сервера (_kt_entry_message, фикс-строка). */
export function ktEntryMessage(userId, keyType, pubKeyHash, prevHash, seq) {
    return new TextEncoder().encode(
        `vortex-kt-entry:v1:${userId}:${keyType}:${pubKeyHash}:${prevHash || ''}:${seq}`);
}

/**
 * Проверяет нода-подписи KT-лога пользователя. Возвращает УЛИКУ, не вердикт-доверия.
 * @returns {Promise<{nodePubkey:string, total:number, signed:number, badSig:number,
 *                    nodeKeyChanged:boolean, entries:Array}>}
 */
export async function verifyKtLog(userId) {
    const out = { nodePubkey: '', total: 0, signed: 0, badSig: 0, nodeKeyChanged: false, entries: [] };
    let resp;
    try {
        resp = await api('GET', `/api/keys/transparency/${userId}`);
    } catch (e) {
        console.debug('[kt-verify] fetch failed:', e?.message);
        return out;
    }
    out.nodePubkey = resp?.node_pubkey || '';
    const entries = resp?.entries || [];
    out.total = entries.length;

    // TOFU-пин ключа ноды: смена — сигнал (первый шаг к пиннингу; полноценно — Фаза 2/3).
    if (out.nodePubkey) {
        try {
            const prev = localStorage.getItem(_NODE_PIN);
            if (prev && prev !== out.nodePubkey) out.nodeKeyChanged = true;
            else if (!prev) localStorage.setItem(_NODE_PIN, out.nodePubkey);
        } catch { /* storage недоступен */ }
    }

    for (const e of entries) {
        let sig = null;
        if (e.node_sig && out.nodePubkey) {
            try {
                const ok = await edVerify(
                    out.nodePubkey, ktEntryMessage(userId, e.key_type, e.pub_key_hash, e.prev_hash, e.seq), e.node_sig);
                sig = ok ? 'ok' : 'bad';
                if (ok) out.signed++; else out.badSig++;
            } catch { sig = 'bad'; out.badSig++; }
        } else {
            sig = 'none';   // legacy-запись без нода-подписи (до Фазы 1) — не улика атаки
        }
        out.entries.push({ ...e, sig });
    }
    return out;
}

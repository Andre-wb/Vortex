// static/js/dr/history-store.js
// Персистентный локальный стор расшифрованного плейнтекста v2-сообщений
// (ADR-001, закрытие главного гейта §2.7).
//
// ЗАЧЕМ. Double Ratchet структурно не может повторно расшифровать сообщение с
// уже израсходованным ключом. Vortex же перерасшифровывает историю из
// серверного шифртекста при каждом открытии комнаты → v2-история иначе
// превращалась бы в плейсхолдеры после перезагрузки. Решение (как message-DB в
// Signal): при ПЕРВОЙ живой расшифровке кэшируем плейнтекст локально; история
// и дубли доставки читаются из кэша, БЕЗ повторного расхода ключей ратчета.
//
// БЕЗОПАСНОСТЬ. Плейнтекст не лежит в IndexedDB в открытом виде: он пере-
// шифрован AES-256-GCM под per-account локальным ключом (localStorage
// `vortex_dr_hist_key_<userId>`). Профиль совпадает с v1 (roomKey+шифртекст,
// оба локальные): доступ к истории требует и ключ, и БД. Ключ чистится при
// logout (префикс `vortex_dr_`) и removeAccount.

import { indexedDbBackend } from './session-store.js';

const HIST_KEY_PREFIX = 'vortex_dr_hist_key';

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function _historyKey() {
    const userId = window.AppState?.user?.user_id;
    if (!userId) throw new Error('history store requires a logged-in user');
    const name = `${HIST_KEY_PREFIX}_${userId}`;
    let hex = localStorage.getItem(name);
    if (!hex) {
        hex = toHex(crypto.getRandomValues(new Uint8Array(32)));
        localStorage.setItem(name, hex);
    }
    return crypto.subtle.importKey('raw', fromHex(hex), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * @param {object} backend — KV { get, put, delete } (IndexedDB или in-memory)
 * @returns стор с put/get/delete по (roomId, msgId)
 */
export function createHistoryStore(backend) {
    const k = (roomId, msgId) => `${roomId}:${msgId}`;
    return {
        /** Кэширует плейнтекст (пере-шифрованный). No-op при отсутствии msgId. */
        async put(roomId, msgId, plaintext) {
            if (msgId == null) return;
            const key = await _historyKey();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext),
            );
            await backend.put(k(roomId, msgId), { iv: toHex(iv), ct: toHex(new Uint8Array(ct)) });
        },

        /** @returns {Promise<string|null>} кэшированный плейнтекст или null. */
        async get(roomId, msgId) {
            if (msgId == null) return null;
            const rec = await backend.get(k(roomId, msgId));
            if (!rec || !rec.iv || !rec.ct) return null;
            try {
                const key = await _historyKey();
                const pt = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: fromHex(rec.iv) }, key, fromHex(rec.ct),
                );
                return new TextDecoder().decode(pt);
            } catch {
                return null;   // ключ сменился/запись битая — как cache miss
            }
        },

        async delete(roomId, msgId) {
            await backend.delete(k(roomId, msgId));
        },
    };
}

/**
 * Cache-first расшифровка: кэш → иначе decryptThunk() + кэшируем результат.
 * Кэш переживает перезагрузку и делает дубли доставки идемпотентными (не
 * расходуют ключ ратчета повторно).
 * @param {object} store — createHistoryStore(...)
 * @param {string|number} roomId
 * @param {string|number} msgId
 * @param {() => Promise<string>} decryptThunk — живая транспортная расшифровка
 * @returns {Promise<string>} plaintext
 */
export async function decryptWithCache(store, roomId, msgId, decryptThunk) {
    const cached = await store.get(roomId, msgId);
    if (cached != null) return cached;
    const pt = await decryptThunk();
    try {
        await store.put(roomId, msgId, pt);
    } catch (e) {
        console.debug('[v2] history cache write failed:', e?.message);
    }
    return pt;
}

/** Продовый бэкенд истории на IndexedDB. */
export function historyBackend() {
    return indexedDbBackend('vortex_v2_history', 'messages');
}

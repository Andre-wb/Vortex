// static/js/dr/session-store.js
// Персистентное хранилище DR-сессий с дисциплиной single-writer.
//
// Состояние DR мутабельно: параллельное продвижение ратчета из двух вкладок
// форкает сессию и необратимо ломает расшифровку. Поэтому все операции
// над сессией идут под Web Locks (navigator.locks) с per-session ключом.
// BroadcastChannel для DR-состояния ЗАПРЕЩЁН (источник форков).
//
// Бэкенд хранения инъектируется (тестопригодность без реального IndexedDB):
//   backend: { get(key)->Promise<obj|null>, put(key,obj)->Promise, delete(key)->Promise }
// Продовый бэкенд — IndexedDB (indexedDbBackend), тестовый — in-memory.

import { serializeState, deserializeState } from './ratchet.js';

const KEY_PREFIX = 'dr-session:';

/**
 * @param {object} backend — KV-бэкенд { get, put, delete }
 * @param {object} [opts]
 * @param {object} [opts.lockManager] — navigator.locks-совместимый (для тестов);
 *        по умолчанию берётся navigator.locks, при отсутствии — без блокировки.
 */
export function createSessionStore(backend, opts = {}) {
    const lockManager = opts.lockManager
        || (typeof navigator !== 'undefined' ? navigator.locks : null);

    async function withLock(sessionId, fn) {
        if (lockManager && typeof lockManager.request === 'function') {
            return lockManager.request(`vortex-dr-${sessionId}`, fn);
        }
        // Web Locks недоступны (например, старый браузер) — single-writer НЕ
        // гарантирован. Деградируем, но помечаем: это осознанный fallback.
        console.warn('[dr] Web Locks unavailable — DR session single-writer not enforced');
        return fn();
    }

    const k = sessionId => `${KEY_PREFIX}${sessionId}`;

    return {
        /** Выполняет fn под per-session блокировкой (single-writer). */
        withLock,

        /** Загружает состояние сессии или null. Вызывать под withLock. */
        async load(sessionId) {
            const raw = await backend.get(k(sessionId));
            return raw ? deserializeState(raw) : null;
        },

        /** Сохраняет состояние сессии. Вызывать под withLock. */
        async save(sessionId, state) {
            await backend.put(k(sessionId), await serializeState(state));
        },

        /** Удаляет сессию. */
        async delete(sessionId) {
            return backend.delete(k(sessionId));
        },

        /**
         * Атомарно (под блокировкой) load → fn(state) → save. Единственный
         * безопасный способ провести encrypt/decrypt: загрузка, мутация/создание
         * и запись состояния — под одной блокировкой, без гонки вкладок.
         *
         * Контракт fn: получает текущее состояние (или null для новой сессии) и
         * возвращает { state, result }, где state — состояние для сохранения
         * (то же мутированное ЛИБО новосозданное для prekey-сообщения; null —
         * не сохранять), result — возвращаемое значение (например, plaintext).
         *
         * @param {string} sessionId
         * @param {(state: object|null) => Promise<{state: object|null, result: any}>} fn
         * @returns {Promise<any>} result из fn
         */
        async withSession(sessionId, fn) {
            return withLock(sessionId, async () => {
                const raw = await backend.get(k(sessionId));
                const state = raw ? await deserializeState(raw) : null;
                const { state: nextState, result } = await fn(state);
                if (nextState) {
                    await backend.put(k(sessionId), await serializeState(nextState));
                }
                return result;
            });
        },
    };
}

/**
 * Продовый бэкенд на IndexedDB. Хранит сериализованные объекты состояния.
 * @param {string} [dbName]
 * @param {string} [storeName]
 */
export function indexedDbBackend(dbName = 'vortex_dr', storeName = 'sessions') {
    let _dbPromise = null;

    function _open() {
        if (_dbPromise) return _dbPromise;
        _dbPromise = new Promise((resolve, reject) => {
            const req = indexedDB.open(dbName, 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(storeName)) db.createObjectStore(storeName);
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
        return _dbPromise;
    }

    function _tx(mode, fn) {
        return _open().then(db => new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, mode);
            const store = tx.objectStore(storeName);
            const req = fn(store);
            tx.oncomplete = () => resolve(req && req.result);
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        }));
    }

    return {
        get: key => _tx('readonly', store => store.get(key)).then(v => v ?? null),
        put: (key, value) => _tx('readwrite', store => store.put(value, key)),
        delete: key => _tx('readwrite', store => store.delete(key)),
    };
}

/** In-memory бэкенд (тесты / fallback). */
export function memoryBackend() {
    const map = new Map();
    return {
        get: async key => (map.has(key) ? JSON.parse(map.get(key)) : null),
        put: async (key, value) => { map.set(key, JSON.stringify(value)); },
        delete: async key => { map.delete(key); },
    };
}

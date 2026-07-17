/**
 * history-store.test.js
 * Локальный стор плейнтекста v2-истории: пере-шифрование под
 * per-account ключом, put/get/delete, cache-first (decryptWithCache) —
 * решает ре-рендер истории и дубли доставки без повторного расхода ключей.
 */

const { createHistoryStore, decryptWithCache } = require('../dr/history-store.js');
const { memoryBackend } = require('../dr/session-store.js');

beforeEach(() => {
    localStorage.clear();
    window.AppState = { user: { user_id: 7 } };
});

describe('createHistoryStore (re-encrypted at rest)', () => {
    test('put → get round-trip', async () => {
        const store = createHistoryStore(memoryBackend());
        await store.put(42, 100, 'секретная история');
        expect(await store.get(42, 100)).toBe('секретная история');
    });

    test('get промаха возвращает null', async () => {
        const store = createHistoryStore(memoryBackend());
        expect(await store.get(42, 999)).toBeNull();
    });

    test('put без msgId — no-op', async () => {
        const store = createHistoryStore(memoryBackend());
        await store.put(42, null, 'x');
        expect(await store.get(42, null)).toBeNull();
    });

    test('в бэкенде НЕ лежит плейнтекст (только iv+ct)', async () => {
        const backend = memoryBackend();
        const store = createHistoryStore(backend);
        await store.put(42, 100, 'PLAINTEXT_MARKER');
        const rec = await backend.get('42:100');
        expect(rec.iv).toMatch(/^[0-9a-f]{24}$/);
        expect(rec.ct).toMatch(/^[0-9a-f]+$/);
        expect(JSON.stringify(rec)).not.toContain('PLAINTEXT_MARKER');
    });

    test('другой account (сменившийся ключ) не может расшифровать → null', async () => {
        const backend = memoryBackend();
        const store = createHistoryStore(backend);
        await store.put(42, 100, 'мой плейнтекст');
        // Сменили аккаунт → другой history-ключ → cache miss (не краш)
        window.AppState = { user: { user_id: 8 } };
        expect(await store.get(42, 100)).toBeNull();
    });

    test('delete удаляет запись', async () => {
        const store = createHistoryStore(memoryBackend());
        await store.put(42, 100, 'x');
        await store.delete(42, 100);
        expect(await store.get(42, 100)).toBeNull();
    });
});

describe('decryptWithCache (cache-first)', () => {
    test('cache miss → зовёт thunk и кэширует', async () => {
        const store = createHistoryStore(memoryBackend());
        const thunk = jest.fn().mockResolvedValue('расшифровано вживую');
        const r = await decryptWithCache(store, 42, 100, thunk);
        expect(r).toBe('расшифровано вживую');
        expect(thunk).toHaveBeenCalledTimes(1);
        expect(await store.get(42, 100)).toBe('расшифровано вживую');
    });

    test('cache hit → НЕ зовёт thunk (история/дубль не расходуют ключ ратчета)', async () => {
        const store = createHistoryStore(memoryBackend());
        await store.put(42, 100, 'из кэша');
        const thunk = jest.fn().mockResolvedValue('не должно вызваться');
        const r = await decryptWithCache(store, 42, 100, thunk);
        expect(r).toBe('из кэша');
        expect(thunk).not.toHaveBeenCalled();
    });

    test('повторная доставка того же msgId идемпотентна (thunk один раз)', async () => {
        const store = createHistoryStore(memoryBackend());
        const thunk = jest.fn().mockResolvedValue('m0');
        await decryptWithCache(store, 42, 100, thunk);   // первая доставка
        await decryptWithCache(store, 42, 100, thunk);   // дубль
        expect(thunk).toHaveBeenCalledTimes(1);          // ратчет продвинут только раз
    });

    test('ошибка записи кэша не роняет расшифровку', async () => {
        const brokenStore = {
            get: async () => null,
            put: async () => { throw new Error('IDB write failed'); },
        };
        const r = await decryptWithCache(brokenStore, 42, 100, async () => 'ok despite write fail');
        expect(r).toBe('ok despite write fail');
    });
});

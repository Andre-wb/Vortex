/**
 * room-key-heal.test.js
 * O2b: self-heal негодного room-key (ADR-005 §4.0). Правило детекции (хилить всё
 * КРОМЕ "requires local Kyber identity" + только при загруженном priv), удаление
 * СЕРВЕРНОЙ строки, bounded-not-spinning, reset на успехе.
 */

jest.mock('../utils.js', () => ({ api: jest.fn() }));

const { api } = require('../utils.js');
const { selfHealRoomKey, markRoomKeyHealthy } = require('../chat/room-crypto.js');

beforeEach(() => {
    api.mockReset();
    api.mockResolvedValue({});
});

test('нехилимо: "requires local Kyber identity" → skip, без DELETE', async () => {
    const r = await selfHealRoomKey(1, new Error('hybrid room key requires local Kyber identity'), true);
    expect(r).toBe('skip');
    expect(api).not.toHaveBeenCalled();
});

test('false-positive guard: priv не загружен → skip, без DELETE', async () => {
    const r = await selfHealRoomKey(2, new Error('OperationError'), false);
    expect(r).toBe('skip');
    expect(api).not.toHaveBeenCalled();
});

test('валидный провал + priv → healing, удаляет СЕРВЕРНУЮ строку', async () => {
    const r = await selfHealRoomKey(3, new Error('The operation failed'), true);
    expect(r).toBe('healing');
    expect(api).toHaveBeenCalledWith('DELETE', '/api/rooms/3/my-key');
});

test('bounded-not-spinning: после HEAL_MAX(2) → unrecoverable, НЕ крутит', async () => {
    expect(await selfHealRoomKey(4, new Error('x'), true)).toBe('healing');   // 1
    expect(await selfHealRoomKey(4, new Error('x'), true)).toBe('healing');   // 2
    api.mockClear();
    const r = await selfHealRoomKey(4, new Error('x'), true);                 // 3 → стоп
    expect(r).toBe('unrecoverable');
    expect(api).not.toHaveBeenCalled();
});

test('reset на успехе: markRoomKeyHealthy → можно снова хилить', async () => {
    await selfHealRoomKey(5, new Error('x'), true);
    await selfHealRoomKey(5, new Error('x'), true);   // HEAL_MAX достигнут
    markRoomKeyHealthy(5);
    api.mockClear();
    const r = await selfHealRoomKey(5, new Error('x'), true);
    expect(r).toBe('healing');
    expect(api).toHaveBeenCalledWith('DELETE', '/api/rooms/5/my-key');
});

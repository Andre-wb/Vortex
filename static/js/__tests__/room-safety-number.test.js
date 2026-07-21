/**
 * room-safety-number.test.js (ADR-008 G5)
 * computeRoomSafetyNumber: агрегированный код группы. Cross-impl пин с Python
 * (та же сериализация — sort LOWERCASE hex, домен "vortex-room-sn:v1"), sort-
 * независимость (все участники видят один код), детект смены ключа/состава.
 */

const { computeRoomSafetyNumber } = require('../fingerprint.js');

// Вектор из Python (app/tests/test_room_safety_number.py — тот же расчёт).
const EDS = ['ff'.repeat(32), 'aa'.repeat(32), '0f'.repeat(32)];
const HASHHEX = '14820ad9c2507332d385f6e164b448e28b1b89b96e90ea0ebecb95efac10475a';

test('cross-impl: JS room_sn == Python-вектор', async () => {
    const r = await computeRoomSafetyNumber(42, EDS);
    expect(r.hashHex).toBe(HASHHEX);
});

test('порядок/регистр входа не влияет (sort lowercase) → все видят один код', async () => {
    const a = await computeRoomSafetyNumber(42, ['FF'.repeat(32), 'aa'.repeat(32), '0f'.repeat(32)]);
    const b = await computeRoomSafetyNumber(42, ['0f'.repeat(32), 'AA'.repeat(32), 'ff'.repeat(32)]);
    expect(a.hashHex).toBe(b.hashHex);
    expect(a.hashHex).toBe(HASHHEX);
});

test('смена ключа одного участника → ДРУГОЙ код (детект)', async () => {
    const base = await computeRoomSafetyNumber(42, EDS);
    const changed = await computeRoomSafetyNumber(42, ['ff'.repeat(32), 'aa'.repeat(32), 'be'.repeat(32)]);
    expect(changed.hashHex).not.toBe(base.hashHex);
});

test('room_id входит в код (разные комнаты → разные коды)', async () => {
    const a = await computeRoomSafetyNumber(42, EDS);
    const b = await computeRoomSafetyNumber(43, EDS);
    expect(a.hashHex).not.toBe(b.hashHex);
});

test('формат: UPPERCASE hex-блоки по 4 + 6 emoji', async () => {
    const r = await computeRoomSafetyNumber(42, EDS);
    expect(r.blocks).toMatch(/^([0-9A-F]{4} )+[0-9A-F]{1,4}$/);
    expect(r.emojis).toHaveLength(6);
    expect(r.hashHex).toMatch(/^[0-9a-f]{64}$/);
});

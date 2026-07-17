/**
 * v2-fanout.test.js
 * M2/M3.2b: контейнер fan-out `{ from, subs }`. `from` — устройство-отправитель
 * (маршрутизация сессии на приёме), `subs` — карта под-конвертов по получателю.
 * Выбор своего под-конверта, passthrough одиночного envelope. Fan-out шифрование
 * (производство карт) — на M3.2c; здесь контейнер тестируется на синтетике.
 */

const { getClientDeviceId } = require('../utils.js');
const {
    isFanoutBlob, encodeFanout, decodeFanout, selectForThisDevice,
    fanoutDeviceCount, fanoutSender,
} = require('../dr/v2-fanout.js');

// Правдоподобные одиночные v2-envelope hex (тип 0x02 normal + произвольный хвост)
const ENV_A = '02' + 'aa'.repeat(40);
const ENV_B = '02' + 'bb'.repeat(40);
const SENDER = 'ee'.repeat(16);   // client_device_id устройства-отправителя

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    window.AppState = { user: { user_id: 7 } };
});

describe('формат контейнера', () => {
    test('encode → decode round-trip (from + subs)', () => {
        const subs = { ['11'.repeat(16)]: ENV_A, ['22'.repeat(16)]: ENV_B };
        const blob = encodeFanout(SENDER, subs);
        expect(isFanoutBlob(blob)).toBe(true);
        const obj = decodeFanout(blob);
        expect(obj.from).toBe(SENDER);
        expect(obj.subs).toEqual(subs);
        expect(fanoutSender(blob)).toBe(SENDER);
    });

    test('одиночный envelope hex НЕ распознаётся как blob', () => {
        expect(isFanoutBlob(ENV_A)).toBe(false);
        expect(decodeFanout(ENV_A)).toBeNull();
        expect(fanoutDeviceCount(ENV_A)).toBe(0);
        expect(fanoutSender(ENV_A)).toBeNull();
    });

    test('битый blob → decode null (в т.ч. без from)', () => {
        expect(decodeFanout('v2fan:not-json')).toBeNull();
        expect(decodeFanout('v2fan:{"nope":1}')).toBeNull();
        expect(decodeFanout('v2fan:{"subs":{}}')).toBeNull();   // нет from → невалиден
    });

    test('encodeFanout требует from и объект subs', () => {
        expect(() => encodeFanout(null, { a: ENV_A })).toThrow();      // нет from
        expect(() => encodeFanout(SENDER, null)).toThrow();           // subs не объект
        expect(() => encodeFanout(SENDER, 'x')).toThrow();
    });
});

describe('выбор под-конверта на приёме', () => {
    test('одиночный envelope проходит как есть (passthrough)', () => {
        expect(selectForThisDevice(ENV_A, '11'.repeat(16))).toBe(ENV_A);
    });

    test('синтетическая карта на 2 устройства: каждое выбирает свой под-конверт', () => {
        const devA = '11'.repeat(16), devB = '22'.repeat(16);
        const blob = encodeFanout(SENDER, { [devA]: ENV_A, [devB]: ENV_B });
        // Один blob хранится/доставляется как одна строка (анонимность BMP)
        expect(typeof blob).toBe('string');
        expect(fanoutDeviceCount(blob)).toBe(2);
        // from общий, каждое устройство извлекает СВОЙ под-конверт
        expect(fanoutSender(blob)).toBe(SENDER);
        expect(selectForThisDevice(blob, devA)).toBe(ENV_A);
        expect(selectForThisDevice(blob, devB)).toBe(ENV_B);
    });

    test('blob без под-конверта для нашего устройства → null (не нам)', () => {
        const blob = encodeFanout(SENDER, { ['11'.repeat(16)]: ENV_A });
        expect(selectForThisDevice(blob, '99'.repeat(16))).toBeNull();
    });

    test('deviceId по умолчанию — getClientDeviceId()', () => {
        const myId = getClientDeviceId();
        const blob = encodeFanout(SENDER, { [myId]: ENV_A, ['33'.repeat(16)]: ENV_B });
        expect(selectForThisDevice(blob)).toBe(ENV_A);
    });
});

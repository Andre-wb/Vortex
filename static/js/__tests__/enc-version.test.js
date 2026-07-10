/**
 * enc-version.test.js
 * Тесты реестра версий конверта (ADR-001, батч 2): клиент считает
 * известными отсутствие поля (до-версионные v0/v1-сообщения) и версии 0/1;
 * любая более новая версия — неизвестна (рендерится плейсхолдер,
 * расшифровка не пытается угадать формат).
 */

const { ENC_V_CURRENT, isKnownEncVersion } = require('../chat/enc-version.js');

describe('enc-version registry', () => {
    test('текущая версия отправки — 1 (sender-chain)', () => {
        expect(ENC_V_CURRENT).toBe(1);
    });

    test('отсутствие поля — известный (до-версионный) конверт', () => {
        expect(isKnownEncVersion(undefined)).toBe(true);
        expect(isKnownEncVersion(null)).toBe(true);
    });

    test('v0 и v1 известны', () => {
        expect(isKnownEncVersion(0)).toBe(true);
        expect(isKnownEncVersion(1)).toBe(true);
    });

    test('будущие версии неизвестны', () => {
        expect(isKnownEncVersion(2)).toBe(false);
        expect(isKnownEncVersion(3)).toBe(false);
        expect(isKnownEncVersion(255)).toBe(false);
    });

    test('мусор неизвестен', () => {
        expect(isKnownEncVersion('1')).toBe(false);
        expect(isKnownEncVersion(1.5)).toBe(false);
        expect(isKnownEncVersion(-1)).toBe(false);
    });
});

/**
 * prekey-store.test.js
 * Клиентское хранилище приватных prekey (ADR-001, батч 6a): персист/чтение
 * SPK и OPK по id, per-account изоляция, удаление OPK (forward secrecy).
 */

const {
    storePrekeyPrivates, hasPrekeyPrivates, getSpkPrivate,
    getOpkPrivate, deleteOpkPrivate, clearPrekeyPrivates,
} = require('../dr/prekey-store.js');

beforeEach(() => {
    localStorage.clear();
    window.AppState = { user: { user_id: 7 } };
});

test('storePrekeyPrivates + getSpkPrivate/getOpkPrivate round-trip', () => {
    storePrekeyPrivates({ id: 1, jwk: '{"spk":true}' }, [
        { id: 100, jwk: '{"opk":100}' },
        { id: 101, jwk: '{"opk":101}' },
    ]);
    expect(hasPrekeyPrivates()).toBe(true);
    expect(getSpkPrivate(1)).toEqual({ id: 1, jwk: '{"spk":true}' });
    expect(getOpkPrivate(100)).toBe('{"opk":100}');
    expect(getOpkPrivate(101)).toBe('{"opk":101}');
});

test('getSpkPrivate возвращает null для другого (ротированного) id', () => {
    storePrekeyPrivates({ id: 1, jwk: '{"spk":true}' }, []);
    expect(getSpkPrivate(2)).toBeNull();
});

test('hasPrekeyPrivates() = false до публикации (пользователь батча 4)', () => {
    expect(hasPrekeyPrivates()).toBe(false);
});

test('deleteOpkPrivate удаляет использованный OPK (FS), идемпотентно', () => {
    storePrekeyPrivates({ id: 1, jwk: 's' }, [{ id: 100, jwk: 'o' }]);
    expect(getOpkPrivate(100)).toBe('o');
    deleteOpkPrivate(100);
    expect(getOpkPrivate(100)).toBeNull();
    expect(() => deleteOpkPrivate(100)).not.toThrow();   // повторно — no-op
});

test('republish добавляет OPK, сохраняя прежние', () => {
    storePrekeyPrivates({ id: 1, jwk: 's1' }, [{ id: 100, jwk: 'o100' }]);
    storePrekeyPrivates({ id: 1, jwk: 's2' }, [{ id: 200, jwk: 'o200' }]);
    expect(getOpkPrivate(100)).toBe('o100');   // старый на месте
    expect(getOpkPrivate(200)).toBe('o200');   // новый добавлен
    expect(getSpkPrivate(1).jwk).toBe('s2');   // SPK перезаписан
});

test('per-account изоляция: разные userId — разные сторы', () => {
    window.AppState.user.user_id = 1;
    storePrekeyPrivates({ id: 1, jwk: 'acc1' }, []);
    window.AppState.user.user_id = 2;
    expect(hasPrekeyPrivates()).toBe(false);   // у аккаунта 2 своего нет
    window.AppState.user.user_id = 1;
    expect(getSpkPrivate(1).jwk).toBe('acc1');
});

test('clearPrekeyPrivates удаляет стор аккаунта', () => {
    storePrekeyPrivates({ id: 1, jwk: 's' }, []);
    clearPrekeyPrivates(7);
    expect(hasPrekeyPrivates()).toBe(false);
});

test('без залогиненного пользователя storePrekeyPrivates бросает', () => {
    window.AppState = { user: {} };
    expect(() => storePrekeyPrivates({ id: 1, jwk: 's' }, [])).toThrow();
});

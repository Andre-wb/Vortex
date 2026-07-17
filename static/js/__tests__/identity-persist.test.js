/**
 * identity-persist.test.js
 * Пароль-шифрованная персистентность аккаунтного Ed25519 через logout
 *: `_enc`-копия переживает очистку плейнтекста и
 * восстанавливается по паролю; неверный пароль — не восстанавливает; no-op
 * без пароля/плейнтекста.
 */

const { saveEd25519Enc, restoreEd25519Enc } = require('../dr/identity-persist.js');

const UID = 42;
const SLOT = `vortex_ed25519_identity_${UID}`;
const ENC = `vortex_ed25519_identity_${UID}_enc`;
const IDENTITY = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', d: 'aaa', x: 'bbb' });

beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });

test('save создаёт `_enc`-копию из плейнтекста', async () => {
    localStorage.setItem(SLOT, IDENTITY);
    await saveEd25519Enc(UID, 'passphrase-123');
    expect(localStorage.getItem(ENC)).toBeTruthy();
    expect(localStorage.getItem(ENC)).not.toContain('OKP');   // зашифровано, не плейнтекст
});

test('_enc переживает очистку плейнтекста (симуляция logout) и восстанавливается по паролю', async () => {
    localStorage.setItem(SLOT, IDENTITY);
    await saveEd25519Enc(UID, 'pw');

    // «logout»: плейнтекст-слот чистится, `_enc` остаётся (как в auth.js с !endsWith('_enc'))
    localStorage.removeItem(SLOT);
    sessionStorage.removeItem(SLOT);
    expect(localStorage.getItem(SLOT)).toBeNull();
    expect(localStorage.getItem(ENC)).toBeTruthy();

    // «login»: restore по паролю возвращает ТУ ЖЕ идентичность (не форк)
    const ok = await restoreEd25519Enc(UID, 'pw');
    expect(ok).toBe(true);
    expect(localStorage.getItem(SLOT)).toBe(IDENTITY);
    expect(sessionStorage.getItem(SLOT)).toBe(IDENTITY);
});

test('неверный пароль не восстанавливает', async () => {
    localStorage.setItem(SLOT, IDENTITY);
    await saveEd25519Enc(UID, 'right');
    localStorage.removeItem(SLOT);
    const ok = await restoreEd25519Enc(UID, 'wrong');
    expect(ok).toBe(false);
    expect(localStorage.getItem(SLOT)).toBeNull();
});

test('restore no-op, если плейнтекст уже есть (не перезаписывает)', async () => {
    localStorage.setItem(SLOT, IDENTITY);
    await saveEd25519Enc(UID, 'pw');
    localStorage.setItem(SLOT, JSON.stringify({ current: true }));   // текущий плейнтекст
    const ok = await restoreEd25519Enc(UID, 'pw');
    expect(ok).toBe(true);
    expect(JSON.parse(localStorage.getItem(SLOT)).current).toBe(true);   // не перезаписан из _enc
});

test('save no-op без пароля или без плейнтекста', async () => {
    await saveEd25519Enc(UID, null);                    // нет пароля
    expect(localStorage.getItem(ENC)).toBeNull();
    await saveEd25519Enc(UID, 'pw');                    // нет плейнтекста
    expect(localStorage.getItem(ENC)).toBeNull();
});

test('restore false, если ни плейнтекста, ни `_enc`', async () => {
    expect(await restoreEd25519Enc(UID, 'pw')).toBe(false);
});

/**
 * message-cipher-v2-send.test.js
 * Логика выбора v2-отправки в DM (ADR-001, батч 6b): фичефлаг, capability
 * (supports_v2), TOFU (identity_key == известный peer pub), верификация
 * подписей бандла, кэширование решения, фолбэк в v1 (null).
 *
 * Мокаем ../utils.js (api) и ../dr/prekeys.js (edVerify), чтобы изолировать
 * решение от сети и криптопроверок подписи.
 */

const mockApi = jest.fn();
jest.mock('../utils.js', () => ({ api: (...a) => mockApi(...a) }));

let mockEdVerifyResult = true;
jest.mock('../dr/prekeys.js', () => ({ edVerify: async () => mockEdVerifyResult }));

// Мокаем сам DR-establish, чтобы тест проверял ИМЕННО решение (флаг/capability/
// TOFU/кэш), а не крипто — оно покрыто в dr-v2-session.test.js.
const mockDrEncrypt = jest.fn();
jest.mock('../dr/session.js', () => ({
    encryptV2: (...a) => mockDrEncrypt(...a),
    decryptV2: jest.fn(),
    dmSessionId: (id) => `dm:${id}`,
    importX25519PrivJwk: async () => ({}),
}));
jest.mock('../dr/session-store.js', () => ({
    createSessionStore: () => ({}),
    indexedDbBackend: () => ({}),
}));

const { encryptV2ForDm } = require('../chat/message-cipher.js');

const PEER_PUB = 'ab'.repeat(32);

function goodBundle(overrides = {}) {
    return {
        identity_key: PEER_PUB,
        signed_prekey: 'cd'.repeat(32),
        signed_prekey_id: 1,
        signed_prekey_sig: '11'.repeat(64),
        identity_key_ed: '22'.repeat(32),
        identity_key_sig: '33'.repeat(64),
        supports_v2: true,
        one_time_prekey: 'ef'.repeat(32),
        one_time_prekey_id: 100,
        ...overrides,
    };
}

function dmRoom() {
    return { id: 42, is_dm: true, dm_user: { user_id: 7, x25519_public_key: PEER_PUB } };
}

beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    mockApi.mockReset();
    mockDrEncrypt.mockReset();
    mockEdVerifyResult = true;
    window.AppState = { user: { user_id: 1, x25519_public_key: 'aa'.repeat(32) }, x25519PrivateKey: '{"kty":"OKP"}' };
    localStorage.setItem('vortex_v2_dm_enabled', '1');   // флаг вкл по умолчанию в тестах
    // Дефолт: симулируем establish — encryptV2 дёргает getPeerBundle (где живут
    // проверки capability/TOFU/подписей), затем возвращает «конверт».
    mockDrEncrypt.mockImplementation(async (store, sid, ctx) => { await ctx.getPeerBundle(); return 'deadbeef'; });
});

test('флаг выкл → null (v1), без сетевых запросов', async () => {
    localStorage.removeItem('vortex_v2_dm_enabled');
    const r = await encryptV2ForDm(dmRoom(), 'hi');
    expect(r).toBeNull();
    expect(mockApi).not.toHaveBeenCalled();
});

test('не-DM комната → null', async () => {
    const r = await encryptV2ForDm({ id: 5, is_dm: false }, 'hi');
    expect(r).toBeNull();
});

test('успешный establish → {enc_v:2, ciphertext}, решение кэшируется как yes', async () => {
    mockApi.mockResolvedValue(goodBundle());
    const room = dmRoom();
    const r = await encryptV2ForDm(room, 'hi');
    expect(r).toEqual({ enc_v: 2, ciphertext: 'deadbeef' });
    expect(room._v2).toBe('yes');
});

test('адресат без supports_v2 → null и кэш no (перезапросов больше нет)', async () => {
    mockApi.mockResolvedValue(goodBundle({ supports_v2: false }));
    const room = dmRoom();
    expect(await encryptV2ForDm(room, 'm1')).toBeNull();
    expect(room._v2).toBe('no');
    // Второе сообщение: кэш no → сразу v1, без establish/запроса бандла
    mockApi.mockClear();
    mockDrEncrypt.mockClear();
    expect(await encryptV2ForDm(room, 'm2')).toBeNull();
    expect(mockDrEncrypt).not.toHaveBeenCalled();   // establish при _v2==='no' не вызывается
    expect(mockApi).not.toHaveBeenCalled();
});

test('TOFU: identity_key бандла ≠ известный peer pub → null, кэш no', async () => {
    mockApi.mockResolvedValue(goodBundle({ identity_key: 'ff'.repeat(32) }));
    const room = dmRoom();
    expect(await encryptV2ForDm(room, 'hi')).toBeNull();
    expect(room._v2).toBe('no');
});

test('битые подписи бандла → null, кэш no', async () => {
    mockEdVerifyResult = false;
    mockApi.mockResolvedValue(goodBundle());
    const room = dmRoom();
    expect(await encryptV2ForDm(room, 'hi')).toBeNull();
    expect(room._v2).toBe('no');
});

test('транзиентная ошибка сети при establish → null, но НЕ кэшируется (повтор)', async () => {
    // encryptV2 (establish) вызывает getPeerBundle → api бросает сетевую ошибку
    mockDrEncrypt.mockImplementation(async (store, sid, ctx) => { await ctx.getPeerBundle(); });
    mockApi.mockRejectedValue(new Error('network down'));
    const room = dmRoom();
    expect(await encryptV2ForDm(room, 'hi')).toBeNull();
    expect(room._v2).toBeUndefined();   // не кэшировано → следующее сообщение повторит
});

test('установленная сессия: getPeerBundle не дёргается (encryptV2 сам решает)', async () => {
    // Симулируем «сессия есть»: mockDrEncrypt возвращает конверт, не трогая getPeerBundle
    mockApi.mockResolvedValue(goodBundle());
    const room = dmRoom();
    await encryptV2ForDm(room, 'first');   // establish
    mockApi.mockClear();
    mockDrEncrypt.mockResolvedValue('cafe');
    const r = await encryptV2ForDm(room, 'second');
    expect(r).toEqual({ enc_v: 2, ciphertext: 'cafe' });
});

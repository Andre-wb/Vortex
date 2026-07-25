/**
 * kt-verify.test.js (ADR-009 Фаза 1)
 * Клиентская проверка нода-подписи KT-записи. Cross-impl: нода (Python) подписала
 * запись фикс-сериализацией → JS edVerify. Плюс: серверная подмена pub_key_hash при
 * той же подписи → не сходится (улика). КРУКС: это non-repudiation-субстрат, не
 * детекция — тест проверяет ФАКТ подписи, не «ключ честный». Вектор из
 * app/tests/test_kt_node_sig.py.
 */

const mockApi = jest.fn();
jest.mock('../utils.js', () => ({ ...jest.requireActual('../utils.js'), api: (...a) => mockApi(...a) }));

const { ktEntryMessage, verifyKtLog } = require('../dr/kt-verify.js');
const { edVerify } = require('../dr/prekeys.js');

const NODE_PUB = 'a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0';
const NODE_SIG = 'abe83fb1cede4608250f204b25eae68074fc1d8c651f169b581ceb6c1eab71f52ee54f51414dc092ccbfe15c32c669a116b3984f321efcc5f7a2c4e750ec6008';
const H = 'ab'.repeat(32);

test('сериализация нагрузки зафиксирована (prev=null → пусто)', () => {
    const s = new TextDecoder().decode(ktEntryMessage(1, 'account_ed', H, null, 1));
    expect(s).toBe(`vortex-kt-entry:v1:1:account_ed:${H}::1`);
});

test('cross-impl: Python нода-подпись → JS edVerify проходит под node_pubkey', async () => {
    const ok = await edVerify(NODE_PUB, ktEntryMessage(1, 'account_ed', H, null, 1), NODE_SIG);
    expect(ok).toBe(true);
});

test('подмена pub_key_hash (сервер сменил ключ) → подпись не сходится (улика)', async () => {
    const ok = await edVerify(NODE_PUB, ktEntryMessage(1, 'account_ed', 'cd'.repeat(32), null, 1), NODE_SIG);
    expect(ok).toBe(false);
});

test('подмена seq → не сходится (запись нельзя переставить)', async () => {
    const ok = await edVerify(NODE_PUB, ktEntryMessage(1, 'account_ed', H, null, 2), NODE_SIG);
    expect(ok).toBe(false);
});

test('чужой node_pubkey → не сходится', async () => {
    const ok = await edVerify('ff'.repeat(32), ktEntryMessage(1, 'account_ed', H, null, 1), NODE_SIG);
    expect(ok).toBe(false);
});

describe('verifyKtLog (оркестрация)', () => {
    const VALID = { key_type: 'account_ed', pub_key_hash: H, prev_hash: null, seq: 1, node_sig: NODE_SIG };
    const TAMPERED = { key_type: 'account_ed', pub_key_hash: 'cd'.repeat(32), prev_hash: null, seq: 1, node_sig: NODE_SIG };
    const LEGACY = { key_type: 'x25519', pub_key_hash: '11'.repeat(32), prev_hash: null, seq: 2, node_sig: null };

    beforeEach(() => { mockApi.mockReset(); localStorage.clear(); });

    test('считает signed/badSig; legacy (node_sig null) не улика; TOFU-пин ставится', async () => {
        mockApi.mockResolvedValueOnce({ node_pubkey: NODE_PUB, entries: [VALID, TAMPERED, LEGACY] });
        const r = await verifyKtLog(1);
        expect(r.total).toBe(3);
        expect(r.signed).toBe(1);          // только VALID сошёлся
        expect(r.badSig).toBe(1);          // TAMPERED — подпись не сошлась
        expect(r.nodeKeyChanged).toBe(false);
        expect(localStorage.getItem('vortex_kt_node_pubkey')).toBe(NODE_PUB);  // first-sight пин
    });

    test('смена ключа ноды vs пин → nodeKeyChanged (аномалия, не тихо)', async () => {
        localStorage.setItem('vortex_kt_node_pubkey', 'ee'.repeat(32));   // припиненный прежде
        mockApi.mockResolvedValueOnce({ node_pubkey: NODE_PUB, entries: [] });
        const r = await verifyKtLog(1);
        expect(r.nodeKeyChanged).toBe(true);
    });

    test('fetch fail → пустая улика (не бросает)', async () => {
        mockApi.mockRejectedValueOnce(new Error('network'));
        const r = await verifyKtLog(1);
        expect(r.total).toBe(0);
        expect(r.signed).toBe(0);
    });
});

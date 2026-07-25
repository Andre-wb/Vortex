/**
 * kt-evidence.test.js (ADR-009 Фаза 2)
 * Удержание нода-подписанной атестации + сборка пары «старый+новый» на смене ключа +
 * самопроверяемый экспорт. Несущее: старая атестация УДЕРЖАНА локально → злая нода,
 * убрав старый ключ из раздаваемого лога, не сотрёт улику. КРУКС: reset-неоднозначно,
 * эскалация человеку, не автодействие. Вектор из app/tests/test_kt_evidence.py.
 */

const mockApi = jest.fn();
jest.mock('../utils.js', () => ({ ...jest.requireActual('../utils.js'), api: (...a) => mockApi(...a) }));

const {
    retainAttestation, getRetained, detectEquivocation, exportEvidence,
    verifyEvidenceBlob, ktPubKeyHash,
} = require('../dr/kt-evidence.js');

const NPUB = 'a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0';
const ED_OLD = 'aa'.repeat(32), ED_NEW = 'bb'.repeat(32);
const H_OLD = 'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb';
const H_NEW = 'a0fab1377f49a759b57f63318262ebe89fabfc990e8e93ceac2984561482b9d4';
const SIG_OLD = 'c67bd57efd5b4461490f4fc139931247f0511d6036ff745bb586263da6a2b3b3b45f762a65a90a487fb05a65261162f5426dbd25521e3529e70d6869666af30a';
const SIG_NEW = '966dbad377d3f065f3ef6168e4501086da050d3505e65c2d21dfe1aa6a20eb2823dacb7e5e72bc527998225badd9c71197f6e6ea5d64474a6bb9479ec0de380a';

const PEER = 1;
const logWith = (...entries) => ({ node_pubkey: NPUB, entries });
const eOld = { key_type: 'account_ed', pub_key_hash: H_OLD, prev_hash: null, seq: 1, node_sig: SIG_OLD };
const eNew = { key_type: 'account_ed', pub_key_hash: H_NEW, prev_hash: null, seq: 2, node_sig: SIG_NEW };

beforeEach(() => { mockApi.mockReset(); localStorage.clear(); localStorage.setItem('vortex_kt_evidence_enabled', '1'); });

test('ktPubKeyHash = sha256(utf8(hex)) — зеркало сервера', async () => {
    expect(await ktPubKeyHash(ED_OLD)).toBe(H_OLD);
    expect(await ktPubKeyHash(ED_NEW)).toBe(H_NEW);
});

test('retain: удерживает нода-подписанную атестацию текущей личности', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    const rec = await retainAttestation(PEER, ED_OLD);
    expect(rec).not.toBeNull();
    expect(getRetained(PEER).accountEdHex).toBe(ED_OLD);
    expect(getRetained(PEER).nodeSig).toBe(SIG_OLD);
});

test('retain: НЕ удерживает, если запись не нода-подписана (sig не сходится)', async () => {
    mockApi.mockResolvedValueOnce(logWith({ ...eOld, node_sig: 'ff'.repeat(64) }));
    const rec = await retainAttestation(PEER, ED_OLD);
    expect(rec).toBeNull();
    expect(getRetained(PEER)).toBeNull();
});

test('detect: на смене Ed собирает пару старый(локально)+новый(из лога), resetAmbiguous', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);              // удержали старую
    // Нода теперь раздаёт лог, где СТАРОЙ нет (withholding) — но новая есть.
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const ev = await detectEquivocation(PEER, ED_NEW);
    expect(ev).not.toBeNull();
    expect(ev.resetAmbiguous).toBe(true);
    expect(ev.old.accountEdHex).toBe(ED_OLD);          // пережила withholding (локально)
    expect(ev.new.accountEdHex).toBe(ED_NEW);
});

test('detect: тот же ключ (не изменился) → null', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    const ev = await detectEquivocation(PEER, ED_OLD);
    expect(ev).toBeNull();
});

test('detect: нет удержанной старой → null (нечего сравнивать)', async () => {
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const ev = await detectEquivocation(PEER, ED_NEW);
    expect(ev).toBeNull();
});

test('export → самопроверяемый блоб: обе statements нода-подписаны, ключи различны', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const ev = await detectEquivocation(PEER, ED_NEW);
    const blob = exportEvidence(ev);
    const parsed = JSON.parse(blob);
    expect(parsed.vortex_kt_evidence).toBe('v1');
    expect(parsed.reset_ambiguous).toBe(true);
    // Третья сторона проверяет БЕЗ доверия отправителю:
    const v = await verifyEvidenceBlob(blob);
    expect(v.valid).toBe(true);
    expect(v.distinctKeys).toBe(true);
});

test('подделанный блоб (сменили pub_key_hash) → verifyEvidenceBlob отвергает', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const ev = await detectEquivocation(PEER, ED_NEW);
    const parsed = JSON.parse(exportEvidence(ev));
    parsed.statements[0].pub_key_hash = 'cd'.repeat(32);   // подмена → sig не сойдётся
    const v = await verifyEvidenceBlob(parsed);
    expect(v.valid).toBe(false);
});

test('флаг ВЫКЛ → retain/detect no-op (дормантно)', async () => {
    localStorage.setItem('vortex_kt_evidence_enabled', '0');
    const rec = await retainAttestation(PEER, ED_OLD);
    expect(rec).toBeNull();
    expect(mockApi).not.toHaveBeenCalled();
    const ev = await detectEquivocation(PEER, ED_NEW);
    expect(ev).toBeNull();
});

test('retain дедуп: та же личность повторно → без нового фетча', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    expect(mockApi).toHaveBeenCalledTimes(1);
    await retainAttestation(PEER, ED_OLD);              // уже удержана
    expect(mockApi).toHaveBeenCalledTimes(1);           // без второго фетча
});

test('удержание на ПЕРВЫЙ TOFU-пин (не только OOB) — пир, не сверявшийся вручную', async () => {
    const { pinPeerAccountEd } = require('../dr/identity-pin.js');
    mockApi.mockResolvedValue(logWith(eOld));
    pinPeerAccountEd(PEER, ED_OLD);                     // первый контакт → пин + удержание (fire-and-forget)
    for (let i = 0; i < 50 && !getRetained(PEER); i++) await new Promise(r => setTimeout(r, 5));
    expect(getRetained(PEER)?.accountEdHex).toBe(ED_OLD);
});

test('verifyEvidenceBlob отвергает пару из ключей РАЗНЫХ юзеров', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const parsed = JSON.parse(exportEvidence(await detectEquivocation(PEER, ED_NEW)));
    parsed.statements[1].user_id = 999;                 // вторая statement про другого юзера
    const v = await verifyEvidenceBlob(parsed);
    expect(v.valid).toBe(false);                        // не «пара про пира»
});

test('sameNode: одинаковый node_pubkey → true (различает миграцию ноды)', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const v = await verifyEvidenceBlob(exportEvidence(await detectEquivocation(PEER, ED_NEW)));
    expect(v.valid).toBe(true);
    expect(v.sameNode).toBe(true);
});

test('verifyEvidenceBlob отвергает ДВЕ ОДИНАКОВЫЕ statements (не улика)', async () => {
    mockApi.mockResolvedValueOnce(logWith(eOld));
    await retainAttestation(PEER, ED_OLD);
    mockApi.mockResolvedValueOnce(logWith(eNew));
    const parsed = JSON.parse(exportEvidence(await detectEquivocation(PEER, ED_NEW)));
    parsed.statements[1] = { ...parsed.statements[0] };    // обе про один ключ
    const v = await verifyEvidenceBlob(parsed);
    expect(v.valid).toBe(false);
});

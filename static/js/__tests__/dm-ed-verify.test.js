/**
 * dm-ed-verify.test.js (ADR-008 §4.6)
 * Миграция DM-верификации на account-Ed (единая identity-верификация с группами).
 * Дормантно за vortex_dm_ed_verify_enabled. Доказывает: (1) выключено → legacy
 * passthrough; (2) «сверил раз — verified везде» через ТОТ ЖЕ источник ed
 * (pinnedPeerAccountEd, что пинит и групповой путь); (3) старую X25519-верификацию
 * НЕ переносим автоматически (needsReverify) — сервер мог подсунуть свой E'.
 *
 * Cross-impl отпечатка Ed уже пиннится member-fingerprint.test.js — здесь чистая
 * UI-логика маршрутизации статуса/режима, серверных изменений нет.
 */

const { dmEdVerifyEnabled, dmVerifiedState } = require('../fingerprint.js');
const { pinPeerAccountEd } = require('../dr/identity-pin.js');
const { markIdentityVerified } = require('../dr/member-verify.js');

const PEER = 2;
const ED = 'aa'.repeat(32);

beforeEach(() => {
    localStorage.clear();
    window.AppState = { user: { user_id: 1 } };
});

test('флаг ВЫКЛ (дефолт) → edMode=false, legacy X25519-статус passthrough', () => {
    const st = dmVerifiedState(PEER, true);
    expect(dmEdVerifyEnabled()).toBe(false);
    expect(st.edMode).toBe(false);
    expect(st.verified).toBe(true);          // старый fingerprint_verified как есть
    expect(st.needsReverify).toBe(false);
});

test('ВКЛ, но нет пиннутого Ed → edMode=false, legacy passthrough (нечем Ed-сверять)', () => {
    localStorage.setItem('vortex_dm_ed_verify_enabled', '1');
    const st = dmVerifiedState(PEER, true);
    expect(st.edMode).toBe(false);
    expect(st.verified).toBe(true);
});

test('ЕДИНСТВО: сверил account-Ed (как в группе) → DM репортит verified, ТОТ ЖЕ ed', () => {
    localStorage.setItem('vortex_dm_ed_verify_enabled', '1');
    pinPeerAccountEd(PEER, ED);               // источник ed — общий с групповым путём
    markIdentityVerified(PEER, ED);           // OOB-сверка (та же запись, что у групп)
    const st = dmVerifiedState(PEER, false);
    expect(st.edMode).toBe(true);
    expect(st.verified).toBe(true);           // верифицирован в DM без отдельной DM-сверки
    expect(st.peerEd).toBe(ED);               // ← тот же ключ, а не расходящийся источник
});

test('БЕЗ авто-миграции: X25519-сверен, но не Ed → verified=false + needsReverify', () => {
    localStorage.setItem('vortex_dm_ed_verify_enabled', '1');
    pinPeerAccountEd(PEER, ED);               // Ed запиннен (TOFU), но НЕ OOB-сверен
    const st = dmVerifiedState(PEER, true);   // legacy X25519 = сверен
    expect(st.verified).toBe(false);          // НЕ повышаем автоматически (несостоятельно)
    expect(st.needsReverify).toBe(true);      // просим пере-сверить над Ed
    expect(st.peerEd).toBe(ED);
});

test('смена пиннутого Ed → прежняя Ed-верификация не переносится (verified=false)', () => {
    localStorage.setItem('vortex_dm_ed_verify_enabled', '1');
    pinPeerAccountEd(PEER, ED);
    markIdentityVerified(PEER, ED);           // сверили ED
    // Пин сменился на другой Ed (identity-pin НЕ перезаписывает, но эмулируем новый пир-слот)
    localStorage.setItem(`vortex_peer_acct_ed_${PEER}`, 'bb'.repeat(32));
    const st = dmVerifiedState(PEER, false);
    expect(st.verified).toBe(false);          // verified привязан к КОНКРЕТНОМУ ed
});

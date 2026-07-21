/**
 * member-fingerprint.test.js (ADR-008 G6/F6)
 * Отпечаток account-Ed участника + QR-переиспользование. Критерий приёмки #6:
 * cross-impl Python↔JS расчёта fp, детерминизм, симметрия sort. Плюс: QR-payload
 * симметричен → скан QR одного участника подтверждает сверку у другого; подмена
 * ключа рушит матч (F6-детект). Вектор — из app/tests/test_member_fingerprint.py.
 */

const {
    computeFingerprint, computeEmojiFingerprint,
    fingerprintQRPayload, parseFingerprintQR,
} = require('../fingerprint.js');

// Cross-impl вектор (Python — тот же расчёт: sort([a,b].lower()) + ':' → SHA-256 → UPPER hex).
const EDA = 'aa'.repeat(32);
const EDB = 'bb'.repeat(32);
const BLOCKS = '6173 CF9D 3267 E6B9 2610 2C8B 1498 1265 8D05 D834 916F D23F 7451 C48C 8881 47AB';
const QR_HEX = '6173CF9D3267E6B926102C8B149812658D05D834916FD23F7451C48C888147AB';
const EMOJIS = ['🌲', '🔥', '🐦', '🐠', '⭐', '🌸'];

test('cross-impl: computeFingerprint(edA, edB) == Python-вектор', async () => {
    expect(await computeFingerprint(EDA, EDB)).toBe(BLOCKS);
});

test('симметрия sort: fp(A,B) == fp(B,A) → обе стороны видят один отпечаток', async () => {
    expect(await computeFingerprint(EDA, EDB)).toBe(await computeFingerprint(EDB, EDA));
});

test('cross-impl: emoji-отпечаток == Python-вектор', async () => {
    expect(await computeEmojiFingerprint(EDA, EDB)).toEqual(EMOJIS);
});

test('QR-payload: "VORTEX-FP:" + hex без пробелов; round-trip parse', async () => {
    const fp = await computeFingerprint(EDA, EDB);
    const payload = fingerprintQRPayload(fp);
    expect(payload).toBe('VORTEX-FP:' + QR_HEX);
    expect(parseFingerprintQR(payload)).toBe(QR_HEX);
});

test('cross-scan: QR-payload участника A == локальный hex у B → скан подтверждает', async () => {
    const fpA = await computeFingerprint(EDA, EDB);       // QR, который показывает A
    const fpB = await computeFingerprint(EDB, EDA);       // локальный отпечаток у B
    const scannedHex = parseFingerprintQR(fingerprintQRPayload(fpA));
    const localHex = fpB.replace(/\s/g, '');
    expect(scannedHex).toBe(localHex);                    // match → verifyCurrentFingerprint
});

test('подмена Ed участника → скан НЕ совпадает (F6-детект, без ложной верификации)', async () => {
    const edBfake = 'cc'.repeat(32);                      // сервер подменил Ed у B
    const fpReal = await computeFingerprint(EDA, EDB);    // локальный hex у честного B
    const fpSeen = await computeFingerprint(EDA, edBfake);// то, что A видит/кодирует в QR
    const scannedHex = parseFingerprintQR(fingerprintQRPayload(fpSeen));
    expect(scannedHex).not.toBe(fpReal.replace(/\s/g, ''));
});

test('parseFingerprintQR отклоняет не-VORTEX-FP', () => {
    expect(parseFingerprintQR('https://evil/' + QR_HEX)).toBeNull();
    expect(parseFingerprintQR(null)).toBeNull();
    expect(parseFingerprintQR('')).toBeNull();
});

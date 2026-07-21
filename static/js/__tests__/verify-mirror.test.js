/**
 * verify-mirror.test.js (ADR-008 §4.2)
 * Кросс-девайсный мирор OOB-верификаций. Cross-impl (критерий 6): цепочка,
 * подписанная PYTHON'ом (device-key подписал attest-payload, account-Ed подписал
 * device-cert), верифицируется JS — device-cert→account-Ed + attest-sig. Плюс:
 * сериализация payload зафиксирована; подмена рвёт проверку. Вектор — из
 * app/tests/test_verify_mirror.py.
 */

const mockApi = jest.fn();
jest.mock('../utils.js', () => ({ ...jest.requireActual('../utils.js'), api: (...a) => mockApi(...a) }));

const { attestPayload, syncAttestations, publishAttestation } = require('../dr/verify-mirror.js');
const { edVerify, saveAccountLinkMaterial } = require('../dr/prekeys.js');
const { verifyDeviceCert } = require('../dr/device-identity.js');
const { isIdentityVerified, markIdentityVerified } = require('../dr/member-verify.js');

// Вектор из Python (Ed25519 seed 00..1f = account, 0x11*32 = device sign key).
const V = {
    acctEdPub:  '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8',
    devSignPub: 'd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737',
    deviceId:   '00112233445566778899aabbccddeeff',
    x3dhPub:    'a1'.repeat(32),
    certSig:    '811510219d61f6af65bb3714e30a4f75a6605ce093a9b5f63a1ddad663effb164ca74fff1145fdf82de61078251ddcb85f693de76faa8ae09ff1e80dc6697205',
    attestSig:  '1e655a9648896fef959224953ce66de958c6bc62416b089ad78607046d64945b399b04c1195b229f7a12a19d18d0e397532ed80332859610759851c7a7b1d80c',
    owner: 1, peer: 2, ed: 'cd'.repeat(32), state: 'verified', signedAt: 1700000000,
};

test('сериализация payload зафиксирована (cross-impl канон)', () => {
    const s = new TextDecoder().decode(attestPayload(V.owner, V.peer, V.ed, V.state, V.signedAt));
    expect(s).toBe(`vortex-verify-attest:v1:1:2:${V.ed}:verified:1700000000`);
});

test('ed приводится к lowercase в payload', () => {
    const a = new TextDecoder().decode(attestPayload(V.owner, V.peer, V.ed.toUpperCase(), V.state, V.signedAt));
    const b = new TextDecoder().decode(attestPayload(V.owner, V.peer, V.ed, V.state, V.signedAt));
    expect(a).toBe(b);
});

test('cross-impl: Python device-cert → JS verifyDeviceCert проходит против account-Ed', async () => {
    const ok = await verifyDeviceCert(V.deviceId, V.x3dhPub, V.devSignPub, V.certSig, V.acctEdPub);
    expect(ok).toBe(true);
});

test('cross-impl: Python attest-sig → JS edVerify проходит под device-ключом', async () => {
    const ok = await edVerify(V.devSignPub, attestPayload(V.owner, V.peer, V.ed, V.state, V.signedAt), V.attestSig);
    expect(ok).toBe(true);
});

test('cert против ЧУЖОГО account-Ed → отказ (подписант не мой → запись отвергается)', async () => {
    const ok = await verifyDeviceCert(V.deviceId, V.x3dhPub, V.devSignPub, V.certSig, 'ff'.repeat(32));
    expect(ok).toBe(false);
});

test('подмена payload (сервер сменил verified_ed) → attest-sig не сходится', async () => {
    const ok = await edVerify(V.devSignPub, attestPayload(V.owner, V.peer, 'be'.repeat(32), V.state, V.signedAt), V.attestSig);
    expect(ok).toBe(false);
});

test('подмена state (verified→revoked при том же sig) → не сходится', async () => {
    const ok = await edVerify(V.devSignPub, attestPayload(V.owner, V.peer, V.ed, 'revoked', V.signedAt), V.attestSig);
    expect(ok).toBe(false);
});

describe('оркестрация syncAttestations / publishAttestation', () => {
    // Полная валидная verified-запись (Python-вектор) + revoked для peer=3.
    const VALID = {
        peer_user_id: V.peer, verified_ed: V.ed, state: V.state, signed_at: V.signedAt,
        client_device_id: V.deviceId, device_x3dh_pub: V.x3dhPub, device_sign_pub: V.devSignPub,
        device_cert_sig: V.certSig, attest_sig: V.attestSig,
    };
    const REVOKED = {
        peer_user_id: 3, verified_ed: 'ab'.repeat(32), state: 'revoked', signed_at: 1700000001,
        client_device_id: V.deviceId, device_x3dh_pub: V.x3dhPub, device_sign_pub: V.devSignPub,
        device_cert_sig: V.certSig,
        attest_sig: '5e649b1d29c8b0266354aaf755005b4a6f2846df732519bb7ba419e55f31156d874887ad241de3906da4fbdaac3098131dbc3f24432fdbeb122056231b51ab08',
    };

    beforeEach(() => {
        mockApi.mockReset();
        localStorage.clear();
        window.AppState = { user: { user_id: V.owner } };
        saveAccountLinkMaterial(V.owner, V.acctEdPub, 'x');   // _myAccountEdPub → мой account-Ed
        localStorage.setItem('vortex_verify_mirror_enabled', '1');
    });

    test('валидная verified применяется (mark на ПРАВИЛЬНЫЙ ed); битая отвергается', async () => {
        const TAMPERED = { ...VALID, peer_user_id: 9, verified_ed: 'ff'.repeat(32) }; // sig не над этим ed
        mockApi.mockResolvedValueOnce({ attestations: [VALID, TAMPERED] });
        const r = await syncAttestations();
        expect(r.applied).toBe(1);
        expect(r.rejected).toBe(1);
        expect(isIdentityVerified(V.peer, V.ed)).toBe(true);      // применено к верному ed
        expect(isIdentityVerified(9, 'ff'.repeat(32))).toBe(false);
    });

    test('revoked снимает верификацию (state-routing)', async () => {
        markIdentityVerified(3, 'ab'.repeat(32));                 // была верифицирована
        mockApi.mockResolvedValueOnce({ attestations: [REVOKED] });
        const r = await syncAttestations();
        expect(r.applied).toBe(1);
        expect(isIdentityVerified(3, 'ab'.repeat(32))).toBe(false);
    });

    test('cert против ЧУЖОГО account-Ed → запись НЕ применяется', async () => {
        saveAccountLinkMaterial(V.owner, 'ff'.repeat(32), 'x');   // мой account-Ed не тот, что подписал cert
        mockApi.mockResolvedValueOnce({ attestations: [VALID] });
        const r = await syncAttestations();
        expect(r.applied).toBe(0);
        expect(r.rejected).toBe(1);
        expect(isIdentityVerified(V.peer, V.ed)).toBe(false);
    });

    test('флаг ВЫКЛ → sync и publish no-op (без сети)', async () => {
        localStorage.setItem('vortex_verify_mirror_enabled', '0');
        const r = await syncAttestations();
        expect(r.applied).toBe(0);
        await publishAttestation(V.peer, V.ed, 'verified');
        expect(mockApi).not.toHaveBeenCalled();                  // дормантно
    });
});

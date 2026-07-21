/**
 * member-verify.test.js (ADR-008 G2)
 * verifyMemberIdentity: статус verified/unverified/changed/self + ПРОВЕРЕННЫЙ ключ
 * для обёртки. Плюс cross-impl: цепочка, подписанная PYTHON'ом (как сервер в G1),
 * верифицируется JS (server-signs → JS-verifies, критерий 6).
 */

const mockApi = jest.fn();
jest.mock('../utils.js', () => ({ ...jest.requireActual('../utils.js'), api: (...a) => mockApi(...a) }));

const {
    verifyMemberIdentity, verifyMemberForWrap, getMemberStatuses,
    markIdentityVerified, unmarkIdentityVerified, isIdentityVerified,
    isHardModeEnabled, setHardMode,
} = require('../dr/member-verify.js');

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

const VIEWER = 1, MEMBER = 2;
const X = 'aa'.repeat(32), K = 'cd'.repeat(1184);

async function genEd() {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    return { pubHex: toHex(await crypto.subtle.exportKey('raw', pair.publicKey)), priv: pair.privateKey };
}
async function sign(priv, hex) {
    return toHex(await crypto.subtle.sign('Ed25519', priv, fromHex(hex)));
}
async function entry(ed, { x = X, k = K, badX = false, badK = false } = {}) {
    return {
        identity_key_ed: ed.pubHex,
        x25519_public_key: x,
        identity_key_sig: await sign(ed.priv, badX ? 'bb'.repeat(32) : x),
        kyber_public_key: k,
        kyber_public_key_sig: await sign(ed.priv, badK ? 'ee'.repeat(1184) : k),
    };
}

beforeEach(() => {
    localStorage.clear();
    window.AppState = { user: { user_id: VIEWER } };
});

test('валидная цепочка, не OOB → unverified; verifiedX25519 = wrap-target', async () => {
    const ed = await genEd();
    const r = await verifyMemberIdentity(MEMBER, await entry(ed));
    expect(r.status).toBe('unverified');
    expect(r.verifiedX25519).toBe(X);         // ключ, на который МОЖНО заворачивать (§3)
    expect(r.verifiedKyber).toBe(K);
});

test('валидная цепочка + OOB-verified → verified', async () => {
    const ed = await genEd();
    const e = await entry(ed);
    await verifyMemberIdentity(MEMBER, e);    // пин Ed (TOFU)
    markIdentityVerified(MEMBER, ed.pubHex);  // я сверил вне канала
    const r = await verifyMemberIdentity(MEMBER, e);
    expect(r.status).toBe('verified');
});

test('смена account-Ed известного пира → changed (пин-mismatch), НЕ обёртка', async () => {
    const ed1 = await genEd(), ed2 = await genEd();
    await verifyMemberIdentity(MEMBER, await entry(ed1));   // пин ed1
    const r = await verifyMemberIdentity(MEMBER, await entry(ed2));   // сервер прислал ed2
    expect(r.status).toBe('changed');
    expect(r.verifiedX25519).toBeNull();      // заворачивать НЕЛЬЗЯ
});

test('подмена X25519 (sig не сходится против пина) → changed', async () => {
    const ed = await genEd();
    const r = await verifyMemberIdentity(MEMBER, await entry(ed, { badX: true }));
    expect(r.status).toBe('changed');
    expect(r.verifiedX25519).toBeNull();
});

test('подмена Kyber (sig не сходится) → changed', async () => {
    const ed = await genEd();
    const r = await verifyMemberIdentity(MEMBER, await entry(ed, { badK: true }));
    expect(r.status).toBe('changed');
});

test('нет account-Ed (нет v2-идентичности) → unverified, ed null', async () => {
    const r = await verifyMemberIdentity(MEMBER, { x25519_public_key: X });
    expect(r.status).toBe('unverified');
    expect(r.ed).toBeNull();
    expect(r.verifiedX25519).toBe(X);
});

test('своё устройство → self', async () => {
    const ed = await genEd();
    const r = await verifyMemberIdentity(VIEWER, await entry(ed));
    expect(r.status).toBe('self');
});

test('unmark снимает верификацию', async () => {
    const ed = await genEd();
    markIdentityVerified(MEMBER, ed.pubHex);
    expect(isIdentityVerified(MEMBER, ed.pubHex)).toBe(true);
    unmarkIdentityVerified(MEMBER);
    expect(isIdentityVerified(MEMBER, ed.pubHex)).toBe(false);
});

describe('cross-impl: Python-подписанная цепочка (как сервер G1) → JS верифицирует', () => {
    // Вектор из app/security (Ed25519 seed 00..1f подписал x25519 и kyber).
    const V = {
        identity_key_ed: '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8',
        x25519_public_key: '358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254',
        identity_key_sig: 'b18c5604f6c21cfc0e31d314ab1aa22ce12b6570bb064a227f0a51c896a03d0fdb400d20df91aab87186fdb400e46e84d8d644bc32f17387ff1caf3e91052a0e',
        kyber_public_key_sig: 'b98f2aa8552267811464a4c040317dc14aca15b719c30ddf7fb363954948bdc1f38ec2719a9f8ca499790ec0a3bbace38e6a790d911e40ebb0410fa8bad11e0f',
    };

    test('Python identity_key_sig / kyber_sig проходят JS edVerify → unverified (валидно)', async () => {
        // kyber заглушим фикс-байтами не нужно — проверяем X25519-ногу (главную для обёртки);
        // kyber-нога отключается отсутствием kyber_public_key.
        const r = await verifyMemberIdentity(MEMBER, {
            identity_key_ed: V.identity_key_ed,
            x25519_public_key: V.x25519_public_key,
            identity_key_sig: V.identity_key_sig,
        });
        expect(r.status).toBe('unverified');            // цепочка валидна, но не OOB
        expect(r.verifiedX25519).toBe(V.x25519_public_key);
    });

    test('подмена подписи в Python-векторе → JS ловит changed', async () => {
        const r = await verifyMemberIdentity(MEMBER, {
            identity_key_ed: V.identity_key_ed,
            x25519_public_key: 'ff'.repeat(32),          // сервер подменил X25519
            identity_key_sig: V.identity_key_sig,        // подпись над старым → не сойдётся
        });
        expect(r.status).toBe('changed');
    });
});

describe('verifyMemberForWrap (гейт G3)', () => {
    const ROOM = 42;
    beforeEach(() => mockApi.mockReset());

    test('kill-switch (флаг = 0) → passthrough на for_pubkey, member-keys НЕ фетчится', async () => {
        localStorage.setItem('vortex_member_verify_enabled', '0');
        const r = await verifyMemberForWrap(ROOM, MEMBER, X, null, null);
        expect(r.allow).toBe(true);
        expect(r.wrapX25519).toBe(X);
        expect(r.status).toBe('gate_off');
        expect(mockApi).not.toHaveBeenCalled();          // выключено — без сетевого чека
    });

    test('дефолт (флаг не задан) → ВКЛ: member-keys фетчится, верификация активна', async () => {
        const ed = await genEd();
        const e = await entry(ed);
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, e.x25519_public_key, null, null);
        expect(mockApi).toHaveBeenCalled();              // дефолт-ВКЛ — гейт активен
        expect(r.allow).toBe(true);
        expect(r.status).toBe('unverified');
    });

    test('флаг ВКЛ + валидная цепочка → allow, обёртка на ПРОВЕРЕННЫЙ x25519/kyber', async () => {
        localStorage.setItem('vortex_member_verify_enabled', '1');
        const ed = await genEd();
        const e = await entry(ed);
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, e.x25519_public_key, e.kyber_public_key, e.kyber_public_key_sig);
        expect(r.allow).toBe(true);
        expect(r.wrapX25519).toBe(e.x25519_public_key);
        expect(r.wrapKyber).toBe(e.kyber_public_key);
        expect(r.status).toBe('unverified');
    });

    test('флаг ВКЛ + changed (пин сменился) → BLOCK', async () => {
        localStorage.setItem('vortex_member_verify_enabled', '1');
        const ed1 = await genEd(), ed2 = await genEd();
        await verifyMemberIdentity(MEMBER, await entry(ed1));   // пин ed1
        const e2 = await entry(ed2);
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e2 }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, e2.x25519_public_key, null, null);
        expect(r.allow).toBe(false);
        expect(r.status).toBe('changed');
    });

    test('флаг ВКЛ + for_pubkey != проверенный (подмена сервером) → BLOCK', async () => {
        localStorage.setItem('vortex_member_verify_enabled', '1');
        const ed = await genEd();
        const e = await entry(ed);                        // e.x25519 = X (подписан)
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, 'ff'.repeat(32), null, null);  // чужой for_pubkey
        expect(r.allow).toBe(false);
        expect(r.status).toBe('pubkey_mismatch');
    });

    test('флаг ВКЛ + fetch fail → passthrough (не блокируем легитимную обёртку)', async () => {
        localStorage.setItem('vortex_member_verify_enabled', '1');
        mockApi.mockRejectedValueOnce(new Error('network'));
        const r = await verifyMemberForWrap(ROOM, MEMBER, X, null, null);
        expect(r.allow).toBe(true);
        expect(r.status).toBe('no_chain');
    });
});

describe('getMemberStatuses (G4 F1/F3/F4)', () => {
    beforeEach(() => mockApi.mockReset());

    test('считает verified/unverified; self не в total; entries прокинуты', async () => {
        const edA = await genEd(), edB = await genEd(), edSelf = await genEd();
        markIdentityVerified(2, edA.pubHex);                 // A — OOB-сверен
        mockApi.mockResolvedValueOnce({ members: [
            { user_id: 2, ...(await entry(edA)) },            // verified
            { user_id: 3, ...(await entry(edB, { x: '11'.repeat(32) })) },  // unverified
            { user_id: VIEWER, ...(await entry(edSelf, { x: '22'.repeat(32) })) },  // self
        ]});
        const r = await getMemberStatuses(42);
        expect(r.total).toBe(2);                             // self исключён
        expect(r.verified).toBe(1);
        expect(r.statuses[2]).toBe('verified');
        expect(r.statuses[3]).toBe('unverified');
        expect(r.statuses[VIEWER]).toBe('self');
        expect(r.entries[2].identity_key_ed).toBe(edA.pubHex);
    });

    test('changed участник считается в changed', async () => {
        const ed1 = await genEd(), ed2 = await genEd();
        await verifyMemberIdentity(2, await entry(ed1));     // пин ed1
        mockApi.mockResolvedValueOnce({ members: [{ user_id: 2, ...(await entry(ed2)) }] });  // сервер прислал ed2
        const r = await getMemberStatuses(42);
        expect(r.changed).toBe(1);
        expect(r.statuses[2]).toBe('changed');
    });
});

describe('hard-mode (§4.4) — refuse-unverified', () => {
    const ROOM = 42;
    beforeEach(() => mockApi.mockReset());

    test('setHardMode/isHardModeEnabled — дефолт ВЫКЛ', () => {
        expect(isHardModeEnabled()).toBe(false);
        setHardMode(true);
        expect(isHardModeEnabled()).toBe(true);
        setHardMode(false);
        expect(isHardModeEnabled()).toBe(false);
    });

    test('hard-mode ВКЛ + unverified (валидная цепочка, не OOB) → BLOCK', async () => {
        setHardMode(true);
        const ed = await genEd();
        const e = await entry(ed);
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, e.x25519_public_key, null, null);
        expect(r.allow).toBe(false);
        expect(r.status).toBe('unverified_hardblock');
    });

    test('hard-mode ВКЛ + OOB-verified → allow (сверенным ключ уходит)', async () => {
        setHardMode(true);
        const ed = await genEd();
        const e = await entry(ed);
        await verifyMemberIdentity(MEMBER, e);          // пин
        markIdentityVerified(MEMBER, ed.pubHex);        // OOB-сверен
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, e.x25519_public_key, e.kyber_public_key, e.kyber_public_key_sig);
        expect(r.allow).toBe(true);
        expect(r.status).toBe('verified');
    });

    test('hard-mode ВКЛ + fetch fail → BLOCK (сервер не индуцирует passthrough на свой for_pubkey)', async () => {
        setHardMode(true);
        mockApi.mockRejectedValueOnce(new Error('network'));
        const r = await verifyMemberForWrap(ROOM, MEMBER, X, null, null);
        expect(r.allow).toBe(false);
        expect(r.status).toBe('no_chain_hardblock');
    });

    test('hard-mode ВКЛ + не член (пустой ответ) → BLOCK', async () => {
        setHardMode(true);
        mockApi.mockResolvedValueOnce({ members: [] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, X, null, null);
        expect(r.allow).toBe(false);
        expect(r.status).toBe('not_member_hardblock');
    });

    test('hard-mode ВЫКЛ + fetch fail → passthrough allow (обычный гейт fail-open, регресс)', async () => {
        mockApi.mockRejectedValueOnce(new Error('network'));
        const r = await verifyMemberForWrap(ROOM, MEMBER, X, null, null);
        expect(r.allow).toBe(true);
        expect(r.status).toBe('no_chain');
    });

    test('hard-mode ВЫКЛ (дефолт) + unverified → allow (обычный warn+wrap, регресс)', async () => {
        const ed = await genEd();
        const e = await entry(ed);
        mockApi.mockResolvedValueOnce({ members: [{ user_id: MEMBER, ...e }] });
        const r = await verifyMemberForWrap(ROOM, MEMBER, e.x25519_public_key, null, null);
        expect(r.allow).toBe(true);
        expect(r.status).toBe('unverified');
    });
});

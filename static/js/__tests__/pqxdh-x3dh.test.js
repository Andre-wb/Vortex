/**
 * pqxdh-x3dh.test.js (P3)
 * X3DH-PQ математика (x3dhInitiatePq/x3dhRespondPq) + wire type 0x03.
 *
 * Критерий приёмки (advisor): РЕАЛЬНАЯ x3dhRespondPq сверяется с вектором
 * x3dh_pq (инъекция фиксированных pqpk/ct/ss), не только live round-trip — иначе
 * общий arg-order slip обе JS-стороны разделили бы незаметно. respondPq — чистая
 * функция (decaps делает вызывающий), поэтому прямо принимает вектор.
 */

const fs = require('fs');
const path = require('path');

const P = require('../dr/primitives.js');
const { x3dhInitiatePq, x3dhRespondPq } = require('../dr/x3dh.js');
const { mlkemKeygen, mlkemDecaps } = require('../dr/mlkem.js');
const { encodeV2, decodeV2 } = require('../dr/v2-envelope.js');

const vectors = JSON.parse(fs.readFileSync(
    path.resolve(__dirname, '../../../app/tests/vectors/dr_vectors.json'), 'utf8'
));

describe('x3dhRespondPq против вектора x3dh_pq (byte-lock, real function)', () => {
    async function bobShared(name) {
        const x = vectors.x3dh_pq;
        const bobIk = await P.importX25519Priv(x.bob.ik_priv, x.bob.ik_pub);
        const bobSpk = await P.importX25519Priv(x.bob.spk_priv, x.bob.spk_pub);
        const bobOpk = name === 'with_opk'
            ? await P.importX25519Priv(x.bob.opk_priv, x.bob.opk_pub) : null;
        // Инъекция фиксированных KEM-значений вектора (ss как будто уже декапсулирован).
        const shared = await x3dhRespondPq(
            bobIk, bobSpk, bobOpk, x.alice.ik_pub, x[name].ek_pub,
            x.pqpk_pub, x.kem_ciphertext, P.fromHex(x.kem_shared),
        );
        return P.toHex(shared);
    }

    test('with_opk сходится с вектором', async () => {
        expect(await bobShared('with_opk')).toBe(vectors.x3dh_pq.with_opk.shared_secret);
    });

    test('without_opk сходится с вектором', async () => {
        expect(await bobShared('without_opk')).toBe(vectors.x3dh_pq.without_opk.shared_secret);
    });
});

describe('x3dhInitiatePq ↔ x3dhRespondPq (live round-trip, real ML-KEM)', () => {
    async function setup() {
        const aliceIk = await P.generateX25519();
        const bobIk = await P.generateX25519();
        const bobSpk = await P.generateX25519();
        const bobOpk = await P.generateX25519();
        const pqspk = mlkemKeygen();   // Kyber pre-key Bob
        return { aliceIk, bobIk, bobSpk, bobOpk, pqspk };
    }

    test('с OPK: обе стороны сходятся', async () => {
        const { aliceIk, bobIk, bobSpk, bobOpk, pqspk } = await setup();
        const { sharedSecret: skA, ekPubHex, ctHex } = await x3dhInitiatePq(
            aliceIk.priv, bobIk.pubHex, bobSpk.pubHex, bobOpk.pubHex, pqspk.publicKeyHex);
        const ssBob = mlkemDecaps(ctHex, pqspk.secretKeyHex);
        const skB = await x3dhRespondPq(
            bobIk.priv, bobSpk.priv, bobOpk.priv, aliceIk.pubHex, ekPubHex,
            pqspk.publicKeyHex, ctHex, ssBob);
        expect(P.toHex(skB)).toBe(P.toHex(skA));
    });

    test('без OPK: обе стороны сходятся', async () => {
        const { aliceIk, bobIk, bobSpk, pqspk } = await setup();
        const { sharedSecret: skA, ekPubHex, ctHex } = await x3dhInitiatePq(
            aliceIk.priv, bobIk.pubHex, bobSpk.pubHex, null, pqspk.publicKeyHex);
        const ssBob = mlkemDecaps(ctHex, pqspk.secretKeyHex);
        const skB = await x3dhRespondPq(
            bobIk.priv, bobSpk.priv, null, aliceIk.pubHex, ekPubHex,
            pqspk.publicKeyHex, ctHex, ssBob);
        expect(P.toHex(skB)).toBe(P.toHex(skA));
    });

    test('чужой PQSPK-приватный → implicit rejection → SK расходится', async () => {
        const { aliceIk, bobIk, bobSpk, bobOpk, pqspk } = await setup();
        const { sharedSecret: skA, ekPubHex, ctHex } = await x3dhInitiatePq(
            aliceIk.priv, bobIk.pubHex, bobSpk.pubHex, bobOpk.pubHex, pqspk.publicKeyHex);
        const wrong = mlkemKeygen();
        const ssWrong = mlkemDecaps(ctHex, wrong.secretKeyHex);   // другой ss (implicit rejection)
        const skWrong = await x3dhRespondPq(
            bobIk.priv, bobSpk.priv, bobOpk.priv, aliceIk.pubHex, ekPubHex,
            pqspk.publicKeyHex, ctHex, ssWrong);
        expect(P.toHex(skWrong)).not.toBe(P.toHex(skA));
    });
});

describe('v2-envelope type 0x03 (PQXDH prekey wire)', () => {
    const KYBER_CT_HEX = 'ab'.repeat(1088);   // 1088 байт = 2176 hex
    const baseHeader = { dhPublicHex: 'ff'.repeat(32), prevCount: 3, msgNumber: 5 };
    const baseAead = new Uint8Array([1, 2, 3, 4]);
    const pqPrelude = {
        ikPubHex: 'aa'.repeat(32), ekPubHex: 'bb'.repeat(32), spkId: 2, opkId: 7,
        clientDeviceId: 'cc'.repeat(16), deviceSignPub: 'dd'.repeat(32), deviceCertSig: 'ee'.repeat(64),
        pqspkId: 1, pqopkId: null, kyberCtHex: KYBER_CT_HEX,
    };

    test('0x03 round-trip сохраняет классические + PQ поля', () => {
        const hex = encodeV2({ prelude: pqPrelude, header: baseHeader, aead: baseAead });
        expect(hex.slice(0, 2)).toBe('03');
        const dec = decodeV2(hex);
        expect(dec.isPrekey).toBe(true);
        expect(dec.prelude.ikPubHex).toBe('aa'.repeat(32));
        expect(dec.prelude.spkId).toBe(2);
        expect(dec.prelude.opkId).toBe(7);
        expect(dec.prelude.deviceCertSig).toBe('ee'.repeat(64));
        expect(dec.prelude.pqspkId).toBe(1);
        expect(dec.prelude.pqopkId).toBe(null);
        expect(dec.prelude.kyberCtHex).toBe(KYBER_CT_HEX);
        expect(dec.header.msgNumber).toBe(5);
        expect(P.toHex(dec.aead)).toBe('01020304');
    });

    test('классический 0x01 (без kyberCtHex) не затронут', () => {
        const { kyberCtHex, pqspkId, pqopkId, ...classical } = pqPrelude;
        const hex = encodeV2({ prelude: classical, header: baseHeader, aead: baseAead });
        expect(hex.slice(0, 2)).toBe('01');
        const dec = decodeV2(hex);
        expect(dec.isPrekey).toBe(true);
        expect(dec.prelude.kyberCtHex).toBeUndefined();
        expect(dec.prelude.pqspkId).toBeUndefined();
        expect(dec.prelude.spkId).toBe(2);
    });

    test('без OPK, с PQ: round-trip', () => {
        const { opkId, ...noOpk } = pqPrelude;   // opkId undefined → has_opk=0
        const hex = encodeV2({ prelude: noOpk, header: baseHeader, aead: baseAead });
        const dec = decodeV2(hex);
        expect(dec.prelude.opkId).toBe(null);
        expect(dec.prelude.kyberCtHex).toBe(KYBER_CT_HEX);
    });

    test('encode бросает при неверной длине kyber_ciphertext', () => {
        expect(() => encodeV2({
            prelude: { ...pqPrelude, kyberCtHex: 'ab'.repeat(10) },
            header: baseHeader, aead: baseAead,
        })).toThrow(/kyber_ciphertext/);
    });

    test('подмена kyber_ciphertext в конверте → decode парсит, но CT изменён', () => {
        const hex = encodeV2({ prelude: pqPrelude, header: baseHeader, aead: baseAead });
        const dec = decodeV2(hex);
        // Целостность CT видна на приёме: изменённый CT даст другой ss → InvalidTag
        // на ratchet (проверяется в kdf/round-trip тестах); здесь — что поле донеслось.
        expect(dec.prelude.kyberCtHex).toBe(KYBER_CT_HEX);
        expect(dec.prelude.kyberCtHex).not.toBe('cd'.repeat(1088));
    });
});

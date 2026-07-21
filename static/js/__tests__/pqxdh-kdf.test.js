/**
 * pqxdh-kdf.test.js
 * Паритет PQXDH KDF (P1) с Python-референсом.
 * Векторы: app/tests/vectors/dr_vectors.json (x3dh_pq, сгенерированы double_ratchet.py).
 *
 * KEM (ML-KEM) в P1 не запускается — pqpk/ct/ss берутся фиксированными из вектора
 * (KEM считает клиент в P3). Здесь проверяется только byte-parity конкатенации
 * km ‖ pqpk ‖ ct ‖ ss под info="vortex-pqxdh": km-блок воспроизводится DH-операциями
 * respond-стороны (как x3dhRespond), затем kdfX3dhPq обязан сойтись с Python.
 */

const fs = require('fs');
const path = require('path');

const P = require('../dr/primitives.js');

const vectors = JSON.parse(fs.readFileSync(
    path.resolve(__dirname, '../../../app/tests/vectors/dr_vectors.json'), 'utf8'
));

// Восстанавливает km respond-стороны (Bob): 0xFF*32 ‖ DH1‖DH2‖DH3[‖DH4].
async function bobKm(name) {
    const x = vectors.x3dh_pq;
    const bobIk = await P.importX25519Priv(x.bob.ik_priv, x.bob.ik_pub);
    const bobSpk = await P.importX25519Priv(x.bob.spk_priv, x.bob.spk_pub);
    const dh1 = await P.dh(bobSpk, x.alice.ik_pub);
    const dh2 = await P.dh(bobIk, x[name].ek_pub);
    const dh3 = await P.dh(bobSpk, x[name].ek_pub);
    const parts = [P.X3DH_F, dh1, dh2, dh3];
    if (name === 'with_opk') {
        const bobOpk = await P.importX25519Priv(x.bob.opk_priv, x.bob.opk_pub);
        parts.push(await P.dh(bobOpk, x[name].ek_pub));
    }
    return P.concatBytes(...parts);
}

async function bobSharedPq(name) {
    const x = vectors.x3dh_pq;
    const km = await bobKm(name);
    const ss = await P.kdfX3dhPq(
        km, P.fromHex(x.pqpk_pub), P.fromHex(x.kem_ciphertext), P.fromHex(x.kem_shared),
    );
    return P.toHex(ss);
}

describe('PQXDH KDF parity (P1)', () => {
    test('kdfX3dhPq воспроизводит shared_secret из вектора (with_opk)', async () => {
        expect(await bobSharedPq('with_opk')).toBe(vectors.x3dh_pq.with_opk.shared_secret);
    });

    test('kdfX3dhPq воспроизводит shared_secret из вектора (without_opk)', async () => {
        expect(await bobSharedPq('without_opk')).toBe(vectors.x3dh_pq.without_opk.shared_secret);
    });

    test('info домен-сепарация: классический kdfX3dh(km) ≠ pqxdh', async () => {
        // Та же km-часть без KEM под info="vortex-x3dh" даёт другой ключ.
        const km = await bobKm('without_opk');
        const classical = P.toHex(await P.kdfX3dh(km));
        expect(classical).not.toBe(vectors.x3dh_pq.without_opk.shared_secret);
    });

    test('привязка KEM-транскрипта: подмена ct → другой ключ', async () => {
        const x = vectors.x3dh_pq;
        const km = await bobKm('without_opk');
        const ctBad = P.fromHex(x.kem_ciphertext);
        ctBad[0] ^= 0x01;
        const ss = P.toHex(await P.kdfX3dhPq(
            km, P.fromHex(x.pqpk_pub), ctBad, P.fromHex(x.kem_shared),
        ));
        expect(ss).not.toBe(x.without_opk.shared_secret);
    });
});

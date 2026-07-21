// pqxdh.spec.js
// ГЕЙТ активации PQXDH (P7): post-quantum X3DH в РЕАЛЬНОМ браузере. jsdom (jest)
// использует полифилл crypto.subtle — этот стек кусал на real-vs-polyfill. Здесь —
// НАСТОЯЩИЙ движок (Gecko/WebKit/Blink):
//   1. ML-KEM keygen/encaps/decaps корректность + byte-identity getPublic(sk)==pub
//      (иначе KDF-binding расходится → тихий InvalidTag).
//   2. Полный X3DH-PQ round-trip (initiate encaps ↔ respond decaps) на движке.
//   3. Wire 0x03 encode/decode.
//   4. Реальный published PQSPK-sig над СЫРЫМИ байтами (P2↔P5 seam).
//   5. PQOPK-путь (one-time).
//
// Требует запущенного сервера (webServer в playwright.config авто-стартует).
// Запуск: node_modules/.bin/playwright test pqxdh --project=mozilla-firefox --project=apple-safari
//
// ПРЕДУСЛОВИЕ перед выходом приложения в сеть: этот гейт ЗЕЛЁНЫЙ на ≥2 движках.
// (Default-on активирован pre-launch; kill-switch vortex_pqxdh_enabled='0'.)

const { test, expect } = require('@playwright/test');

test.describe('PQXDH (real browser crypto)', () => {
    test('ML-KEM + X3DH-PQ round-trip + 0x03 wire + published-sig + PQOPK', async ({ page }) => {
        await page.goto('/');

        const result = await page.evaluate(async () => {
            const MLKEM = await import('/static/js/dr/mlkem.js');
            const P = await import('/static/js/dr/primitives.js');
            const X3 = await import('/static/js/dr/x3dh.js');
            const ENV = await import('/static/js/dr/v2-envelope.js');
            const PK = await import('/static/js/dr/prekeys.js');

            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(x => parseInt(x, 16)));
            const out = {};

            async function genX() {
                const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
                return { priv: pair.privateKey, pubHex: toHex(await crypto.subtle.exportKey('raw', pair.publicKey)) };
            }

            // --- 1. ML-KEM correctness + byte-identity ---
            const kp = MLKEM.mlkemKeygen();
            const enc = MLKEM.mlkemEncaps(kp.publicKeyHex);
            out.mlkem_match = toHex(enc.sharedSecret) === toHex(MLKEM.mlkemDecaps(enc.cipherTextHex, kp.secretKeyHex));
            out.getpublic_byte_identity = MLKEM.mlkemGetPublic(kp.secretKeyHex) === kp.publicKeyHex;

            // --- 2. Full X3DH-PQ round-trip on the engine ---
            const aliceIk = await genX();
            const bobIk = await genX(); const bobSpk = await genX(); const bobOpk = await genX();
            const pqspk = MLKEM.mlkemKeygen();
            const init = await X3.x3dhInitiatePq(aliceIk.priv, bobIk.pubHex, bobSpk.pubHex, bobOpk.pubHex, pqspk.publicKeyHex);
            const ss = MLKEM.mlkemDecaps(init.ctHex, pqspk.secretKeyHex);
            const skB = await X3.x3dhRespondPq(
                bobIk.priv, bobSpk.priv, bobOpk.priv, aliceIk.pubHex, init.ekPubHex,
                MLKEM.mlkemGetPublic(pqspk.secretKeyHex), init.ctHex, ss);
            out.x3dh_pq_agree = toHex(skB) === toHex(init.sharedSecret);
            // Чужой PQSPK-priv → implicit rejection → расходится
            const wrong = MLKEM.mlkemKeygen();
            const skW = await X3.x3dhRespondPq(
                bobIk.priv, bobSpk.priv, bobOpk.priv, aliceIk.pubHex, init.ekPubHex,
                MLKEM.mlkemGetPublic(pqspk.secretKeyHex), init.ctHex,
                MLKEM.mlkemDecaps(init.ctHex, wrong.secretKeyHex));
            out.x3dh_pq_wrong_diverges = toHex(skW) !== toHex(init.sharedSecret);

            // --- 3. Wire 0x03 encode/decode ---
            const prelude = {
                ikPubHex: aliceIk.pubHex, ekPubHex: init.ekPubHex, spkId: 1, opkId: 7,
                clientDeviceId: 'cc'.repeat(16), deviceSignPub: 'dd'.repeat(32), deviceCertSig: 'ee'.repeat(64),
                pqspkId: 1, pqopkId: null, kyberCtHex: init.ctHex,
            };
            const hex = ENV.encodeV2({ prelude, header: { dhPublicHex: 'ff'.repeat(32), prevCount: 0, msgNumber: 0 }, aead: new Uint8Array([1, 2, 3, 4]) });
            const dw = ENV.decodeV2(hex);
            out.wire_0x03 = hex.slice(0, 2) === '03' && dw.prelude.kyberCtHex === init.ctHex && dw.prelude.pqspkId === 1;

            // --- 4. Published PQSPK-sig над СЫРЫМИ байтами (P2↔P5 seam) ---
            const edPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const edPubHex = toHex(await crypto.subtle.exportKey('raw', edPair.publicKey));
            const edPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', edPair.privateKey));
            const sig = await PK.edSign(edPrivJwk, fromHex(pqspk.publicKeyHex));
            out.pqspk_sig_verifies = await PK.edVerify(edPubHex, fromHex(pqspk.publicKeyHex), sig);
            const otherEd = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            out.pqspk_sig_wrong_ed_fails = !(await PK.edVerify(
                toHex(await crypto.subtle.exportKey('raw', otherEd.publicKey)), fromHex(pqspk.publicKeyHex), sig));

            // --- 5. PQOPK (one-time) путь ---
            const pqopk = MLKEM.mlkemKeygen();
            const initO = await X3.x3dhInitiatePq(aliceIk.priv, bobIk.pubHex, bobSpk.pubHex, null, pqopk.publicKeyHex);
            const skO = await X3.x3dhRespondPq(
                bobIk.priv, bobSpk.priv, null, aliceIk.pubHex, initO.ekPubHex,
                MLKEM.mlkemGetPublic(pqopk.secretKeyHex), initO.ctHex,
                MLKEM.mlkemDecaps(initO.ctHex, pqopk.secretKeyHex));
            out.pqopk_agree = toHex(skO) === toHex(initO.sharedSecret);

            return out;
        });

        expect(result.mlkem_match, 'ML-KEM encaps/decaps agree').toBe(true);
        expect(result.getpublic_byte_identity, 'mlkemGetPublic(sk) === keygen pub (byte-identity)').toBe(true);
        expect(result.x3dh_pq_agree, 'x3dhInitiatePq ↔ x3dhRespondPq agree on engine').toBe(true);
        expect(result.x3dh_pq_wrong_diverges, 'wrong PQSPK priv → divergent SK').toBe(true);
        expect(result.wire_0x03, '0x03 envelope encode/decode round-trip').toBe(true);
        expect(result.pqspk_sig_verifies, 'PQSPK sig over raw bytes verifies (P2↔P5 seam)').toBe(true);
        expect(result.pqspk_sig_wrong_ed_fails, 'wrong device Ed → sig fails').toBe(true);
        expect(result.pqopk_agree, 'PQOPK one-time path agrees on engine').toBe(true);
    });
});

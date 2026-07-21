// pq-hybrid.spec.js
// ГЕЙТ активации PQ-отправки (K5): pure-JS ML-KEM-768 + гибридная обёртка ключей
// в РЕАЛЬНОМ браузере. jsdom (jest) использует полифилл crypto.subtle — этот стек
// уже кусал на real-vs-polyfill Web Crypto. Здесь проверяется НАСТОЯЩИЙ движок:
//   1. ML-KEM keygen/encaps/decaps корректность + perf (pure-JS, без WASM/eval).
//   2. Гибрид hybridEciesEncrypt → decryptRoomKeyEnvelope (приём через свой слот).
//   3. Реальный published-sig round-trip: signKyberPub(аккаунтный Ed) → edVerify —
//      именно эту цепочку делает resolvePeerKyberPub (raw-байты↔hex, не unit-синтетика).
//   4. Stories: wrapStoryKeyForContacts (гибрид) → unwrapStoryKey.
//
// Требует запущенного сервера (Vortex), раздающего static/js/* как ESM.
// Запуск: VORTEX_URL=http://localhost:8000 node_modules/.bin/playwright test pq-hybrid
//
// БЛОКЕР флипа vortex_pq_hybrid_enabled: этот гейт должен быть ЗЕЛЁНЫМ
// (≥ Chrome + Firefox; WebKit желателен) ДО включения отправки.

const { test, expect } = require('@playwright/test');

test.describe('Post-quantum hybrid (real browser crypto)', () => {
    test('ML-KEM correctness + hybrid round-trip + published-sig + stories', async ({ page }) => {
        await page.goto('/');

        const result = await page.evaluate(async () => {
            const MLKEM = await import('/static/js/dr/mlkem.js');
            const CRYPTO = await import('/static/js/crypto.js');
            const KID = await import('/static/js/dr/kyber-identity.js');
            const PK = await import('/static/js/dr/prekeys.js');

            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(x => parseInt(x, 16)));
            const out = {};

            // --- 1. ML-KEM-768 correctness + perf on the real engine ---
            const t0 = performance.now();
            const kp = MLKEM.mlkemKeygen();
            const t1 = performance.now();
            const enc = MLKEM.mlkemEncaps(kp.publicKeyHex);
            const t2 = performance.now();
            const dec = MLKEM.mlkemDecaps(enc.cipherTextHex, kp.secretKeyHex);
            const t3 = performance.now();
            out.mlkem_shared_match = toHex(enc.sharedSecret) === toHex(dec);
            out.mlkem_pub_len = kp.publicKeyHex.length;      // 2368
            out.mlkem_ct_len = enc.cipherTextHex.length;     // 2176
            out.perf_keygen_ms = t1 - t0;
            out.perf_encaps_ms = t2 - t1;
            out.perf_decaps_ms = t3 - t2;
            // Чужой Kyber-priv → другой shared (негатив)
            const other = MLKEM.mlkemKeygen();
            out.mlkem_wrong_priv_differs =
                toHex(MLKEM.mlkemDecaps(enc.cipherTextHex, other.secretKeyHex)) !== toHex(enc.sharedSecret);

            // --- 2. Hybrid ECIES: sender knows only recipient pubs; recipient only privs ---
            const rxPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const rxPubHex = toHex(await crypto.subtle.exportKey('raw', rxPair.publicKey));
            const rxPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', rxPair.privateKey));
            const rxKyber = MLKEM.mlkemKeygen();
            const roomKey = crypto.getRandomValues(new Uint8Array(32));

            const env = await CRYPTO.hybridEciesEncrypt(roomKey, rxPubHex, rxKyber.publicKeyHex);
            out.hybrid_marker = env.hybrid === true && /^[0-9a-f]{2176}$/.test(env.kyber_ciphertext || '');
            const dec1 = await CRYPTO.hybridEciesDecrypt(env, rxPrivJwk, rxKyber.secretKeyHex);
            out.hybrid_roundtrip = toHex(dec1) === toHex(roomKey);

            // Приём через decryptRoomKeyEnvelope (K4b): свой Kyber-priv из слота юзера
            const uid = 4242;
            window.AppState = { user: { user_id: uid } };
            localStorage.setItem(`vortex_kyber_priv_${uid}`, rxKyber.secretKeyHex);
            const dec2 = await CRYPTO.decryptRoomKeyEnvelope(env, rxPrivJwk);
            out.receive_via_slot = toHex(dec2) === toHex(roomKey);

            // --- 3. Real published-sig chain: signKyberPub(Ed) → edVerify (as resolvePeerKyberPub does) ---
            const edPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const edPubHex = toHex(await crypto.subtle.exportKey('raw', edPair.publicKey));
            const edPrivJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', edPair.privateKey));
            const sig = await KID.signKyberPub(rxKyber.publicKeyHex, edPrivJwk);
            out.sig_verifies = await PK.edVerify(edPubHex, fromHex(rxKyber.publicKeyHex), sig);
            // Чужой Ed не верифицирует (Б2-аутентичность)
            const otherEd = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const otherEdHex = toHex(await crypto.subtle.exportKey('raw', otherEd.publicKey));
            out.sig_wrong_ed_fails = !(await PK.edVerify(otherEdHex, fromHex(rxKyber.publicKeyHex), sig));

            // --- 4. Stories: hybrid wrap for a contact (verified kyber_pub) → unwrap ---
            const storyKey = crypto.getRandomValues(new Uint8Array(32));
            const [senv] = await CRYPTO.wrapStoryKeyForContacts(storyKey, [
                { user_id: uid, pub_key: rxPubHex, kyber_pub: rxKyber.publicKeyHex },
            ]);
            out.story_hybrid = senv.hybrid === true;
            const sdec = await CRYPTO.unwrapStoryKey(senv, rxPrivJwk);
            out.story_roundtrip = toHex(sdec) === toHex(storyKey);

            return out;
        });

        // --- Assertions (gate) ---
        expect(result.mlkem_shared_match, 'ML-KEM encaps/decaps shared secret matches').toBe(true);
        expect(result.mlkem_pub_len, 'ML-KEM-768 pub = 2368 hex').toBe(2368);
        expect(result.mlkem_ct_len, 'ML-KEM-768 ct = 2176 hex').toBe(2176);
        expect(result.mlkem_wrong_priv_differs, 'wrong Kyber priv → different shared').toBe(true);

        expect(result.hybrid_marker, 'hybrid envelope well-formed').toBe(true);
        expect(result.hybrid_roundtrip, 'hybrid encrypt→decrypt round-trip').toBe(true);
        expect(result.receive_via_slot, 'decryptRoomKeyEnvelope picks account Kyber-priv from slot').toBe(true);

        expect(result.sig_verifies, 'signKyberPub → edVerify (real published-sig chain)').toBe(true);
        expect(result.sig_wrong_ed_fails, 'wrong account Ed → sig fails (Б2 authenticity)').toBe(true);

        expect(result.story_hybrid, 'story key wrapped hybrid for verified contact').toBe(true);
        expect(result.story_roundtrip, 'story key hybrid round-trip').toBe(true);

        // Perf sanity (pure-JS ML-KEM должен быть быстрым — единицы мс на движке).
        expect(result.perf_keygen_ms, 'ML-KEM keygen perf').toBeLessThan(200);
        expect(result.perf_encaps_ms, 'ML-KEM encaps perf').toBeLessThan(200);
        expect(result.perf_decaps_ms, 'ML-KEM decaps perf').toBeLessThan(200);
    });
});

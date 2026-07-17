// dr-fanout.spec.js
// ГЕЙТ активации v2-отправки (M3.3): device-rooted fan-out в РЕАЛЬНОМ браузере.
// jsdom (jest) использует полифилл crypto.subtle — этот стек уже кусал на
// real-vs-polyfill Web Crypto (raw-X25519-import → JWK {d,x}). Здесь проверяется,
// что НАСТОЯЩИЙ crypto.subtle делает device-rooted X3DH (X25519) + Ed25519
// cert-verify + fan-out round-trip на реальном IndexedDB, байт-совместимо.
//
// Требует запущенного сервера (Vortex), раздающего static/js/dr/* как ESM.
// Запуск: VORTEX_URL=http://localhost:8000 node_modules/.bin/playwright test dr-fanout
//
// БЛОКЕР флипа флага vortex_v2_dm_enabled: этот гейт должен быть ЗЕЛЁНЫМ
// (≥ Chrome + Firefox; WebKit желателен) ДО включения отправки.

const { test, expect } = require('@playwright/test');

test.describe('DR device-rooted fan-out (real browser crypto)', () => {
    test('device-rooted X3DH + cert verify + fan-out round-trip + cert-invalid', async ({ page }) => {
        await page.goto('/');

        const result = await page.evaluate(async () => {
            const DI = await import('/static/js/dr/device-identity.js');
            const SES = await import('/static/js/dr/session.js');
            const STORE = await import('/static/js/dr/session-store.js');
            const PK = await import('/static/js/dr/prekey-store.js');
            const FAN = await import('/static/js/dr/v2-fanout.js');
            const ENV = await import('/static/js/dr/v2-envelope.js');

            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            async function genX25519() {
                const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
                const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
                return { pubHex: toHex(raw), privJwk: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)), priv: pair.privateKey };
            }
            async function genEd() {
                const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
                return { pubHex: toHex(await crypto.subtle.exportKey('raw', pair.publicKey)), priv: pair.privateKey };
            }
            const edSign = async (priv, msg) => toHex(await crypto.subtle.sign('Ed25519', priv, msg));

            const ALICE_DEV = 'a1'.repeat(16), BOB_DEV = 'b2'.repeat(16);

            // Bob (получатель): device x3dh + SPK + OPK в реальном prekey-store
            window.AppState = { user: { user_id: 2 } };
            const bobX3dh = await genX25519(), bobSpk = await genX25519(), bobOpk = await genX25519();
            PK.storePrekeyPrivates({ id: 1, jwk: bobSpk.privJwk }, [{ id: 100, jwk: bobOpk.privJwk }]);
            const bobBundle = {
                device_x3dh_pub: bobX3dh.pubHex, signed_prekey: bobSpk.pubHex, signed_prekey_id: 1,
                one_time_prekey: bobOpk.pubHex, one_time_prekey_id: 100,
            };

            // Alice (инициатор): device x3dh + sign + аккаунтный Ed25519 + cert над тройкой
            const aliceX3dh = await genX25519(), aliceSign = await genEd(), aliceAcct = await genEd();
            const certSig = await edSign(aliceAcct.priv, DI.certMessage(ALICE_DEV, aliceX3dh.pubHex, aliceSign.pubHex));

            // Alice шифрует (device-rooted X3DH, cert в прелюде) на реальном IndexedDB
            const aliceStore = STORE.createSessionStore(STORE.indexedDbBackend('vortex_dr_fanout_a'));
            const env = await SES.encryptV2(aliceStore, SES.dmSessionId(42, BOB_DEV), {
                myDeviceX3dhPriv: aliceX3dh.priv, myDeviceX3dhPubHex: aliceX3dh.pubHex,
                myCert: { clientDeviceId: ALICE_DEV, deviceSignPub: aliceSign.pubHex, deviceCertSig: certSig },
                getPeerBundle: async () => bobBundle,
            }, 'hello real browser');

            // fan-out контейнер: одна обёртка, выбор своего под-конверта, sender id
            const blob = FAN.encodeFanout(ALICE_DEV, { [BOB_DEV]: env });
            const selected = FAN.selectForThisDevice(blob, BOB_DEV);
            const senderDev = FAN.fanoutSender(blob);

            // Bob расшифровывает: cert против аккаунтного Ed25519 Alice
            const bobStore = STORE.createSessionStore(STORE.indexedDbBackend('vortex_dr_fanout_b'));
            const bobX3dhPriv = await SES.importX25519PrivJwk(bobX3dh.privJwk);
            const plain = await SES.decryptV2(bobStore, SES.dmSessionId(42, senderDev),
                { myDeviceX3dhPriv: bobX3dhPriv, trustedSenderAccountEd: aliceAcct.pubHex }, selected);

            // cert-invalid: чужой (серверный) аккаунтный Ed25519 → отказ ДО X3DH
            let certRejected = false;
            try {
                const evil = await genEd();
                const s2 = STORE.createSessionStore(STORE.indexedDbBackend('vortex_dr_fanout_c'));
                await SES.decryptV2(s2, SES.dmSessionId(99, senderDev),
                    { myDeviceX3dhPriv: bobX3dhPriv, trustedSenderAccountEd: evil.pubHex }, selected);
            } catch (e) { certRejected = (e.code === 'cert_invalid') || /cert/i.test(e.message || ''); }

            return {
                plain, senderDev, aliceDev: ALICE_DEV,
                isPrekey: ENV.decodeV2(env).isPrekey,
                certInPrelude: ENV.decodeV2(env).prelude.clientDeviceId,
                certRejected,
            };
        });

        expect(result.plain).toBe('hello real browser');   // real-browser device-rooted X3DH сошёлся
        expect(result.senderDev).toBe(result.aliceDev);     // fan-out `from`
        expect(result.isPrekey).toBe(true);
        expect(result.certInPrelude).toBe(result.aliceDev); // cert инициатора в прелюде
        expect(result.certRejected).toBe(true);             // чужой корень → cert отвергнут
    });
});

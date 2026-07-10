// dr-session-store.spec.js
// Валидация DR-хранилища сессий на РЕАЛЬНЫХ IndexedDB + Web Locks в браузере
// (ADR-001, батч 6a). Юнит-тесты (jest) проверяют логику против in-memory
// бэкенда и мок-локов; здесь проверяется, что продовый indexedDbBackend и
// настоящий navigator.locks работают. Это ГЕЙТ на включение флага в батче 6b.
//
// Требует запущенного сервера (Vortex), раздающего static/js/dr/* как ESM.
// Запуск: VORTEX_URL=http://localhost:8000 node_modules/.bin/playwright test dr-session-store

const { test, expect } = require('@playwright/test');

test.describe('DR session-store: real IndexedDB + Web Locks', () => {
    test('persist across reload + concurrent withSession serialize (no fork)', async ({ page }) => {
        await page.goto('/');

        // Настраиваем сессию, сохраняем в реальный IndexedDB, готовим сообщения.
        const setup = await page.evaluate(async () => {
            const P = await import('/static/js/dr/primitives.js');
            const R = await import('/static/js/dr/ratchet.js');
            const S = await import('/static/js/dr/session-store.js');

            const bobSpk = await P.generateX25519();
            const shared = crypto.getRandomValues(new Uint8Array(32));
            const alice = await R.ratchetInitAlice(shared, bobSpk.pubHex);
            const bob = R.ratchetInitBob(shared, bobSpk.priv, bobSpk.pubHex);

            const store = S.createSessionStore(S.indexedDbBackend('vortex_dr_test'));
            await store.save('t', bob);

            const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
            const mk = async (txt) => {
                const m = await R.ratchetEncrypt(alice, new TextEncoder().encode(txt));
                return { header: m.header, ct: toHex(m.ciphertext) };
            };
            const m0 = await mk('m0');
            const m1 = await mk('m1');
            const m2 = await mk('persisted after reload');

            // Два конкурентных входящих — реальный navigator.locks обязан их
            // сериализовать, иначе состояние форкнется и вторая расшифровка сломётся.
            const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));
            const dec = b => new TextDecoder().decode(b);
            const [r0, r1] = await Promise.all([
                store.withSession('t', async s => ({ state: s, result: dec(await R.ratchetDecrypt(s, m0.header, fromHex(m0.ct))) })),
                store.withSession('t', async s => ({ state: s, result: dec(await R.ratchetDecrypt(s, m1.header, fromHex(m1.ct))) })),
            ]);

            return {
                hasLocks: typeof navigator.locks?.request === 'function',
                concurrent: [r0, r1].sort(),
                m2,
            };
        });

        expect(setup.hasLocks).toBe(true);                 // реальные Web Locks присутствуют
        expect(setup.concurrent).toEqual(['m0', 'm1']);    // сериализовано, без форка

        // Перезагрузка страницы → состояние сессии в реальном IndexedDB переживает.
        await page.reload();

        const afterReload = await page.evaluate(async (m2) => {
            const R = await import('/static/js/dr/ratchet.js');
            const S = await import('/static/js/dr/session-store.js');
            const store = S.createSessionStore(S.indexedDbBackend('vortex_dr_test'));
            const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));
            const dec = b => new TextDecoder().decode(b);
            return store.withSession('t', async (state) => {
                if (!state) return { state: null, result: '[NO STATE]' };
                const pt = dec(await R.ratchetDecrypt(state, m2.header, fromHex(m2.ct)));
                return { state, result: pt };
            });
        }, setup.m2);

        expect(afterReload).toBe('persisted after reload');   // сессия пережила reload

        // Чистим тестовую БД.
        await page.evaluate(() => new Promise(res => {
            const req = indexedDB.deleteDatabase('vortex_dr_test');
            req.onsuccess = req.onerror = req.onblocked = () => res();
        }));
    });
});

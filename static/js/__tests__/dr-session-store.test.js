/**
 * dr-session-store.test.js
 * Персистентность DR-сессий и дисциплина single-writer.
 * IndexedDB/Web Locks в jsdom отсутствуют — тестируем логику против
 * инъектируемого in-memory бэкенда и мок-lockManager.
 */

const P = require('../dr/primitives.js');
const R = require('../dr/ratchet.js');
const { createSessionStore, memoryBackend } = require('../dr/session-store.js');

const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);

async function makeSession() {
    const bobSpk = await P.generateX25519();
    const shared = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const alice = await R.ratchetInitAlice(shared, bobSpk.pubHex);
    const bob = R.ratchetInitBob(shared, bobSpk.priv, bobSpk.pubHex);
    return { alice, bob };
}

describe('session persistence (in-memory backend)', () => {
    test('save → load восстанавливает работоспособную сессию', async () => {
        const store = createSessionStore(memoryBackend());
        const { alice, bob } = await makeSession();

        await store.save('sess1', bob);
        const a = await R.ratchetEncrypt(alice, enc('after restart'));

        // «Перезапуск контекста»: загружаем bob заново из бэкенда
        const restored = await store.load('sess1');
        expect(dec(await R.ratchetDecrypt(restored, a.header, a.ciphertext))).toBe('after restart');
    });

    test('load несуществующей сессии возвращает null', async () => {
        const store = createSessionStore(memoryBackend());
        expect(await store.load('nope')).toBeNull();
    });

    test('delete удаляет сессию', async () => {
        const store = createSessionStore(memoryBackend());
        const { bob } = await makeSession();
        await store.save('s', bob);
        await store.delete('s');
        expect(await store.load('s')).toBeNull();
    });

    test('withSession атомарно продвигает и персистит состояние', async () => {
        const store = createSessionStore(memoryBackend());
        const { alice, bob } = await makeSession();
        await store.save('conv', bob);

        const msgs = [];
        for (let i = 0; i < 3; i++) msgs.push(await R.ratchetEncrypt(alice, enc(`m${i}`)));

        // Каждое входящее обрабатываем в отдельном withSession (как разные события)
        for (const m of msgs) {
            const text = await store.withSession('conv', async (state) => {
                const pt = dec(await R.ratchetDecrypt(state, m.header, m.ciphertext));
                return { state, result: pt };   // мутированное состояние → персист
            });
            expect(text).toBe(`m${msgs.indexOf(m)}`);
        }
    });

    test('withSession создаёт и персистит новую сессию (state === null → возврат state)', async () => {
        const store = createSessionStore(memoryBackend());
        const { alice, bob } = await makeSession();
        const a = await R.ratchetEncrypt(alice, enc('hello new session'));

        // Сессии ещё нет — fn получает null, создаёт (здесь просто bob) и расшифровывает
        const text = await store.withSession('fresh', async (state) => {
            expect(state).toBeNull();
            const pt = dec(await R.ratchetDecrypt(bob, a.header, a.ciphertext));
            return { state: bob, result: pt };   // новосозданное состояние → персист
        });
        expect(text).toBe('hello new session');
        expect(await store.load('fresh')).not.toBeNull();   // сессия сохранена
    });
});

describe('single-writer discipline', () => {
    test('withSession выполняется под предоставленным lockManager', async () => {
        const calls = [];
        const lockManager = {
            request: (name, fn) => { calls.push(name); return fn(); },
        };
        const store = createSessionStore(memoryBackend(), { lockManager });
        const { bob } = await makeSession();
        await store.save('locked', bob);
        await store.withSession('locked', async (state) => ({ state, result: 'ok' }));

        expect(calls).toContain('vortex-dr-locked');   // withSession берёт блокировку
    });

    test('mock lockManager сериализует конкурентные withSession (нет форка состояния)', async () => {
        // Мок Web Locks: строго последовательное исполнение по имени.
        const queues = new Map();
        const lockManager = {
            request(name, fn) {
                const prev = queues.get(name) || Promise.resolve();
                const run = prev.then(fn);
                queues.set(name, run.catch(() => {}));
                return run;
            },
        };
        const store = createSessionStore(memoryBackend(), { lockManager });
        const { alice, bob } = await makeSession();
        await store.save('race', bob);

        const m0 = await R.ratchetEncrypt(alice, enc('first'));
        const m1 = await R.ratchetEncrypt(alice, enc('second'));

        // Запускаем два входящих «одновременно» — блокировка обязана их
        // сериализовать, иначе состояние форкнется и вторая расшифровка сломается.
        const [r0, r1] = await Promise.all([
            store.withSession('race', async s => ({ state: s, result: dec(await R.ratchetDecrypt(s, m0.header, m0.ciphertext)) })),
            store.withSession('race', async s => ({ state: s, result: dec(await R.ratchetDecrypt(s, m1.header, m1.ciphertext)) })),
        ]);
        expect([r0, r1].sort()).toEqual(['first', 'second']);
    });
});

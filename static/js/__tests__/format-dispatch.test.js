/**
 * format-dispatch.test.js
 *
 * Характеризационные тесты ТЕКУЩЕГО поведения ratchetDecrypt (crypto.js):
 * эвристика различения форматов v0/v1, legacy-фолбэки и переинициализация
 * цепочки из roomKey. Батч 1 миграции по ADR-001
 * (docs/adr/001-message-encryption-versions.md).
 *
 * Эти тесты пиннят поведение, на которое опирается прод, — в том числе
 * свойства, признанные дефектными (отсутствие настоящей forward secrecy).
 * При внедрении явного enc_v (батч 2) и Double Ratchet (батчи 5-6) тесты
 * фиксируют, что legacy-пути не сломаны.
 */

const {
    initRatchet,
    ratchetEncrypt,
    ratchetDecrypt,
    clearRatchet,
} = require('../crypto.js');

/** Random 32-byte room key */
function randomRoomKey() {
    return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

/**
 * Шифрует в legacy-формате v0: hex(nonce(12) + AES-256-GCM(text)) прямо на
 * roomKey (как _legacyDecrypt ожидает, crypto.js:432). Первые 4 байта nonce
 * задаются явно — от них зависит эвристика диспатча (crypto.js:356).
 */
async function legacyEncrypt(text, roomKeyBytes, nonceFirst4) {
    const nonce = new Uint8Array(12);
    nonce.set(nonceFirst4, 0);
    nonce.set(globalThis.crypto.getRandomValues(new Uint8Array(8)), 4);
    const key = await globalThis.crypto.subtle.importKey(
        'raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const ct = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(text)
    );
    return toHex(nonce) + toHex(ct);
}

describe('Эвристика диспатча форматов (crypto.js:349, :356)', () => {
    test('legacy v0: первые 4 байта nonce > 100000 → ветка legacy', async () => {
        const roomKey = randomRoomKey();
        // 0xDEADBEEF = 3735928559 > 100000 → ratchetDecrypt уходит в legacy
        const ct = await legacyEncrypt('legacy path', roomKey, [0xde, 0xad, 0xbe, 0xef]);
        const plain = await ratchetDecrypt(ct, 'fd-legacy-room', 'alice', roomKey);
        expect(plain).toBe('legacy path');
    });

    test('legacy v0 с "маленьким" nonce (< 100000) сначала принимается за ratchet, но восстанавливается финальным legacy-фолбэком (crypto.js:414)', async () => {
        const roomKey = randomRoomKey();
        // Первые 4 байта = 5 → эвристика считает это v1-counter'ом.
        // Расшифровка как ratchet проваливается → reinit-retry проваливается →
        // финальный фолбэк _legacyDecrypt читает сообщение.
        const ct = await legacyEncrypt('ambiguous nonce', roomKey, [0x00, 0x00, 0x00, 0x05]);
        const plain = await ratchetDecrypt(ct, 'fd-ambiguous-room', 'alice', roomKey);
        expect(plain).toBe('ambiguous nonce');
    });

    test('вход короче 20 байт уходит в legacy и падает (невалидный GCM)', async () => {
        const roomKey = randomRoomKey();
        const ct = '00'.repeat(16); // 16 байт < 20 → legacy (crypto.js:349) → invalid
        await expect(ratchetDecrypt(ct, 'fd-short-room', 'alice', roomKey))
            .rejects.toThrow();
    });

    test('повреждённый v1-шифртекст отвергается после всех фолбэков', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'fd-tamper-room';
        initRatchet(roomId, 'alice', roomKey);
        const ct = await ratchetEncrypt('intact', roomId, 'alice', roomKey);
        const tampered = ct.slice(0, -2) + (ct.slice(-2) === '00' ? '01' : '00');
        initRatchet(roomId, 'alice', roomKey);
        await expect(ratchetDecrypt(tampered, roomId, 'alice', roomKey))
            .rejects.toThrow();
    });
});

describe('Переинициализация цепочки из roomKey (crypto.js:372, :396)', () => {
    test('перезагрузка отправителя: counter=0 после counter=1 расшифровывается через reinit', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'fd-reload-room';
        const sender = 'bob';

        // Отправитель шлёт два сообщения
        initRatchet(roomId, sender, roomKey);
        const ct0 = await ratchetEncrypt('m0', roomId, sender, roomKey);
        const ct1 = await ratchetEncrypt('m1', roomId, sender, roomKey);

        // Получатель читает оба — его цепочка на позиции 2
        initRatchet(roomId, sender, roomKey);
        expect(await ratchetDecrypt(ct0, roomId, sender, roomKey)).toBe('m0');
        expect(await ratchetDecrypt(ct1, roomId, sender, roomKey)).toBe('m1');

        // «Перезагрузка» отправителя: цепочка сброшена, counter снова 0
        initRatchet(roomId, sender, roomKey);
        const ctAfterReload = await ratchetEncrypt('after reload', roomId, sender, roomKey);
        expect(ctAfterReload.slice(0, 8)).toBe('00000000');

        // Текущее поведение: получатель молча переинициализируется из roomKey
        // и читает сообщение. Это и есть отсутствие настоящего ратчета —
        // постоянный seed позволяет откатить цепочку (уходит в v2, ADR-001).
        expect(await ratchetDecrypt(ctAfterReload, roomId, sender, roomKey)).toBe('after reload');
    });

    test('пропуск вперёд: свежий получатель читает counter=2 без 0 и 1 (fast-forward, crypto.js:383)', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'fd-skip-room';
        const sender = 'carol';

        initRatchet(roomId, sender, roomKey);
        const cts = [];
        for (const m of ['m0', 'm1', 'm2']) {
            cts.push(await ratchetEncrypt(m, roomId, sender, roomKey));
        }

        clearRatchet(roomId); // получатель без состояния
        expect(await ratchetDecrypt(cts[2], roomId, sender, roomKey)).toBe('m2');
        // Более ранние сообщения тоже читаются — через reinit с нуля
        expect(await ratchetDecrypt(cts[0], roomId, sender, roomKey)).toBe('m0');
        expect(await ratchetDecrypt(cts[1], roomId, sender, roomKey)).toBe('m1');
    });

    test('ДОКУМЕНТИРУЕТ ОТСУТСТВИЕ FS: прошлое сообщение читается при знании одного лишь roomKey', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'fd-no-fs-room';
        const sender = 'dave';

        initRatchet(roomId, sender, roomKey);
        const oldCt = await ratchetEncrypt('прошлое сообщение', roomId, sender, roomKey);

        // Всё состояние цепочек уничтожено — у «атакующего» только roomKey
        // (который лежит в localStorage, crypto.js:132-150) и шифртекст.
        clearRatchet(roomId);
        const plain = await ratchetDecrypt(oldCt, roomId, sender, roomKey);

        // Текущее поведение: история восстанавливается. Настоящая forward
        // secrecy (v2, ADR-001) обязана сделать этот сценарий невозможным.
        expect(plain).toBe('прошлое сообщение');
    });
});

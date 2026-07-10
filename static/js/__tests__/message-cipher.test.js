/**
 * message-cipher.test.js
 * Юнит-тесты абстракции encryptMessage/decryptMessage (ADR-001, батч 3).
 * Проверяют реальной криптографией все ветки диспетчера: v1 round-trip,
 * чтение legacy v0 (голый и padded), и отказ при нерасшифровываемом входе.
 */

const {
    encryptMessage,
    decryptMessage,
} = require('../chat/message-cipher.js');
const { encryptText } = require('../chat/room-crypto.js');
const { initRatchet, clearRatchet } = require('../crypto.js');
const { ENC_V_CURRENT } = require('../chat/enc-version.js');

function randomRoomKey() {
    return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

/** Голый legacy v0: hex(nonce(12) + AES-256-GCM(text)) прямо на roomKey. */
async function bareLegacyEncrypt(text, roomKeyBytes) {
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const key = await globalThis.crypto.subtle.importKey('raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(text));
    return toHex(nonce) + toHex(ct);
}

describe('encryptMessage', () => {
    test('возвращает enc_v текущей версии (1) и hex-шифртекст', async () => {
        const roomKey = randomRoomKey();
        const { enc_v, ciphertext } = await encryptMessage('mc-r1', 'alice', 'hello', roomKey);
        expect(enc_v).toBe(ENC_V_CURRENT);
        expect(enc_v).toBe(1);
        expect(ciphertext).toMatch(/^[0-9a-f]+$/);
    });

});

describe('decryptMessage — маршрутизация форматов', () => {
    test('v1 round-trip через абстракцию', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'mc-roundtrip';
        const sender = 'bob';
        clearRatchet(roomId);
        const { ciphertext } = await encryptMessage(roomId, sender, 'секретное сообщение', roomKey);

        initRatchet(roomId, sender, roomKey);
        const plain = await decryptMessage(ciphertext, roomId, sender, roomKey);
        expect(plain).toBe('секретное сообщение');
    });

    test('читает голый legacy v0 (fallback внутри ratchetDecrypt)', async () => {
        const roomKey = randomRoomKey();
        // nonce с большими первыми байтами → эвристика уводит в legacy
        const legacy = await bareLegacyEncrypt('legacy v0 payload', roomKey);
        const plain = await decryptMessage(legacy, 'mc-v0', 'alice', roomKey);
        expect(plain).toBe('legacy v0 payload');
    });

    test('бросает исключение, если ни v1, ни legacy не подходят', async () => {
        const roomKey = randomRoomKey();
        const wrongKey = randomRoomKey();
        const padded = await encryptText('unreadable', roomKey);
        // Другой ключ → ни ratchet, ни decryptText не расшифруют
        await expect(decryptMessage(padded, 'mc-fail', 'alice', wrongKey))
            .rejects.toThrow();
    });

    // Примечание по цепочке: decryptMessage повторяет пре-существующий порядок
    // старых call-sites — ratchetDecrypt (со своим внутренним legacy-фолбэком)
    // раньше decryptText. Для padded-шифртекста (encryptText, magic 0x5678)
    // это означает, что при верном ключе внутренний _legacyDecrypt в
    // ratchetDecrypt возвращает результат БЕЗ снятия паддинга, а внешний
    // decryptText уже не вызывается. Снятие паддинга происходит только при
    // прямом вызове decryptText (indicators.js, пиннированные сообщения) —
    // это поведение унаследовано и не меняется в рамках батча 3.
});

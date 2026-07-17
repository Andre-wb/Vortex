/**
 * cipher-guard.test.js
 * Статический guard: вне message-cipher.js и crypto.js
 * никто не должен вызывать ratchetEncrypt/ratchetDecrypt напрямую — всё
 * шифрование/расшифровка сообщений идёт через абстракцию message-cipher.js.
 *
 * indicators.js легитимно использует decryptText (это legacy-примитив, не
 * ratchet-вызов) и guard не нарушает.
 *
 * Каталог dr/ — крипто-ядро Double Ratchet: там ФУНКЦИИ
 * ratchetEncrypt/ratchetDecrypt определяются (совпадение имён с Python-
 * референсом), это не chat call-site. Исключаем его из проверки; message-cipher
 * подключит dr/, а chat-код вне dr/ по-прежнему под запретом.
 */

const fs = require('fs');
const path = require('path');

const STATIC_JS = path.resolve(__dirname, '..');
const ALLOWED = new Set(['crypto.js', 'message-cipher.js']);
const RATCHET_CALL = /\bratchet(Encrypt|Decrypt)\s*\(/;

/** Рекурсивно собирает .js-файлы, исключая тесты, node_modules, сборку и dr/-ядро. */
function collectJsFiles(dir) {
    const out = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === '__tests__' || entry.name === 'node_modules'
                || entry.name === 'dist' || entry.name === 'dr') continue;
            out.push(...collectJsFiles(full));
        } else if (entry.name.endsWith('.js')) {
            out.push(full);
        }
    }
    return out;
}

describe('message-cipher guard', () => {
    test('нет прямых вызовов ratchetEncrypt/ratchetDecrypt вне message-cipher.js и crypto.js', () => {
        const offenders = [];
        for (const file of collectJsFiles(STATIC_JS)) {
            if (ALLOWED.has(path.basename(file))) continue;
            const lines = fs.readFileSync(file, 'utf8').split('\n');
            lines.forEach((line, i) => {
                if (RATCHET_CALL.test(line)) {
                    offenders.push(`${path.relative(STATIC_JS, file)}:${i + 1}: ${line.trim()}`);
                }
            });
        }
        expect(offenders).toEqual([]);
    });
});

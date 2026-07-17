// static/js/dr/v2-fanout.js
// M2: контейнер fan-out для v2. Одно сообщение несёт `{ from, subs }`:
//   from — client_device_id УСТРОЙСТВА-ОТПРАВИТЕЛЯ (для маршрутизации сессии
//          на приёме: normal-конверты прелюды не несут, а по одному ей не понять,
//          какое устройство отправителя их сделало);
//   subs — карта под-конвертов { client_device_id получателя → v2-envelope-hex }.
// Сервер хранит ОДИН blob на сообщение (per-room, анонимность BMP: «сервер не
// знает, кто получает»); каждое устройство забирает общий blob, выбирает свой
// под-конверт по своему client_device_id и ключует сессию по `from`.
//
// `from` — cleartext (нужен ДО расшифровки, чтобы выбрать сессию). Безопасно под
// BMP: получатель анонимен, отправитель и так известен серверу по sender_id;
// гранулярность до устройства — малая утечка по уже-известной оси.
//
// Здесь — только ФОРМАТ контейнера и выбор под-конверта на приёме. Производство
// многоэлементных карт (fan-out шифрование N устройствам) придёт с mesh-сессиями.
//
// Маркер `v2fan:` отличает blob от одиночного v2-envelope: последний — hex
// (начинается с байта типа 0x01/0x02, т.е. "01"/"02"), маркер начинается с 'v'.

import { getClientDeviceId } from '../utils.js';

const FANOUT_PREFIX = 'v2fan:';

/** true, если строка — fan-out blob (а не одиночный v2-envelope hex). */
export function isFanoutBlob(s) {
    return typeof s === 'string' && s.startsWith(FANOUT_PREFIX);
}

/**
 * Кодирует карту под-конвертов в blob-строку.
 * @param {string} senderDeviceId — client_device_id устройства-отправителя (`from`)
 * @param {Object<string,string>} subsByDevice — { client_device_id получателя(hex) → v2-envelope(hex) }
 * @returns {string}
 */
export function encodeFanout(senderDeviceId, subsByDevice) {
    if (!senderDeviceId || typeof senderDeviceId !== 'string') {
        throw new Error('encodeFanout: senderDeviceId (from) required');
    }
    if (!subsByDevice || typeof subsByDevice !== 'object') {
        throw new Error('encodeFanout: subsByDevice must be an object');
    }
    return FANOUT_PREFIX + JSON.stringify({ from: senderDeviceId, subs: subsByDevice });
}

/**
 * Декодирует blob в { from, subs } либо null, если это не корректный fan-out blob.
 * @param {string} blob
 * @returns {{from: string, subs: Object<string,string>}|null}
 */
export function decodeFanout(blob) {
    if (!isFanoutBlob(blob)) return null;
    try {
        const obj = JSON.parse(blob.slice(FANOUT_PREFIX.length));
        if (obj && typeof obj.from === 'string' && obj.subs && typeof obj.subs === 'object') return obj;
        return null;
    } catch {
        return null;
    }
}

/**
 * client_device_id устройства-отправителя (`from`) для маршрутизации сессии на
 * приёме, либо null для одиночного envelope / битого blob.
 * @param {string} ciphertext
 * @returns {string|null}
 */
export function fanoutSender(ciphertext) {
    const obj = decodeFanout(ciphertext);
    return obj ? obj.from : null;
}

/**
 * Разворачивает входящий ciphertext для ЭТОГО устройства:
 *   • одиночный v2-envelope (не blob)                     → возвращается как есть;
 *   • fan-out blob с под-конвертом для нашего deviceId     → внутренний envelope (hex);
 *   • fan-out blob БЕЗ под-конверта для нас (или битый)    → null (сообщение не нам).
 * @param {string} ciphertext
 * @param {string} [deviceId] — client_device_id этого устройства
 * @returns {string|null}
 */
export function selectForThisDevice(ciphertext, deviceId = getClientDeviceId()) {
    if (!isFanoutBlob(ciphertext)) return ciphertext;
    const obj = decodeFanout(ciphertext);
    if (!obj) return null;
    const inner = obj.subs[deviceId];
    return typeof inner === 'string' ? inner : null;
}

/** Число под-конвертов в blob (0 для одиночного envelope). Диагностика/тесты. */
export function fanoutDeviceCount(ciphertext) {
    const obj = decodeFanout(ciphertext);
    return obj ? Object.keys(obj.subs).length : 0;
}

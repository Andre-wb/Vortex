// static/js/dr/v2-envelope.js
// Формат провода для enc_v:2 (ADR-001, батч 6a). Hex-строка в поле ciphertext.
//
// Два типа (как PreKeySignalMessage / SignalMessage):
//   type 0x01 — prekey (установление сессии): несёт X3DH-прелюдию
//   type 0x02 — normal: только Double Ratchet
//
// Раскладка байт:
//   [1]  type
//   если prekey:
//     [32] initiator_identity_pub   (X25519 IK инициатора — для X3DH-respond)
//     [32] initiator_ephemeral_pub  (EK инициатора)
//     [4]  spk_id                    (BE uint32 — какой Signed Pre-Key адресата)
//     [1]  has_opk (0/1); если 1: [4] opk_id (BE uint32)
//   [40]  dr_header                  (dh_public(32) + prev_count + msg_number)
//   [..]  aead                       (nonce(12) + AES-256-GCM ct+tag)
//
// Прелюдия НЕ входит в AAD (AAD — только 40-байтный header). Это допустимо:
// подмена прелюды меняет выведенный root key → ratchet_decrypt падает InvalidTag.
// Транзитивно связано, отдельный MAC не нужен (ADR §2.4г).

import { fromHex, toHex, concatBytes, serializeHeader } from './primitives.js';

const TYPE_PREKEY = 0x01;
const TYPE_NORMAL = 0x02;

function _u32be(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, false);
    return b;
}

/**
 * Кодирует v2-конверт в hex.
 * @param {object} args
 * @param {{ikPubHex:string, ekPubHex:string, spkId:number, opkId:number|null}|null} args.prelude
 *        — X3DH-прелюдия для prekey-сообщения, либо null для normal
 * @param {{dhPublicHex:string, prevCount:number, msgNumber:number}} args.header
 * @param {Uint8Array} args.aead — nonce(12)+ct
 * @returns {string} hex
 */
export function encodeV2({ prelude, header, aead }) {
    const parts = [];
    if (prelude) {
        parts.push(new Uint8Array([TYPE_PREKEY]));
        parts.push(fromHex(prelude.ikPubHex));
        parts.push(fromHex(prelude.ekPubHex));
        parts.push(_u32be(prelude.spkId));
        if (prelude.opkId != null) {
            parts.push(new Uint8Array([1]));
            parts.push(_u32be(prelude.opkId));
        } else {
            parts.push(new Uint8Array([0]));
        }
    } else {
        parts.push(new Uint8Array([TYPE_NORMAL]));
    }
    parts.push(serializeHeader(header));
    parts.push(aead);
    return toHex(concatBytes(...parts));
}

/**
 * Декодирует v2-конверт.
 * @param {string} hex
 * @returns {{isPrekey:boolean, prelude:object|null, header:object, aead:Uint8Array}}
 * @throws Error при некорректной длине/типе
 */
export function decodeV2(hex) {
    const raw = fromHex(hex);
    if (raw.length < 1) throw new Error('v2 envelope: empty');
    const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    let off = 0;
    const type = raw[off++];

    let prelude = null;
    if (type === TYPE_PREKEY) {
        if (raw.length < 1 + 32 + 32 + 4 + 1 + 40) throw new Error('v2 prekey envelope too short');
        const ikPubHex = toHex(raw.slice(off, off + 32)); off += 32;
        const ekPubHex = toHex(raw.slice(off, off + 32)); off += 32;
        const spkId = dv.getUint32(off, false); off += 4;
        const hasOpk = raw[off++];
        let opkId = null;
        if (hasOpk) { opkId = dv.getUint32(off, false); off += 4; }
        prelude = { ikPubHex, ekPubHex, spkId, opkId };
    } else if (type !== TYPE_NORMAL) {
        throw new Error(`v2 envelope: unknown type 0x${type.toString(16)}`);
    }

    if (raw.length - off < 40) throw new Error('v2 envelope: missing header');
    const headerBytes = raw.slice(off, off + 40); off += 40;
    const header = {
        dhPublicHex: toHex(headerBytes.slice(0, 32)),
        prevCount: new DataView(headerBytes.buffer, headerBytes.byteOffset).getUint32(32, false),
        msgNumber: new DataView(headerBytes.buffer, headerBytes.byteOffset).getUint32(36, false),
    };
    const aead = raw.slice(off);

    return { isPrekey: type === TYPE_PREKEY, prelude, header, aead };
}

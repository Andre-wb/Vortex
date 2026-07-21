// static/js/dr/v2-envelope.js
// Формат провода для enc_v:2. Hex-строка в поле ciphertext.
//
// Три типа (как PreKeySignalMessage / SignalMessage + PQXDH-вариант):
//   type 0x01 — prekey (установление сессии): несёт X3DH-прелюдию
//   type 0x02 — normal: только Double Ratchet
//   type 0x03 — PQXDH-prekey: 0x01 + KEM-поля (post-quantum установление)
//
// Раскладка байт:
//   [1]  type
//   если prekey (0x01 или 0x03):
//     [32] initiator_device_x3dh_pub (X25519 device X3DH-ключ инициатора = IK для respond)
//     [32] initiator_ephemeral_pub   (EK инициатора)
//     [4]  spk_id                     (BE uint32 — какой Signed Pre-Key адресата)
//     [1]  has_opk (0/1); если 1: [4] opk_id (BE uint32)
//     [16] initiator_client_device_id
//     [32] initiator_device_sign_pub
//     [64] initiator_device_cert_sig  (аккаунтный Ed25519 подписал cert над тройкой)
//   если PQXDH-prekey (0x03) — дополнительно:
//     [4]    pqspk_id                 (BE uint32 — какой Kyber pre-key адресата)
//     [1]    has_pqopk (0/1); если 1: [4] pqopk_id (BE uint32) — зарезервировано под P6
//     [1088] kyber_ciphertext         (ML-KEM-768 CT; адресат декапсулирует своим PQSPK-priv)
//   [40]  dr_header                   (dh_public(32) + prev_count + msg_number)
//   [..]  aead                        (nonce(12) + AES-256-GCM ct+tag)
//
// Cert инициатора (client_device_id, device_sign_pub, cert_sig) едет в прелюде,
// т.к. ответчик обязан привязать device-ключ инициатора к его аккаунту —
// verifyDeviceCert против ПРИПИНЕННОГО аккаунтного Ed25519 отправителя. Без этого
// сервер вставил бы свой device-ключ и выдал себя за отправителя.
//
// Прелюдия НЕ входит в AAD (AAD — только 40-байтный header). Это допустимо и
// после расширения: cert_sig покрывает client_device_id ‖ device_x3dh_pub ‖
// device_sign_pub, а device_x3dh_pub(=IK) ещё и кормит root key. Подмена любого
// поля прелюды → cert падает ЛИБО ratchet_decrypt InvalidTag. Отдельный MAC не нужен.
// Для 0x03: подмена kyber_ciphertext → ML-KEM implicit rejection даёт другой SS →
// другой root key (km_pq §3.2) → InvalidTag; CT в AAD не нужен.

import { fromHex, toHex, concatBytes, serializeHeader } from './primitives.js';

const TYPE_PREKEY = 0x01;
const TYPE_NORMAL = 0x02;
const TYPE_PREKEY_PQ = 0x03;

// ML-KEM-768 ciphertext — фиксированная длина (байт).
const KYBER_CT_LEN = 1088;

function _u32be(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, false);
    return b;
}

/**
 * Кодирует v2-конверт в hex.
 * @param {object} args
 * @param {{ikPubHex:string, ekPubHex:string, spkId:number, opkId:number|null,
 *          clientDeviceId:string, deviceSignPub:string, deviceCertSig:string}|null} args.prelude
 *        — X3DH-прелюдия для prekey-сообщения (с device-cert инициатора), либо null для normal
 * @param {{dhPublicHex:string, prevCount:number, msgNumber:number}} args.header
 * @param {Uint8Array} args.aead — nonce(12)+ct
 * @returns {string} hex
 */
export function encodeV2({ prelude, header, aead }) {
    const parts = [];
    if (prelude) {
        if (!prelude.clientDeviceId || !prelude.deviceSignPub || !prelude.deviceCertSig) {
            throw new Error('encodeV2: prekey prelude requires device cert (clientDeviceId/deviceSignPub/deviceCertSig)');
        }
        // PQXDH-прелюда (0x03) — по наличию kyber_ciphertext; иначе классический 0x01.
        const isPq = prelude.kyberCtHex != null;
        parts.push(new Uint8Array([isPq ? TYPE_PREKEY_PQ : TYPE_PREKEY]));
        parts.push(fromHex(prelude.ikPubHex));
        parts.push(fromHex(prelude.ekPubHex));
        parts.push(_u32be(prelude.spkId));
        if (prelude.opkId != null) {
            parts.push(new Uint8Array([1]));
            parts.push(_u32be(prelude.opkId));
        } else {
            parts.push(new Uint8Array([0]));
        }
        parts.push(fromHex(prelude.clientDeviceId));   // 16
        parts.push(fromHex(prelude.deviceSignPub));    // 32
        parts.push(fromHex(prelude.deviceCertSig));    // 64
        if (isPq) {
            parts.push(_u32be(prelude.pqspkId));
            if (prelude.pqopkId != null) {
                parts.push(new Uint8Array([1]));
                parts.push(_u32be(prelude.pqopkId));
            } else {
                parts.push(new Uint8Array([0]));       // has_pqopk=0 (P6 зарезервировано)
            }
            const ct = fromHex(prelude.kyberCtHex);
            if (ct.length !== KYBER_CT_LEN) {
                throw new Error(`encodeV2: kyber_ciphertext must be ${KYBER_CT_LEN} bytes, got ${ct.length}`);
            }
            parts.push(ct);                            // 1088
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
    if (type === TYPE_PREKEY || type === TYPE_PREKEY_PQ) {
        const isPq = type === TYPE_PREKEY_PQ;
        if (raw.length < 1 + 32 + 32 + 4 + 1 + 112 + 40) throw new Error('v2 prekey envelope too short');
        const ikPubHex = toHex(raw.slice(off, off + 32)); off += 32;
        const ekPubHex = toHex(raw.slice(off, off + 32)); off += 32;
        const spkId = dv.getUint32(off, false); off += 4;
        const hasOpk = raw[off++];
        let opkId = null;
        if (hasOpk) { opkId = dv.getUint32(off, false); off += 4; }
        // device-cert инициатора (см. раскладку сверху)
        if (raw.length - off < 112 + 40) throw new Error('v2 prekey envelope: missing device cert');
        const clientDeviceId = toHex(raw.slice(off, off + 16)); off += 16;
        const deviceSignPub = toHex(raw.slice(off, off + 32)); off += 32;
        const deviceCertSig = toHex(raw.slice(off, off + 64)); off += 64;
        prelude = { ikPubHex, ekPubHex, spkId, opkId, clientDeviceId, deviceSignPub, deviceCertSig };
        if (isPq) {
            // PQXDH-хвост: pqspk_id ‖ has_pqopk[+pqopk_id] ‖ kyber_ciphertext
            if (raw.length - off < 4 + 1 + 40) throw new Error('v2 pqxdh envelope: missing kyber fields');
            const pqspkId = dv.getUint32(off, false); off += 4;
            const hasPqopk = raw[off++];
            let pqopkId = null;
            if (hasPqopk) {
                if (raw.length - off < 4 + KYBER_CT_LEN + 40) throw new Error('v2 pqxdh envelope: missing pqopk_id');
                pqopkId = dv.getUint32(off, false); off += 4;
            }
            if (raw.length - off < KYBER_CT_LEN + 40) throw new Error('v2 pqxdh envelope: missing kyber_ciphertext');
            const kyberCtHex = toHex(raw.slice(off, off + KYBER_CT_LEN)); off += KYBER_CT_LEN;
            prelude.pqspkId = pqspkId;
            prelude.pqopkId = pqopkId;
            prelude.kyberCtHex = kyberCtHex;
        }
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

    return { isPrekey: type === TYPE_PREKEY || type === TYPE_PREKEY_PQ, prelude, header, aead };
}

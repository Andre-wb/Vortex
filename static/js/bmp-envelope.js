/**
 * bmp-envelope.js — Unified BMP Envelope Format
 *
 * All message types (text, typing, reaction, edit, delete, signal, etc.)
 * are packed into fixed-size encrypted envelopes so the server cannot
 * distinguish message types by size or pattern.
 *
 * Envelope structure (plaintext, before encryption):
 *   [1B version][1B msg_type][2B payload_length][payload JSON][padding][8B nonce]
 *
 * The entire plaintext is encrypted with AES-256-GCM using a key derived
 * from the room key via HKDF(info="bmp-envelope").
 *
 * Bucket sizes: 1024 (control), 4096 (messages), 16384 (large)
 * All envelopes are padded to the nearest bucket boundary.
 */

// ═══════════════════════════════════════════════════════════════
// MESSAGE TYPE CODES
// ═══════════════════════════════════════════════════════════════

export const MSG = {
    COVER:          0x00,
    MESSAGE:        0x01,
    EDIT:           0x02,
    DELETE:         0x03,
    TYPING:         0x04,
    READ_RECEIPT:   0x05,
    REACTION:       0x06,
    FILE_META:      0x07,
    PIN:            0x08,
    POLL:           0x09,
    SIGNAL:         0x0A,
    PRESENCE:       0x0B,
    SCREENSHOT:     0x0C,
    KEY_EXCHANGE:   0x0D,
    THREAD:         0x0E,
    FORWARD:        0x0F,
    STICKER:        0x10,
    VOICE_EVENT:    0x13,
    FILE_SENDING:   0x14,
};

export const BUCKET_SIZES = [1024, 4096, 16384];

const ENVELOPE_VERSION = 1;
const HEADER_SIZE = 4;  // 1 + 1 + 2
const NONCE_SIZE = 8;
const IV_SIZE = 12;     // AES-GCM IV
const TAG_SIZE = 16;    // AES-GCM auth tag
const HKDF_INFO = new TextEncoder().encode('bmp-envelope');
const HKDF_SALT = new Uint8Array(32); // zero salt

// ═══════════════════════════════════════════════════════════════
// KEY DERIVATION
// ═══════════════════════════════════════════════════════════════

/**
 * Derive a BMP envelope encryption key from the room key.
 * Uses HKDF-SHA256 with info="bmp-envelope" to domain-separate
 * from message encryption keys.
 *
 * @param {Uint8Array} roomKey - 32-byte room key
 * @returns {Promise<CryptoKey>} AES-256-GCM key for envelope encryption
 */
async function _deriveEnvelopeKey(roomKey) {
    const baseKey = await crypto.subtle.importKey('raw', roomKey, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO },
        baseKey, 256
    );
    return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ═══════════════════════════════════════════════════════════════
// PACK ENVELOPE
// ═══════════════════════════════════════════════════════════════

/**
 * Pack a message into a fixed-size encrypted BMP envelope.
 *
 * @param {number} msgType - Message type code (from MSG enum)
 * @param {Object} payload - JSON-serializable payload
 * @param {Uint8Array} roomKey - 32-byte room key
 * @returns {Promise<string>} Hex-encoded encrypted envelope
 */
export async function packEnvelope(msgType, payload, roomKey) {
    // 1. Serialize payload to JSON bytes
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
    const payloadLen = payloadBytes.length;

    // 2. Build plaintext: [version][type][len_hi][len_lo][payload][padding][nonce]
    const contentSize = HEADER_SIZE + payloadLen + NONCE_SIZE;

    // 3. Select smallest bucket that fits (content + IV + TAG overhead for encryption)
    const encryptedOverhead = IV_SIZE + TAG_SIZE;
    let bucketSize = BUCKET_SIZES[BUCKET_SIZES.length - 1]; // default largest
    for (const bs of BUCKET_SIZES) {
        if (contentSize + encryptedOverhead <= bs) {
            bucketSize = bs;
            break;
        }
    }

    // 4. Plaintext size = bucket - IV - TAG (so encrypted output = bucket exactly)
    const plaintextSize = bucketSize - encryptedOverhead;
    const plaintext = new Uint8Array(plaintextSize);

    // Header
    plaintext[0] = ENVELOPE_VERSION;
    plaintext[1] = msgType;
    plaintext[2] = (payloadLen >> 8) & 0xFF;
    plaintext[3] = payloadLen & 0xFF;

    // Payload
    plaintext.set(payloadBytes, HEADER_SIZE);

    // Random padding (fills gap between payload end and nonce position)
    const paddingStart = HEADER_SIZE + payloadLen;
    const paddingEnd = plaintextSize - NONCE_SIZE;
    if (paddingEnd > paddingStart) {
        const padding = crypto.getRandomValues(new Uint8Array(paddingEnd - paddingStart));
        plaintext.set(padding, paddingStart);
    }

    // Random nonce for deduplication (last 8 bytes)
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
    plaintext.set(nonce, plaintextSize - NONCE_SIZE);

    // 5. Encrypt with AES-256-GCM
    const key = await _deriveEnvelopeKey(roomKey);
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_SIZE * 8 },
        key, plaintext
    );

    // 6. Output: [IV (12B)][ciphertext+tag] → total = bucketSize exactly
    const output = new Uint8Array(IV_SIZE + ciphertext.byteLength);
    output.set(iv, 0);
    output.set(new Uint8Array(ciphertext), IV_SIZE);

    // 7. Convert to hex
    return Array.from(output).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ═══════════════════════════════════════════════════════════════
// UNPACK ENVELOPE
// ═══════════════════════════════════════════════════════════════

/**
 * Unpack and decrypt a BMP envelope.
 *
 * @param {string} hexData - Hex-encoded encrypted envelope
 * @param {Uint8Array} roomKey - 32-byte room key
 * @returns {Promise<{type: number, payload: Object, nonce: Uint8Array}|null>}
 */
export async function unpackEnvelope(hexData, roomKey) {
    try {
        // 1. Hex → bytes
        const data = new Uint8Array(hexData.match(/.{2}/g).map(h => parseInt(h, 16)));

        // 2. Extract IV and ciphertext
        const iv = data.slice(0, IV_SIZE);
        const ciphertext = data.slice(IV_SIZE);

        // 3. Decrypt
        const key = await _deriveEnvelopeKey(roomKey);
        const plaintext = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: TAG_SIZE * 8 },
            key, ciphertext
        ));

        // 4. Parse header
        const version = plaintext[0];
        if (version !== ENVELOPE_VERSION) return null;

        const msgType = plaintext[1];
        const payloadLen = (plaintext[2] << 8) | plaintext[3];

        // 5. Extract payload
        const payloadBytes = plaintext.slice(HEADER_SIZE, HEADER_SIZE + payloadLen);
        const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

        // 6. Extract dedup nonce (last 8 bytes of plaintext)
        const dedupNonce = plaintext.slice(plaintext.length - NONCE_SIZE);

        // 7. Cover traffic → discard
        if (msgType === MSG.COVER) return null;

        return { type: msgType, payload, nonce: dedupNonce };
    } catch {
        return null; // Decryption failure = not for us (cover traffic from other rooms)
    }
}

// ═══════════════════════════════════════════════════════════════
// COVER TRAFFIC ENVELOPE
// ═══════════════════════════════════════════════════════════════

/**
 * Generate a cover traffic envelope (type 0x00).
 * Indistinguishable from real 1KB control envelopes.
 *
 * @param {Uint8Array} roomKey - Any room key (or random 32 bytes)
 * @returns {Promise<string>} Hex-encoded 1KB encrypted envelope
 */
export async function packCoverEnvelope(roomKey) {
    return packEnvelope(MSG.COVER, {}, roomKey);
}

// ═══════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════

/**
 * Get the bucket size for a given envelope hex string.
 * All envelopes of the same bucket look identical in size.
 */
export function getEnvelopeSize(hexData) {
    return hexData.length / 2; // hex = 2 chars per byte
}

/**
 * Check if a hex blob is a valid BMP envelope (by size).
 */
export function isValidEnvelopeSize(hexData) {
    const size = hexData.length / 2;
    return BUCKET_SIZES.includes(size);
}

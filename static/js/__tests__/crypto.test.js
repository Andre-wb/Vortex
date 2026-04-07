/**
 * crypto.test.js
 * Comprehensive unit tests for static/js/crypto.js
 *
 * setup.js (loaded via jest.config.js setupFiles) wires Node's built-in
 * WebCrypto onto globalThis.crypto before this file runs, so all
 * crypto.subtle calls in the module under test use a real implementation.
 */

// ── Import the module under test ──────────────────────────────────────────────
const {
    eciesEncrypt,
    eciesDecrypt,
    encryptFile,
    decryptFile,
    getRoomKey,
    setRoomKey,
    initRatchet,
    ratchetEncrypt,
    ratchetDecrypt,
    clearRatchet,
} = require('../crypto.js');

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Generate a fresh X25519 key-pair and return { pubHex, privJwk }. */
async function makeKeyPair() {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey(
        { name: 'X25519' }, true, ['deriveBits']
    );
    const pubRaw = await subtle.exportKey('raw', pair.publicKey);
    const pubHex = Array.from(new Uint8Array(pubRaw))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    const privJwk = JSON.stringify(await subtle.exportKey('jwk', pair.privateKey));
    return { pubHex, privJwk };
}

/** Convert a string to Uint8Array */
const encode = str => new TextEncoder().encode(str);

/** Random 32-byte room key */
function randomRoomKey() {
    return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 1 – toHex / fromHex (internal helpers exercised indirectly)
// ─────────────────────────────────────────────────────────────────────────────

describe('Hex encoding (via encryptFile / eciesEncrypt output)', () => {
    test('encryptFile returns an ArrayBuffer', async () => {
        const key = randomRoomKey();
        const result = await encryptFile(encode('hello').buffer, key);
        expect(result).toBeInstanceOf(ArrayBuffer);
    });

    test('encryptFile output is 12 bytes (nonce) + ciphertext larger than input', async () => {
        const key = randomRoomKey();
        const plaintext = encode('test data');
        const result = await encryptFile(plaintext.buffer, key);
        // nonce(12) + ciphertext (plaintext + 16-byte GCM tag)
        expect(result.byteLength).toBe(12 + plaintext.byteLength + 16);
    });

    test('eciesEncrypt returns ephemeral_pub as 64-char hex string', async () => {
        const kp = await makeKeyPair();
        const roomKey = randomRoomKey();
        const { ephemeral_pub } = await eciesEncrypt(roomKey, kp.pubHex);
        expect(typeof ephemeral_pub).toBe('string');
        // X25519 raw public key = 32 bytes = 64 hex chars
        expect(ephemeral_pub).toHaveLength(64);
        expect(ephemeral_pub).toMatch(/^[0-9a-f]+$/);
    });

    test('eciesEncrypt ciphertext is a hex string', async () => {
        const kp = await makeKeyPair();
        const roomKey = randomRoomKey();
        const { ciphertext } = await eciesEncrypt(roomKey, kp.pubHex);
        expect(typeof ciphertext).toBe('string');
        expect(ciphertext).toMatch(/^[0-9a-f]+$/);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 2 – X25519 key generation (ECIES helper)
// ─────────────────────────────────────────────────────────────────────────────

describe('X25519 key generation', () => {
    test('makeKeyPair produces a 64-char hex public key', async () => {
        const { pubHex } = await makeKeyPair();
        expect(pubHex).toHaveLength(64);
    });

    test('two calls to makeKeyPair produce different public keys', async () => {
        const a = await makeKeyPair();
        const b = await makeKeyPair();
        expect(a.pubHex).not.toBe(b.pubHex);
    });

    test('private key JWK can be round-tripped through JSON.parse', async () => {
        const { privJwk } = await makeKeyPair();
        const parsed = JSON.parse(privJwk);
        expect(parsed.kty).toBe('OKP');
        expect(parsed.crv).toBe('X25519');
        expect(typeof parsed.d).toBe('string');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 3 – ECIES encrypt / decrypt round-trip
// ─────────────────────────────────────────────────────────────────────────────

describe('ECIES encrypt / decrypt', () => {
    test('eciesDecrypt recovers the original room key', async () => {
        const kp = await makeKeyPair();
        const original = randomRoomKey();
        const { ephemeral_pub, ciphertext } = await eciesEncrypt(original, kp.pubHex);
        const recovered = await eciesDecrypt(ephemeral_pub, ciphertext, kp.privJwk);
        expect(recovered).toBeInstanceOf(Uint8Array);
        expect(Array.from(recovered)).toEqual(Array.from(original));
    });

    test('each eciesEncrypt call uses a fresh ephemeral key (different ciphertext)', async () => {
        const kp = await makeKeyPair();
        const roomKey = randomRoomKey();
        const r1 = await eciesEncrypt(roomKey, kp.pubHex);
        const r2 = await eciesEncrypt(roomKey, kp.pubHex);
        // Different ephemeral keys → different ciphertexts (forward secrecy)
        expect(r1.ephemeral_pub).not.toBe(r2.ephemeral_pub);
        expect(r1.ciphertext).not.toBe(r2.ciphertext);
    });

    test('decrypting with wrong private key throws', async () => {
        const kp1 = await makeKeyPair();
        const kp2 = await makeKeyPair();
        const roomKey = randomRoomKey();
        const { ephemeral_pub, ciphertext } = await eciesEncrypt(roomKey, kp1.pubHex);
        await expect(eciesDecrypt(ephemeral_pub, ciphertext, kp2.privJwk))
            .rejects.toThrow();
    });

    test('eciesEncrypt works with a 32-byte all-zero room key', async () => {
        const kp = await makeKeyPair();
        const zeroKey = new Uint8Array(32); // all zeros
        const { ephemeral_pub, ciphertext } = await eciesEncrypt(zeroKey, kp.pubHex);
        const recovered = await eciesDecrypt(ephemeral_pub, ciphertext, kp.privJwk);
        expect(Array.from(recovered)).toEqual(Array.from(zeroKey));
    });

    test('recovered room key has correct length (32 bytes)', async () => {
        const kp = await makeKeyPair();
        const roomKey = randomRoomKey();
        const enc = await eciesEncrypt(roomKey, kp.pubHex);
        const dec = await eciesDecrypt(enc.ephemeral_pub, enc.ciphertext, kp.privJwk);
        expect(dec.byteLength).toBe(32);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 4 – AES-GCM file encrypt / decrypt
// ─────────────────────────────────────────────────────────────────────────────

describe('AES-GCM file encrypt / decrypt', () => {
    test('decryptFile recovers original plaintext', async () => {
        const key = randomRoomKey();
        const msg = 'Hello, Vortex!';
        const enc = await encryptFile(encode(msg).buffer, key);
        const dec = await decryptFile(enc, key);
        expect(new TextDecoder().decode(dec)).toBe(msg);
    });

    test('decryptFile recovers binary data unchanged', async () => {
        const key = randomRoomKey();
        const original = new Uint8Array([0, 1, 2, 3, 255, 254, 253]);
        const enc = await encryptFile(original.buffer, key);
        const dec = await decryptFile(enc, key);
        expect(Array.from(new Uint8Array(dec))).toEqual(Array.from(original));
    });

    test('different keys produce different ciphertexts', async () => {
        const key1 = randomRoomKey();
        const key2 = randomRoomKey();
        const data = encode('same plaintext').buffer;
        const enc1 = await encryptFile(data, key1);
        const enc2 = await encryptFile(data, key2);
        expect(Buffer.from(enc1).toString('hex')).not.toBe(Buffer.from(enc2).toString('hex'));
    });

    test('decryptFile with wrong key throws', async () => {
        const key1 = randomRoomKey();
        const key2 = randomRoomKey();
        const enc = await encryptFile(encode('secret').buffer, key1);
        await expect(decryptFile(enc, key2)).rejects.toThrow();
    });

    test('encrypting empty ArrayBuffer works', async () => {
        const key = randomRoomKey();
        const enc = await encryptFile(new ArrayBuffer(0), key);
        const dec = await decryptFile(enc, key);
        expect(new Uint8Array(dec).byteLength).toBe(0);
    });

    test('encryptFile nonce is always different (random IV)', async () => {
        const key = randomRoomKey();
        const data = encode('same data').buffer;
        const enc1 = await encryptFile(data, key);
        const enc2 = await encryptFile(data, key);
        const nonce1 = Buffer.from(enc1, 0, 12).toString('hex');
        const nonce2 = Buffer.from(enc2, 0, 12).toString('hex');
        expect(nonce1).not.toBe(nonce2);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 5 – Room key store (in-memory)
// ─────────────────────────────────────────────────────────────────────────────

describe('Room key store', () => {
    test('getRoomKey returns null for unknown room', () => {
        expect(getRoomKey('nonexistent-room-99999')).toBeNull();
    });

    test('setRoomKey / getRoomKey round-trip', () => {
        const key = randomRoomKey();
        setRoomKey('room-42', key);
        expect(Array.from(getRoomKey('room-42'))).toEqual(Array.from(key));
    });

    test('overwriting a room key replaces the previous value', () => {
        const key1 = randomRoomKey();
        const key2 = randomRoomKey();
        setRoomKey('room-overwrite', key1);
        setRoomKey('room-overwrite', key2);
        expect(Array.from(getRoomKey('room-overwrite'))).toEqual(Array.from(key2));
    });

    test('different room IDs are stored independently', () => {
        const key1 = randomRoomKey();
        const key2 = randomRoomKey();
        setRoomKey('room-A', key1);
        setRoomKey('room-B', key2);
        expect(Array.from(getRoomKey('room-A'))).toEqual(Array.from(key1));
        expect(Array.from(getRoomKey('room-B'))).toEqual(Array.from(key2));
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 6 – Message Ratchet (forward secrecy / KDF chain)
// ─────────────────────────────────────────────────────────────────────────────

describe('Message ratchet – initRatchet', () => {
    test('initRatchet does not throw', () => {
        const key = randomRoomKey();
        expect(() => initRatchet('r1', 'alice', key)).not.toThrow();
    });

    test('re-initialising an existing chain resets it', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'ratchet-reset-room';
        const sender = 'bob';

        initRatchet(roomId, sender, roomKey);
        const msg1 = await ratchetEncrypt('first', roomId, sender, roomKey);

        // Re-init resets counter back to 0
        initRatchet(roomId, sender, roomKey);
        // After re-init the counter starts from 0 again → same counter byte sequence
        const msgAfterReset = await ratchetEncrypt('first', roomId, sender, roomKey);

        // The counter embedded in both should be 0 (first 4 hex chars = "00000000")
        expect(msg1.slice(0, 8)).toBe('00000000');
        expect(msgAfterReset.slice(0, 8)).toBe('00000000');
    });
});

describe('Message ratchet – ratchetEncrypt / ratchetDecrypt', () => {
    test('single encrypt/decrypt round-trip', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'roundtrip-room';
        const sender = 'charlie';

        initRatchet(roomId, sender, roomKey);
        const ct = await ratchetEncrypt('hello world', roomId, sender, roomKey);

        initRatchet(roomId, sender, roomKey);
        const plain = await ratchetDecrypt(ct, roomId, sender, roomKey);
        expect(plain).toBe('hello world');
    });

    test('ratchetEncrypt returns a hex string', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'hex-check-room';
        const sender = 'dave';
        initRatchet(roomId, sender, roomKey);
        const ct = await ratchetEncrypt('test', roomId, sender, roomKey);
        expect(ct).toMatch(/^[0-9a-f]+$/);
    });

    test('counter increments with each message', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'counter-room';
        const sender = 'eve';
        initRatchet(roomId, sender, roomKey);

        const ct0 = await ratchetEncrypt('msg0', roomId, sender, roomKey);
        const ct1 = await ratchetEncrypt('msg1', roomId, sender, roomKey);

        // First 8 hex chars encode a uint32 counter (big-endian)
        expect(ct0.slice(0, 8)).toBe('00000000'); // counter = 0
        expect(ct1.slice(0, 8)).toBe('00000001'); // counter = 1
    });

    test('multiple sequential messages decrypt correctly', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'seq-room';
        const sender = 'frank';
        const messages = ['alpha', 'beta', 'gamma', 'delta'];

        initRatchet(roomId, sender, roomKey);
        const ciphertexts = [];
        for (const m of messages) {
            ciphertexts.push(await ratchetEncrypt(m, roomId, sender, roomKey));
        }

        // Decrypt must follow the same ratchet order
        initRatchet(roomId, sender, roomKey);
        for (let i = 0; i < messages.length; i++) {
            const plain = await ratchetDecrypt(ciphertexts[i], roomId, sender, roomKey);
            expect(plain).toBe(messages[i]);
        }
    });

    test('different senders have independent ratchet chains', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'multi-sender-room';

        initRatchet(roomId, 'sender1', roomKey);
        initRatchet(roomId, 'sender2', roomKey);

        const ct1 = await ratchetEncrypt('from-sender1', roomId, 'sender1', roomKey);
        const ct2 = await ratchetEncrypt('from-sender2', roomId, 'sender2', roomKey);

        // Chains are independent so ciphertexts should differ
        expect(ct1).not.toBe(ct2);

        initRatchet(roomId, 'sender1', roomKey);
        initRatchet(roomId, 'sender2', roomKey);
        expect(await ratchetDecrypt(ct1, roomId, 'sender1', roomKey)).toBe('from-sender1');
        expect(await ratchetDecrypt(ct2, roomId, 'sender2', roomKey)).toBe('from-sender2');
    });
});

describe('clearRatchet', () => {
    test('clearRatchet removes all chains for a room', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'clear-room';

        initRatchet(roomId, 'u1', roomKey);
        initRatchet(roomId, 'u2', roomKey);
        clearRatchet(roomId);

        // After clearing, a new encrypt should auto-init from counter 0
        const ct = await ratchetEncrypt('new', roomId, 'u1', roomKey);
        expect(ct.slice(0, 8)).toBe('00000000');
    });

    test('clearRatchet only removes chains for the specified room', async () => {
        const roomKey = randomRoomKey();
        initRatchet('keep-room', 'user', roomKey);
        initRatchet('remove-room', 'user', roomKey);
        clearRatchet('remove-room');

        // The chain for keep-room is still live (counter did not reset)
        const ct = await ratchetEncrypt('msg', 'keep-room', 'user', roomKey);
        // counter should still be at its previous position (1 if one msg was already sent)
        // Mainly ensure it does NOT throw
        expect(ct).toMatch(/^[0-9a-f]+$/);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Group 7 – HKDF key derivation (tested indirectly through ratchet internals)
// ─────────────────────────────────────────────────────────────────────────────

describe('HKDF / KDF chain (forward secrecy property)', () => {
    test('consecutive ratchet chain keys are different (HKDF advances the chain)', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'hkdf-room';
        const sender = 'hkdf-sender';
        initRatchet(roomId, sender, roomKey);

        // Encrypt two messages; each advances the chain key via HKDF
        const ct0 = await ratchetEncrypt('m0', roomId, sender, roomKey);
        const ct1 = await ratchetEncrypt('m1', roomId, sender, roomKey);

        // The ciphertexts should differ beyond just the counter (different message keys)
        // Strip the 4-byte counter prefix and compare the rest
        expect(ct0.slice(8)).not.toBe(ct1.slice(8));
    });

    test('ratchet ciphertext is deterministically different for identical plaintexts', async () => {
        const roomKey = randomRoomKey();
        const roomId = 'det-room';
        const sender = 'det-sender';

        initRatchet(roomId, sender, roomKey);
        const ct1 = await ratchetEncrypt('same', roomId, sender, roomKey);

        initRatchet(roomId, sender, roomKey);
        const ct2 = await ratchetEncrypt('same', roomId, sender, roomKey);

        // Nonces are random so even two encryptions with fresh ratchets differ
        // (different IVs in AES-GCM)
        // Counter bytes (0..7) are identical (both = 0), rest differs
        expect(ct1.slice(0, 8)).toBe(ct2.slice(0, 8)); // counter matches
        // The overall ciphertext almost certainly differs due to random nonce
        // This assertion is probabilistic but the chance of collision is 2^-96
        expect(ct1.slice(8)).not.toBe(ct2.slice(8));
    });
});

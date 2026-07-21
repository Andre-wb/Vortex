// static/js/dr/primitives.js
// Криптографические примитивы Double Ratchet. Байт-в-байт совместимы с
// референсом app/security/double_ratchet.py (проверяется против
// app/tests/vectors/dr_vectors.json).
//
// X25519: Web Crypto не экспортирует/импортирует X25519 private как raw, но
// умеет через JWK ({d,x}). Приватный скаляр сериализуем как d (raw hex),
// импортируем, собирая {d,x} JWK из приватного+публичного hex.

const subtle = () => globalThis.crypto.subtle;

export const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
export const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

function _b64urlFromBytes(bytes) {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function _bytesFromB64url(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
}

export function concatBytes(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}

// X25519

/** Генерирует X25519 пару. Возвращает { priv: CryptoKey (extractable), pubHex }. */
export async function generateX25519() {
    const pair = await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubRaw = await subtle().exportKey('raw', pair.publicKey);
    return { priv: pair.privateKey, pubHex: toHex(pubRaw) };
}

/** Импортирует X25519 публичный ключ из hex → CryptoKey. */
export async function importX25519Pub(pubHex) {
    return subtle().importKey('raw', fromHex(pubHex), { name: 'X25519' }, false, []);
}

/**
 * Импортирует X25519 приватный ключ из raw hex + публичный hex (нужен для JWK.x).
 * extractable=true, чтобы состояние можно было пересериализовать.
 */
export async function importX25519Priv(privHex, pubHex) {
    const jwk = {
        kty: 'OKP', crv: 'X25519',
        d: _b64urlFromBytes(fromHex(privHex)),
        x: _b64urlFromBytes(fromHex(pubHex)),
    };
    return subtle().importKey('jwk', jwk, { name: 'X25519' }, true, ['deriveBits']);
}

/** Экспортирует raw hex приватного скаляра из CryptoKey (через JWK.d). */
export async function exportX25519PrivHex(privKey) {
    const jwk = await subtle().exportKey('jwk', privKey);
    return toHex(_bytesFromB64url(jwk.d));
}

/** X25519 Diffie-Hellman: DH(privKey, peerPubHex) → 32 байта. */
export async function dh(privKey, peerPubHex) {
    const peer = await importX25519Pub(peerPubHex);
    const bits = await subtle().deriveBits({ name: 'X25519', public: peer }, privKey, 256);
    return new Uint8Array(bits);
}

// KDF chains — точное соответствие double_ratchet.py

/**
 * kdf_ck — Signal-standard, СЫРОЙ HMAC-SHA256 (НЕ HKDF):
 *   new_chain_key = HMAC(ck, 0x02); message_key = HMAC(ck, 0x01).
 */
export async function kdfCk(ckBytes) {
    const key = await subtle().importKey('raw', ckBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const newCk = new Uint8Array(await subtle().sign('HMAC', key, new Uint8Array([0x02])));
    const mk    = new Uint8Array(await subtle().sign('HMAC', key, new Uint8Array([0x01])));
    return { newCk, mk };
}

/**
 * kdf_rk — HKDF-SHA256(ikm=dh_out, salt=rk, info="vortex-double-ratchet", 64 байта)
 * → (root_key[:32], chain_key[32:]). salt=rk, ikm=dh_out — не перепутать.
 */
export async function kdfRk(rkBytes, dhOutBytes) {
    const key = await subtle().importKey('raw', dhOutBytes, 'HKDF', false, ['deriveBits']);
    const bits = new Uint8Array(await subtle().deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: rkBytes, info: new TextEncoder().encode('vortex-double-ratchet') },
        key, 512,
    ));
    return { rootKey: bits.slice(0, 32), chainKey: bits.slice(32, 64) };
}

const X3DH_INFO = new TextEncoder().encode('vortex-x3dh');

/** X3DH KDF: HKDF-SHA256(ikm=km, salt=0x00*32, info="vortex-x3dh", 32 байта). */
export async function kdfX3dh(kmBytes) {
    const key = await subtle().importKey('raw', kmBytes, 'HKDF', false, ['deriveBits']);
    const bits = await subtle().deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: X3DH_INFO },
        key, 256,
    );
    return new Uint8Array(bits);
}

/** Байт-префикс X3DH: 0xFF * 32 (доменное разделение). */
export const X3DH_F = new Uint8Array(32).fill(0xff);

const X3DH_PQ_INFO = new TextEncoder().encode('vortex-pqxdh');

/**
 * PQXDH KDF: HKDF-SHA256(ikm = km ‖ pqpk ‖ ct ‖ ss, salt=0x00*32,
 * info="vortex-pqxdh", 32 байта). Привязывает KEM-транскрипт (публичный
 * pre-key адресата + ciphertext + shared secret) прямо в деривацию — строго
 * сильнее спек-минимума PQXDH (SS в KDF + PQPK в AD) и не зависит от
 * внутреннего binding-свойства ML-KEM. info домен-сепарирует от классического
 * "vortex-x3dh" (тот не трогаем). Порядок конкатенации здесь — канон (байт-lock).
 * @param {Uint8Array} kmBytes — 0xFF*32 ‖ DH1‖DH2‖DH3[‖DH4]
 * @param {Uint8Array} pqpkBytes — Kyber pre-key pub адресата (1184 байта)
 * @param {Uint8Array} ctBytes — KEM ciphertext (1088 байт)
 * @param {Uint8Array} ssBytes — KEM shared secret (32 байта)
 * @returns {Promise<Uint8Array>} 32 байта
 */
export async function kdfX3dhPq(kmBytes, pqpkBytes, ctBytes, ssBytes) {
    // Tripwire на порядок аргументов: KEM-части ML-KEM-768 имеют фиксированные
    // длины — перестановка pqpk/ct/ss (обе JS-стороны разделили бы её и молча
    // interop'нули бы на не-спек-деривации) ловится сразу.
    if (pqpkBytes.length !== 1184 || ctBytes.length !== 1088 || ssBytes.length !== 32) {
        throw new Error(
            `kdfX3dhPq: bad KEM lengths pqpk=${pqpkBytes.length} ct=${ctBytes.length} ss=${ssBytes.length}`);
    }
    const ikm = concatBytes(kmBytes, pqpkBytes, ctBytes, ssBytes);
    const key = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await subtle().deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: X3DH_PQ_INFO },
        key, 256,
    );
    return new Uint8Array(bits);
}

// AES-256-GCM

/** Шифрует: nonce(12) + AES-256-GCM(pt) с aad. Возвращает Uint8Array. */
export async function aeadEncrypt(mkBytes, plaintextBytes, aadBytes) {
    const key = await subtle().importKey('raw', mkBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle().encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadBytes }, key, plaintextBytes,
    );
    return concatBytes(nonce, new Uint8Array(ct));
}

/** Расшифровывает nonce(12)+ct с aad. Бросает при неверном теге. */
export async function aeadDecrypt(mkBytes, dataBytes, aadBytes) {
    const key = await subtle().importKey('raw', mkBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const nonce = dataBytes.slice(0, 12);
    const ct    = dataBytes.slice(12);
    const pt = await subtle().decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadBytes }, key, ct,
    );
    return new Uint8Array(pt);
}

// Header — 40 байт, используется как AAD

/**
 * serializeHeader — dh_public(32) + big-endian uint32 prev_count + uint32 msg_number.
 * Ровно 40 байт (соответствует Header.serialize в double_ratchet.py).
 */
export function serializeHeader({ dhPublicHex, prevCount, msgNumber }) {
    const out = new Uint8Array(40);
    out.set(fromHex(dhPublicHex), 0);
    const dv = new DataView(out.buffer);
    dv.setUint32(32, prevCount >>> 0, false);   // big-endian
    dv.setUint32(36, msgNumber >>> 0, false);
    return out;
}

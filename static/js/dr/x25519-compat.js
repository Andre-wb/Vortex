const RAW_LEN = 32;

let _nativeProbe = null;
let _fallbackMod = null;

function _subtle() {
    return globalThis.crypto?.subtle;
}

function _toHex(bytes) {
    return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function _fromHex(hex) {
    return Uint8Array.from(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function _b64url(bytes) {
    let bin = '';
    for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function _unb64url(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function _fallback() {
    if (!_fallbackMod) {
        const mod = await import('../vendor/x25519.js');
        _fallbackMod = mod.x25519;
    }
    return _fallbackMod;
}

export function isNativeX25519() {
    return _nativeProbe === true;
}

async function _hasNative() {
    if (_nativeProbe !== null) return _nativeProbe;
    const subtle = _subtle();
    if (!subtle) {
        _nativeProbe = false;
        return false;
    }
    try {
        const pair = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        await subtle.exportKey('raw', pair.publicKey);
        await subtle.exportKey('jwk', pair.privateKey);
        await subtle.deriveBits({ name: 'X25519', public: pair.publicKey }, pair.privateKey, 256);
        _nativeProbe = true;
    } catch {
        _nativeProbe = false;
    }
    return _nativeProbe;
}

function _wrapPub(bytes) {
    return { _x25519: 'public', bytes: new Uint8Array(bytes) };
}

function _wrapPriv(privBytes, pubBytes) {
    return { _x25519: 'private', bytes: new Uint8Array(privBytes), pub: new Uint8Array(pubBytes) };
}

export async function generateKeyPair() {
    if (await _hasNative()) {
        const pair = await _subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
        return { privateKey: pair.privateKey, publicKey: pair.publicKey };
    }
    const x = await _fallback();
    const priv = globalThis.crypto.getRandomValues(new Uint8Array(RAW_LEN));
    const pub = x.getPublicKey(priv);
    return { privateKey: _wrapPriv(priv, pub), publicKey: _wrapPub(pub) };
}

export async function importPublicRaw(rawBytes) {
    const bytes = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    if (bytes.length !== RAW_LEN) throw new Error('x25519: public key must be 32 bytes');
    if (await _hasNative()) {
        return _subtle().importKey('raw', bytes, { name: 'X25519' }, false, []);
    }
    await _fallback();
    return _wrapPub(bytes);
}

export async function importPublicHex(pubHex) {
    return importPublicRaw(_fromHex(pubHex));
}

export async function importPrivateJwk(jwk, extractable = true) {
    const obj = typeof jwk === 'string' ? JSON.parse(jwk) : jwk;
    if (await _hasNative()) {
        return _subtle().importKey('jwk', obj, { name: 'X25519' }, extractable, ['deriveBits']);
    }
    const x = await _fallback();
    if (!obj?.d) throw new Error('x25519: JWK has no private component');
    const priv = _unb64url(obj.d);
    const pub = obj.x ? _unb64url(obj.x) : x.getPublicKey(priv);
    return _wrapPriv(priv, pub);
}

export async function importPrivateHex(privHex, pubHex) {
    return importPrivateJwk({
        kty: 'OKP',
        crv: 'X25519',
        d: _b64url(_fromHex(privHex)),
        x: _b64url(_fromHex(pubHex)),
    });
}

export async function exportPublicRaw(key) {
    if (key?._x25519) {
        return (key._x25519 === 'private' ? key.pub : key.bytes).slice().buffer;
    }
    return _subtle().exportKey('raw', key);
}

export async function exportPublicHex(key) {
    return _toHex(await exportPublicRaw(key));
}

export async function exportPrivateJwk(key) {
    if (key?._x25519 === 'private') {
        return {
            kty: 'OKP',
            crv: 'X25519',
            d: _b64url(key.bytes),
            x: _b64url(key.pub),
            key_ops: ['deriveBits'],
            ext: true,
        };
    }
    return _subtle().exportKey('jwk', key);
}

export async function deriveBits(privateKey, publicKey) {
    if (privateKey?._x25519 || publicKey?._x25519) {
        const x = await _fallback();
        const priv = privateKey?._x25519 === 'private' ? privateKey.bytes : null;
        const pub = publicKey?._x25519 ? (publicKey._x25519 === 'private' ? publicKey.pub : publicKey.bytes) : null;
        if (!priv || !pub) throw new Error('x25519: cannot mix native and fallback keys');
        return x.getSharedSecret(priv, pub).slice().buffer;
    }
    return _subtle().deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256);
}

export async function deriveSharedHex(privateKey, peerPubHex) {
    const peer = await importPublicHex(peerPubHex);
    return new Uint8Array(await deriveBits(privateKey, peer));
}

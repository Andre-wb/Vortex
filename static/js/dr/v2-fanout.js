import { getClientDeviceId } from '../utils.js';

const FANOUT_PREFIX = 'v2fan:';
const FANOUT_PREFIX_HEX = '763266616e3a';

function _toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function _fromHex(hex) {
    return Uint8Array.from(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function _unwrap(s) {
    if (typeof s !== 'string') return null;
    if (s.startsWith(FANOUT_PREFIX)) return s;
    if (!s.startsWith(FANOUT_PREFIX_HEX)) return null;
    if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) return null;
    try {
        return new TextDecoder().decode(_fromHex(s));
    } catch {
        return null;
    }
}

export function isFanoutBlob(s) {
    return _unwrap(s) !== null;
}

export function encodeFanout(senderDeviceId, subsByDevice) {
    if (!senderDeviceId || typeof senderDeviceId !== 'string') {
        throw new Error('encodeFanout: senderDeviceId (from) required');
    }
    if (!subsByDevice || typeof subsByDevice !== 'object') {
        throw new Error('encodeFanout: subsByDevice must be an object');
    }
    const payload = FANOUT_PREFIX + JSON.stringify({ from: senderDeviceId, subs: subsByDevice });
    return _toHex(new TextEncoder().encode(payload));
}

export function decodeFanout(blob) {
    const unwrapped = _unwrap(blob);
    if (unwrapped === null) return null;
    try {
        const obj = JSON.parse(unwrapped.slice(FANOUT_PREFIX.length));
        if (obj && typeof obj.from === 'string' && obj.subs && typeof obj.subs === 'object') return obj;
        return null;
    } catch {
        return null;
    }
}

export function fanoutSender(ciphertext) {
    const obj = decodeFanout(ciphertext);
    return obj ? obj.from : null;
}

export function selectForThisDevice(ciphertext, deviceId = getClientDeviceId()) {
    if (!isFanoutBlob(ciphertext)) return ciphertext;
    const obj = decodeFanout(ciphertext);
    if (!obj) return null;
    const inner = obj.subs[deviceId];
    return typeof inner === 'string' ? inner : null;
}

export function fanoutDeviceCount(ciphertext) {
    const obj = decodeFanout(ciphertext);
    return obj ? Object.keys(obj.subs).length : 0;
}

// static/js/e2e_media_worker.js
// ============================================================================
// Worker для E2E шифрования/дешифрования медиа-фреймов WebRTC.
// Используется через RTCRtpScriptTransform (Firefox 117+, Safari 15.4+, Chrome 118+).
//
// Формат фрейма: [AES-GCM(payload)] [iv(12)] [0x0C]
// ============================================================================

'use strict';

const NONCE_LEN = 12;
const TRAILER   = NONCE_LEN + 1;

async function encryptFrame(key, frame, controller) {
    const iv   = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const data = new Uint8Array(frame.data);

    try {
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: new Uint8Array(0) },
            key, data
        );
        const enc = new Uint8Array(encrypted);
        const out = new Uint8Array(enc.byteLength + TRAILER);
        out.set(enc, 0);
        out.set(iv, enc.byteLength);
        out[out.byteLength - 1] = NONCE_LEN;
        frame.data = out.buffer;
    } catch (_) {
        // pass through on error
    }
    controller.enqueue(frame);
}

async function decryptFrame(key, frame, controller) {
    const data = new Uint8Array(frame.data);

    if (data.byteLength < TRAILER + 16) {
        controller.enqueue(frame);
        return;
    }

    const ivLen = data[data.byteLength - 1];
    if (ivLen !== NONCE_LEN) {
        controller.enqueue(frame);
        return;
    }

    const iv        = data.slice(data.byteLength - TRAILER, data.byteLength - 1);
    const encrypted = data.slice(0, data.byteLength - TRAILER);

    try {
        frame.data = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: new Uint8Array(0) },
            key, encrypted
        );
    } catch (_) {
        // pass through on error (unencrypted peer or key mismatch)
    }
    controller.enqueue(frame);
}

// RTCRtpScriptTransform event handler
self.onrtctransform = async (event) => {
    const { operation, keyBytes } = event.transformer.options;
    const usages = operation === 'encrypt' ? ['encrypt'] : ['decrypt'];

    const key = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, usages
    );

    const transform = new TransformStream({
        transform: (frame, controller) =>
            operation === 'encrypt'
                ? encryptFrame(key, frame, controller)
                : decryptFrame(key, frame, controller),
    });

    event.transformer.readable
        .pipeThrough(transform)
        .pipeTo(event.transformer.writable);
};

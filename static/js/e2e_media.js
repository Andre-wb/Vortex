// static/js/e2e_media.js
// ============================================================================
// E2E Media Frame Encryption — AES-256-GCM поверх WebRTC DTLS-SRTP.
//
// Два пути в зависимости от браузера:
//   1. RTCRtpScriptTransform (Firefox 117+, Safari 15.4+, Chrome 118+)
//      — стандартный W3C API, шифрование в Worker (e2e_media_worker.js)
//   2. createEncodedStreams (Chrome 86–117)
//      — legacy Chromium API, шифрование на main thread
//
// Формат зашифрованного фрейма:
//   [AES-GCM(payload)] [iv (12 bytes)] [0x0C]
// ============================================================================

const NONCE_LEN = 12;
const TRAILER   = NONCE_LEN + 1;

// ─── Feature detection ─────────────────────────────────────────────────────

function _supportsScriptTransform() {
    return typeof RTCRtpScriptTransform !== 'undefined';
}

function _supportsEncodedStreams() {
    return typeof RTCRtpSender !== 'undefined' &&
        typeof RTCRtpSender.prototype.createEncodedStreams === 'function';
}

/**
 * Проверяет поддержку E2E media encryption в текущем браузере.
 * Firefox 117+, Safari 15.4+, Chrome 86+.
 */
export function isE2ESupported() {
    return _supportsScriptTransform() || _supportsEncodedStreams();
}

/**
 * Нужно ли ставить encodedInsertableStreams: true в RTCPeerConnection config.
 * Требуется только для legacy createEncodedStreams (Chrome 86–117).
 * RTCRtpScriptTransform (Firefox/Safari/Chrome 118+) НЕ нуждается в этом флаге.
 */
export function needsEncodedInsertableStreams() {
    return !_supportsScriptTransform() && _supportsEncodedStreams();
}

// ─── Worker (lazy singleton) ────────────────────────────────────────────────

let _e2eWorker = null;

function _getWorker() {
    if (!_e2eWorker) {
        _e2eWorker = new Worker('/static/js/e2e_media_worker.js');
    }
    return _e2eWorker;
}

// ─── Key derivation ─────────────────────────────────────────────────────────

/**
 * Создаёт AES-256-GCM ключ для медиа-шифрования из ключа комнаты и callId.
 * HKDF-SHA256 с info="vortex-media-e2e" для domain separation.
 *
 * Возвращает объект { key, raw }:
 *   key — CryptoKey для main-thread шифрования (createEncodedStreams path)
 *   raw — Uint8Array(32) для передачи в Worker (RTCRtpScriptTransform path)
 *
 * @param {Uint8Array} roomKeyBytes - 32-байтный ключ комнаты
 * @param {string} callId - идентификатор звонка
 * @returns {Promise<{key: CryptoKey, raw: Uint8Array}>}
 */
export async function deriveMediaKey(roomKeyBytes, callId) {
    const ikm  = await crypto.subtle.importKey('raw', roomKeyBytes, 'HKDF', false, ['deriveBits']);
    const salt = new TextEncoder().encode(callId || 'default-call');
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: new TextEncoder().encode('vortex-media-e2e'),
        },
        ikm, 256
    );
    const raw = new Uint8Array(bits);
    const key = await crypto.subtle.importKey(
        'raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    return { key, raw };
}

// ─── Main-thread frame encrypt/decrypt (createEncodedStreams fallback) ──────

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
    } catch (e) {
        console.warn('[E2E-Media] encrypt error, passing through:', e.message);
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
        // unencrypted peer or key mismatch — pass through
    }
    controller.enqueue(frame);
}

// ─── Transform setup ────────────────────────────────────────────────────────

/**
 * Устанавливает шифрующий transform на RTCRtpSender.
 * @param {RTCRtpSender} sender
 * @param {{key: CryptoKey, raw: Uint8Array}} mediaKey
 */
export function setupSenderTransform(sender, mediaKey) {
    if (!sender || !mediaKey) return;

    // Path 1: RTCRtpScriptTransform (Firefox 117+, Safari 15.4+, Chrome 118+)
    if (_supportsScriptTransform()) {
        const buf = mediaKey.raw.buffer.slice(0);  // copy — transfer moves ownership
        sender.transform = new RTCRtpScriptTransform(
            _getWorker(),
            { operation: 'encrypt', keyBytes: buf },
            [buf]
        );
        return;
    }

    // Path 2: createEncodedStreams (Chrome 86–117)
    if (typeof sender.createEncodedStreams === 'function') {
        const { readable, writable } = sender.createEncodedStreams();
        readable
            .pipeThrough(new TransformStream({
                transform: (frame, ctrl) => encryptFrame(mediaKey.key, frame, ctrl),
            }))
            .pipeTo(writable);
        return;
    }

    console.warn('[E2E-Media] No Insertable Streams API for sender');
}

/**
 * Устанавливает дешифрующий transform на RTCRtpReceiver.
 * @param {RTCRtpReceiver} receiver
 * @param {{key: CryptoKey, raw: Uint8Array}} mediaKey
 */
export function setupReceiverTransform(receiver, mediaKey) {
    if (!receiver || !mediaKey) return;

    // Path 1: RTCRtpScriptTransform
    if (_supportsScriptTransform()) {
        const buf = mediaKey.raw.buffer.slice(0);
        receiver.transform = new RTCRtpScriptTransform(
            _getWorker(),
            { operation: 'decrypt', keyBytes: buf },
            [buf]
        );
        return;
    }

    // Path 2: createEncodedStreams
    if (typeof receiver.createEncodedStreams === 'function') {
        const { readable, writable } = receiver.createEncodedStreams();
        readable
            .pipeThrough(new TransformStream({
                transform: (frame, ctrl) => decryptFrame(mediaKey.key, frame, ctrl),
            }))
            .pipeTo(writable);
        return;
    }

    console.warn('[E2E-Media] No Insertable Streams API for receiver');
}

/**
 * Устанавливает E2E на всех senders и receivers RTCPeerConnection.
 * Вызывается ПОСЛЕ addTrack().
 *
 * @param {RTCPeerConnection} pc
 * @param {{key: CryptoKey, raw: Uint8Array}} mediaKey
 */
export function setupPeerE2E(pc, mediaKey) {
    if (!pc || !mediaKey || !isE2ESupported()) return;

    for (const sender of pc.getSenders()) {
        if (sender.track) {
            setupSenderTransform(sender, mediaKey);
        }
    }

    const origOntrack = pc.ontrack;
    pc.ontrack = (e) => {
        if (e.receiver) {
            setupReceiverTransform(e.receiver, mediaKey);
        }
        if (origOntrack) origOntrack(e);
    };
}

/**
 * Устанавливает E2E на sender, добавляемый позже (screen share, новый video track).
 * @param {RTCRtpSender} sender
 * @param {{key: CryptoKey, raw: Uint8Array}} mediaKey
 */
export function setupNewSenderE2E(sender, mediaKey) {
    if (!isE2ESupported() || !mediaKey || !sender) return;
    setupSenderTransform(sender, mediaKey);
}

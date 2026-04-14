/**
 * sticker-format.js — Vortex Sticker Format (.sticker / VXS1)
 *
 * Бинарный формат:
 * ┌──────────────────────────────────────────────┐
 * │ Magic      │ 4 bytes  │ "VXS1"               │
 * │ Version    │ 1 byte   │ 0x01                  │
 * │ Flags      │ 1 byte   │ bit0=animated         │
 * │ Meta Len   │ 2 bytes  │ uint16 LE             │
 * │ Metadata   │ N bytes  │ JSON UTF-8            │
 * │ Payload    │ rest     │ WebP image data       │
 * └──────────────────────────────────────────────┘
 *
 * Metadata JSON:
 * {
 *   "name": "sticker name",
 *   "emoji": "😀",
 *   "pack_id": "my_stickers",
 *   "author_id": 123,
 *   "width": 512,
 *   "height": 512,
 *   "created_at": "2026-...",
 *   "signature": "hmac-hex"  // HMAC-SHA256(payload, user_key)
 * }
 */

const VXS_MAGIC = new Uint8Array([0x56, 0x58, 0x53, 0x31]); // "VXS1"
const VXS_VERSION = 0x01;
const STICKER_SIZE = 512;
const STICKER_MAX_BYTES = 512 * 1024; // 512 KB max

// ── Encode: image → .sticker binary ─────────────────────────────────────────

/**
 * Convert any image (File/Blob) to .sticker format.
 * @param {File|Blob} imageFile - source image
 * @param {Object} meta - { name, emoji, pack_id, author_id }
 * @returns {Promise<{blob: Blob, metadata: Object}>}
 */
export async function createSticker(imageFile, meta = {}) {
    // 1. Load image into canvas
    const bitmap = await createImageBitmap(imageFile);

    // 2. Resize to 512x512 (fit, preserve aspect, transparent padding)
    const canvas = new OffscreenCanvas(STICKER_SIZE, STICKER_SIZE);
    const ctx = canvas.getContext('2d');

    // Transparent background
    ctx.clearRect(0, 0, STICKER_SIZE, STICKER_SIZE);

    // Fit image inside 512x512
    const scale = Math.min(STICKER_SIZE / bitmap.width, STICKER_SIZE / bitmap.height);
    const w = Math.round(bitmap.width * scale);
    const h = Math.round(bitmap.height * scale);
    const x = Math.round((STICKER_SIZE - w) / 2);
    const y = Math.round((STICKER_SIZE - h) / 2);
    ctx.drawImage(bitmap, x, y, w, h);
    bitmap.close();

    // 3. Export as WebP
    const webpBlob = await canvas.convertToBlob({ type: 'image/webp', quality: 0.9 });
    const payload = new Uint8Array(await webpBlob.arrayBuffer());

    // 4. Compute signature (HMAC-SHA256 of payload with user key)
    let signature = '';
    try {
        const keyStr = window.AppState?.x25519PrivateKey || localStorage.getItem('vortex_x25519_priv') || '';
        if (keyStr) {
            const keyData = new TextEncoder().encode(keyStr.slice(0, 64));
            const hmacKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
            const sig = await crypto.subtle.sign('HMAC', hmacKey, payload);
            signature = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
        }
    } catch {}

    // 5. Build metadata
    const metadata = {
        name: meta.name || imageFile.name?.replace(/\.[^.]+$/, '') || 'sticker',
        emoji: meta.emoji || '',
        pack_id: meta.pack_id || 'my_stickers',
        author_id: meta.author_id || window.AppState?.user?.user_id || 0,
        width: STICKER_SIZE,
        height: STICKER_SIZE,
        created_at: new Date().toISOString(),
        signature,
    };

    const metaBytes = new TextEncoder().encode(JSON.stringify(metadata));

    // 6. Assemble binary
    // Header: magic(4) + version(1) + flags(1) + meta_len(2) + meta(N) + payload
    const totalLen = 4 + 1 + 1 + 2 + metaBytes.length + payload.length;
    const buffer = new Uint8Array(totalLen);
    let offset = 0;

    buffer.set(VXS_MAGIC, offset); offset += 4;           // Magic
    buffer[offset++] = VXS_VERSION;                         // Version
    buffer[offset++] = 0x00;                                // Flags (0 = static)
    buffer[offset] = metaBytes.length & 0xFF;               // Meta len (LE)
    buffer[offset + 1] = (metaBytes.length >> 8) & 0xFF;
    offset += 2;
    buffer.set(metaBytes, offset); offset += metaBytes.length; // Metadata
    buffer.set(payload, offset);                            // Payload (WebP)

    const blob = new Blob([buffer], { type: 'application/x-vortex-sticker' });
    return { blob, metadata };
}


// ── Decode: .sticker binary → image ─────────────────────────────────────────

/**
 * Parse a .sticker file.
 * @param {ArrayBuffer} data
 * @returns {{ metadata: Object, imageBlob: Blob } | null}
 */
export function parseSticker(data) {
    const bytes = new Uint8Array(data);
    if (bytes.length < 8) return null;

    // Check magic
    if (bytes[0] !== 0x56 || bytes[1] !== 0x58 || bytes[2] !== 0x53 || bytes[3] !== 0x31) {
        return null; // Not a VXS1 file
    }

    const version = bytes[4];
    const flags = bytes[5];
    const metaLen = bytes[6] | (bytes[7] << 8);

    if (bytes.length < 8 + metaLen) return null;

    const metaBytes = bytes.slice(8, 8 + metaLen);
    let metadata;
    try {
        metadata = JSON.parse(new TextDecoder().decode(metaBytes));
    } catch {
        return null;
    }

    const payload = bytes.slice(8 + metaLen);
    const imageBlob = new Blob([payload], { type: 'image/webp' });

    return { metadata, imageBlob, animated: !!(flags & 0x01) };
}


/**
 * Create object URL for sticker preview.
 * @param {ArrayBuffer} data - raw .sticker file
 * @returns {string|null} - blob URL for img.src
 */
export function stickerToURL(data) {
    const parsed = parseSticker(data);
    if (!parsed) return null;
    return URL.createObjectURL(parsed.imageBlob);
}


// ── Verify signature ────────────────────────────────────────────────────────

export async function verifySticker(data, authorPubKey) {
    const parsed = parseSticker(data);
    if (!parsed || !parsed.metadata.signature) return false;

    try {
        const payload = new Uint8Array(data).slice(8 + (new Uint8Array(data)[6] | (new Uint8Array(data)[7] << 8)));
        const keyData = new TextEncoder().encode(authorPubKey.slice(0, 64));
        const hmacKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const sigBytes = Uint8Array.from(parsed.metadata.signature.match(/.{2}/g).map(h => parseInt(h, 16)));
        return await crypto.subtle.verify('HMAC', hmacKey, sigBytes, payload);
    } catch {
        return false;
    }
}

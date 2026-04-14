/**
 * sticker-manager.js — Управление пользовательскими стикерпаками (.sticker VXS1)
 *
 * - "Мои стикеры" — пак создаётся автоматически
 * - Добавление через контекстное меню (правый клик → "Добавить в стикеры")
 * - Отправка через стикер-пикер
 */

import { createSticker, parseSticker, stickerToURL } from './sticker-format.js';
import { api } from './utils.js';

const MY_PACK_ID = 'my_stickers';
const STORAGE_KEY = 'vortex_my_stickers'; // [{name, emoji, blob_url, data_b64}]
const MAX_STICKERS = 120;

// ── Local sticker storage ───────────────────────────────────────────────────

function _loadMyStickers() {
    try {
        return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
    } catch { return []; }
}

function _saveMyStickers(stickers) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(stickers));
    } catch (e) {
        console.warn('[Stickers] Storage full:', e.message);
    }
}

/**
 * Add image to "My Stickers" pack.
 * Converts to VXS1 format, stores locally, uploads to server pack.
 *
 * @param {File|Blob} imageFile
 * @param {string} [emoji='']
 * @param {string} [name='']
 */
export async function addToMyStickers(imageFile, emoji = '', name = '') {
    const stickers = _loadMyStickers();
    if (stickers.length >= MAX_STICKERS) {
        window.showToast?.(t('stickers.maxReached', {max: MAX_STICKERS}), 'error');
        return false;
    }

    try {
        // Convert to VXS1
        const { blob, metadata } = await createSticker(imageFile, {
            name: name || imageFile.name?.replace(/\.[^.]+$/, '') || 'sticker',
            emoji,
            pack_id: MY_PACK_ID,
        });

        // Store as base64 in localStorage
        const arrayBuf = await blob.arrayBuffer();
        const b64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuf)));

        // Create preview URL
        const parsed = parseSticker(arrayBuf);
        const previewUrl = parsed ? URL.createObjectURL(parsed.imageBlob) : '';

        const entry = {
            id: Date.now() + '_' + Math.random().toString(36).slice(2, 6),
            name: metadata.name,
            emoji: metadata.emoji,
            preview_url: previewUrl,
            data_b64: b64,
            created_at: metadata.created_at,
        };

        stickers.unshift(entry);
        _saveMyStickers(stickers);

        // Also upload to server sticker pack (non-blocking)
        _uploadToServerPack(blob, metadata).catch(() => {});

        window.showToast?.(t('stickers.stickerAdded'), 'success');
        return true;
    } catch (e) {
        console.error('[Stickers] Failed to create sticker:', e);
        window.showToast?.(t('stickers.createError'), 'error');
        return false;
    }
}

async function _uploadToServerPack(blob, metadata) {
    try {
        // Ensure "My Stickers" pack exists
        let packs = [];
        try {
            const resp = await api('GET', '/api/stickers/packs');
            packs = resp.packs || [];
        } catch {}

        let myPack = packs.find(p => p.name === 'My Stickers' || p.pack_id === MY_PACK_ID);
        if (!myPack) {
            try {
                const created = await api('POST', '/api/stickers/packs', {
                    name: 'My Stickers',
                    description: 'Personal sticker collection',
                });
                myPack = created;
            } catch {}
        }

        if (!myPack?.pack_id && !myPack?.id) return;
        const packId = myPack.pack_id || myPack.id;

        // Upload sticker file
        const formData = new FormData();
        formData.append('file', blob, `${metadata.name}.sticker`);
        formData.append('emoji', metadata.emoji || '');

        const csrfToken = document.cookie.match(/csrf_token=([^;]+)/)?.[1] || '';
        await fetch(`/api/stickers/packs/${packId}/stickers`, {
            method: 'POST',
            body: formData,
            credentials: 'include',
            headers: { 'X-CSRF-Token': csrfToken },
        });
    } catch (e) {
        console.debug('[Stickers] Server upload failed:', e.message);
    }
}


/**
 * Remove sticker from "My Stickers".
 */
export function removeMySticker(stickerId) {
    let stickers = _loadMyStickers();
    stickers = stickers.filter(s => s.id !== stickerId);
    _saveMyStickers(stickers);
}


/**
 * Get all my stickers (for picker).
 * @returns {Array<{id, name, emoji, preview_url, data_b64}>}
 */
export function getMyStickers() {
    const stickers = _loadMyStickers();
    // Regenerate preview URLs (blob URLs don't survive reload)
    return stickers.map(s => {
        if (!s.preview_url || !s.preview_url.startsWith('blob:')) {
            try {
                const raw = Uint8Array.from(atob(s.data_b64), c => c.charCodeAt(0));
                const parsed = parseSticker(raw.buffer);
                if (parsed) s.preview_url = URL.createObjectURL(parsed.imageBlob);
            } catch {}
        }
        return s;
    });
}


/**
 * Send sticker as image message.
 * Decodes VXS1 → extracts WebP → sends as image file.
 */
export async function sendMySticker(stickerId) {
    const stickers = _loadMyStickers();
    const sticker = stickers.find(s => s.id === stickerId);
    if (!sticker) return;

    try {
        const raw = Uint8Array.from(atob(sticker.data_b64), c => c.charCodeAt(0));
        const parsed = parseSticker(raw.buffer);
        if (!parsed) return;

        // Send as custom sticker message
        const S = window.AppState;
        if (!S?.currentRoom?.id || !S.ws || S.ws.readyState !== WebSocket.OPEN) return;

        // Upload WebP as sticker image
        const fileName = `${sticker.name || 'sticker'}.sticker.webp`;
        const formData = new FormData();

        // E2E encrypt
        const { getRoomKey, encryptFile } = await import('./crypto.js');
        const roomKey = getRoomKey(S.currentRoom.id);
        let uploadBlob = parsed.imageBlob;
        if (roomKey) {
            try {
                const buf = await parsed.imageBlob.arrayBuffer();
                const encrypted = await encryptFile(buf, roomKey);
                uploadBlob = new Blob([encrypted], { type: 'application/octet-stream' });
            } catch {}
        }

        formData.append('file', uploadBlob, fileName);
        const csrfToken = S.csrfToken || document.cookie.match(/csrf_token=([^;]+)/)?.[1] || '';

        await fetch(`/api/files/upload/${S.currentRoom.id}`, {
            method: 'POST', body: formData, credentials: 'include',
            headers: { 'X-CSRF-Token': csrfToken },
        });
    } catch (e) {
        console.error('[Stickers] Send failed:', e);
    }
}


// ── Context menu action ─────────────────────────────────────────────────────

/**
 * Add image from chat to stickers (called from context menu).
 * Downloads the image, converts to VXS1, saves.
 */
export async function addImageToStickers(downloadUrl, fileName) {
    try {
        window.showToast?.(t('stickers.creating'), 'info');

        const resp = await fetch(downloadUrl, { credentials: 'include' });
        if (!resp.ok) throw new Error('Download failed');
        let data = await resp.arrayBuffer();

        // Try E2E decrypt
        try {
            const { getRoomKey, decryptFile } = await import('./crypto.js');
            const roomKey = getRoomKey(window.AppState?.currentRoom?.id);
            if (roomKey && data.byteLength > 12) {
                data = await decryptFile(data, roomKey);
            }
        } catch {}

        const blob = new Blob([data]);
        await addToMyStickers(blob, '', fileName);
    } catch (e) {
        window.showToast?.(t('errors.generic') + ': ' + e.message, 'error');
    }
}


// ── Expose to window ────────────────────────────────────────────────────────

window.addToMyStickers = addToMyStickers;
window.sendMySticker = sendMySticker;
window.getMyStickers = getMyStickers;
window.removeMySticker = removeMySticker;
window.addImageToStickers = addImageToStickers;

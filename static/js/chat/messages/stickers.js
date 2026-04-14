// =========================================================================
// Sticker pack popup — показывает пак при клике на стикер в чате
// =========================================================================

let _stickerPopupEl = null;

export function attachStickerClickHandler(msgEl) {
    const img = msgEl.querySelector('.custom-sticker');
    if (!img) return;
    img.style.cursor = 'pointer';
    img.addEventListener('click', (e) => {
        e.stopPropagation();
        const src = img.getAttribute('src') || '';
        // Extract pack_id from /uploads/stickers/{pack_id}/filename
        const m = src.match(/\/uploads\/stickers\/(\d+)\//);
        if (!m) return;
        _openStickerPackPopup(parseInt(m[1]), img);
    });
}

async function _openStickerPackPopup(packId, anchorEl) {
    _closeStickerPackPopup();

    // Pre-check: fetch pack data first to see if already owned
    let packData;
    try {
        const r = await fetch(`/api/stickers/packs/${packId}`);
        if (!r.ok) return;
        packData = await r.json();
        if (packData.pack?.is_favorited || packData.pack?.is_own) return; // already have it
    } catch { return; }

    const popup = document.createElement('div');
    popup.id = 'sticker-pack-popup';
    popup.style.cssText = `
        position:fixed;z-index:9999;
        background:var(--bg2,#1e1e2e);border:1px solid var(--border,rgba(255,255,255,.1));
        border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.4);
        padding:16px;width:320px;max-height:420px;display:flex;flex-direction:column;
        animation:fadeInUp .15s ease;
    `;

    popup.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
            <div id="spp-title" style="font-weight:700;font-size:14px;">Загрузка...</div>
            <button id="spp-close" style="background:none;border:none;color:var(--text3,#888);cursor:pointer;font-size:18px;line-height:1;padding:0 4px;">&times;</button>
        </div>
        <div id="spp-grid" style="display:grid;grid-template-columns:repeat(5,1fr);gap:6px;overflow-y:auto;flex:1;"></div>
        <div id="spp-footer" style="margin-top:12px;display:flex;gap:8px;"></div>
    `;

    document.body.appendChild(popup);
    _stickerPopupEl = popup;

    // Position near anchor
    const rect = anchorEl.getBoundingClientRect();
    const vw = window.innerWidth, vh = window.innerHeight;
    let top = rect.bottom + 8;
    let left = rect.left;
    if (top + 420 > vh) top = rect.top - 428;
    if (left + 320 > vw) left = vw - 328;
    popup.style.top  = Math.max(8, top)  + 'px';
    popup.style.left = Math.max(8, left) + 'px';

    popup.querySelector('#spp-close').onclick = _closeStickerPackPopup;

    // Close on outside click
    setTimeout(() => document.addEventListener('click', _stickerOutsideClick), 10);

    try {
        const pack = packData.pack;

        popup.querySelector('#spp-title').textContent = pack.name;

        const grid = popup.querySelector('#spp-grid');
        (pack.stickers || []).forEach(s => {
            const btn = document.createElement('button');
            btn.style.cssText = 'background:none;border:none;padding:3px;border-radius:8px;cursor:pointer;aspect-ratio:1;display:flex;align-items:center;justify-content:center;transition:background .12s;';
            const img2 = document.createElement('img');
            img2.src = s.image_url;
            img2.alt = s.emoji || 'sticker';
            img2.style.cssText = 'width:48px;height:48px;object-fit:contain;';
            img2.loading = 'lazy';
            btn.appendChild(img2);
            btn.onmouseenter = () => { btn.style.background = 'var(--bg3,rgba(255,255,255,.08))'; };
            btn.onmouseleave = () => { btn.style.background = 'none'; };
            btn.onclick = () => {
                _closeStickerPackPopup();
                window._sendStickerFromPicker?.('[STICKER] img:' + s.image_url);
            };
            grid.appendChild(btn);
        });

        const footer = popup.querySelector('#spp-footer');

        // Добавить / убрать из избранного
        const favBtn = document.createElement('button');
        favBtn.style.cssText = 'flex:1;padding:8px 12px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;border:1px solid var(--border,rgba(255,255,255,.1));background:var(--accent,#7c6af7);color:#fff;transition:opacity .15s;';
        favBtn.textContent = pack.is_favorited ? ('✓ ' + t('stickers.inFavorites')) : ('+ ' + t('stickers.addPack'));
        favBtn.style.opacity = pack.is_favorited ? '0.6' : '1';

        favBtn.onclick = async () => {
            if (pack.is_favorited) {
                await fetch(`/api/stickers/packs/${packId}/favorite`, { method: 'DELETE' });
                pack.is_favorited = false;
                favBtn.textContent = '+ ' + t('stickers.addPack');
                favBtn.style.opacity = '1';
            } else {
                await fetch(`/api/stickers/packs/${packId}/favorite`, { method: 'POST' });
                pack.is_favorited = true;
                favBtn.textContent = '✓ ' + t('stickers.inFavorites');
                favBtn.style.opacity = '0.6';
            }
            // Сбрасываем кеш пикера
            window._invalidateStickerCache?.();
        };
        footer.appendChild(favBtn);

    } catch {
        popup.querySelector('#spp-title').textContent = t('errors.loadingError');
    }
}

function _closeStickerPackPopup() {
    if (_stickerPopupEl) {
        _stickerPopupEl.remove();
        _stickerPopupEl = null;
    }
    document.removeEventListener('click', _stickerOutsideClick);
}

function _stickerOutsideClick(e) {
    if (_stickerPopupEl && !_stickerPopupEl.contains(e.target) && !e.target.closest('.custom-sticker')) {
        _closeStickerPackPopup();
    }
}

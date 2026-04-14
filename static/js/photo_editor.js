// static/js/photo_editor.js
// ============================================================================
// Редактор фото перед отправкой.
// Позволяет изменять яркость, контраст, насыщенность, тон, размытие,
// поворачивать, отражать и применять фильтры.
// ============================================================================

/**
 * @fileoverview photo-editor.js — Редактор фото перед отправкой
 * Тон, яркость, контраст, насыщенность, поворот, зеркало
 */

let _origImage  = null; // оригинальный File/Blob
let _canvas     = null;
let _ctx        = null;
let _onSave     = null; // callback(blob, fileName)

// Значения по умолчанию для всех регулировок
const DEFAULTS = {
    brightness:  100,
    contrast:    100,
    saturation:  100,
    hue:         0,
    blur:        0,
    rotation:    0,
    flipH:       false,
    flipV:       false,
};

let _state = { ...DEFAULTS };

// ── Crop state ─────────────────────────────────────────────────
let _cropActive = false;
let _cropRect   = { x: 0, y: 0, w: 0, h: 0 }; // in canvas-pixel coords
let _cropRatio  = null;  // null = free, or { w, h }
let _cropDrag   = null;  // current drag operation info

/**
 * Открывает редактор фото.
 * @param {File|Blob} file  — изображение
 * @param {Function}  onSave — вызывается с (blob, fileName) когда пользователь сохраняет
 */
export function openPhotoEditor(file, onSave) {
    _origImage = file;
    _onSave    = onSave;
    _state     = { ...DEFAULTS };

    _buildEditorUI();
    _loadImage();
}

/**
 * Fullscreen photo editor with tab bar.
 * NOTE: innerHTML usage is safe — only static SVG/HTML string literals, never user input.
 */
let _activePhotoTab = 'color';

function _peSliderRow(label, id, min, max, val, unit, step) {
    return '<div class="pe-slider-row"><span class="pe-slider-label">' + label + '</span>'
        + '<input type="range" class="pe-slider" id="ed-' + id + '" min="' + min + '" max="' + max
        + '" value="' + val + '"' + (step ? ' step="' + step + '"' : '')
        + ' oninput="window._peUpdate(\'' + id + '\',+this.value)">'
        + '<span class="pe-slider-val" id="lbl-' + id + '">' + val + unit + '</span></div>';
}

function _buildEditorUI() {
    document.getElementById('photo-editor-modal')?.remove();

    const modal = document.createElement('div');
    modal.id = 'photo-editor-modal';
    modal.className = 'pe-root';

    // NOTE: all innerHTML below is static trusted content (SVG icons, layout).
    // No user-supplied data is interpolated.
    modal.innerHTML =
    '<div class="pe-header">'
    +   '<button class="pe-header-btn" onclick="window.closePhotoEditor()">Cancel</button>'
    +   '<span class="pe-title">Photo Editor</span>'
    +   '<button class="pe-header-btn pe-done" onclick="window.savePhotoEdit()">Done</button>'
    + '</div>'
    + '<div class="pe-canvas-area">'
    +   '<div class="pe-canvas-container" id="photo-ed-canvas-container">'
    +     '<canvas id="photo-ed-canvas"></canvas>'
    +   '</div>'
    +   '<div class="crop-ratio-buttons" id="crop-ratio-bar" style="display:none;">'
    +     '<button class="crop-ratio-btn active" data-ratio="free" onclick="window._peCropRatio(\'free\')">Free</button>'
    +     '<button class="crop-ratio-btn" data-ratio="1:1" onclick="window._peCropRatio(\'1:1\')">1:1</button>'
    +     '<button class="crop-ratio-btn" data-ratio="4:3" onclick="window._peCropRatio(\'4:3\')">4:3</button>'
    +     '<button class="crop-ratio-btn" data-ratio="16:9" onclick="window._peCropRatio(\'16:9\')">16:9</button>'
    +     '<span class="crop-action-sep"></span>'
    +     '<button class="crop-ratio-btn crop-apply" onclick="window._peCropApply()">Apply</button>'
    +     '<button class="crop-ratio-btn crop-cancel" onclick="window._peCropCancel()">Cancel</button>'
    +   '</div>'
    + '</div>'
    + '<div class="pe-content" id="pe-content"></div>'
    + '<div class="pe-tabs" id="pe-tabs">'
    +   '<button class="pe-tab active" data-tab="color" onclick="window._peShowTab(\'color\')">'
    +     '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
    +     '<span>Color</span></button>'
    +   '<button class="pe-tab" data-tab="transform" onclick="window._peShowTab(\'transform\')">'
    +     '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>'
    +     '<span>Transform</span></button>'
    +   '<button class="pe-tab" data-tab="crop" onclick="window._peShowTab(\'crop\')">'
    +     '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6.13 1L6 16a2 2 0 002 2h15M1 6.13L16 6a2 2 0 012 2v15"/></svg>'
    +     '<span>Crop</span></button>'
    +   '<button class="pe-tab" data-tab="filters" onclick="window._peShowTab(\'filters\')">'
    +     '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>'
    +     '<span>Filters</span></button>'
    + '</div>';

    document.body.appendChild(modal);
    _canvas = document.getElementById('photo-ed-canvas');
    _ctx    = _canvas.getContext('2d');
    _peShowTab('color');
}

/**
 * Switch tab content in photo editor.
 */
window._peShowTab = (tab) => {
    _activePhotoTab = tab;
    document.querySelectorAll('.pe-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    const content = document.getElementById('pe-content');
    if (!content) return;

    if (tab !== 'crop' && _cropActive) _peCropDeactivate();

    // NOTE: all innerHTML below is static trusted content. No user data is interpolated.
    if (tab === 'color') {
        content.innerHTML = '<div class="pe-tool-panel">'
            + _peSliderRow((window.t?.('photoEditor.brightness')||'Brightness'), 'brightness', 0, 200, _state.brightness, '%')
            + _peSliderRow((window.t?.('photoEditor.contrast')||'Contrast'), 'contrast', 0, 200, _state.contrast, '%')
            + _peSliderRow((window.t?.('photoEditor.saturation')||'Saturation'), 'saturation', 0, 300, _state.saturation, '%')
            + _peSliderRow((window.t?.('photoEditor.hue')||'Hue'), 'hue', 0, 360, _state.hue, '\u00B0')
            + _peSliderRow((window.t?.('photoEditor.blur')||'Blur'), 'blur', 0, 20, _state.blur, 'px', '0.5')
            + '</div>';
    } else if (tab === 'transform') {
        content.innerHTML = '<div class="pe-tool-panel"><div class="pe-btn-grid">'
            + '<button class="pe-action-btn" onclick="window._peRotate(-90)"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 4v6h6M7 10L2.5 5.5A9 9 0 0120.49 9"/></svg><span>-90\u00B0</span></button>'
            + '<button class="pe-action-btn" onclick="window._peRotate(90)"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M23 4v6h-6M17 10l4.5-4.5A9 9 0 003.51 9"/></svg><span>+90\u00B0</span></button>'
            + '<button class="pe-action-btn" onclick="window._peFlip(\'H\')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M8 3H5a2 2 0 00-2 2v14a2 2 0 002 2h3M16 3h3a2 2 0 012 2v14a2 2 0 01-2 2h-3M12 2v20"/></svg><span>Flip H</span></button>'
            + '<button class="pe-action-btn" onclick="window._peFlip(\'V\')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 8V5a2 2 0 012-2h14a2 2 0 012 2v3M3 16v3a2 2 0 002 2h14a2 2 0 002-2v-3M2 12h20"/></svg><span>Flip V</span></button>'
            + '</div><button class="pe-reset-btn" onclick="window._peReset()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 4v6h6M3.51 15a9 9 0 102.13-9.36L1 10"/></svg> Reset all</button></div>';
    } else if (tab === 'crop') {
        if (!_cropActive) _peCropActivate();
        content.innerHTML = '<div class="pe-tool-panel"><div class="pe-note">Drag the handles to crop. Pick an aspect ratio above.</div></div>';
    } else if (tab === 'filters') {
        var html = '<div class="pe-tool-panel"><div class="pe-filter-grid">';
        [['none',(window.t?.('photoEditor.none')||'None')],['grayscale',(window.t?.('photoEditor.bw')||'B&W')],['sepia',(window.t?.('photoEditor.sepia')||'Sepia')],['vivid',(window.t?.('photoEditor.vivid')||'Vivid')],['cold',(window.t?.('photoEditor.cold')||'Cold')],['warm',(window.t?.('photoEditor.warm')||'Warm')],['drama',(window.t?.('photoEditor.drama')||'Drama')]].forEach(function(f) {
            html += '<button class="pe-filter-btn" onclick="window._peFilter(\'' + f[0] + '\')">' + f[1] + '</button>';
        });
        content.innerHTML = html + '</div></div>';
    }
};

/**
 * Загружает изображение в canvas, масштабируя до 800px по большей стороне.
 */
function _loadImage() {
    const url = URL.createObjectURL(_origImage);
    const img = new Image();
    img.onload = () => {
        const MAX = 800;
        let w = img.naturalWidth, h = img.naturalHeight;
        if (w > MAX || h > MAX) {
            if (w > h) { h = Math.round(h * MAX / w); w = MAX; }
            else       { w = Math.round(w * MAX / h); h = MAX; }
        }
        _canvas.width  = w;
        _canvas.height = h;
        _canvas._img   = img;
        _canvas._naturalW = img.naturalWidth;
        _canvas._naturalH = img.naturalHeight;
        URL.revokeObjectURL(url);
        _redraw();
    };
    img.src = url;
}

/**
 * Перерисовывает canvas с учётом текущих настроек (_state).
 * Применяет CSS-фильтры, поворот, отражение.
 */
function _redraw() {
    if (!_canvas?._img) return;
    const img = _canvas._img;
    const s   = _state;
    const w   = _canvas.width, h = _canvas.height;

    _ctx.save();
    _ctx.clearRect(0, 0, w, h);
    _ctx.filter = [
        `brightness(${s.brightness}%)`,
        `contrast(${s.contrast}%)`,
        `saturate(${s.saturation}%)`,
        `hue-rotate(${s.hue}deg)`,
        s.blur > 0 ? `blur(${s.blur}px)` : '',
    ].filter(Boolean).join(' ');
    _ctx.translate(w / 2, h / 2);
    _ctx.rotate((s.rotation * Math.PI) / 180);
    _ctx.scale(s.flipH ? -1 : 1, s.flipV ? -1 : 1);

    const isRot = s.rotation % 180 !== 0;
    const dw    = isRot ? h : w;
    const dh    = isRot ? w : h;
    _ctx.drawImage(img, -dw / 2, -dh / 2, dw, dh);
    _ctx.restore();
}

/**
 * Обработчик изменения ползунка (вызывается из HTML).
 * @param {string} key - название параметра (brightness, contrast, ...)
 * @param {number} val - новое значение
 */
window._peUpdate = (key, val) => {
    _state[key] = val;
    const lbl = document.getElementById('lbl-' + key);
    if (lbl) {
        const units = { brightness: '%', contrast: '%', saturation: '%', hue: '\u00B0', blur: 'px' };
        lbl.textContent = Math.round(val) + (units[key] || '');
    }
    _redraw();
};

/**
 * Поворачивает изображение на заданное количество градусов.
 * @param {number} deg - угол поворота (положительный или отрицательный)
 */
window._peRotate = (deg) => {
    _state.rotation = (_state.rotation + deg + 360) % 360;
    _redraw();
};

/**
 * Отражает изображение по горизонтали или вертикали.
 * @param {string} axis - 'H' или 'V'
 */
window._peFlip = (axis) => {
    if (axis === 'H') _state.flipH = !_state.flipH;
    else               _state.flipV = !_state.flipV;
    _redraw();
};

/**
 * Применяет предустановленный фильтр.
 * @param {string} name - название фильтра (none, grayscale, sepia, vivid, cold, warm, drama)
 */
window._peFilter = (name) => {
    document.querySelectorAll('.photo-ed-filter-btn').forEach(b => b.classList.remove('active'));
    event?.target?.classList.add('active');

    switch (name) {
        case 'none':
            _state.brightness = 100; _state.contrast = 100;
            _state.saturation = 100; _state.hue = 0; _state.blur = 0;
            break;
        case 'grayscale':
            _state.saturation = 0; _state.brightness = 100; _state.contrast = 110;
            break;
        case 'sepia':
            _state.saturation = 30; _state.brightness = 105;
            _state.hue = 20; _state.contrast = 90;
            break;
        case 'vivid':
            _state.saturation = 180; _state.brightness = 110;
            _state.contrast = 120; _state.hue = 0;
            break;
        case 'cold':
            _state.saturation = 90; _state.brightness = 100;
            _state.hue = 200; _state.contrast = 105;
            break;
        case 'warm':
            _state.saturation = 110; _state.brightness = 105;
            _state.hue = 15; _state.contrast = 100;
            break;
        case 'drama':
            _state.saturation = 120; _state.brightness = 90;
            _state.contrast = 150; _state.hue = 0; _state.blur = 0;
            break;
    }

    // Обновляем ползунки и подписи
    ['brightness','contrast','saturation','hue','blur'].forEach(k => {
        const el = document.getElementById(`ed-${k}`);
        if (el) el.value = _state[k];
        const lb = document.getElementById(`lbl-${k}`);
        if (lb) lb.textContent = Math.round(_state[k]);
    });
    _redraw();
};

/**
 * Сбрасывает все настройки к значениям по умолчанию.
 */
window._peReset = () => {
    _state = { ...DEFAULTS };
    ['brightness','contrast','saturation','hue','blur'].forEach(k => {
        const el = document.getElementById(`ed-${k}`);
        if (el) el.value = DEFAULTS[k];
        const lb = document.getElementById(`lbl-${k}`);
        if (lb) lb.textContent = Math.round(DEFAULTS[k]);
    });
    _redraw();
};

// ============================================================================
// CROP TOOL
// ============================================================================

/**
 * Toggle crop mode on/off.
 */
window._peCropToggle = () => {
    if (_cropActive) { _peCropDeactivate(); return; }
    _peCropActivate();
};

/**
 * Activate crop mode: show overlay, default crop rect = full canvas.
 */
function _peCropActivate() {
    _cropActive = true;
    _cropRatio  = null;
    document.getElementById('btn-crop-toggle')?.classList.add('active');
    document.getElementById('crop-ratio-bar').style.display = 'flex';

    // Reset ratio button highlight
    document.querySelectorAll('.crop-ratio-btn[data-ratio]').forEach(b => b.classList.remove('active'));
    document.querySelector('.crop-ratio-btn[data-ratio="free"]')?.classList.add('active');

    // Initialize crop rect to full canvas display size
    const cRect = _canvas.getBoundingClientRect();
    _cropRect = { x: 0, y: 0, w: cRect.width, h: cRect.height };

    _peCropBuildOverlay();
}

/**
 * Deactivate crop mode: remove overlay.
 */
function _peCropDeactivate() {
    _cropActive = false;
    _cropRatio  = null;
    document.getElementById('btn-crop-toggle')?.classList.remove('active');
    document.getElementById('crop-ratio-bar').style.display = 'none';
    document.getElementById('crop-overlay-root')?.remove();
}

/**
 * Build / rebuild the crop overlay DOM on top of the canvas.
 */
function _peCropBuildOverlay() {
    document.getElementById('crop-overlay-root')?.remove();

    const container = document.getElementById('photo-ed-canvas-container');
    if (!container) return;

    const root = document.createElement('div');
    root.id = 'crop-overlay-root';
    root.className = 'crop-overlay';

    // Dark masks (top, right, bottom, left) around the crop area
    root.innerHTML = `
        <div class="crop-mask crop-mask-top"></div>
        <div class="crop-mask crop-mask-right"></div>
        <div class="crop-mask crop-mask-bottom"></div>
        <div class="crop-mask crop-mask-left"></div>
        <div class="crop-selection" id="crop-selection">
            <div class="crop-handle crop-handle-nw" data-handle="nw"></div>
            <div class="crop-handle crop-handle-ne" data-handle="ne"></div>
            <div class="crop-handle crop-handle-sw" data-handle="sw"></div>
            <div class="crop-handle crop-handle-se" data-handle="se"></div>
            <div class="crop-handle crop-handle-n"  data-handle="n"></div>
            <div class="crop-handle crop-handle-s"  data-handle="s"></div>
            <div class="crop-handle crop-handle-e"  data-handle="e"></div>
            <div class="crop-handle crop-handle-w"  data-handle="w"></div>
        </div>`;

    container.appendChild(root);
    _peCropPositionOverlay();

    // Attach pointer events
    root.addEventListener('pointerdown', _peCropPointerDown);
    document.addEventListener('pointermove', _peCropPointerMove);
    document.addEventListener('pointerup', _peCropPointerUp);
}

/**
 * Position the dark mask regions and selection box based on _cropRect.
 */
function _peCropPositionOverlay() {
    const cRect = _canvas.getBoundingClientRect();
    const overlay = document.getElementById('crop-overlay-root');
    if (!overlay) return;

    const cW = cRect.width;
    const cH = cRect.height;

    // Clamp crop rect inside canvas display bounds
    _cropRect.x = Math.max(0, Math.min(_cropRect.x, cW - 20));
    _cropRect.y = Math.max(0, Math.min(_cropRect.y, cH - 20));
    _cropRect.w = Math.max(20, Math.min(_cropRect.w, cW - _cropRect.x));
    _cropRect.h = Math.max(20, Math.min(_cropRect.h, cH - _cropRect.y));

    const { x, y, w, h } = _cropRect;

    // Position the overlay to match the canvas exactly
    overlay.style.width  = cW + 'px';
    overlay.style.height = cH + 'px';

    // Masks
    const top    = overlay.querySelector('.crop-mask-top');
    const right  = overlay.querySelector('.crop-mask-right');
    const bottom = overlay.querySelector('.crop-mask-bottom');
    const left   = overlay.querySelector('.crop-mask-left');

    top.style.cssText    = `left:0;top:0;width:${cW}px;height:${y}px;`;
    bottom.style.cssText = `left:0;top:${y + h}px;width:${cW}px;height:${cH - y - h}px;`;
    left.style.cssText   = `left:0;top:${y}px;width:${x}px;height:${h}px;`;
    right.style.cssText  = `left:${x + w}px;top:${y}px;width:${cW - x - w}px;height:${h}px;`;

    // Selection box
    const sel = document.getElementById('crop-selection');
    if (sel) {
        sel.style.left   = x + 'px';
        sel.style.top    = y + 'px';
        sel.style.width  = w + 'px';
        sel.style.height = h + 'px';
    }
}

/**
 * Pointer down: determine if user grabs a handle or the selection body.
 */
function _peCropPointerDown(e) {
    if (!_cropActive) return;
    e.preventDefault();

    const handle = e.target.dataset?.handle;
    const overlay = document.getElementById('crop-overlay-root');
    const oRect   = overlay.getBoundingClientRect();
    const px = e.clientX - oRect.left;
    const py = e.clientY - oRect.top;

    if (handle) {
        _cropDrag = { type: 'handle', handle, startX: px, startY: py, startRect: { ..._cropRect } };
    } else if (e.target.id === 'crop-selection' || e.target.closest('#crop-selection')) {
        _cropDrag = { type: 'move', startX: px, startY: py, startRect: { ..._cropRect } };
    }
}

/**
 * Pointer move: resize or move the crop rect.
 */
function _peCropPointerMove(e) {
    if (!_cropDrag || !_cropActive) return;
    e.preventDefault();

    const overlay = document.getElementById('crop-overlay-root');
    if (!overlay) return;
    const oRect = overlay.getBoundingClientRect();
    const px = e.clientX - oRect.left;
    const py = e.clientY - oRect.top;
    const dx = px - _cropDrag.startX;
    const dy = py - _cropDrag.startY;

    const cW = oRect.width;
    const cH = oRect.height;
    const sr = _cropDrag.startRect;

    if (_cropDrag.type === 'move') {
        let nx = sr.x + dx;
        let ny = sr.y + dy;
        nx = Math.max(0, Math.min(nx, cW - sr.w));
        ny = Math.max(0, Math.min(ny, cH - sr.h));
        _cropRect.x = nx;
        _cropRect.y = ny;
    } else if (_cropDrag.type === 'handle') {
        const h = _cropDrag.handle;
        let nx = sr.x, ny = sr.y, nw = sr.w, nh = sr.h;

        // Horizontal resize
        if (h.includes('w')) {
            nw = sr.w - dx;
            nx = sr.x + dx;
            if (nx < 0) { nw += nx; nx = 0; }
            if (nw < 20) { nx = nx + nw - 20; nw = 20; }
        }
        if (h.includes('e')) {
            nw = sr.w + dx;
            if (nx + nw > cW) nw = cW - nx;
            if (nw < 20) nw = 20;
        }

        // Vertical resize
        if (h.includes('n')) {
            nh = sr.h - dy;
            ny = sr.y + dy;
            if (ny < 0) { nh += ny; ny = 0; }
            if (nh < 20) { ny = ny + nh - 20; nh = 20; }
        }
        if (h.includes('s')) {
            nh = sr.h + dy;
            if (ny + nh > cH) nh = cH - ny;
            if (nh < 20) nh = 20;
        }

        // Enforce aspect ratio
        if (_cropRatio) {
            const ar = _cropRatio.w / _cropRatio.h;
            if (h === 'n' || h === 's') {
                nw = nh * ar;
                if (nx + nw > cW) { nw = cW - nx; nh = nw / ar; }
            } else if (h === 'e' || h === 'w') {
                nh = nw / ar;
                if (ny + nh > cH) { nh = cH - ny; nw = nh * ar; }
            } else {
                // Corner handles: use the dominant axis
                const candidateH = nw / ar;
                const candidateW = nh * ar;
                if (candidateH <= cH - ny && candidateH >= 20) {
                    nh = candidateH;
                } else {
                    nw = candidateW;
                }
            }
        }

        _cropRect = { x: nx, y: ny, w: nw, h: nh };
    }

    _peCropPositionOverlay();
}

/**
 * Pointer up: end drag.
 */
function _peCropPointerUp() {
    _cropDrag = null;
}

/**
 * Set aspect ratio for crop.
 */
window._peCropRatio = (ratio) => {
    document.querySelectorAll('.crop-ratio-btn[data-ratio]').forEach(b => b.classList.remove('active'));
    document.querySelector(`.crop-ratio-btn[data-ratio="${ratio}"]`)?.classList.add('active');

    if (ratio === 'free') {
        _cropRatio = null;
        return;
    }

    const [rw, rh] = ratio.split(':').map(Number);
    _cropRatio = { w: rw, h: rh };

    // Adjust current crop rect to match new ratio, keeping it centered
    const cRect = _canvas.getBoundingClientRect();
    const cW = cRect.width;
    const cH = cRect.height;
    const ar = rw / rh;

    const cx = _cropRect.x + _cropRect.w / 2;
    const cy = _cropRect.y + _cropRect.h / 2;

    let newW, newH;
    if (_cropRect.w / _cropRect.h > ar) {
        newH = _cropRect.h;
        newW = newH * ar;
    } else {
        newW = _cropRect.w;
        newH = newW / ar;
    }

    let newX = cx - newW / 2;
    let newY = cy - newH / 2;

    // Clamp
    if (newX < 0) newX = 0;
    if (newY < 0) newY = 0;
    if (newX + newW > cW) newX = cW - newW;
    if (newY + newH > cH) newY = cH - newH;

    _cropRect = { x: newX, y: newY, w: newW, h: newH };
    _peCropPositionOverlay();
};

/**
 * Apply crop: cut the image to the selected region and replace canvas content.
 */
window._peCropApply = () => {
    if (!_cropActive || !_canvas?._img) return;

    // Convert display-pixel crop rect to actual canvas-pixel coordinates
    const cRect = _canvas.getBoundingClientRect();
    const scaleX = _canvas.width / cRect.width;
    const scaleY = _canvas.height / cRect.height;

    const sx = Math.round(_cropRect.x * scaleX);
    const sy = Math.round(_cropRect.y * scaleY);
    const sw = Math.round(_cropRect.w * scaleX);
    const sh = Math.round(_cropRect.h * scaleY);

    // Extract the cropped pixel data from current (rendered) canvas
    const imgData = _ctx.getImageData(sx, sy, sw, sh);

    // Create a temp image from the current canvas (with all filters applied)
    const tmpCanvas = document.createElement('canvas');
    tmpCanvas.width  = sw;
    tmpCanvas.height = sh;
    const tmpCtx = tmpCanvas.getContext('2d');
    tmpCtx.putImageData(imgData, 0, 0);

    // Create a new Image from the cropped data
    const croppedImg = new Image();
    croppedImg.onload = () => {
        // Resize main canvas
        _canvas.width  = sw;
        _canvas.height = sh;

        // Update internal references so future redraws use the cropped image
        _canvas._img = croppedImg;
        _canvas._naturalW = sw;
        _canvas._naturalH = sh;

        // Reset transform-related state since we baked the transforms into the crop
        _state.rotation = 0;
        _state.flipH = false;
        _state.flipV = false;
        _state.brightness = 100;
        _state.contrast = 100;
        _state.saturation = 100;
        _state.hue = 0;
        _state.blur = 0;

        // Update sliders/labels to match reset state
        ['brightness','contrast','saturation','hue','blur'].forEach(k => {
            const el = document.getElementById(`ed-${k}`);
            if (el) el.value = _state[k];
            const lb = document.getElementById(`lbl-${k}`);
            if (lb) lb.textContent = Math.round(_state[k]);
        });

        _redraw();
        _peCropDeactivate();
    };
    croppedImg.src = tmpCanvas.toDataURL('image/png');
};

/**
 * Cancel crop.
 */
window._peCropCancel = () => {
    _peCropDeactivate();
};

// ============================================================================
// END CROP TOOL
// ============================================================================

/**
 * Закрывает редактор и удаляет модальное окно.
 */
window.closePhotoEditor = () => {
    _peCropDeactivate();
    document.removeEventListener('pointermove', _peCropPointerMove);
    document.removeEventListener('pointerup', _peCropPointerUp);
    document.getElementById('photo-editor-modal')?.remove();
    _origImage = null; _onSave = null;
};

/**
 * Сохраняет отредактированное изображение в полном размере,
 * вызывает колбэк _onSave и закрывает редактор.
 */
window.savePhotoEdit = () => {
    if (!_canvas) return;
    const offscreen = document.createElement('canvas');
    const ox = _canvas._naturalW || _canvas.width;
    const oy = _canvas._naturalH || _canvas.height;
    const s  = _state;

    offscreen.width  = ox;
    offscreen.height = oy;
    const oc = offscreen.getContext('2d');

    oc.filter = [
        `brightness(${s.brightness}%)`,
        `contrast(${s.contrast}%)`,
        `saturate(${s.saturation}%)`,
        `hue-rotate(${s.hue}deg)`,
        s.blur > 0 ? `blur(${s.blur}px)` : '',
    ].filter(Boolean).join(' ');

    oc.save();
    oc.translate(ox / 2, oy / 2);
    oc.rotate((s.rotation * Math.PI) / 180);
    oc.scale(s.flipH ? -1 : 1, s.flipV ? -1 : 1);
    const isRot = s.rotation % 180 !== 0;
    const dw    = isRot ? oy : ox;
    const dh    = isRot ? ox : oy;
    oc.drawImage(_canvas._img, -dw / 2, -dh / 2, dw, dh);
    oc.restore();

    offscreen.toBlob(blob => {
        const origName = _origImage?.name || 'photo.jpg';
        const ext      = origName.split('.').pop() || 'jpg';
        const newName  = origName.replace(/\.[^.]+$/, '') + '_edited.' + ext;

        if (_onSave) _onSave(blob, newName);
        window.closePhotoEditor();
    }, 'image/jpeg', 0.92);
};
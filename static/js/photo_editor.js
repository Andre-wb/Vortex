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
 * Создаёт DOM-элементы редактора и вставляет их в body.
 */
function _buildEditorUI() {
    document.getElementById('photo-editor-modal')?.remove();

    const modal = document.createElement('div');
    modal.id        = 'photo-editor-modal';
    modal.className = 'photo-editor-modal';

    modal.innerHTML = `
    <div class="photo-editor-inner">
        <div class="photo-editor-header">
            <span class="photo-editor-title"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:4px;"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg> Редактор фото</span>
            <button class="photo-editor-close" onclick="window.closePhotoEditor()"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></button>
        </div>

        <div class="photo-editor-body">
            <div class="photo-editor-canvas-wrap">
                <div class="photo-ed-canvas-container" id="photo-ed-canvas-container">
                    <canvas id="photo-ed-canvas"></canvas>
                    <!-- crop overlay, injected dynamically -->
                </div>

                <div class="crop-ratio-buttons" id="crop-ratio-bar" style="display:none;">
                    <button class="crop-ratio-btn active" data-ratio="free" onclick="window._peCropRatio('free')">Свободно</button>
                    <button class="crop-ratio-btn" data-ratio="1:1" onclick="window._peCropRatio('1:1')">1:1</button>
                    <button class="crop-ratio-btn" data-ratio="4:3" onclick="window._peCropRatio('4:3')">4:3</button>
                    <button class="crop-ratio-btn" data-ratio="16:9" onclick="window._peCropRatio('16:9')">16:9</button>
                    <span class="crop-action-sep"></span>
                    <button class="crop-ratio-btn crop-apply" onclick="window._peCropApply()">Применить</button>
                    <button class="crop-ratio-btn crop-cancel" onclick="window._peCropCancel()">Отмена</button>
                </div>
            </div>

            <div class="photo-editor-controls">

                <div class="photo-ed-section">
                    <div class="photo-ed-section-title"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:4px;"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9c.83 0 1.5-.67 1.5-1.5 0-.39-.15-.74-.39-1.01-.23-.26-.38-.61-.38-1-.01-.83.67-1.49 1.5-1.49H16c2.76 0 5-2.24 5-5 0-4.42-4.03-8-9-8zm-5.5 9c-.83 0-1.5-.67-1.5-1.5S5.67 9 6.5 9 8 9.67 8 10.5 7.33 12 6.5 12zm3-4C8.67 8 8 7.33 8 6.5S8.67 5 9.5 5s1.5.67 1.5 1.5S10.33 8 9.5 8zm5 0c-.83 0-1.5-.67-1.5-1.5S13.67 5 14.5 5s1.5.67 1.5 1.5S15.33 8 14.5 8zm3 4c-.83 0-1.5-.67-1.5-1.5S16.67 9 17.5 9s1.5.67 1.5 1.5-.67 1.5-1.5 1.5z"/></svg> Цвет</div>

                    <label>Яркость <span id="lbl-brightness">100</span>%</label>
                    <input type="range" id="ed-brightness" min="0" max="200" value="100"
                        oninput="window._peUpdate('brightness',+this.value)">

                    <label>Контраст <span id="lbl-contrast">100</span>%</label>
                    <input type="range" id="ed-contrast" min="0" max="200" value="100"
                        oninput="window._peUpdate('contrast',+this.value)">

                    <label>Насыщенность <span id="lbl-saturation">100</span>%</label>
                    <input type="range" id="ed-saturation" min="0" max="300" value="100"
                        oninput="window._peUpdate('saturation',+this.value)">

                    <label>Тон <span id="lbl-hue">0</span>°</label>
                    <input type="range" id="ed-hue" min="0" max="360" value="0"
                        oninput="window._peUpdate('hue',+this.value)">

                    <label>Размытие <span id="lbl-blur">0</span>px</label>
                    <input type="range" id="ed-blur" min="0" max="20" value="0" step="0.5"
                        oninput="window._peUpdate('blur',+this.value)">
                </div>

                <div class="photo-ed-section">
                    <div class="photo-ed-section-title"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:4px;"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg> Трансформация</div>
                    <div class="photo-ed-btns">
                        <button class="photo-ed-btn" onclick="window._peRotate(-90)" title="Повернуть влево"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M7.11 8.53 5.7 7.11C4.8 8.27 4.24 9.61 4.07 11h2.02c.14-.87.49-1.72 1.02-2.47zM6.09 13H4.07c.17 1.39.72 2.73 1.62 3.89l1.41-1.42c-.52-.75-.87-1.59-1.01-2.47zm1.01 5.32c1.16.9 2.51 1.44 3.9 1.61V17.9c-.87-.15-1.71-.49-2.46-1.03L7.1 18.32zM13 4.07V1L8.45 5.55 13 10V6.09c2.84.48 5 2.94 5 5.91s-2.16 5.43-5 5.91v2.02c3.95-.49 7-3.85 7-7.93s-3.05-7.44-7-7.93z"/></svg> -90°</button>
                        <button class="photo-ed-btn" onclick="window._peRotate(90)"  title="Повернуть вправо"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M15.55 5.55 11 1v3.07C7.06 4.56 4 7.92 4 12s3.05 7.44 7 7.93v-2.02c-2.84-.48-5-2.94-5-5.91s2.16-5.43 5-5.91V10l4.55-4.45zM19.93 11c-.17-1.39-.72-2.73-1.62-3.89l-1.42 1.42c.54.75.88 1.6 1.02 2.47h2.02zM13 17.9v2.02c1.39-.17 2.74-.71 3.9-1.61l-1.44-1.44c-.75.54-1.59.89-2.46 1.03zm3.89-2.42 1.42 1.41c.9-1.16 1.45-2.5 1.62-3.89h-2.02c-.14.87-.48 1.72-1.02 2.48z"/></svg> +90°</button>
                        <button class="photo-ed-btn" onclick="window._peFlip('H')"  title="Зеркало по горизонтали"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M15 21h2v-2h-2v2zm4-12h2V7h-2v2zM3 5v14c0 1.1.9 2 2 2h4v-2H5V5h4V3H5c-1.1 0-2 .9-2 2zm16-2v2h2c0-1.1-.9-2-2-2zm-8 20h2V1h-2v22zm8-6h2v-2h-2v2zM15 5h2V3h-2v2zm4 8h2v-2h-2v2zm0 8c1.1 0 2-.9 2-2h-2v2z"/></svg> Гор.</button>
                        <button class="photo-ed-btn" onclick="window._peFlip('V')"  title="Зеркало по вертикали"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M3 9h2V7H3v2zm0-4h2V3H3c0 1.1.9 2 2 2zm0 8h2v-2H3v2zm0 8c0 1.1.9 2 2 2v-2H3zm18 0h-2v2c1.1 0 2-.9 2-2zm-8 2h2V1h-2v22zm8-6h2v-2h-2v2zM21 3v2h2c0-1.1-.9-2-2-2zm0 6h2V7h-2v2zm-4 12h2v-2h-2v2zm4-8h2v-2h-2v2zm0-12v2h2c0-1.1-.9-2-2-2z"/></svg> Верт.</button>
                        <button class="photo-ed-btn" id="btn-crop-toggle" onclick="window._peCropToggle()" title="Обрезать"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M17 15h2V7c0-1.1-.9-2-2-2H9v2h8v8zM7 17V1H5v4H1v2h4v10c0 1.1.9 2 2 2h10v4h2v-4h4v-2H7z"/></svg> Обрезка</button>
                    </div>
                </div>

                <div class="photo-ed-section">
                    <div class="photo-ed-section-title"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:4px;"><path d="M17.66 7.93L12 2.27 6.34 7.93c-3.12 3.12-3.12 8.19 0 11.31A7.98 7.98 0 0012 21.58c2.05 0 4.1-.78 5.66-2.34 3.12-3.12 3.12-8.19 0-11.31zM12 19.59c-1.6 0-3.11-.62-4.24-1.76C6.62 16.69 6 15.19 6 13.59s.62-3.11 1.76-4.24L12 5.1v14.49z"/></svg> Фильтры</div>
                    <div class="photo-ed-filters">
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('none')">Нет</button>
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('grayscale')">Ч/Б</button>
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('sepia')">Сепия</button>
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('vivid')">Яркий</button>
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('cold')">Холодный</button>
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('warm')">Тёплый</button>
                        <button class="photo-ed-filter-btn" onclick="window._peFilter('drama')">Драма</button>
                    </div>
                </div>

                <div class="photo-ed-section">
                    <button class="photo-ed-btn secondary" onclick="window._peReset()"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:2px;"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg> Сбросить</button>
                </div>
            </div>
        </div>

        <div class="photo-editor-footer">
            <button class="btn btn-secondary" onclick="window.closePhotoEditor()">Отмена</button>
            <button class="btn btn-primary"   onclick="window.savePhotoEdit()"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:4px;"><path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg> Сохранить и отправить</button>
        </div>
    </div>`;

    document.body.appendChild(modal);
    requestAnimationFrame(() => modal.classList.add('visible'));

    _canvas = document.getElementById('photo-ed-canvas');
    _ctx    = _canvas.getContext('2d');
}

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
    const lbl = document.getElementById(`lbl-${key}`);
    if (lbl) lbl.textContent = Math.round(val);
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
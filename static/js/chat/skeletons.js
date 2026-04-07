/**
 * Vortex Skeleton Loaders — shimmer placeholders during loading.
 *
 * Показывает скелетоны для:
 *   1. Список комнат (при загрузке приложения)
 *   2. История сообщений (при открытии комнаты)
 *   3. Прогресс-бар загрузки файлов
 *   4. WebSocket connecting spinner
 */

// ── Room List Skeleton ──────────────────────────────────────────────────────

/**
 * Показать скелетоны в списке комнат (5 заглушек).
 */
export function showRoomsSkeleton() {
    const el = document.getElementById('rooms-list');
    if (!el) return;

    let html = '';
    for (let i = 0; i < 6; i++) {
        const nameW = 40 + Math.random() * 35;
        const msgW  = 25 + Math.random() * 25;
        html += `
        <div class="skeleton-room">
            <div class="skeleton skeleton-room-avatar"></div>
            <div class="skeleton-room-lines">
                <div class="skeleton skeleton-room-name" style="width:${nameW}%"></div>
                <div class="skeleton skeleton-room-msg" style="width:${msgW}%"></div>
            </div>
        </div>`;
    }
    el.innerHTML = html;
}

/**
 * Убрать скелетоны и показать контент с fade-in.
 */
export function hideRoomsSkeleton() {
    const el = document.getElementById('rooms-list');
    if (!el) return;
    el.classList.add('content-loaded');
    // Remove animation class after it finishes
    setTimeout(() => el.classList.remove('content-loaded'), 300);
}


// ── Messages Skeleton ───────────────────────────────────────────────────────

/**
 * Показать скелетоны сообщений (8 заглушек разной ширины).
 */
export function showMessagesSkeleton() {
    const el = document.getElementById('messages-container');
    if (!el) return;

    const sizes = ['short', 'medium', 'long', 'medium', 'short', 'long', 'medium', 'short'];
    const own   = [false,   false,    false,  true,     true,    false,  false,     true];

    let html = '<div class="skeleton-messages">';
    for (let i = 0; i < sizes.length; i++) {
        const cls = own[i] ? 'skeleton-msg own' : 'skeleton-msg';
        html += `
        <div class="${cls}">
            ${own[i] ? '' : '<div class="skeleton skeleton-msg-avatar"></div>'}
            <div class="skeleton-msg-body">
                ${own[i] ? '' : '<div class="skeleton skeleton-msg-name"></div>'}
                <div class="skeleton skeleton-msg-text ${sizes[i]}"></div>
                <div class="skeleton skeleton-msg-time"></div>
            </div>
        </div>`;
    }
    html += '</div>';
    el.innerHTML = html;
}

/**
 * Убрать скелетоны сообщений (вызывается перед рендерингом реальных сообщений).
 */
export function hideMessagesSkeleton() {
    const el = document.getElementById('messages-container');
    if (!el) return;
    // Skeleton will be replaced by actual content via innerHTML = ''
    // Add fade-in to the container
    el.classList.add('content-loaded');
    setTimeout(() => el.classList.remove('content-loaded'), 300);
}


// ── WebSocket Connecting Spinner ────────────────────────────────────────────

/**
 * Показать спиннер подключения.
 */
export function showConnectingSpinner() {
    const el = document.getElementById('messages-container');
    if (!el) return;
    el.innerHTML = `
        <div class="ws-connecting">
            <div class="ws-spinner"></div>
            <span>${t('app.connecting')}</span>
        </div>`;
}


// ── File Upload Progress Bar ────────────────────────────────────────────────

let _progressEl = null;

/**
 * Показать прогресс-бар загрузки файла.
 * @param {string} filename - имя файла
 */
export function showUploadProgress(filename) {
    removeUploadProgress();

    const container = document.createElement('div');
    container.className = 'upload-progress-container';
    container.id = 'upload-progress';
    container.innerHTML = `
        <div class="upload-progress-info">
            <span><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:3px;"><path d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5a2.5 2.5 0 0 1 5 0v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5a2.5 2.5 0 0 0 5 0V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/></svg>${_esc(filename)}</span>
            <span id="upload-progress-pct">0%</span>
        </div>
        <div class="upload-progress-bar">
            <div class="upload-progress-fill" id="upload-progress-fill" style="width:0%"></div>
        </div>
        <div style="display:flex;justify-content:flex-end;">
            <button class="upload-progress-cancel" onclick="window._cancelCurrentUpload?.()">${t('app.cancel')}</button>
        </div>`;

    const inputArea = document.getElementById('input-area');
    if (inputArea) {
        inputArea.parentElement.insertBefore(container, inputArea);
    }
    _progressEl = container;
}

/**
 * Обновить процент загрузки.
 * @param {number} percent - 0-100
 */
export function updateUploadProgress(percent) {
    const fill = document.getElementById('upload-progress-fill');
    const pct  = document.getElementById('upload-progress-pct');
    if (fill) fill.style.width = `${percent}%`;
    if (pct)  pct.textContent = `${percent}%`;
}

/**
 * Убрать прогресс-бар.
 */
export function removeUploadProgress() {
    const el = document.getElementById('upload-progress');
    if (el) {
        el.style.opacity = '0';
        el.style.transition = 'opacity 0.2s';
        setTimeout(() => el.remove(), 200);
    }
    _progressEl = null;
}

function _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

// static/js/utils.js
// ============================================================================
// Набор вспомогательных утилит, используемых во всём приложении:
// работа с DOM, форматирование дат/времени/размеров, работа с куками,
// универсальная функция запросов к API с CSRF-защитой, управление модалками,
// уведомления и прокрутка.
// ============================================================================

// ----------------------------------------------------------------------------
// DOM helper
// ----------------------------------------------------------------------------
/**
 * Короткая функция для получения элемента по id.
 * @param {string} id - идентификатор элемента
 * @returns {HTMLElement|null}
 */
export const $ = id => document.getElementById(id);

// ----------------------------------------------------------------------------
// Экранирование HTML-спецсимволов (защита от XSS)
// ----------------------------------------------------------------------------
/**
 * Заменяет опасные символы на HTML-сущности.
 * @param {string} str - исходная строка
 * @returns {string} экранированная строка
 */
export function esc(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ----------------------------------------------------------------------------
// Форматирование времени и даты
// ----------------------------------------------------------------------------
/**
 * Форматирует ISO-дату в локальное время (ЧЧ:ММ).
 * @param {string} iso - дата в ISO формате
 * @returns {string}
 */
// Ensure ISO string is always parsed as UTC (append Z if no timezone offset present).
// Fixes browsers that inconsistently parse "2024-01-01T12:00:00" as local vs UTC.
function _asUTC(iso) {
    if (!iso) return iso;
    return /Z$|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + 'Z';
}

export function fmtTime(iso) {
    const d = new Date(_asUTC(iso));
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/**
 * Форматирует ISO-дату: если сегодня – "Сегодня", иначе день месяц.
 * @param {string} iso - дата в ISO формате
 * @returns {string}
 */
export function fmtDate(iso) {
    const d = new Date(_asUTC(iso));
    const today = new Date();
    if (d.toDateString() === today.toDateString()) return window.t?.('time.today') || 'Today';
    return d.toLocaleDateString('ru', { day: 'numeric', month: 'long' });
}

/**
 * Форматирует размер в байтах в человекочитаемый вид (Б, КБ, МБ).
 * @param {number} bytes - размер в байтах
 * @returns {string}
 */
export function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' ' + (window.t?.('file.bytesShort') || 'B');
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' ' + (window.t?.('file.kbShort') || 'KB');
    return (bytes / 1024 / 1024).toFixed(1) + ' ' + (window.t?.('file.mbShort') || 'MB');
}

// ----------------------------------------------------------------------------
// Работа с куками
// ----------------------------------------------------------------------------
/**
 * Возвращает значение cookie по имени.
 * @param {string} name - имя cookie
 * @returns {string|null}
 */
export function getCookie(name) {
    const v = document.cookie.split(';').find(c => c.trim().startsWith(name + '='));
    return v ? v.trim().slice(name.length + 1) : null;
}

// ----------------------------------------------------------------------------
// Универсальная функция для запросов к API с поддержкой CSRF и таймаута
// ----------------------------------------------------------------------------
/**
 * Выполняет HTTP-запрос к API.
 * Автоматически добавляет заголовок X-CSRF-Token для методов, изменяющих данные.
 * Устанавливает таймаут 10 секунд через AbortController.
 * @param {string} method - HTTP метод (GET, POST, ...)
 * @param {string} path - путь (начинается с /api/...)
 * @param {Object} [body] - тело запроса (будет преобразовано в JSON)
 * @returns {Promise<any>} распарсенный JSON ответа
 * @throws {Error} с сообщением об ошибке
 */
export async function api(method, path, body) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const state = window.AppState;
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && state?.csrfToken) {
        opts.headers['X-CSRF-Token'] = state.csrfToken;
    }

    // Таймаут 10 секунд
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
        const r = await fetch(path, { ...opts, signal: controller.signal });
        clearTimeout(timeoutId);
        const data = await r.json().catch(() => ({}));
        if (!r.ok) {
            const msg = data.detail || data.error || data.message || `Server error (HTTP ${r.status})`;
            throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
        }
        return data;
    } catch (err) {
        clearTimeout(timeoutId);
        // Обработка таймаута
        if (err.name === 'AbortError') {
            throw new Error('Server not responding (timeout). Try again.');
        }
        // Обработка сетевых ошибок
        if (err instanceof TypeError && err.message.toLowerCase().includes('fetch')) {
            throw new Error('No connection to server.');
        }
        throw err;
    }
}

// ----------------------------------------------------------------------------
// Загрузка CSRF-токена
// ----------------------------------------------------------------------------
/**
 * Получает CSRF-токен с сервера и сохраняет в AppState.
 */
export async function loadCsrfToken() {
    try {
        const d = await api('GET', '/api/authentication/csrf-token');
        window.AppState.csrfToken = d.csrf_token;
    } catch { }
}

// ----------------------------------------------------------------------------
// Управление модальными окнами
// ----------------------------------------------------------------------------
/**
 * Открывает модальное окно (добавляет класс 'show').
 * @param {string} id - id модального окна
 */
export function openModal(id) {
    const el = $(id);
    if (!el) { console.warn('openModal: element not found:', id); return; }
    el.classList.add('show');
}

/**
 * Закрывает модальное окно (убирает класс 'show').
 * @param {string} id - id модального окна
 */
export function closeModal(id) {
    const el = $(id);
    if (!el) return;
    el.classList.remove('show');
}

// ----------------------------------------------------------------------------
// Кастомные модалки вместо prompt / confirm / alert
// ----------------------------------------------------------------------------

let _vxModalStyled = false;
function _ensureVxModalStyle() {
    if (_vxModalStyled) return;
    _vxModalStyled = true;
    const s = document.createElement('style');
    s.textContent = `
    .vx-modal-backdrop {
        position:fixed;inset:0;z-index:10000;
        background:rgba(0,0,0,.55);backdrop-filter:blur(6px);
        display:flex;align-items:center;justify-content:center;
        animation:vxFadeIn .15s ease;
    }
    @keyframes vxFadeIn { from{opacity:0} to{opacity:1} }
    .vx-modal-box {
        background:var(--bg2,#1a1a2e);border:1px solid var(--border,rgba(255,255,255,.1));
        border-radius:16px;padding:24px;min-width:320px;max-width:420px;width:90vw;
        box-shadow:0 16px 48px rgba(0,0,0,.4);animation:vxSlideUp .2s ease;
    }
    @keyframes vxSlideUp { from{transform:translateY(12px);opacity:0} to{transform:translateY(0);opacity:1} }
    .vx-modal-title {
        font-size:15px;font-weight:600;color:var(--text,#fff);margin-bottom:16px;line-height:1.4;
        white-space:pre-line;
    }
    .vx-modal-input {
        width:100%;padding:10px 14px;border-radius:10px;border:1px solid var(--border,rgba(255,255,255,.1));
        background:var(--bg3,rgba(255,255,255,.05));color:var(--text,#fff);font-size:14px;
        outline:none;box-sizing:border-box;transition:border-color .15s;
    }
    .vx-modal-input:focus { border-color:var(--accent,#7c3aed); }
    .vx-modal-input::placeholder { color:var(--text3,rgba(255,255,255,.35)); }
    .vx-modal-token {
        width:100%;padding:10px 14px;border-radius:10px;border:1px solid var(--border,rgba(255,255,255,.1));
        background:var(--bg3,rgba(255,255,255,.05));color:var(--accent2,#06b6d4);font-size:13px;
        font-family:monospace;word-break:break-all;user-select:all;line-height:1.5;margin-bottom:4px;
    }
    .vx-modal-btns {
        display:flex;gap:8px;justify-content:flex-end;margin-top:16px;
    }
    .vx-modal-btn {
        padding:8px 20px;border-radius:10px;border:none;cursor:pointer;font-size:13px;font-weight:500;
        transition:all .15s;
    }
    .vx-modal-btn.cancel {
        background:var(--bg3,rgba(255,255,255,.08));color:var(--text2,rgba(255,255,255,.7));
    }
    .vx-modal-btn.cancel:hover { background:rgba(255,255,255,.12); }
    .vx-modal-btn.primary {
        background:var(--accent,#7c3aed);color:#fff;
    }
    .vx-modal-btn.primary:hover { filter:brightness(1.15); }
    .vx-modal-btn.danger {
        background:var(--red,#ef4444);color:#fff;
    }
    .vx-modal-btn.danger:hover { filter:brightness(1.15); }
    .vx-modal-btn.copy {
        background:var(--bg3,rgba(255,255,255,.08));color:var(--text,#fff);
    }
    .vx-modal-btn.copy:hover { background:rgba(255,255,255,.12); }
    .vx-modal-select-list {
        display:flex;flex-direction:column;gap:4px;margin-top:4px;
    }
    .vx-modal-select-item {
        padding:10px 14px;border-radius:10px;cursor:pointer;font-size:13px;
        color:var(--text,#fff);transition:background .12s;display:flex;align-items:center;
        justify-content:space-between;border:1px solid transparent;
    }
    .vx-modal-select-item:hover { background:rgba(255,255,255,.06); }
    .vx-modal-select-item.active {
        background:rgba(124,58,237,.15);border-color:var(--accent,#7c3aed);
    }
    .vx-modal-select-item .vx-check {
        color:var(--accent,#7c3aed);font-size:16px;display:none;
    }
    .vx-modal-select-item.active .vx-check { display:inline; }

    /* Light theme */
    body[data-theme="light"] .vx-modal-box {
        background:#fff;border-color:rgba(0,0,0,.1);
        box-shadow:0 16px 48px rgba(0,0,0,.15);
    }
    body[data-theme="light"] .vx-modal-title { color:#1a1a2e; }
    body[data-theme="light"] .vx-modal-input {
        background:#f5f5f5;border-color:rgba(0,0,0,.12);color:#1a1a2e;
    }
    body[data-theme="light"] .vx-modal-input::placeholder { color:rgba(0,0,0,.4); }
    body[data-theme="light"] .vx-modal-token {
        background:#f5f5f5;border-color:rgba(0,0,0,.1);color:#0d6efd;
    }
    body[data-theme="light"] .vx-modal-btn.cancel {
        background:rgba(0,0,0,.06);color:#555;
    }
    body[data-theme="light"] .vx-modal-btn.cancel:hover { background:rgba(0,0,0,.1); }
    body[data-theme="light"] .vx-modal-btn.copy {
        background:rgba(0,0,0,.06);color:#1a1a2e;
    }
    body[data-theme="light"] .vx-modal-select-item { color:#1a1a2e; }
    body[data-theme="light"] .vx-modal-select-item:hover { background:rgba(0,0,0,.04); }
    `;
    document.head.appendChild(s);
}

/**
 * Кастомный prompt — возвращает Promise<string|null>.
 * @param {string} title - заголовок
 * @param {string} [defaultValue=''] - начальное значение
 * @param {string} [placeholder=''] - плейсхолдер
 */
export function vxPrompt(title, defaultValue = '', placeholder = '') {
    _ensureVxModalStyle();
    return new Promise(resolve => {
        const backdrop = document.createElement('div');
        backdrop.className = 'vx-modal-backdrop';
        const box = document.createElement('div');
        box.className = 'vx-modal-box';
        const titleEl = document.createElement('div');
        titleEl.className = 'vx-modal-title';
        titleEl.textContent = title;
        const isPassword = /парол|password/i.test(placeholder) || /парол|password/i.test(title);
        const inputWrap = document.createElement('div');
        inputWrap.style.cssText = 'position:relative;';
        const input = document.createElement('input');
        input.className = 'vx-modal-input';
        input.value = defaultValue;
        input.placeholder = placeholder;
        if (isPassword) {
            input.type = 'password';
            input.style.paddingRight = '40px';
            const eyeBtn = document.createElement('button');
            eyeBtn.type = 'button';
            eyeBtn.className = 'pass-eye-btn';
            eyeBtn.style.cssText = 'position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;padding:4px;color:var(--text3);display:flex;z-index:2;';
            // Static SVG icons for eye toggle — safe content
            eyeBtn.innerHTML = '<svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>'
                + '<svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
            eyeBtn.onclick = () => window.togglePassEye?.(eyeBtn);
            inputWrap.append(input, eyeBtn);
        } else {
            inputWrap.appendChild(input);
        }
        const btns = document.createElement('div');
        btns.className = 'vx-modal-btns';
        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'vx-modal-btn cancel';
        cancelBtn.textContent = window.t?.('app.cancel') || 'Cancel';
        const okBtn = document.createElement('button');
        okBtn.className = 'vx-modal-btn primary';
        okBtn.textContent = 'OK';
        btns.append(cancelBtn, okBtn);
        box.append(titleEl, inputWrap, btns);
        backdrop.appendChild(box);
        document.body.appendChild(backdrop);
        input.focus();
        if (!isPassword) input.select();

        const close = (val) => { backdrop.remove(); resolve(val); };
        cancelBtn.addEventListener('click', () => close(null));
        backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(null); });
        okBtn.addEventListener('click', () => close(input.value));
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') close(input.value);
            if (e.key === 'Escape') close(null);
        });
    });
}
window.vxPrompt = vxPrompt;

/**
 * Кастомный confirm — возвращает Promise<boolean>.
 * @param {string} title - текст
 * @param {object} [opts] - { danger: boolean, ok: string, cancel: string }
 */
export function vxConfirm(title, opts = {}) {
    _ensureVxModalStyle();
    return new Promise(resolve => {
        const backdrop = document.createElement('div');
        backdrop.className = 'vx-modal-backdrop';
        const box = document.createElement('div');
        box.className = 'vx-modal-box';
        const titleEl = document.createElement('div');
        titleEl.className = 'vx-modal-title';
        titleEl.textContent = title;
        const btns = document.createElement('div');
        btns.className = 'vx-modal-btns';
        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'vx-modal-btn cancel';
        cancelBtn.textContent = opts.cancel || window.t?.('app.cancel') || 'Cancel';
        const okBtn = document.createElement('button');
        okBtn.className = `vx-modal-btn ${opts.danger ? 'danger' : 'primary'}`;
        okBtn.textContent = opts.ok || 'OK';
        btns.append(cancelBtn, okBtn);
        box.append(titleEl, btns);
        backdrop.appendChild(box);
        document.body.appendChild(backdrop);
        okBtn.focus();

        const close = (val) => { backdrop.remove(); resolve(val); };
        cancelBtn.addEventListener('click', () => close(false));
        backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(false); });
        okBtn.addEventListener('click', () => close(true));
        backdrop.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') close(false);
        });
    });
}
window.vxConfirm = vxConfirm;

/**
 * Кастомный alert (с кнопкой копирования для токенов).
 * @param {string} title - заголовок
 * @param {object} [opts] - { token: string (покажет поле с копированием) }
 */
export function vxAlert(title, opts = {}) {
    _ensureVxModalStyle();
    return new Promise(resolve => {
        const backdrop = document.createElement('div');
        backdrop.className = 'vx-modal-backdrop';
        const box = document.createElement('div');
        box.className = 'vx-modal-box';
        const titleEl = document.createElement('div');
        titleEl.className = 'vx-modal-title';
        titleEl.textContent = title;
        box.appendChild(titleEl);

        if (opts.token) {
            const tokenEl = document.createElement('div');
            tokenEl.className = 'vx-modal-token';
            tokenEl.textContent = opts.token;
            box.appendChild(tokenEl);
        }

        const btns = document.createElement('div');
        btns.className = 'vx-modal-btns';
        if (opts.token) {
            const copyBtn = document.createElement('button');
            copyBtn.className = 'vx-modal-btn copy';
            copyBtn.textContent = window.t?.('ctx.copy') || 'Copy';
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(opts.token).then(() => {
                    copyBtn.textContent = '✓';
                    setTimeout(() => { copyBtn.textContent = window.t?.('ctx.copy') || 'Copy'; }, 1500);
                });
            });
            btns.appendChild(copyBtn);
        }
        const okBtn = document.createElement('button');
        okBtn.className = 'vx-modal-btn primary';
        okBtn.textContent = 'OK';
        btns.appendChild(okBtn);
        box.appendChild(btns);
        backdrop.appendChild(box);
        document.body.appendChild(backdrop);
        okBtn.focus();

        const close = () => { backdrop.remove(); resolve(); };
        okBtn.addEventListener('click', close);
        backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
        backdrop.addEventListener('keydown', (e) => { if (e.key === 'Escape' || e.key === 'Enter') close(); });
    });
}
window.vxAlert = vxAlert;

/**
 * Кастомный select из списка опций.
 * @param {string} title - заголовок
 * @param {Array<{label:string, value:any}>} options - опции
 * @param {any} [currentValue] - текущее значение (подсвечивается)
 * @returns {Promise<any|null>} - выбранное значение или null
 */
export function vxSelect(title, options, currentValue) {
    _ensureVxModalStyle();
    return new Promise(resolve => {
        const backdrop = document.createElement('div');
        backdrop.className = 'vx-modal-backdrop';
        const box = document.createElement('div');
        box.className = 'vx-modal-box';
        const titleEl = document.createElement('div');
        titleEl.className = 'vx-modal-title';
        titleEl.textContent = title;
        box.appendChild(titleEl);

        const list = document.createElement('div');
        list.className = 'vx-modal-select-list';
        options.forEach(opt => {
            const item = document.createElement('div');
            item.className = 'vx-modal-select-item';
            if (opt.value === currentValue) item.classList.add('active');
            const label = document.createElement('span');
            label.textContent = opt.label;
            const check = document.createElement('span');
            check.className = 'vx-check';
            check.textContent = '✓';
            item.append(label, check);
            item.addEventListener('click', () => { backdrop.remove(); resolve(opt.value); });
            list.appendChild(item);
        });
        box.appendChild(list);

        const btns = document.createElement('div');
        btns.className = 'vx-modal-btns';
        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'vx-modal-btn cancel';
        cancelBtn.textContent = window.t?.('app.cancel') || 'Cancel';
        btns.appendChild(cancelBtn);
        box.appendChild(btns);
        backdrop.appendChild(box);
        document.body.appendChild(backdrop);

        const close = () => { backdrop.remove(); resolve(null); };
        cancelBtn.addEventListener('click', close);
        backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
        backdrop.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
    });
}
window.vxSelect = vxSelect;

// ----------------------------------------------------------------------------
// Показ всплывающих уведомлений
// ----------------------------------------------------------------------------
/**
 * Показывает алерт в указанном элементе на 5 секунд.
 * @param {string} id - id элемента для сообщения
 * @param {string} msg - текст сообщения
 * @param {string} [type='error'] - тип (error, success, ...)
 */
export function showAlert(id, msg, type = 'error') {
    const el = $(id);
    if (el) {
        el.textContent = msg;
        el.className = `alert show alert-${type}`;
        setTimeout(() => el.classList.remove('show'), 5000);
        return;
    }
    // Fallback: id is actually the message (2-arg call pattern)
    if (typeof id === 'string' && !msg) {
        msg = id; type = 'error';
    } else if (typeof id === 'string' && typeof msg === 'string' && !$(id)) {
        // showAlert('message text', 'success') — 2-arg pattern
        type = msg; msg = id;
    }
    // Use toast system if available, otherwise console
    if (typeof window.showToast === 'function') {
        window.showToast(msg, type === 'success' ? 'success' : type === 'error' ? 'error' : 'info');
    } else {
        console.warn(`[alert] ${type}: ${msg}`);
    }
}

// ----------------------------------------------------------------------------
// Прокрутка контейнера сообщений вниз
// ----------------------------------------------------------------------------
/**
 * Прокручивает контейнер с сообщениями в самый низ.
 * @param {boolean} [smooth=false] - использовать плавную прокрутку
 */
export function scrollToBottom(smooth = false) {
    const c = $('messages-container');
    if (c) c.scrollTo({ top: c.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
}
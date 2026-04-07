// node_setup/static/js/setup/utils.js — вспомогательные утилиты

/**
 * Показывает сообщение об ошибке/успехе в указанном alert-блоке.
 * @param {string} sid - суффикс id (например 's1' → alert-s1)
 * @param {string} msg - текст сообщения
 * @param {string} type - тип ('error', 'success', 'info')
 */
function showAlert(sid, msg, type = 'error') {
    const el = document.getElementById('alert-' + sid);
    if (!el) return;
    el.textContent = msg;
    el.className   = `alert show alert-${type}`;
}

/**
 * Скрывает alert-блок.
 * @param {string} sid
 */
function hideAlert(sid) {
    document.getElementById('alert-' + sid)?.classList.remove('show');
}

/**
 * Экранирует HTML-спецсимволы для безопасного вывода.
 * @param {string} s
 * @returns {string}
 */
function esc(s) {
    return String(s || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/**
 * Копирует текст из указанного элемента (внутри .code-block) в буфер обмена.
 * @param {string} id - id элемента (обычно code-block)
 */
function copyCode(id) {
    const el   = document.getElementById(id);
    const text = el.querySelector('span')?.textContent || el.textContent;
    navigator.clipboard.writeText(text.trim()).then(() => {
        const btn = el.querySelector('.code-copy');
        if (btn) {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
            setTimeout(() => btn.textContent = 'copy', 1500);
        }
    });
}

/**
 * Функция debounce для ограничения частоты вызова.
 * @param {Function} fn - функция
 * @param {number} ms - задержка в мс
 * @returns {Function}
 */
function debounce(fn, ms) {
    let t;
    return function (...args) {
        clearTimeout(t);
        t = setTimeout(() => fn.apply(this, args), ms);
    };
}

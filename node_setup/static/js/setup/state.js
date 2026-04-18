// node_setup/static/js/setup/state.js — глобальное состояние мастера + инициализация

// ── Состояние приложения ─────────────────────────────────────────────────────
const state = {
    step:       0,          // current step (0=lang, 1-6=main steps)
    sslMode:    'self',     // выбранный способ SSL: 'self', 'mkcert', 'le', 'skip'
    sslDone:    false,      // был ли SSL успешно сгенерирован (или пропущен)
    sslSkipped: false,      // true, если выбран пропуск SSL
    caCmd:      '',         // команда для ручной установки CA (если нужно)
    nodeUrl:    '',         // итоговый URL узла (http://... или https://...)
    sysInfo:    null,       // данные о системе с сервера (из /api/info)
    config:     null,       // объект с конфигурацией узла (имя, порты и т.д.)
};

// ── Состояние шага «Режим сети» ─────────────────────────────────────────────
let _networkMode = 'local';
let _regMode     = 'open';
let _inviteCode  = '';

// ── Инициализация при загрузке страницы ──────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
    await loadSysInfo();       // загружаем информацию о системе
    prefillDeviceName();       // заполняем поле имени устройства hostname'ом
    checkMkcert();             // проверяем доступность mkcert и помечаем опцию
    bindPortValidation();      // привязываем валидацию порта при вводе
});

/**
 * Загружает системную информацию с сервера (GET /api/info).
 * Обновляет state.sysInfo, отображает локальный IP и статус.
 */
async function loadSysInfo() {
    try {
        const r    = await fetch('/api/info');
        state.sysInfo = await r.json();
        const ip   = state.sysInfo.local_ips?.[0] || 'unknown';
        const ok   = ip !== 'unknown';
        document.getElementById('ip-dot').className  = 'dot ' + (ok ? 'dot-green' : 'dot-yellow');
        document.getElementById('ip-text').textContent = `Local IP: ${ip}`;
    } catch {
        document.getElementById('ip-text').textContent = 'Could not detect IP';
    }
}

// ============================================================================
// MAIN — глобальное состояние и инициализация
// ============================================================================

import { $, loadCsrfToken, api } from './utils.js';  // добавили api
import { checkSession } from './auth.js';
import { startPeerPolling } from './peers.js';
import { showWelcome } from './ui.js';

// Глобальное состояние
window.AppState = {
    user: null,
    rooms: [],
    currentRoom: null,
    token: null,
    ws: null,
    signalWs: null,
    peers: [],
    peersInterval: null,
    typingTimeout: null,
    selectedEmoji: '👤',
    pc: null,
    localStream: null,
    isMuted: false,
    isCamOff: false,
    nodePublicKey: null,
    sessionKeys: {},
    csrfToken: null,
};

// Функция запуска приложения после успешной аутентификации
window.bootApp = async function bootApp() {
    $('auth-screen').style.display = 'none';
    $('app').style.display = 'flex';

    $('sb-avatar').textContent = AppState.user.avatar_emoji || '👤';
    $('sb-name').textContent = AppState.user.display_name || AppState.user.username;
    $('sb-phone').textContent = AppState.user.phone;

    await loadCsrfToken();
    setInterval(loadCsrfToken, 600_000);

    try {
        const d = await api('GET', '/api/keys/pubkey');
        AppState.nodePublicKey = d.pubkey_hex;
        console.log('🔑 X25519 pubkey:', AppState.nodePublicKey.slice(0, 16) + '...');
    } catch { }

    await import('./rooms.js').then(m => m.loadMyRooms());
    startPeerPolling();
    showWelcome();
};

// Привязываем глобальные функции, вызываемые из HTML
import * as auth from './auth.js';
import * as rooms from './rooms.js';
import * as chat from './chat.js';
import * as peers from './peers.js';
import * as webrtc from './webrtc.js';
import * as ui from './ui.js';

Object.assign(window, auth, rooms, chat, peers, webrtc, ui);

// Закрытие модалок по оверлею
document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', e => {
        if (e.target === el) el.classList.remove('show');
    });
});

// Enter в authentication-формах
document.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
        if ($('login-form').style.display !== 'none' &&
            (document.activeElement === $('l-login') || document.activeElement === $('l-pass'))) {
            window.doLogin();
        }
    }
});

// Запуск проверки сессии при загрузке страницы
window.addEventListener('DOMContentLoaded', checkSession);
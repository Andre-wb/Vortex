import { $, api, showAlert, openModal, closeModal } from './utils.js';

// ============================================================================
// AUTH
// ============================================================================

export function switchTab(tab) {
    $('login-form').style.display = tab === 'login' ? '' : 'none';
    $('register-form').style.display = tab === 'register' ? '' : 'none';
    document.querySelectorAll('.auth-tab').forEach((t, i) => {
        t.classList.toggle('active', (i === 0) === (tab === 'login'));
    });
    $('auth-alert').classList.remove('show');
}

export function selectEmoji(btn) {
    document.querySelectorAll('.emoji-btn').forEach(b => b.classList.remove('emoji-selected'));
    btn.classList.add('emoji-selected');
    window.AppState.selectedEmoji = btn.dataset.emoji;
}

export async function doLogin() {
    try {
        const data = await api('POST', '/api/authentication/login', {
            phone_or_username: $('l-login').value.trim(),
            password: $('l-pass').value,
        });
        window.AppState.user = data;
        window.bootApp(); // из main.js
    } catch (e) {
        showAlert('auth-alert', e.message);
    }
}

export async function doRegister() {
    try {
        const data = await api('POST', '/api/authentication/register', {
            phone: $('r-phone').value.trim(),
            username: $('r-username').value.trim(),
            password: $('r-pass').value,
            display_name: $('r-display').value.trim(),
            avatar_emoji: window.AppState.selectedEmoji,
        });
        window.AppState.user = data;
        window.bootApp();
    } catch (e) {
        showAlert('auth-alert', e.message);
    }
}

export async function doLogout() {
    try {
        await api('POST', '/api/authentication/logout');
    } catch { }
    window.AppState.user = null;
    window.AppState.ws?.close();
    window.AppState.ws = null;
    $('app').style.display = 'none';
    $('auth-screen').style.display = 'flex';
    $('auth-screen').className = 'screen active';
}

export async function checkSession() {
    try {
        const data = await api('GET', '/api/authentication/me');
        window.AppState.user = data;
        window.bootApp();
    } catch {
        // не авторизован — остаёмся на экране входа
    }
}
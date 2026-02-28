// ============================================================================
// UTILS
// ============================================================================

// DOM helper
export const $ = id => document.getElementById(id);

// Escaping
export function esc(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Time formatting
export function fmtTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' });
}

export function fmtDate(iso) {
    const d = new Date(iso);
    const today = new Date();
    if (d.toDateString() === today.toDateString()) return 'Сегодня';
    return d.toLocaleDateString('ru', { day: 'numeric', month: 'long' });
}

export function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' Б';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' КБ';
    return (bytes / 1024 / 1024).toFixed(1) + ' МБ';
}

// Cookies
export function getCookie(name) {
    const v = document.cookie.split(';').find(c => c.trim().startsWith(name + '='));
    return v ? v.trim().slice(name.length + 1) : null;
}

// API helper with CSRF
export async function api(method, path, body) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const state = window.AppState;
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && state.csrfToken) {
        opts.headers['X-CSRF-Token'] = state.csrfToken;
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    try {
        const r = await fetch(path, { ...opts, signal: controller.signal });
        clearTimeout(timeoutId);
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.detail || data.error || `HTTP ${r.status}`);
        return data;
    } catch (err) {
        clearTimeout(timeoutId);
        throw err;
    }
}

// Load CSRF token
export async function loadCsrfToken() {
    try {
        const d = await api('GET', '/api/authentication/csrf-token');
        window.AppState.csrfToken = d.csrf_token;
    } catch { }
}

// Modal helpers
export function openModal(id) {
    $(id).classList.add('show');
}
export function closeModal(id) {
    $(id).classList.remove('show');
}

// Alerts
export function showAlert(id, msg, type = 'error') {
    const el = $(id);
    el.textContent = msg;
    el.className = `alert show alert-${type}`;
    setTimeout(() => el.classList.remove('show'), 5000);
}

// Scroll to bottom
export function scrollToBottom(smooth = false) {
    const c = $('messages-container');
    if (c) c.scrollTo({ top: c.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
}
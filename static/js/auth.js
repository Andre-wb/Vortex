// static/js/auth.js
import { $, api, showAlert, openModal, closeModal } from './utils.js';
import { stopMultiplexCover } from './notifications.js';
import { validatePasswords, getFullPhone } from './phone_password.js';

// ============================================================================
// X25519 КЛЮЧЕВАЯ ПАРА
// ============================================================================

const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');

/**
 * Генерирует X25519 ключевую пару.
 * ВАЖНО: Web Crypto API не позволяет экспортировать X25519 private key как 'raw'
 * — только 'jwk'. Поэтому храним приватный ключ как JWK JSON-строку.
 */
async function generateX25519Keypair() {
    try {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'X25519' }, true, ['deriveBits']
        );
        const publicRaw  = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        return {
            publicKeyHex:  toHex(publicRaw),
            privateKeyJwk: JSON.stringify(privateJwk),
        };
    } catch (e) {
        console.error('X25519 generateKey failed:', e);
        throw new Error(t('auth.browserNoX25519'));
    }
}

// ============================================================================
// Шифрование приватного ключа для localStorage (PBKDF2 + AES-GCM)
// ============================================================================

async function _encryptForStorage(data, password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(data));
    // Format: salt(16) + iv(12) + ciphertext
    const result = new Uint8Array(salt.length + iv.length + ct.byteLength);
    result.set(salt, 0);
    result.set(iv, 16);
    result.set(new Uint8Array(ct), 28);
    return btoa(String.fromCharCode(...result));
}

async function _decryptFromStorage(b64data, password) {
    const enc = new TextEncoder();
    const raw = Uint8Array.from(atob(b64data), c => c.charCodeAt(0));
    const salt = raw.slice(0, 16);
    const iv = raw.slice(16, 28);
    const ct = raw.slice(28);
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(plain);
}

// ============================================================================
// Хранение ключей
// ============================================================================

async function savePrivateKey(jwkString, password) {
    // Всегда сохраняем незашифрованную копию — и в localStorage, и в sessionStorage.
    // localStorage переживает закрытие браузера, sessionStorage — перезагрузку страницы.
    // Зашифрованная копия хранится дополнительно для восстановления на другом устройстве.
    localStorage.setItem('vortex_x25519_priv', jwkString);
    sessionStorage.setItem('vortex_x25519_priv', jwkString);

    // Также сохраняем per-user копию для мультиаккаунта
    const userId = window.AppState?.user?.user_id;
    if (userId) {
        localStorage.setItem(`vortex_x25519_priv_${userId}`, jwkString);
    }

    if (password) {
        try {
            const encrypted = await _encryptForStorage(jwkString, password);
            localStorage.setItem('vortex_x25519_priv_enc', encrypted);
        } catch (e) {
            console.warn('Не удалось зашифровать ключ:', e);
        }
    }
}

/**
 * Загружает приватный ключ из localStorage.
 * Если ключ зашифрован — требуется пароль для расшифровки.
 * Если найден старый незашифрованный ключ — возвращает его (для обратной совместимости).
 */
async function _loadPrivateKeyWithPassword(password) {
    // Пробуем зашифрованный ключ
    const encrypted = localStorage.getItem('vortex_x25519_priv_enc');
    if (encrypted && password) {
        try {
            const jwk = await _decryptFromStorage(encrypted, password);
            // Проверяем что результат — валидный JSON
            JSON.parse(jwk);
            // Сохраняем в sessionStorage для доступа при перезагрузке страницы
            sessionStorage.setItem('vortex_x25519_priv', jwk);
            return jwk;
        } catch (e) {
            console.warn('Не удалось расшифровать ключ:', e);
        }
    }

    // sessionStorage (сохраняется между перезагрузками страницы)
    const fromSession = sessionStorage.getItem('vortex_x25519_priv');
    if (fromSession) return fromSession;

    // Обратная совместимость: незашифрованный ключ
    const plain = localStorage.getItem('vortex_x25519_priv');
    if (plain) {
        // Миграция: шифруем старый ключ если есть пароль
        if (password) {
            try {
                await savePrivateKey(plain, password);
                console.info('Ключ мигрирован в зашифрованное хранилище');
            } catch (e) {
                console.warn('Миграция ключа не удалась:', e);
            }
        }
        return plain;
    }

    return null;
}

/**
 * Синхронная загрузка ключа (для обратной совместимости).
 * Пробует незашифрованный ключ, затем проверяет наличие зашифрованного.
 */
export function loadPrivateKey() {
    // 1. sessionStorage (сохраняется при логине, живёт до закрытия вкладки)
    const fromSession = sessionStorage.getItem('vortex_x25519_priv');
    if (fromSession) return fromSession;

    // 2. Незашифрованный ключ в localStorage
    const plain = localStorage.getItem('vortex_x25519_priv');
    if (plain) return plain;

    // 3. Если есть только зашифрованный — вернуть null (нужен пароль при логине)
    if (localStorage.getItem('vortex_x25519_priv_enc')) return null;

    return null;
}

// Вспомогательная: восстанавливаем публичный ключ из JWK
function _recoverPubkeyFromJwk(jwkString) {
    try {
        const jwk = JSON.parse(jwkString);
        if (jwk.x) {
            const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(b64);
            return Array.from(
                binary, c => c.charCodeAt(0).toString(16).padStart(2, '0')
            ).join('');
        }
    } catch (e) { console.debug('pubkey recovery failed:', e); }
    return null;
}

// ============================================================================
// Вспомогательная: загрузка ключа + восстановление публичного ключа
// ============================================================================

async function _tryLoadKey(password) {
    const saved = await _loadPrivateKeyWithPassword(password);
    if (saved) {
        window.AppState.x25519PrivateKey = saved;
        if (!window.AppState.user.x25519_public_key) {
            const pubHex = _recoverPubkeyFromJwk(saved);
            if (pubHex) window.AppState.user.x25519_public_key = pubHex;
        }
    }
}

// ============================================================================
// MULTI-ACCOUNT (до 4 аккаунтов)
// ============================================================================

const MAX_ACCOUNTS = 4;

/** Загружает список сохранённых аккаунтов из localStorage */
export function getAccounts() {
    try {
        return JSON.parse(localStorage.getItem('vortex_accounts') || '[]');
    } catch { return []; }
}

/** Сохраняет список аккаунтов в localStorage */
function _setAccounts(accounts) {
    localStorage.setItem('vortex_accounts', JSON.stringify(accounts));
}

/** Сохраняет данные текущего пользователя в список аккаунтов */
function _saveCurrentAccount() {
    const u = window.AppState.user;
    if (!u) return;
    const userId = u.user_id;

    // Сохраняем приватный ключ per-user
    const privKey = window.AppState.x25519PrivateKey
        || sessionStorage.getItem('vortex_x25519_priv')
        || localStorage.getItem('vortex_x25519_priv');
    if (privKey) {
        localStorage.setItem(`vortex_x25519_priv_${userId}`, privKey);
    }

    // Обновляем запись в списке аккаунтов
    const accounts = getAccounts();
    const entry = {
        user_id:      userId,
        username:     u.username,
        phone:        u.phone,
        display_name: u.display_name || u.username,
        avatar_emoji: u.avatar_emoji || null,
        avatar_url:   u.avatar_url || null,
    };
    const idx = accounts.findIndex(a => a.user_id === userId);
    if (idx >= 0) {
        accounts[idx] = entry;
    } else if (accounts.length < MAX_ACCOUNTS) {
        accounts.push(entry);
    }
    _setAccounts(accounts);
    localStorage.setItem('vortex_current_account_id', String(userId));
}

/**
 * Переключение на другой аккаунт через X25519 challenge-response.
 * Не требует пароля — только приватный ключ.
 */
export async function switchAccount(userId) {
    const accounts = getAccounts();
    const target = accounts.find(a => a.user_id === userId);
    if (!target) { alert(t('auth.accountNotFound')); return; }

    // Загружаем приватный ключ целевого аккаунта
    const targetPrivKey = localStorage.getItem(`vortex_x25519_priv_${userId}`);
    if (!targetPrivKey) {
        alert(t('auth.keyNotFound'));
        return;
    }

    // Сохраняем текущий аккаунт перед переключением
    _saveCurrentAccount();

    // Закрываем текущую сессию и все WebSocket'ы
    try { await api('POST', '/api/authentication/logout'); } catch (e) { console.debug('logout during switch failed:', e); }
    stopMultiplexCover();
    if (window.AppState.ws) { window.AppState.ws.onclose = null; window.AppState.ws.close(); window.AppState.ws = null; }
    if (window.AppState.notifWs) { window.AppState.notifWs.onclose = null; window.AppState.notifWs.close(); window.AppState.notifWs = null; }
    if (window.AppState.signalWs) { window.AppState.signalWs.onclose = null; window.AppState.signalWs.close(); window.AppState.signalWs = null; }

    try {
        // Шаг 1: получаем challenge
        const ch = await api('GET', `/api/authentication/challenge?identifier=${encodeURIComponent(target.username)}`);

        // Шаг 2: вычисляем proof через Web Crypto
        const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

        // Импортируем наш приватный ключ
        const privKeyObj = await crypto.subtle.importKey(
            'jwk', JSON.parse(targetPrivKey), { name: 'X25519' }, false, ['deriveBits']
        );

        // Импортируем публичный ключ сервера
        const serverPubKey = await crypto.subtle.importKey(
            'raw', fromHex(ch.server_pubkey), { name: 'X25519' }, false, []
        );

        // X25519 DH -> shared secret
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'X25519', public: serverPubKey }, privKeyObj, 256
        );

        // HMAC-SHA256(shared, challenge)
        const hmacKey = await crypto.subtle.importKey(
            'raw', sharedBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const proofBytes = await crypto.subtle.sign('HMAC', hmacKey, fromHex(ch.challenge));
        const proofHex = toHex(proofBytes);

        // Восстанавливаем публичный ключ из JWK
        const pubHex = _recoverPubkeyFromJwk(targetPrivKey);

        // Шаг 3: login-key
        const data = await api('POST', '/api/authentication/login-key', {
            challenge_id: ch.challenge_id,
            pubkey:       pubHex,
            proof:        proofHex,
        });

        // Успешно переключились
        window.AppState.user = data;
        window.AppState.x25519PrivateKey = targetPrivKey;
        localStorage.setItem('vortex_x25519_priv', targetPrivKey);
        sessionStorage.setItem('vortex_x25519_priv', targetPrivKey);
        localStorage.setItem('vortex_current_account_id', String(userId));

        closeModal('profile-modal');
        window.bootApp();
    } catch (e) {
        console.error('Ошибка переключения аккаунта:', e);
        alert(t('auth.switchFailed') + ': ' + (e.message || e));
        // Показываем экран логина как fallback
        window.AppState.user = null;
        window.AppState.x25519PrivateKey = null;
        $('app').style.display = 'none';
        $('auth-screen').style.display = 'flex';
        $('auth-screen').className = 'screen active';
    }
}

/**
 * Добавить новый аккаунт: сохраняем текущий, выходим, показываем экран авторизации.
 */
export async function addNewAccount() {
    const accounts = getAccounts();
    if (accounts.length >= MAX_ACCOUNTS) {
        alert(t('auth.maxAccounts'));
        return;
    }

    // Сохраняем текущий аккаунт
    _saveCurrentAccount();

    // Помечаем что мы в режиме добавления аккаунта
    window._addingNewAccount = true;

    // Логаут текущего
    closeModal('profile-modal');
    await doLogout();
}

/**
 * Удалить аккаунт из списка (не удаляет сам аккаунт на сервере).
 */
export function removeAccount(userId) {
    const currentUserId = window.AppState.user?.user_id;
    if (userId === currentUserId) return; // нельзя удалить текущий

    let accounts = getAccounts();
    accounts = accounts.filter(a => a.user_id !== userId);
    _setAccounts(accounts);

    // Удаляем приватный ключ
    localStorage.removeItem(`vortex_x25519_priv_${userId}`);
}

// ============================================================================
// AUTH
// ============================================================================

export function switchTab(tab) {
    const forms = {
        login:    $('login-form'),
        register: $('register-form'),
        qr:       $('qr-form'),
        passkey:  $('passkey-form'),
        seed:     $('seed-form'),
    };
    for (const [key, el] of Object.entries(forms)) {
        if (el) el.style.display = tab === key ? '' : 'none';
    }

    // Only 2 visible tabs: login(0) and register(1); qr/passkey/seed are sub-pages of login
    const isLoginGroup = tab === 'login' || tab === 'qr' || tab === 'passkey' || tab === 'seed';
    document.querySelectorAll('.auth-tab').forEach((t, i) => {
        t.classList.toggle('active', (isLoginGroup && i === 0) || (tab === 'register' && i === 1));
    });

    const alert = $('auth-alert');
    if (alert) alert.classList.remove('show');
    if (tab === 'register') checkRegistrationMode();
    if (tab === 'qr' && window.initQRLogin) window.initQRLogin();
}

export function selectEmoji(btn) {
    document.querySelectorAll('.emoji-btn').forEach(b => b.classList.remove('emoji-selected'));
    btn.classList.add('emoji-selected');
    window.AppState.selectedEmoji = btn.dataset.emoji;
}

export function switchAvatarTab(tab) {
    const emojiPanel = $('avatar-emoji-panel');
    const photoPanel = $('avatar-photo-panel');
    if (emojiPanel) emojiPanel.style.display = tab === 'emoji' ? '' : 'none';
    if (photoPanel) photoPanel.style.display = tab === 'photo' ? '' : 'none';
    const emojiTab = $('avatar-emoji-tab');
    const photoTab = $('avatar-photo-tab');
    if (emojiTab) emojiTab.classList.toggle('active', tab === 'emoji');
    if (photoTab) photoTab.classList.toggle('active', tab === 'photo');
}

export function previewAvatar(input) {
    if (!input.files || !input.files[0]) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const preview = $('avatar-preview');
        if (!preview) return;
        // Safe DOM: remove children and add img
        while (preview.firstChild) preview.removeChild(preview.firstChild);
        const img = document.createElement('img');
        img.src = e.target.result;
        img.alt = 'Avatar';
        preview.appendChild(img);
    };
    reader.readAsDataURL(input.files[0]);
}

export async function doSeedLogin() {
    const username = $('seed-username')?.value?.trim();
    const phrase = $('seed-phrase')?.value?.trim();
    if (!username || !phrase) {
        showAlert('auth-alert', 'Введите имя пользователя и seed-фразу', 'error');
        return;
    }
    const words = phrase.split(/\s+/);
    if (words.length !== 24) {
        showAlert('auth-alert', 'Seed-фраза должна содержать 24 слова', 'error');
        return;
    }
    try {
        const data = await api('POST', '/api/authentication/seed-login', {
            username, seed_phrase: phrase,
        });
        window.AppState.user = data;
        showAlert('auth-alert', 'Доступ восстановлен', 'success');
        if (typeof window.bootApp === 'function') window.bootApp();
    } catch (e) {
        showAlert('auth-alert', e.message, 'error');
    }
}

export function selectNetMode(mode) {
    window.AppState.networkMode = mode;
}

export async function doLogin() {
    try {
        const password = $('l-pass').value;
        const data = await api('POST', '/api/authentication/login', {
            phone_or_username: $('l-login').value.trim(),
            password:          password,
        });

        // 2FA: если сервер требует TOTP-код, показываем поле ввода
        if (data.requires_2fa) {
            window._2fa_user_id = data.user_id;
            window._2fa_password = password;
            // Убираем старый промпт если есть
            const old = document.getElementById('2fa-prompt');
            if (old) old.remove();
            const loginForm = $('login-form');
            const prompt = document.createElement('div');
            prompt.id = '2fa-prompt';
            prompt.className = 'form-group';
            prompt.innerHTML = `
                <label class="form-label">${t('auth.twoFACode')}</label>
                <input class="form-input" id="2fa-code" type="text" inputmode="numeric"
                       maxlength="6" placeholder="000000"
                       style="text-align:center;letter-spacing:8px;font-size:24px;">
                <button class="btn btn-primary" style="margin-top:8px;" onclick="verify2FA()">${t('app.confirm')}</button>
            `;
            loginForm.appendChild(prompt);
            $('2fa-code')?.focus();
            return;
        }

        window.AppState.user = data;
        await _tryLoadKey(password);

        // Мультиаккаунт: сохраняем в список аккаунтов
        _saveCurrentAccount();

        window.bootApp();
    } catch (e) {
        showAlert('auth-alert', e.message);
    }
}

export async function verify2FA() {
    try {
        const code = $('2fa-code')?.value?.trim();
        if (!code || code.length !== 6) {
            showAlert('auth-alert', t('auth.twoFAHint'));
            return;
        }
        const data = await api('POST', '/api/authentication/2fa/verify-login', {
            user_id: window._2fa_user_id,
            code: code,
        });
        window.AppState.user = data;
        const password = window._2fa_password;
        await _tryLoadKey(password);
        // Cleanup
        const prompt = document.getElementById('2fa-prompt');
        if (prompt) prompt.remove();
        delete window._2fa_user_id;
        delete window._2fa_password;

        // Мультиаккаунт: сохраняем в список аккаунтов
        _saveCurrentAccount();

        window.bootApp();
    } catch (e) {
        showAlert('auth-alert', e.message);
    }
}

// Проверяет режим регистрации при открытии формы
export async function checkRegistrationMode() {
    try {
        const data = await api('GET', '/api/authentication/registration-info');
        const inviteGroup = $('invite-code-group');
        const closedMsg   = $('reg-closed-msg');
        const regBtn      = $('register-btn');

        if (data.mode === 'closed') {
            if (inviteGroup) inviteGroup.style.display = 'none';
            if (closedMsg) closedMsg.style.display = '';
            if (regBtn) regBtn.style.display = 'none';
        } else if (data.mode === 'invite') {
            if (inviteGroup) inviteGroup.style.display = '';
            if (closedMsg) closedMsg.style.display = 'none';
            if (regBtn) regBtn.style.display = '';
        } else {
            if (inviteGroup) inviteGroup.style.display = 'none';
            if (closedMsg) closedMsg.style.display = 'none';
            if (regBtn) regBtn.style.display = '';
        }
    } catch (e) { console.debug('reg mode check failed:', e); }
}

export async function doRegister() {
    // Validate password confirmation
    const pwError = validatePasswords();
    if (pwError) {
        showAlert('auth-alert', pwError, 'error');
        return;
    }

    const btn = $('register-btn');
    if (btn) { btn.disabled = true; btn.textContent = '\u23f3 ' + t('auth.creating'); }

    try {
        const { publicKeyHex, privateKeyJwk } = await generateX25519Keypair();
        const password = $('r-pass').value;

        const regBody = {
            phone:             getFullPhone(),
            username:          $('r-username').value.trim(),
            password:          password,
            display_name:      $('r-display').value.trim(),
            avatar_emoji:      window.AppState.selectedEmoji,
            x25519_public_key: publicKeyHex,
        };
        const emailVal = $('r-email')?.value?.trim();
        if (emailVal) regBody.email = emailVal;
        const inviteVal = $('r-invite')?.value?.trim();
        if (inviteVal) regBody.invite_code = inviteVal;

        const data = await api('POST', '/api/authentication/register', regBody);

        // Пользователь создан в БД — теперь только post-processing (ошибки здесь не откатывают регистрацию)
        window.AppState.user = data;
        window.AppState.user.x25519_public_key = publicKeyHex;

        try {
            await savePrivateKey(privateKeyJwk, password);
            window.AppState.x25519PrivateKey = privateKeyJwk;
            console.info('X25519 keypair создан, приватный ключ зашифрован в localStorage');
        } catch (e) {
            console.warn('Не удалось сохранить приватный ключ:', e);
        }

        // Upload avatar photo if selected during registration
        const avatarFile = document.getElementById('avatar-file');
        if (avatarFile && avatarFile.files && avatarFile.files[0]) {
            try {
                const formData = new FormData();
                formData.append('file', avatarFile.files[0]);
                const resp = await fetch('/api/authentication/avatar', {
                    method: 'POST',
                    body: formData,
                    credentials: 'same-origin'
                });
                const avData = await resp.json();
                if (resp.ok && avData.avatar_url) {
                    window.AppState.user.avatar_url = avData.avatar_url;
                }
            } catch (e) {
                console.warn('Avatar upload failed:', e);
            }
        }

        // Мультиаккаунт: сохраняем в список аккаунтов
        _saveCurrentAccount();

        window.bootApp();
    } catch (e) {
        // Эта ветка срабатывает ТОЛЬКО если сам API /register вернул ошибку (пользователь НЕ создан)
        showAlert('auth-alert', e.message);
        if (btn) { btn.disabled = false; btn.textContent = t('auth.register'); }
    }
}

export async function doLogout() {
    try { await api('POST', '/api/authentication/logout'); } catch (e) { console.debug('logout error:', e); }
    stopMultiplexCover();
    window.AppState.user             = null;
    window.AppState.x25519PrivateKey = null;
    if (window.AppState.ws) { window.AppState.ws.onclose = null; window.AppState.ws.close(); window.AppState.ws = null; }
    if (window.AppState.notifWs) { window.AppState.notifWs.onclose = null; window.AppState.notifWs.close(); window.AppState.notifWs = null; }
    if (window.AppState.signalWs) { window.AppState.signalWs.onclose = null; window.AppState.signalWs.close(); window.AppState.signalWs = null; }
    $('app').style.display         = 'none';
    $('auth-screen').style.display = 'flex';
    $('auth-screen').className     = 'screen active';
}

export async function checkSession() {
    try {
        const data = await api('GET', '/api/authentication/me');
        window.AppState.user = data;
        // При восстановлении сессии пароль недоступен — пробуем незашифрованный ключ
        await _tryLoadKey(null);
        // Если есть зашифрованный ключ но нет незашифрованного —
        // ключ будет загружен при следующем логине с паролем.

        // Мультиаккаунт: обновляем данные в списке аккаунтов
        _saveCurrentAccount();

        window.bootApp();
    } catch {
        // не авторизован
    }
}

export function exportPrivateKey() {
    // Экспорт работает только для незашифрованного ключа или уже расшифрованного в памяти
    const key = window.AppState.x25519PrivateKey || localStorage.getItem('vortex_x25519_priv');
    if (!key) { alert(t('auth.keyNotFound')); return; }
    const blob = new Blob([key], { type: 'application/json' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = 'vortex_key_backup.json';
    a.click();
    URL.revokeObjectURL(url);
}

export async function importPrivateKey(file) {
    const text = await file.text();
    try {
        JSON.parse(text);
        // Сохраняем как незашифрованный — будет мигрирован при следующем логине
        localStorage.setItem('vortex_x25519_priv', text);
        window.AppState.x25519PrivateKey = text;
        alert(t('auth.keyImported'));
    } catch {
        alert(t('auth.keyInvalidFormat'));
    }
}

// ============================================================================
// QR LOGIN
// ============================================================================

let _qrPollTimer = null;
let _qrSessionId = null;
let _qrExpireTimer = null;

export async function initQRLogin() {
    clearQRPoll();
    if (_qrExpireTimer) { clearTimeout(_qrExpireTimer); _qrExpireTimer = null; }
    const svgEl = document.getElementById('qr-login-svg');
    const statusEl = document.getElementById('qr-login-status');
    if (svgEl) svgEl.innerHTML = '';
    if (statusEl) statusEl.textContent = t('auth.qrLoading');
    try {
        const resp = await fetch('/api/authentication/qr-init', { method: 'POST', credentials: 'include' });
        if (!resp.ok) throw new Error(t('auth.qrServerError'));
        const data = await resp.json();
        _qrSessionId = data.session_id;
        if (svgEl) {
            svgEl.innerHTML = data.qr_svg;
            // Масштабируем SVG под контейнер
            const svg = svgEl.querySelector('svg');
            if (svg) {
                if (!svg.getAttribute('viewBox')) {
                    const w = svg.getAttribute('width');
                    const h = svg.getAttribute('height');
                    if (w && h) svg.setAttribute('viewBox', `0 0 ${parseFloat(w)} ${parseFloat(h)}`);
                }
                svg.setAttribute('width', '100%');
                svg.setAttribute('height', '100%');
            }
        }
        if (statusEl) statusEl.textContent = t('auth.qrWaiting');
        _qrPollTimer = setInterval(_qrPoll, 1500);
        _qrExpireTimer = setTimeout(() => {
            clearQRPoll();
            if (statusEl) statusEl.textContent = t('auth.qrExpired');
            if (svgEl) svgEl.innerHTML = `<div style="padding:40px;color:#999;">${t('auth.qrExpiredShort')}</div>`;
        }, data.expires_in * 1000);
    } catch (e) {
        if (statusEl) statusEl.textContent = t('auth.qrError').replace('{error}', e.message);
    }
}

async function _qrPoll() {
    if (!_qrSessionId) return;
    try {
        const resp = await fetch('/api/authentication/qr-check/' + _qrSessionId, { credentials: 'include' });
        if (resp.status === 401 || resp.status === 404) {
            clearQRPoll();
            const statusEl = document.getElementById('qr-login-status');
            if (statusEl) statusEl.textContent = t('auth.qrSessionExpired');
            return;
        }
        const data = await resp.json();
        if (data.confirmed) {
            clearQRPoll();
            const statusEl = document.getElementById('qr-login-status');
            if (statusEl) statusEl.textContent = t('auth.qrSuccess');
            setTimeout(() => location.reload(), 800);
        }
    } catch (e) { console.debug('qr poll error:', e); }
}

export function clearQRPoll() {
    if (_qrPollTimer) { clearInterval(_qrPollTimer); _qrPollTimer = null; }
    if (_qrExpireTimer) { clearTimeout(_qrExpireTimer); _qrExpireTimer = null; }
}

export function refreshQR() { initQRLogin(); }

// ============================================================================
// PASSKEY (WebAuthn)
// ============================================================================

function _b64urlToBuffer(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
}

function _bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function doPasskeyLogin() {
    const statusEl = document.getElementById('passkey-status');
    const btn = document.getElementById('passkey-login-btn');
    function _status(msg, isError) {
        if (!statusEl) return;
        statusEl.style.display = 'block';
        statusEl.textContent = msg;
        statusEl.style.color = isError ? 'var(--red)' : 'var(--text2)';
    }

    if (!window.PublicKeyCredential) {
        _status('Ваш браузер не поддерживает Passkey / WebAuthn', true);
        return;
    }

    try {
        if (btn) btn.disabled = true;
        _status('Запрашиваем параметры...', false);

        const resp1 = await fetch('/api/authentication/passkey/login-options', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
        });
        if (!resp1.ok) throw new Error('Сервер вернул ' + resp1.status);
        const data1 = await resp1.json();
        const opts = data1.options;

        opts.challenge = _b64urlToBuffer(opts.challenge);
        if (opts.allowCredentials) {
            opts.allowCredentials = opts.allowCredentials.map(c => {
                c.id = _b64urlToBuffer(c.id);
                return c;
            });
        }

        _status('Подтвердите вход на устройстве...', false);

        const assertion = await navigator.credentials.get({ publicKey: opts });

        _status('Проверяем...', false);

        const credential = {
            id:    assertion.id,
            rawId: _bufferToB64url(assertion.rawId),
            type:  assertion.type,
            response: {
                authenticatorData: _bufferToB64url(assertion.response.authenticatorData),
                clientDataJSON:    _bufferToB64url(assertion.response.clientDataJSON),
                signature:         _bufferToB64url(assertion.response.signature),
                userHandle:        assertion.response.userHandle
                    ? _bufferToB64url(assertion.response.userHandle) : null,
            },
        };

        const resp2 = await fetch('/api/authentication/passkey/login-verify', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: data1.session_id, credential }),
        });
        if (!resp2.ok) {
            const err = await resp2.json().catch(() => ({}));
            throw new Error(err.detail || 'Ошибка верификации');
        }

        // Загружаем X25519 ключ из storage если есть (без пароля — passkey не предоставляет пароль)
        try {
            const rawKey = localStorage.getItem('vortex_x25519_priv');
            if (rawKey) {
                window.AppState.x25519PrivateKey = rawKey;
            }
        } catch (_) {}

        _status('Вход выполнен!', false);
        if (statusEl) statusEl.style.color = 'var(--green, #4caf50)';
        setTimeout(() => location.reload(), 800);

    } catch (e) {
        if (e.name === 'NotAllowedError') {
            _status('Отменено пользователем', true);
        } else {
            _status('Ошибка: ' + e.message, true);
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

export async function registerPasskey() {
    if (!window.PublicKeyCredential) {
        alert('Ваш браузер не поддерживает Passkey');
        return false;
    }
    try {
        const resp1 = await fetch('/api/authentication/passkey/register-options', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
        });
        if (!resp1.ok) throw new Error('Сервер вернул ' + resp1.status);
        const data1 = await resp1.json();
        const opts = data1.options;

        opts.challenge = _b64urlToBuffer(opts.challenge);
        opts.user.id = _b64urlToBuffer(opts.user.id);
        if (opts.excludeCredentials) {
            opts.excludeCredentials = opts.excludeCredentials.map(c => {
                c.id = _b64urlToBuffer(c.id);
                return c;
            });
        }

        const attestation = await navigator.credentials.create({ publicKey: opts });

        const credential = {
            id:    attestation.id,
            rawId: _bufferToB64url(attestation.rawId),
            type:  attestation.type,
            response: {
                attestationObject: _bufferToB64url(attestation.response.attestationObject),
                clientDataJSON:    _bufferToB64url(attestation.response.clientDataJSON),
            },
        };

        const resp2 = await fetch('/api/authentication/passkey/register-verify', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: data1.session_id, credential }),
        });
        if (!resp2.ok) {
            const err = await resp2.json().catch(() => ({}));
            throw new Error(err.detail || 'Ошибка верификации');
        }

        alert('Passkey успешно привязан!');
        return true;
    } catch (e) {
        if (e.name === 'NotAllowedError') return false;
        alert('Ошибка привязки Passkey: ' + e.message);
        return false;
    }
}

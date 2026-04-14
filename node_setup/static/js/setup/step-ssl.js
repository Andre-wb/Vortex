// node_setup/static/js/setup/step-ssl.js — шаг 3: выбор и генерация SSL

/**
 * Проверяет доступность mkcert из sysInfo и обновляет бейдж опции.
 */
function checkMkcert() {
    const avail = state.sysInfo?.ssl_methods?.mkcert;
    const opt   = document.getElementById('opt-mkcert');
    const badge = document.getElementById('mkcert-badge');
    if (avail) {
        badge.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:3px;"><path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg> Установлен';
        badge.className = 'ssl-badge badge-recommended';
    } else {
        opt.classList.add('unavailable');
        badge.textContent = 'Не установлен';
        badge.className   = 'ssl-badge badge-advanced';
    }
}

/**
 * Выбирает режим SSL (self, mkcert, le, skip) и обновляет интерфейс.
 * @param {string} mode
 */
function selectSSL(mode) {
    state.sslMode = mode;

    ['self', 'mkcert', 'le', 'skip'].forEach(m => {
        document.getElementById('opt-' + m)?.classList.remove('selected');
        document.getElementById('detail-' + m)?.classList.remove('active');
    });

    document.getElementById('opt-' + mode).classList.add('selected');
    document.getElementById('detail-' + mode).classList.add('active');

    document.getElementById('btn-ssl-gen').textContent =
        mode === 'skip' ? 'Пропустить SSL →' : 'Сгенерировать →';
}

/**
 * Генерирует SSL-сертификаты, вызывая соответствующий API-эндпоинт.
 * Отображает процесс в терминальном блоке.
 */
async function generateSSL() {
    const btn      = document.getElementById('btn-ssl-gen');
    const block    = document.getElementById('ssl-gen-block');
    const terminal = document.getElementById('ssl-terminal');

    btn.disabled  = true;
    btn.innerHTML = '<span class="spinner"></span> Генерация...';
    block.style.display = 'block';
    terminal.innerHTML  = '';

    const log = (text, cls = 'line-dim') => {
        terminal.innerHTML += `<div class="${cls}">${text}</div>`;
        terminal.scrollTop  = 99999;
    };

    try {
        switch (state.sslMode) {

            case 'skip': {
                log('⚡ SSL пропущен. Узел будет работать по HTTP.', 'line-warn');
                state.sslDone    = true;
                state.sslSkipped = true;
                _setStep(4);
                break;
            }

            case 'self': {
                log('⚡ Генерация CA и серверного сертификата...', 'line-info');
                const installCa = document.getElementById('install-ca').checked;
                const pwdEl = document.getElementById('admin-password');
                const adminPwd = (pwdEl && pwdEl.value) || '';

                // Валидация: если хочет установить CA — пароль обязателен
                if (installCa && !adminPwd) {
                    showAlert('s3', 'Введите пароль администратора для установки CA', 'error');
                    btn.disabled = false;
                    btn.textContent = 'Сгенерировать →';
                    return;
                }

                const body = {
                    org_name:       document.getElementById('ssl-org').value || 'Vortex Node',
                    install_ca:     installCa,
                    admin_password: adminPwd,
                };

                const r = await fetch('/api/ssl/self-signed', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                const d = await r.json();
                if (!r.ok) throw new Error(d.detail || d.message);

                // Очищаем пароль из памяти
                if (pwdEl) pwdEl.value = '';

                log(`✓ CA:   ${d.ca}`,   'line-ok');
                log(`✓ CERT: ${d.cert}`, 'line-ok');
                log(`✓ KEY:  ${d.key}`,  'line-ok');
                log(d.trusted
                        ? '✓ CA установлен в системное хранилище — перезапустите браузер'
                        : '✓ Сертификат создан (CA не устанавливался)',
                    d.trusted ? 'line-ok' : 'line-info');

                state.caCmd   = '';
                state.sslDone = true;
                _setStep(4);
                break;
            }

            case 'mkcert': {
                log('⚡ Запуск mkcert...', 'line-info');
                const r = await fetch('/api/ssl/mkcert', { method: 'POST' });
                const d = await r.json();
                if (!r.ok) throw new Error(d.detail || d.message);
                log(`✓ ${d.message}`, 'line-ok');
                state.sslDone = true;
                _setStep(4);
                break;
            }

            case 'le': {
                const domain  = document.getElementById('le-domain').value.trim();
                const email   = document.getElementById('le-email').value.trim();
                const staging = document.getElementById('le-staging').checked;
                if (!domain) { showAlert('s3', 'Введите домен', 'error'); return; }
                if (!email)  { showAlert('s3', 'Введите email', 'error'); return; }

                log(`⚡ certbot: получение сертификата для ${domain}...`, 'line-info');
                const r = await fetch('/api/ssl/letsencrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain, email, staging }),
                });
                const d = await r.json();
                if (!r.ok) throw new Error(d.detail || d.message);
                log(`✓ ${d.message}`, 'line-ok');
                state.sslDone = true;
                _setStep(4);
                break;
            }
        }

    } catch (e) {
        log(`✗ Ошибка: ${e.message}`, 'line-err');
        showAlert('s3', e.message, 'error');

    } finally {
        btn.disabled    = false;
        btn.textContent = state.sslMode === 'skip' ? 'Пропустить SSL →' : 'Сгенерировать →';
    }
}

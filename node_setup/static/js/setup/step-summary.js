// node_setup/static/js/setup/step-summary.js — шаг 5: сводка + шаг 6: запуск узла

/**
 * Строит сводную информацию для шага 5: отображает введённые данные,
 * URL узла, статус SSL, SSO, режим сети и регистрации.
 */
async function buildSummary() {
    const cfg   = state.config;
    const proto = state.sslSkipped ? 'http' : 'https';
    const ssl   = state.sslSkipped
        ? '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:3px;"><path d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg> HTTP (без SSL)'
        : '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" fill="currentColor" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:3px;"><path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg> HTTPS';
    const modes    = { self: 'Самоподписанный', mkcert: 'mkcert', le: "Let's Encrypt", skip: 'Отключён' };
    const netModes = { local: 'Локальный', global: 'Глобальный' };
    const regModes = { open: 'Открытая', invite: 'По инвайт-коду', closed: 'Закрытая' };
    const ip       = state.sysInfo?.local_ips?.[0] || '—';

    state.nodeUrl = `${proto}://localhost:${cfg.port}`;

    const passkeys   = document.getElementById('passkeys-toggle')?.checked ?? true;
    const ssoSummary = _ssoProviders.length
        ? _ssoProviders.map(p => `${_SSO_ICONS[p.type] || '🔐'} ${_SSO_LABELS[p.type] || p.type}`).join(', ')
        : 'Не настроены';

    document.getElementById('summary-list').innerHTML = `
    <li>
      <span class="label">Имя устройства</span>
      <span class="value">${esc(cfg.device_name)}</span>
    </li>
    <li>
      <span class="label">Адрес</span>
      <span class="value" style="color:var(--teal)">${state.nodeUrl}</span>
    </li>
    <li>
      <span class="label">Локальный IP</span>
      <span class="value">${ip}:${cfg.port}</span>
    </li>
    <li>
      <span class="label">Режим сети</span>
      <span class="value">${netModes[_networkMode] || _networkMode}</span>
    </li>
    <li>
      <span class="label">Регистрация</span>
      <span class="value">${regModes[_regMode] || _regMode}</span>
    </li>
    <li>
      <span class="label">SSL</span>
      <span class="value" style="color:${state.sslSkipped ? 'var(--yellow)' : 'var(--green)'}">
        ${ssl} (${modes[state.sslMode]})
      </span>
    </li>
    <li>
      <span class="label">Passkeys</span>
      <span class="value" style="color:${passkeys ? 'var(--green)' : 'var(--text3)'}">
        ${passkeys ? '✓ Включены' : '✗ Отключены'}
      </span>
    </li>
    <li>
      <span class="label">SSO провайдеры</span>
      <span class="value">${ssoSummary}</span>
    </li>
    <li>
      <span class="label">P2P UDP порт</span>
      <span class="value">${cfg.udp_port}</span>
    </li>
    <li>
      <span class="label">Макс. файл</span>
      <span class="value">${cfg.max_file_mb} МБ</span>
    </li>
  `;

    if (state.caCmd) {
        document.getElementById('ca-install-block').style.display = 'block';
        document.getElementById('ca-cmd-text').textContent = state.caCmd;
    }
}

// ── Шаг 6: Запуск узла ───────────────────────────────────────────────────────

/**
 * Отправляет конфигурацию на сервер, завершает настройку и переходит к шагу 6.
 */
async function launchNode() {
    const btn = document.getElementById('btn-launch');
    btn.disabled  = true;
    btn.innerHTML = '<span class="spinner"></span> Сохранение...';

    try {
        const configBody = Object.assign({}, state.config, {
            network_mode:      _networkMode,
            registration_mode: _regMode,
            invite_code:       _inviteCode,
        });

        const r1 = await fetch('/api/config/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(configBody),
        });
        if (!r1.ok) throw new Error((await r1.json()).detail || 'Ошибка сохранения конфига');

        const r2 = await fetch('/api/setup/complete', { method: 'POST' });
        const d2 = await r2.json();
        if (!r2.ok) throw new Error(d2.detail || 'Ошибка');

        document.getElementById('node-url').textContent = state.nodeUrl;

        if (state.caCmd) {
            document.getElementById('ca-warn-block').style.display = 'block';
            document.getElementById('ca-final').textContent = state.caCmd;
        }

        _setStep(6);
        startRedirectCountdown();

    } catch (e) {
        showAlert('s4', e.message, 'error');
        btn.disabled    = false;
        btn.textContent = '⚡ Запустить узел';
    }
}

/**
 * Запускает обратный отсчёт 5 секунд и перенаправляет на главную страницу узла.
 */
function startRedirectCountdown() {
    let secs  = 5;
    const bar  = document.getElementById('redirect-bar');
    const text = document.getElementById('redirect-text');
    const tick = setInterval(() => {
        secs--;
        bar.style.width  = ((5 - secs) / 5 * 100) + '%';
        text.textContent = `Переход через ${secs} секунд...`;
        if (secs <= 0) {
            clearInterval(tick);
            if (state.nodeUrl) window.location.href = state.nodeUrl;
        }
    }, 1000);
}

/**
 * Открывает URL узла в новой вкладке.
 */
function openNodeUrl() {
    if (state.nodeUrl) window.open(state.nodeUrl, '_blank');
}

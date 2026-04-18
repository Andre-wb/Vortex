// ── Run / Debug ───────────────────────────────────────────────

// Runs compiler synchronously and returns {errors, warns, hints, info}
function _compileSync(code) {
    // Reset diag storage so _gxCompile fills it fresh
    IDE._diagFull  = [];
    IDE._diagLines = {};
    // Run compiler (it updates IDE._diagFull as side-effect)
    _gxCompile(code);
    const diag = IDE._diagFull || [];
    return {
        errors: diag.filter(d => d.sev === 'error'),
        warns:  diag.filter(d => d.sev === 'warn'),
        hints:  diag.filter(d => d.sev === 'hint'),
    };
}

function ideRun() {
    ideAutosave();
    const code = IDE.current?.files[IDE.activeFile] || '';
    const file = IDE.activeFile || 'code';
    const isArx = file.endsWith('.arx');

    ideConsoleTab('output', null);
    document.getElementById('ide-console-output').textContent = '';
    ideLog('output', `▶ Compiling ${file}…`, 'muted');

    // For .arx files, run Architex analysis and show preview
    if (isArx) {
        _arxRunAnalysis(code, file);
        // Автоматически показываем превью при запуске .arx
        if (!IDE.previewVisible) ideShowPreview();
        else ideUpdatePreview(code, file);
        return;
    }

    const { errors, warns, hints } = _compileSync(code);

    if (errors.length > 0) {
        ideLog('output', `✕ Compilation failed — ${errors.length} error${errors.length > 1 ? 's' : ''}`, 'error');
        errors.forEach(e => ideLog('output', `  [${e.line}:${e.col}] ${e.msg}`, 'error'));
        ideLog('output', '→ Fix errors before running. See Problems tab.', 'muted');
        // Flash indicators
        ideOpenProblems();
        return;
    }

    if (warns.length > 0) {
        ideLog('output', `⚠ ${warns.length} warning${warns.length > 1 ? 's' : ''} (running anyway)`, 'warn');
        warns.forEach(w => ideLog('output', `  [${w.line}:${w.col}] ${w.msg}`, 'warn'));
    }

    ideLog('output', '✓ Compiled OK', 'success');
    ideLog('output', '', 'muted');

    // Analyse AST-level facts from the clean token stream
    const tokens = _gxLex(code);
    const handlers = [], flows = [], fns = [], states = [], emits = [], everys = [];
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i], nx = tokens[i+1] || {}, nx2 = tokens[i+2] || {};
        if (t.kind === 'kw' && t.val === 'on') {
            const pat = nx.val || '?';
            handlers.push(pat);
        }
        if (t.kind === 'kw' && t.val === 'fn'  && nx.kind === 'id') fns.push(nx.val);
        if (t.kind === 'kw' && t.val === 'flow' && nx.kind === 'id') flows.push(nx.val);
        if (t.kind === 'kw' && t.val === 'state' && nx.kind === 'id') states.push(nx.val);
        if (t.kind === 'kw' && t.val === 'emit') emits.push(i);
        if (t.kind === 'kw' && t.val === 'every') everys.push(nx.val || '?');
    }

    const uniqH = [...new Set(handlers)];
    if (uniqH.length === 0) {
        ideLog('output', '⚠  No handlers found — add  on /start { emit "Hello!" }', 'warn');
    } else {
        ideLog('output', `Handlers registered (${uniqH.length}):`, 'bold');
        uniqH.forEach(h => ideLog('output', `  on ${h}`, 'success'));
    }
    if (fns.length)    ideLog('output', `Functions:  ${fns.join(', ')}`, 'info');
    if (flows.length)  ideLog('output', `Flows:      ${flows.join(', ')}`, 'info');
    if (states.length) ideLog('output', `State vars: ${states.join(', ')}`, 'info');
    if (everys.length) ideLog('output', `Schedulers: every ${everys.join(', every ')}`, 'info');
    ideLog('output', `Emit calls: ${emits.length}`, 'info');
    if (hints.length)  ideLog('output', `Hints:      ${hints.length} (see Problems tab)`, 'muted');
    ideLog('output', '', 'muted');
    ideLog('output', uniqH.length > 0
        ? `✅ Bot ready — ${uniqH.length} handler(s). Test it in the Simulator →`
        : '⚠  Add at least one handler to use the Simulator.', uniqH.length > 0 ? 'success' : 'warn');
}

function _arxRunAnalysis(code, file) {
    // Parse Architex structure
    const lines = code.split('\n');
    const screens = [], components = [], reactiveVars = [], sendCalls = [], navCalls = [];
    let widgets = 0;

    for (const line of lines) {
        const t = line.trim();
        const screenMatch = t.match(/^@screen\s+(\w+)/);
        if (screenMatch) screens.push(screenMatch[1]);
        const compMatch = t.match(/^@component\s+(\w+)/);
        if (compMatch) components.push(compMatch[1]);
        const rxMatch = t.match(/^\s*~(\w+)\s*(?::.*?)?\s*=/);
        if (rxMatch) reactiveVars.push(rxMatch[1]);
        if (/\bsend\s*\(/.test(t)) sendCalls.push(t);
        if (/\bnavigate\s*\(/.test(t)) navCalls.push(t);
        if (/^\s*(col|row|header|text|button|input|label|image|icon|divider|list|card|badge|toast|tabs|tab|video|audio|table)\b/.test(t)) widgets++;
    }

    // Run linter
    IDE._diagFull = [];
    IDE._diagLines = {};
    _arxLint(code);
    const diag = IDE._diagFull || [];
    const errors = diag.filter(d => d.sev === 'error');
    const warns  = diag.filter(d => d.sev === 'warn');

    if (errors.length > 0) {
        ideLog('output', `✕ ${errors.length} error(s) in ${file}`, 'error');
        errors.forEach(e => ideLog('output', `  [${e.line}:${e.col}] ${e.msg}`, 'error'));
        ideOpenProblems();
        return;
    }

    if (warns.length > 0) {
        ideLog('output', `⚠ ${warns.length} warning(s)`, 'warn');
    }

    ideLog('output', '✓ Architex parsed OK', 'success');
    ideLog('output', '', 'muted');

    if (screens.length) {
        ideLog('output', `Screens (${screens.length}):`, 'bold');
        screens.forEach(s => ideLog('output', `  @screen ${s}`, 'success'));
    }
    if (components.length) {
        ideLog('output', `Components: ${components.join(', ')}`, 'info');
    }
    if (reactiveVars.length) {
        ideLog('output', `Reactive vars: ~${reactiveVars.join(', ~')}`, 'info');
    }
    ideLog('output', `Widgets:    ${widgets}`, 'info');

    if (sendCalls.length) {
        ideLog('output', `send() calls: ${sendCalls.length} (→ Gravitix bot)`, 'info');
    }
    if (navCalls.length) {
        ideLog('output', `navigate():   ${navCalls.length}`, 'info');
    }
    ideLog('output', '', 'muted');

    // Check bridge
    const gravFiles = Object.keys(IDE.current?.files || {}).filter(f => f.endsWith('.grav'));
    if (sendCalls.length > 0 && gravFiles.length > 0) {
        ideLog('output', `🔗 Bridge: ${sendCalls.length} send() → ${gravFiles.join(', ')}`, 'success');
    } else if (sendCalls.length > 0) {
        ideLog('output', '⚠ send() calls found but no .grav file in project — add a bot.grav to handle them', 'warn');
    }

    ideLog('output', screens.length > 0
        ? `✅ Mini App ready — ${screens.length} screen(s), ${widgets} widget(s)`
        : '⚠ No @screen defined — add @screen Main to start', screens.length > 0 ? 'success' : 'warn');
}

function ideDebug() {
    ideAutosave();
    const code = IDE.current?.files[IDE.activeFile] || '';
    const file = IDE.activeFile || 'code';
    const isArx = file.endsWith('.arx');

    ideConsoleTab('debug', null);
    document.getElementById('ide-console-debug').textContent = '';
    ideLog('debug', `🔍 Debug compile: ${file}`, 'bold');

    if (isArx) {
        IDE._diagFull = []; IDE._diagLines = {};
        _arxLint(code);
    }
    const { errors, warns, hints } = isArx
        ? { errors: (IDE._diagFull||[]).filter(d=>d.sev==='error'), warns: (IDE._diagFull||[]).filter(d=>d.sev==='warn'), hints: (IDE._diagFull||[]).filter(d=>d.sev==='hint') }
        : _compileSync(code);
    const lines = code.split('\n');
    const nonEmpty = lines.filter(l => l.trim() && !l.trim().startsWith('//')).length;

    ideLog('debug', `  Lines total:     ${lines.length}`, 'info');
    ideLog('debug', `  Lines with code: ${nonEmpty}`, 'info');
    ideLog('debug', `  Tokens:          ${_gxLex(code).length - 1}`, 'info');  // -1 for EOF
    ideLog('debug', '', 'muted');

    if (errors.length) {
        ideLog('debug', `✕ ${errors.length} compile error(s):`, 'error');
        errors.forEach(e => ideLog('debug', `  line ${e.line}, col ${e.col}: ${e.msg}`, 'error'));
    } else {
        ideLog('debug', '✓ No compile errors', 'success');
    }

    if (warns.length) {
        ideLog('debug', `⚠  ${warns.length} warning(s):`, 'warn');
        warns.forEach(w => ideLog('debug', `  line ${w.line}, col ${w.col}: ${w.msg}`, 'warn'));
    }

    if (hints.length) {
        ideLog('debug', `△  ${hints.length} hint(s):`, 'muted');
        hints.forEach(h => ideLog('debug', `  line ${h.line}: ${h.msg}`, 'muted'));
    }

    // Scope walk: count declarations
    const tokens = _gxLex(code);
    let lets = 0, ons = 0, fns = 0, matchArms = 0, waits = 0;
    tokens.forEach((t, i) => {
        if (t.kind !== 'kw') return;
        if (t.val === 'let')   lets++;
        if (t.val === 'on')    ons++;
        if (t.val === 'fn')    fns++;
        if (t.val === 'wait')  waits++;
        if (tokens[i+1]?.kind === 'op' && tokens[i+1]?.val === '=>') matchArms++;
    });

    ideLog('debug', '', 'muted');
    ideLog('debug', 'Declarations:', 'bold');
    ideLog('debug', `  let:        ${lets}`, 'info');
    ideLog('debug', `  on handler: ${ons}`, 'info');
    ideLog('debug', `  fn:         ${fns}`, 'info');
    ideLog('debug', `  match arms: ${matchArms}`, 'info');
    ideLog('debug', `  wait:       ${waits}`, 'info');

    if (errors.length === 0) {
        ideLog('debug', '', 'muted');
        ideLog('debug', '✅ Debug complete — no blocking errors', 'success');
    } else {
        ideLog('debug', '', 'muted');
        ideLog('debug', `✕ Debug complete — fix ${errors.length} error(s) first`, 'error');
    }
}

// ── Publish / Deploy ──────────────────────────────────────────
let _statusPoll = null;

function _ideProjectId() {
    // Use numeric id, convert to safe string
    return String(IDE.current?.id || 'proj').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function _ideToken() {
    return IDE.current?.token || '';
}

function _ideAllCode() {
    // Concatenate all .grav files in project into one compilation unit
    // (.arx files are handled by the Architex runtime separately)
    if (!IDE.current) return '';
    return Object.entries(IDE.current.files)
        .filter(([name]) => name.endsWith('.grav'))
        .map(([name, code]) => `// ── ${name} ──\n${code}`)
        .join('\n\n');
}

async function idePublish() {
    ideAutosave();
    if (!IDE.current) return;

    const token = _ideToken();
    if (!token) {
        alert((typeof t==='function'?t('ide.noBotTokenAlert'):'This project has no Bot Token set.\nEdit the project and add your Telegram bot token first.'));
        return;
    }

    const code = _ideAllCode();
    const pid  = _ideProjectId();

    ideConsoleTab('output', null);
    document.getElementById('ide-console-output').innerHTML = '';
    ideLog('output', '⬆  Compiling & publishing…', 'muted');
    _setPublishState('loading');

    // Step 1: compile via server
    let compRes;
    try {
        const r = await fetch('/api/ide/compile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken() },
            body: JSON.stringify({ project_id: pid, code }),
        });
        compRes = await r.json();
    } catch(e) {
        ideLog('output', `✕ Network error: ${e.message}`, 'error');
        _setPublishState('stopped'); return;
    }

    if (!compRes.ok) {
        const errs = compRes.errors || [];
        ideLog('output', `✕ Compilation failed — ${errs.length} error(s):`, 'error');
        errs.forEach(e =>
            ideLog('output', `  ${e.line ? `[line ${e.line}] ` : ''}${e.msg || e}`, 'error'));
        ideLog('output', '→ Fix errors before publishing.', 'muted');
        _setPublishState('stopped');
        ideOpenProblems();
        return;
    }

    ideLog('output', '✓ Compiled OK', 'success');
    ideLog('output', '⬆  Deploying bot to server…', 'muted');

    // Step 2: publish
    let pubRes;
    try {
        const r = await fetch('/api/ide/publish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken() },
            body: JSON.stringify({ project_id: pid, code, token }),
        });
        pubRes = await r.json();
    } catch(e) {
        ideLog('output', `✕ Deploy error: ${e.message}`, 'error');
        _setPublishState('stopped'); return;
    }

    if (!pubRes.ok) {
        ideLog('output', `✕ Deploy failed: ${pubRes.error || pubRes.detail || 'unknown'}`, 'error');
        _setPublishState('stopped'); return;
    }

    ideLog('output', `✅ Bot published! PID ${pubRes.pid} — running on server`, 'success');
    ideLog('output', '   Bot is now live. Logs will appear below.', 'muted');
    _setPublishState('running');
    _startStatusPoll();
    _startLogStream();
}

async function ideStopBot() {
    if (!IDE.current) return;
    const pid = _ideProjectId();
    _setPublishState('loading');
    try {
        await fetch(`/api/ide/stop/${pid}`, {
            method: 'POST',
            headers: { 'X-CSRF-Token': _csrfToken() },
        });
    } catch(_) {}
    ideLog('output', '■ Bot stopped', 'warn');
    _setPublishState('stopped');
    _stopStatusPoll();
}

function _setPublishState(state) {
    // state: 'stopped' | 'running' | 'loading' | 'crashed'
    const dot   = document.getElementById('ide-bot-dot');
    const label = document.getElementById('ide-bot-status-label');
    const pub   = document.getElementById('ide-btn-publish');
    const stop  = document.getElementById('ide-btn-stop');
    if (!dot) return;

    dot.className = 'ide-bot-dot ide-bot-dot-' + state;
    label.textContent = { stopped:'offline', running:'live', loading:'deploying…', crashed:'crashed' }[state] || state;
    if (pub)  pub.style.display  = state === 'running' ? 'none' : '';
    if (stop) stop.style.display = state === 'running' ? ''     : 'none';
}

function _startStatusPoll() {
    _stopStatusPoll();
    const pid = _ideProjectId();
    _statusPoll = setInterval(async () => {
        try {
            const r = await fetch(`/api/ide/status/${pid}`);
            const s = await r.json();
            if (s.status === 'running') {
                document.getElementById('ide-bot-status-label').textContent =
                    `live ${_fmtUptime(s.uptime)}`;
            } else {
                _setPublishState(s.status === 'crashed' ? 'crashed' : 'stopped');
                _stopStatusPoll();
            }
        } catch(_) {}
    }, 5000);
}

function _stopStatusPoll() {
    if (_statusPoll) { clearInterval(_statusPoll); _statusPoll = null; }
}

async function _startLogStream() {
    const pid = _ideProjectId();
    let lastLen = 0;
    const poll = setInterval(async () => {
        if (!_statusPoll) { clearInterval(poll); return; }
        try {
            const r = await fetch(`/api/ide/logs/${pid}?n=100`);
            const d = await r.json();
            const lines = d.logs || [];
            if (lines.length > lastLen) {
                lines.slice(lastLen).forEach(l => ideLog('output', `  ${l}`, 'muted'));
                lastLen = lines.length;
            }
        } catch(_) {}
    }, 3000);
}

function _fmtUptime(s) {
    if (!s) return '';
    if (s < 60)   return `${s}s`;
    if (s < 3600) return `${Math.floor(s/60)}m`;
    return `${Math.floor(s/3600)}h`;
}

function _csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

// ── Console ───────────────────────────────────────────────────
function ideLog(pane, msg, type='info') {
    const el = document.getElementById(`ide-console-${pane}`);
    if (!el) return;
    const line = document.createElement('div');
    line.className = `ide-log ide-log-${type}`;
    line.textContent = msg;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

function ideOpenProblems() {
    // Expand console if collapsed
    const console_ = document.getElementById('ide-console');
    if (console_) console_.classList.remove('collapsed');
    ideConsoleTab('problems', null);
    // Scroll problems into view
    const pane = document.getElementById('ide-console-problems');
    if (pane) pane.scrollTop = 0;
}

function ideConsoleTab(name, btn) {
    IDE.consoleTab = name;
    ['output','debug','problems'].forEach(t => {
        const el = document.getElementById(`ide-console-${t}`);
        if (el) el.style.display = t === name ? 'flex' : 'none';
    });
    document.querySelectorAll('.ide-console-tab').forEach(b => b.classList.remove('active'));
    const tabs = document.querySelectorAll('.ide-console-tab');
    const map  = { output: 0, debug: 1, problems: 2 };
    if (tabs[map[name]]) tabs[map[name]].classList.add('active');
}

function ideClearConsole() {
    const el = document.getElementById(`ide-console-${IDE.consoleTab}`);
    if (el) el.innerHTML = '';
}

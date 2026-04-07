// ── Bot Simulator (unique feature) ───────────────────────────
function ideToggleSim() {
    IDE.simVisible = !IDE.simVisible;
    const sim = document.getElementById('ide-simulator');
    const btn = document.getElementById('ide-sim-toggle');
    if (sim) sim.style.display = IDE.simVisible ? 'flex' : 'none';
    if (btn) btn.classList.toggle('active', IDE.simVisible);
}

function ideSimSend() {
    const input = document.getElementById('ide-sim-input');
    if (!input) return;
    const text = input.value.trim();
    if (!text) return;
    input.value = '';

    _simAddMsg(text, 'user');

    const code = IDE.current?.files[IDE.activeFile] || '';
    const responses = _simulateBot(text, code);

    if (responses.length === 0) {
        setTimeout(() => _simAddMsg('…no response (no matching handler)', 'bot-empty'), 300);
    } else {
        responses.forEach((r, i) => setTimeout(() => _simAddMsg(r, 'bot'), 300 + i * 200));
    }
}

function ideSimClear() {
    const msgs = document.getElementById('ide-sim-messages');
    if (msgs) msgs.innerHTML = '<div class="ide-sim-hint">Write Gravitix code and test your bot here in real-time.</div>';
}

function ideSimRefresh() { /* responses update on next send */ }

function _simAddMsg(text, type) {
    const msgs = document.getElementById('ide-sim-messages');
    if (!msgs) return;
    const hint = msgs.querySelector('.ide-sim-hint');
    if (hint) hint.remove();
    const div = document.createElement('div');
    div.className = `ide-sim-msg ide-sim-msg-${type}`;
    div.textContent = text;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

function _simulateBot(userText, code) {
    const results = [];

    // Match command handlers:  on /cmd { ... }
    const cmdMatch = userText.match(/^\/([a-z_][a-z0-9_]*)/);
    if (cmdMatch) {
        const cmd = cmdMatch[1];
        const re  = new RegExp(`on\\s+\\/${cmd}\\b(?:\\s+guard[^{]*)?\\s*\\{([\\s\\S]*?)\\}`, 'g');
        let m;
        while ((m = re.exec(code)) !== null) {
            _extractEmits(m[1]).forEach(e => results.push(_interpolate(e, userText)));
        }
    }

    // Match on msg handlers with match blocks
    if (results.length === 0) {
        const msgRe = /on\s+msg\s*\{([\s\S]*?)\}/g;
        let m2;
        while ((m2 = msgRe.exec(code)) !== null) {
            const body = m2[1];
            // Look for match arms:  /regex/ => emit "..."  or  "str" => emit "..."
            const armRe = /(?:\/([^\/]+)\/([gimsuy]*)|"([^"]+)")\s*=>\s*\{?([^}]*)\}?/g;
            let arm;
            while ((arm = armRe.exec(body)) !== null) {
                const [, pattern, flags, literal, armBody] = arm;
                let matched = false;
                if (pattern) {
                    try { matched = new RegExp(pattern, flags).test(userText); } catch {}
                } else if (literal) {
                    matched = userText.toLowerCase().includes(literal.toLowerCase());
                }
                if (matched) {
                    _extractEmits(armBody).forEach(e => results.push(_interpolate(e, userText)));
                    break;
                }
            }
            // Wildcard _ => emit
            if (results.length === 0) {
                const wildRe = /_\s*=>\s*emit\s+"([^"]+)"/;
                const wm = wildRe.exec(body);
                if (wm) results.push(_interpolate(wm[1], userText));
            }
        }
    }

    // Top-level emits (simple scripts)
    if (results.length === 0 && /^\s*emit\s+"([^"]+)"/.test(code)) {
        const m = code.match(/emit\s+"([^"]+)"/);
        if (m) results.push(m[1]);
    }

    return results;
}

function _extractEmits(code) {
    const res = [];
    const re  = /\bemit\s+"((?:[^"\\]|\\.)*)"/g;
    let m;
    while ((m = re.exec(code)) !== null) res.push(m[1]);
    return res;
}

function _interpolate(template, userText) {
    return template
        .replace(/\{ctx\.first_name\}/g, 'User')
        .replace(/\{ctx\.user_id\}/g,    '12345')
        .replace(/\{ctx\.name\}/g,       'User')
        .replace(/\{ctx\.text\}/g,       userText)
        .replace(/\{[^}]+\}/g,           '…');
}

function _parseHandlers(code) {
    const res = [];
    const re  = /\bon\s+(\/[a-z_]+|msg|photo|video|voice|document|sticker|any)\b/g;
    let m;
    while ((m = re.exec(code)) !== null) res.push(m[1]);
    return [...new Set(res)];
}

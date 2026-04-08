// ── Syntax highlighting ───────────────────────────────────────
function ideUpdateHighlight() {
    const ta = document.getElementById('ide-textarea');
    const hl = document.getElementById('ide-highlight');
    if (!ta || !hl) return;
    const isArx = IDE.activeFile && IDE.activeFile.endsWith('.arx');
    // Uses same escaped highlighting pipeline as _highlightGravitix
    const highlighted = isArx ? _highlightArchitex(ta.value) : _highlightGravitix(ta.value);
    hl.textContent = '';
    hl.insertAdjacentHTML('beforeend', highlighted + '\n');
}

// ── Syntax highlight (line-segment aware) ─────────────────────
function _highlightGravitix(code) {
    const diagFull = IDE._diagFull || [];

    // Build per-line mark ranges: Map<lineNum, [{c0, c1, sev}]>
    const lineMarks = new Map();
    diagFull.forEach(d => {
        if (!d.line || !d.col) return;
        if (!lineMarks.has(d.line)) lineMarks.set(d.line, []);
        lineMarks.get(d.line).push({
            c0:  (d.col || 1) - 1,
            c1:  (d.col || 1) - 1 + (d.len || 1),
            sev: d.sev,
        });
    });

    const lines = code.split('\n');
    return lines.map((line, idx) => {
        const marks = lineMarks.get(idx + 1);
        if (!marks || !marks.length) return _hlSegment(line);

        marks.sort((a, b) => a.c0 - b.c0);
        let out = '', pos = 0;
        for (const { c0, c1, sev } of marks) {
            const s = Math.max(pos, 0);
            const e = Math.min(c1, line.length);
            if (c0 > s) out += _hlSegment(line.slice(s, c0));
            if (c0 < line.length) {
                const cls = sev === 'error' ? 'gx-err-tok'
                          : sev === 'warn'  ? 'gx-warn-tok' : 'gx-hint-tok';
                out += `<span class="${cls}">${_hlSegment(line.slice(c0, e))}</span>`;
            }
            pos = e;
        }
        if (pos < line.length) out += _hlSegment(line.slice(pos));
        return out;
    }).join('\n');
}

// Highlight a single text fragment (no multi-line constructs assumed)
function _hlSegment(text) {
    if (!text) return '';
    let h = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const stash = [];
    const ph = s => { const i = stash.length; stash.push(s); return `\x00_${i}_\x00`; };

    h = h.replace(/\/\*[\s\S]*?\*\//g, m => ph(`<span class="gx-comment">${m}</span>`));
    h = h.replace(/(\/\/[^\n]*)/g,     m => ph(`<span class="gx-comment">${m}</span>`));
    h = h.replace(/"((?:[^"\\]|\\.)*)"/g, (_, s) => {
        const inner = s.replace(/\{([^}]+)\}/g, '<span class="gx-interp">{$1}</span>');
        return ph(`<span class="gx-string">"${inner}"</span>`);
    });
    h = h.replace(/\/((?:[^\/\\\n]|\\.)+)\/([gimsuy]*)/g, m => ph(`<span class="gx-regex">${m}</span>`));
    h = h.replace(/\/([a-z_][a-z0-9_]*)/g, m => ph(`<span class="gx-command">${m}</span>`));

    const kw = 'let|fn|on|flow|state|emit|wait|every|at|guard|match|if|else|elif|return|for|in|while|break|continue|run|true|false|null|env|defer|paginate|with|lang|webhook|http|ui_set|ui_navigate';
    h = h.replace(new RegExp(`\\b(${kw})\\b`, 'g'), '<span class="gx-kw">$1</span>');
    h = h.replace(/\b(int|float|bool|str|list|map|void)\b/g, '<span class="gx-type">$1</span>');
    h = h.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="gx-num">$1</span>');
    h = h.replace(/(\|>|->|=>)/g, '<span class="gx-arrow">$1</span>');
    h = h.replace(/\b(ctx|state)\b/g, '<span class="gx-ctx">$1</span>');
    h = h.replace(/\x00_(\d+)_\x00/g, (_, i) => stash[+i]);
    return h;
}

// ── Architex syntax highlight ─────────────────────────────────
function _highlightArchitex(code) {
    const lines = code.split('\n');
    return lines.map(line => _hlArxSegment(line)).join('\n');
}

function _hlArxSegment(text) {
    if (!text) return '';
    let h = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const stash = [];
    const ph = s => { const i = stash.length; stash.push(s); return `\x00_${i}_\x00`; };

    // Comments
    h = h.replace(/(\/\/[^\n]*)/g, m => ph(`<span class="gx-comment">${m}</span>`));
    // Strings
    h = h.replace(/"((?:[^"\\]|\\.)*)"/g, (m, s) => {
        const inner = s.replace(/\{([^}]+)\}/g, '<span class="gx-interp">{$1}</span>');
        return ph(`<span class="gx-string">"${inner}"</span>`);
    });
    h = h.replace(/'((?:[^'\\]|\\.)*)'/g, m => ph(`<span class="gx-string">${m}</span>`));
    // @keywords
    h = h.replace(/@([A-Za-z_]\w*)/g, (m, kw) => ph(`<span class="gx-kw">@${kw}</span>`));
    // ~reactive variables
    h = h.replace(/~([\w]+(?:\.[\w]+)*)/g, m => ph(`<span class="arx-reactive">${m}</span>`));
    // :: modifiers
    h = h.replace(/::/g, m => ph(`<span class="gx-arrow">::</span>`));
    // => handlers
    h = h.replace(/=>/g, m => ph(`<span class="gx-arrow">=&gt;</span>`));
    // := computed
    h = h.replace(/:=/g, m => ph(`<span class="gx-arrow">:=</span>`));
    // Colors #hex
    h = h.replace(/#([0-9A-Fa-f]{3,8})\b/g, m => ph(`<span class="arx-color">${m}</span>`));
    // Layout/widget keywords
    const arxKw = 'col|row|header|text|button|input|label|image|icon|divider|list|card|badge|toast|tabs|tab|video|audio|table|thead|tbody|tr|th|td|form|field|submit';
    h = h.replace(new RegExp(`\\b(${arxKw})\\b`, 'g'), '<span class="gx-kw">$1</span>');
    // Modifier functions
    const arxMod = 'pad|gap|center|bold|italic|size|color|bg|radius|border|w|h|grow|hidden|visible|placeholder|debounce|format|autoplay|loop|muted|controls|transition|swipeleft|swiperight';
    h = h.replace(new RegExp(`\\b(${arxMod})(?=\\()`, 'g'), '<span class="gx-type">$1</span>');
    // Functions
    h = h.replace(/\b(send|navigate|back|fetch)\b/g, '<span class="gx-ctx">$1</span>');
    // Types
    h = h.replace(/\b(number|string|boolean|array)\b/g, '<span class="gx-type">$1</span>');
    // Numbers
    h = h.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="gx-num">$1</span>');
    // Booleans
    h = h.replace(/\b(true|false)\b/g, '<span class="gx-kw">$1</span>');

    h = h.replace(/\x00_(\d+)_\x00/g, (_, i) => stash[+i]);
    return h;
}

function ideUpdateGutter() {
    const ta = document.getElementById('ide-textarea');
    const gt = document.getElementById('ide-gutter');
    if (!ta || !gt) return;
    const diag = IDE._diagLines || {};
    const lines = ta.value.split('\n').length;
    let html = '';
    for (let i = 1; i <= lines; i++) {
        const sev = diag[i];
        const cls = sev === 'error' ? ' class="gx-gutter-err"'
                  : sev === 'warn'  ? ' class="gx-gutter-warn"'
                  : sev === 'hint'  ? ' class="gx-gutter-hint"' : '';
        html += `<div${cls}>${i}</div>`;
    }
    gt.innerHTML = html;
}

// ── Syntax highlighting ───────────────────────────────────────
function ideUpdateHighlight() {
    const ta = document.getElementById('ide-textarea');
    const hl = document.getElementById('ide-highlight');
    if (!ta || !hl) return;
    hl.innerHTML = _highlightGravitix(ta.value) + '\n';
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

    const kw = 'let|fn|on|flow|state|emit|wait|every|at|guard|match|if|else|elif|return|for|in|while|break|continue|run|true|false|null|env|defer|paginate|with|lang|webhook|http';
    h = h.replace(new RegExp(`\\b(${kw})\\b`, 'g'), '<span class="gx-kw">$1</span>');
    h = h.replace(/\b(int|float|bool|str|list|map|void)\b/g, '<span class="gx-type">$1</span>');
    h = h.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="gx-num">$1</span>');
    h = h.replace(/(\|>|->|=>)/g, '<span class="gx-arrow">$1</span>');
    h = h.replace(/\b(ctx|state)\b/g, '<span class="gx-ctx">$1</span>');
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

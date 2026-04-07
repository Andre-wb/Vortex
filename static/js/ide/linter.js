// ══════════════════════════════════════════════════════════════
//  Gravitix Compile-Time Checker  (lexer + parser + semantic)
// ══════════════════════════════════════════════════════════════

const GX_KW = new Set([
    'let','fn','on','flow','state','emit','wait','every','at',
    'guard','match','if','else','elif','return','for','in',
    'while','break','continue','run','true','false','null','env',
    'defer','paginate','with','lang','webhook','http',
    'enum','impl','spawn','queue','enqueue','embed','audit',
    'fire','watch','select','timeout','mock','expect','validate',
    'remember','recall','batch','admin','section','middleware','sandbox',
    'intents','intent','entities','extract','circuit_breaker','with_breaker',
    'track','canary','channel','breakpoint','simulate','expect_reply',
    'migration','multiplatform','scenario',
    'form','field','submit','table','chart','websocket','stream',
    'permissions','ratelimit','import','typedef','where','try','catch','finally','repl',
]);
const GX_TYPES   = new Set(['int','float','bool','str','list','map','void']);
const GX_BUILTIN = new Set([
    'ctx','msg','text','chat_id','user','args',
    'len','push','pop','keys','values','contains','print',
    'to_str','to_int','to_float','split','join','trim','upper','lower',
    'lowercase','uppercase','sanitize','replace',
    'now','rand','abs','min','max','floor','ceil','sqrt','log',
    'http_get','http_post','set_state','get_state',
    'send','reply','emit_to','bot','event','format','type_of',
    'error','assert','range','filter','sort','reverse','clone',
    'is_null','is_str','is_int','is_list','is_map',
    'now_unix','now_str','int','float','str','bool',
]);

let _lintTimer = null;
function ideLintCode(code) {
    clearTimeout(_lintTimer);
    _lintTimer = setTimeout(() => _gxCompile(code), 200);
}

// ── Lexer ──────────────────────────────────────────────────────
function _gxLex(src) {
    const tokens = [];
    let i = 0, line = 1, col = 1;
    const adv = () => {
        const c = src[i++];
        if (c === '\n') { line++; col = 1; } else col++;
        return c;
    };
    const tok = (kind, val, l, c) => tokens.push({ kind, val, line: l, col: c });

    while (i < src.length) {
        const l = line, c = col, ch = src[i];

        // Whitespace
        if (/\s/.test(ch)) { adv(); continue; }

        // Line comment
        if (ch === '/' && src[i+1] === '/') {
            while (i < src.length && src[i] !== '\n') adv();
            continue;
        }
        // Block comment
        if (ch === '/' && src[i+1] === '*') {
            adv(); adv();
            const startL = l, startC = c;
            while (i < src.length && !(src[i] === '*' && src[i+1] === '/')) adv();
            if (i >= src.length) tok('err', 'Unclosed block comment', startL, startC);
            else { adv(); adv(); }
            continue;
        }

        // String
        if (ch === '"') {
            adv();
            const startL = l, startC = c;
            let closed = false;
            while (i < src.length) {
                if (src[i] === '\\') { adv(); adv(); continue; }
                if (src[i] === '"')  { adv(); closed = true; break; }
                if (src[i] === '\n') break;
                adv();
            }
            tok(closed ? 'string' : 'err', closed ? '' : 'Unclosed string literal', startL, startC);
            continue;
        }

        // Number
        if (/\d/.test(ch) || (ch === '.' && /\d/.test(src[i+1]||''))) {
            let s = '';
            while (i < src.length && /[\d._]/.test(src[i])) s += adv();
            tok('num', s, l, c); continue;
        }

        // Identifier / keyword / type
        if (/[a-zA-Z_]/.test(ch)) {
            let s = '';
            while (i < src.length && /[a-zA-Z0-9_]/.test(src[i])) s += adv();
            tok(GX_KW.has(s) ? 'kw' : GX_TYPES.has(s) ? 'type' : 'id', s, l, c);
            continue;
        }

        // Two-char operators
        const two = ch + (src[i+1]||'');
        if (['|>','=>','->','==','!=','<=','>=','&&','||','+=','-=','*=','/=','**'].includes(two)) {
            adv(); adv(); tok('op', two, l, c); continue;
        }

        // Single-char
        adv(); tok('p', ch, l, c);
    }
    tokens.push({ kind: 'EOF', val: '', line, col });
    return tokens;
}

// ── Parser + Semantic ──────────────────────────────────────────
function _gxCompile(code) {
    const diag = []; // { sev:'error'|'warn'|'hint', line, col, msg }

    const tokens = _gxLex(code);
    let p = 0;
    const cur   = ()    => tokens[p]   || { kind:'EOF', val:'', line:0, col:0 };
    const peek  = (n=1) => tokens[p+n] || { kind:'EOF', val:'', line:0, col:0 };
    const eat   = ()    => tokens[p < tokens.length ? p++ : p] || cur();
    const isP   = v     => cur().kind === 'p'  && cur().val === v;
    const isKw  = v     => cur().kind === 'kw' && cur().val === v;
    const isOp  = v     => cur().kind === 'op' && cur().val === v;

    const _tlen = t => (t.val || '').length || 1;
    const err  = (t, msg) => diag.push({ sev:'error', line: t.line, col: t.col, len: _tlen(t), msg });
    const warn = (t, msg) => diag.push({ sev:'warn',  line: t.line, col: t.col, len: _tlen(t), msg });
    const hint = (t, msg) => diag.push({ sev:'hint',  line: t.line, col: t.col, len: _tlen(t), msg });

    const expect = (kind, val, msg) => {
        if (cur().kind === kind && cur().val === val) return eat();
        err(cur(), msg); return null;
    };
    const expectP = (v, m) => expect('p', v, m);

    // Scope stack: Map<name, {line,col,used,isParam}>
    const scopes   = [new Map()];
    const push     = () => scopes.push(new Map());
    const pop      = () => {
        const s = scopes.pop();
        s.forEach((info, name) => {
            if (!info.used && !info.isParam && !name.startsWith('_'))
                hint({ line: info.line, col: info.col }, `'${name}' declared but never used`);
        });
    };
    const def = (name, t, isParam=false) => {
        const top = scopes[scopes.length-1];
        if (top.has(name))
            warn(t, `'${name}' shadows a previous declaration`);
        top.set(name, { line: t.line, col: t.col, used: false, isParam });
    };
    const use = (name, t) => {
        for (let s = scopes.length-1; s >= 0; s--) {
            if (scopes[s].has(name)) { scopes[s].get(name).used = true; return; }
        }
        if (!GX_BUILTIN.has(name) && !GX_KW.has(name) && !GX_TYPES.has(name))
            warn(t, `Undefined identifier '${name}'`);
    };

    let fnDepth   = 0;
    let loopDepth = 0;
    let stmtCount = 0;

    // ── Helpers ────────────────────────────────────────────────
    function skipTo(...vals) {
        while (cur().kind !== 'EOF' && !vals.includes(cur().val)) eat();
    }
    function eatSemi() {
        if (isP(';')) { eat(); return; }
        const t = cur();
        // ',' is a valid arm-separator in match — don't warn
        if (t.kind !== 'EOF' && !isP('}') && !isP(','))
            warn(t, "Expected ';' — missing semicolon");
    }

    // ── Expr parser ────────────────────────────────────────────
    function parseExpr() { return parsePipe(); }

    function parsePipe() {
        parseOr();
        while (isOp('|>')) {
            eat();
            const t = cur();
            if (t.kind === 'id') { eat(); use(t.val, t); }
            else err(t, "Expected function name after '|>'");
            if (isP('(')) { eat(); parseArgList(); expectP(')', "Expected ')' in pipe call"); }
        }
    }
    function parseOr()  { parseAnd(); while (isOp('||')) { eat(); parseAnd(); } }
    function parseAnd() { parseEq();  while (isOp('&&')) { eat(); parseEq(); } }
    function parseEq() {
        parseCmp();
        while (['==','!='].includes(cur().val) && cur().kind === 'op') { eat(); parseCmp(); }
    }
    function parseCmp() {
        parseAdd();
        while (['<','>','<=','>='].includes(cur().val)) { eat(); parseAdd(); }
    }
    function parseAdd() {
        parseMul();
        while (isP('+') || isP('-')) { eat(); parseMul(); }
    }
    function parseMul() {
        parseUnary();
        while (isP('*') || isP('/') || isP('%') || isOp('**')) { eat(); parseUnary(); }
    }
    function parseUnary() {
        if (isP('-') || isP('!')) { eat(); parseUnary(); return; }
        parsePostfix();
    }
    function parsePostfix() {
        parsePrimary();
        // Field, index, call, assign chaining
        for (;;) {
            if (isP('.')) {
                eat();
                if (cur().kind === 'id') eat();
                else err(cur(), "Expected field name after '.'");
            } else if (isP('[')) {
                eat(); parseExpr(); expectP(']', "Expected ']' to close index");
            } else if (isP('(')) {
                eat(); parseArgList(); expectP(')', "Expected ')' to close call");
            } else if (isP('=') || ['+=','-=','*=','/='].includes(cur().val)) {
                eat(); parseExpr();
            } else break;
        }
    }
    function parseArgList() {
        while (!isP(')') && cur().kind !== 'EOF') {
            parseExpr();
            if (isP(',')) eat(); else break;
        }
    }
    function parsePrimary() {
        const t = cur();
        // Literals
        if (t.kind === 'num' || t.kind === 'string') { eat(); return; }
        if (t.kind === 'kw' && ['true','false','null'].includes(t.val)) { eat(); return; }
        if (t.kind === 'kw' && ['env','ctx','state','msg'].includes(t.val)) { eat(); return; }
        if (t.kind === 'kw' && t.val === 'wait') { eat(); parseExpr(); return; }
        // Type-cast: int(x)
        if (t.kind === 'type') { eat(); if (isP('(')) { eat(); parseArgList(); expectP(')', "Expected ')'"); } return; }
        // Identifier
        if (t.kind === 'id') { eat(); use(t.val, t); return; }
        // Parenthesised
        if (isP('(')) { eat(); parseExpr(); expectP(')', "Expected ')' to close expression"); return; }
        // List literal
        if (isP('[')) { eat(); parseArgList(); expectP(']', "Expected ']' to close list"); return; }
        // Map literal
        if (isP('{')) {
            eat();
            while (!isP('}') && cur().kind !== 'EOF') {
                if (cur().kind === 'string' || cur().kind === 'id') eat();
                expectP(':', "Expected ':' in map entry");
                parseExpr();
                if (isP(',')) eat(); else break;
            }
            expectP('}', "Expected '}' to close map"); return;
        }
        // err token from lexer
        if (t.kind === 'err') { err(t, t.val); eat(); return; }
        // Swallow unrecognised token to avoid cascade
        if (t.kind !== 'EOF' && !isP('}') && !isP(')') && !isP(']') && !isP(';'))
            eat();
    }

    // ── Statements ─────────────────────────────────────────────
    // Safe loop helper: guarantees at least one token consumed per iteration
    function safeWhile(cond, body) {
        while (cond()) {
            const before = p;
            body();
            if (p === before) eat(); // stuck? force-advance to prevent infinite loop
        }
    }

    function parseBlock() {
        const open = cur();
        if (!expectP('{', "Expected '{'")) return;
        push();
        safeWhile(() => cur().kind !== 'EOF' && !isP('}'), parseStmt);
        if (!expectP('}', `Expected '}' to close block (opened line ${open.line})`))
            err({ line: open.line, col: open.col }, "Unclosed '{' — missing '}'");
        pop();
    }

    function parseStmt() {
        stmtCount++;
        const t = cur();
        if (t.kind === 'EOF') return;
        if (isP('}')) return;          // let caller's loop handle it
        if (isP(';')) { eat(); return; }

        if (t.kind === 'kw') switch (t.val) {
            case 'fn':       parseFn();     return;
            case 'on':       parseOn();     return;
            case 'let':      parseLet();    return;
            case 'state':    parseState();  return;
            case 'emit':     parseEmit();   return;
            case 'return':   parseReturn(); return;
            case 'if':       parseIf();     return;
            case 'match':    parseMatch();  return;
            case 'for':      parseFor();    return;
            case 'while':    parseWhile();  return;
            case 'flow':     parseFlow();   return;
            case 'every':    parseEvery();  return;
            case 'at':       parseAt();     return;
            case 'guard':    eat(); parseExpr(); parseBlock(); return;
            case 'run':      eat(); if (isKw('flow')) eat(); if (cur().kind==='id') { eat(); } eatSemi(); return;
            case 'wait':     eat(); if (!isP(';')) parseExpr(); eatSemi(); return;
            case 'break':
                eat();
                if (loopDepth === 0) err(t, "'break' outside loop");
                eatSemi(); return;
            case 'continue':
                eat();
                if (loopDepth === 0) err(t, "'continue' outside loop");
                eatSemi(); return;
            default: eat(); return; // unknown keyword — skip
        }

        // Everything else (identifiers, numbers, strings, stray punctuation)
        // → expression statement; parsePrimary has its own swallow for unknowns
        const before = p;
        parseExpr();
        eatSemi();
        // Final safety: if parseExpr swallowed nothing (stray ) ] ; etc.), eat one token
        if (p === before) eat();
    }

    function parseFn() {
        eat(); // fn
        const nt = cur();
        if (nt.kind !== 'id') { err(nt, "Expected function name after 'fn'"); }
        else { eat(); def(nt.val, nt); scopes[0].get(nt.val).used = true; }
        expectP('(', "Expected '(' after function name");
        push(); // param scope merged with body
        while (!isP(')') && cur().kind !== 'EOF') {
            const pt = cur();
            if (pt.kind === 'id') { eat(); def(pt.val, pt, true); }
            // type annotation  param: type
            if (isP(':')) {
                eat();
                if (cur().kind === 'type' || cur().kind === 'id') eat();
                // generic like list<T>
                if (isP('<')) { eat(); while (!isP('>') && cur().kind !== 'EOF') eat(); if (isP('>')) eat(); }
            }
            if (isP(',')) eat();
        }
        expectP(')', "Expected ')' to close parameters");
        // return type: -> type  OR  : type
        if (isOp('->')) { eat(); if (cur().kind === 'type' || cur().kind === 'id') eat(); }
        else if (isP(':')) { eat(); if (cur().kind === 'type' || cur().kind === 'id') eat(); }
        fnDepth++;
        const ob = cur();
        if (!expectP('{', "Expected '{' to open function body")) { fnDepth--; pop(); return; }
        safeWhile(() => cur().kind !== 'EOF' && !isP('}'), parseStmt);
        if (!expectP('}', `Expected '}' to close fn body (opened line ${ob.line})`))
            err({ line: ob.line, col: ob.col }, "Unclosed fn body");
        pop(); fnDepth--;
    }

    function parseOn() {
        eat(); // on
        const pt = cur();
        if (isP('/')) {
            // /command  pattern — eat '/' and the following name
            eat();
            if (cur().kind === 'id' || cur().kind === 'kw') eat();
        } else if (['string','id','num'].includes(pt.kind) ||
                   (pt.kind === 'kw' && ['msg','true','false','photo','voice','video','audio','document'].includes(pt.val))) {
            eat();
        } else {
            err(pt, "Expected event pattern after 'on' (e.g. \"/start\", msg, /regex/)");
        }
        // optional guard clause
        if (isKw('guard')) { eat(); parseExpr(); }
        fnDepth++; parseBlock(); fnDepth--;
    }

    function parseFlow() {
        eat(); // flow
        const nt = cur();
        if (nt.kind === 'id') { eat(); def(nt.val, nt); scopes[0].has(nt.val) && (scopes[0].get(nt.val).used = true); }
        else err(nt, "Expected flow name after 'flow'");
        fnDepth++; parseBlock(); fnDepth--;
    }

    function parseLet() {
        eat(); // let
        const nt = cur();
        if (nt.kind !== 'id') err(nt, "Expected variable name after 'let'");
        else { eat(); def(nt.val, nt); }
        if (isP(':')) { eat(); if (cur().kind === 'type' || cur().kind === 'id') eat(); }
        if (isP('=')) { eat(); parseExpr(); }
        else err(cur(), "Expected '=' after variable name");
        eatSemi();
    }

    function parseState() {
        // state.field = ...  →  expression statement (state used as lvalue)
        if (peek().kind === 'p' && peek().val === '.') {
            parseExpr(); eatSemi(); return;
        }
        eat(); // state keyword
        // state { field: type = default, ... }  — block declaration form
        if (isP('{')) {
            eat();
            safeWhile(() => !isP('}') && cur().kind !== 'EOF', () => {
                if (cur().kind === 'id') {
                    const ft = cur(); eat();
                    def(ft.val, ft);
                    scopes[0].has(ft.val) && (scopes[0].get(ft.val).used = true);
                } else { err(cur(), "Expected field name in state block"); eat(); return; }
                // : type  (possibly generic map<K,V>)
                if (isP(':')) {
                    eat();
                    if (cur().kind === 'type' || cur().kind === 'id') eat();
                    if (isP('<')) {
                        eat();
                        while (!isP('>') && cur().kind !== 'EOF') eat();
                        if (isP('>')) eat();
                    }
                }
                if (isP('=')) { eat(); parseExpr(); }
                if (isP(',')) eat();
            });
            expectP('}', "Expected '}' to close state block");
            return;
        }
        // state varname = expr  — single-variable legacy form
        const nt = cur();
        if (nt.kind !== 'id') err(nt, "Expected state variable name");
        else { eat(); def(nt.val, nt); scopes[0].has(nt.val) && (scopes[0].get(nt.val).used = true); }
        if (isP('=')) { eat(); parseExpr(); } else err(cur(), "Expected '=' after state name");
        eatSemi();
    }

    function parseEmit() {
        const t = eat(); // emit
        if (isP(';')) err(t, "'emit' requires an expression");
        else parseExpr();
        eatSemi();
    }

    function parseReturn() {
        const t = eat(); // return
        if (fnDepth === 0) err(t, "'return' used outside a function or handler");
        if (!isP(';') && !isP('}')) parseExpr();
        eatSemi();
    }

    function parseIf() {
        eat(); // if
        parseExpr();
        parseBlock();
        while (isKw('elif')) { eat(); parseExpr(); parseBlock(); }
        if (isKw('else')) { eat(); parseBlock(); }
    }

    function parseMatch() {
        eat(); // match
        parseExpr();
        const ob = cur();
        expectP('{', "Expected '{' after match subject");
        let arms = 0;
        safeWhile(() => !isP('}') && cur().kind !== 'EOF', () => {
            arms++;
            const pt = cur();
            if (isP('/')) {
                // regex pattern: /pattern/flags — eat tokens until closing '/'
                const patLine = pt.line;
                eat(); // opening /
                while (!isP('/') && cur().kind !== 'EOF' && cur().line === patLine) eat();
                if (isP('/')) eat(); // closing /
                if (cur().kind === 'id' && cur().line === patLine) eat(); // flags: i, g…
            } else if (['string','num','id','regex'].includes(pt.kind) ||
                       (pt.kind === 'kw' && ['true','false','null'].includes(pt.val)) ||
                       (pt.kind === 'p' && pt.val === '_')) {
                eat();
            } else {
                err(pt, "Expected match arm pattern (string, number, /regex/, or _)"); eat();
            }
            // optional guard
            if (isKw('guard')) { eat(); parseExpr(); }
            // =>
            if (!isOp('=>')) err(cur(), "Expected '=>' in match arm");
            else eat();
            // body: block or statement (emit, let, return, etc.)
            if (isP('{')) parseBlock();
            else { parseStmt(); if (isP(',')) eat(); }
        });
        if (arms === 0) warn(ob, "match has no arms");
        expectP('}', `Expected '}' to close match from line ${ob.line}`);
    }

    function parseFor() {
        eat(); // for
        const vt = cur();
        let pushed = false;
        if (vt.kind !== 'id') err(vt, "Expected variable name in 'for' loop");
        else { eat(); push(); pushed = true; def(vt.val, vt, true); }
        if (!isKw('in')) err(cur(), "Expected 'in' in for loop");
        else eat();
        parseExpr();
        loopDepth++;
        const ob = cur();
        if (!expectP('{', "Expected '{' to open for body")) { loopDepth--; if (pushed) pop(); return; }
        safeWhile(() => !isP('}') && cur().kind !== 'EOF', parseStmt);
        expectP('}', `Expected '}' to close for body (opened line ${ob.line})`);
        if (pushed) pop();
        loopDepth--;
    }

    function parseWhile() {
        eat(); // while
        parseExpr();
        loopDepth++; parseBlock(); loopDepth--;
    }

    function parseEvery() {
        eat(); // every
        const t = cur();
        if (t.kind === 'num') eat();
        else if (t.kind === 'string') eat();
        else err(t, "Expected duration after 'every' (e.g. 60, \"1h\")");
        // optional unit: hours, hour, minutes, seconds, days, weeks, etc.
        if (cur().kind === 'id') eat();
        parseBlock();
    }

    function parseAt() {
        eat(); // at
        parseExpr();
        parseBlock();
    }

    // ── Top-level parse ────────────────────────────────────────
    safeWhile(() => cur().kind !== 'EOF', parseStmt);

    // ── Report ────────────────────────────────────────────────
    const errors = diag.filter(d => d.sev === 'error');
    const warns  = diag.filter(d => d.sev === 'warn');
    const hints  = diag.filter(d => d.sev === 'hint');

    _setIndicator('error', errors);
    _setIndicator('warn',  warns);
    _setIndicator('hint',  hints);

    // Problems panel
    const pane = document.getElementById('ide-console-problems');
    if (pane) {
        if (!diag.length) {
            pane.innerHTML = '<div class="ide-prob-ok">✓ No problems — compiled successfully</div>';
        } else {
            pane.innerHTML = diag.map(d => {
                const cls = { error:'ide-prob-err', warn:'ide-prob-warn', hint:'ide-prob-hint' }[d.sev];
                const ico = { error:'✕', warn:'⚠', hint:'△' }[d.sev];
                return `<div class="ide-prob ${cls}" onclick="ideJumpToLine(${d.line})" style="cursor:pointer;">
                    <span class="ide-prob-icon">${ico}</span>
                    <span class="ide-prob-msg">${_esc(d.msg)}</span>
                    <span class="ide-prob-loc">:${d.line}</span>
                </div>`;
            }).join('');
        }
    }

    // Store full diag for token-level highlight and per-line gutter
    IDE._diagFull  = diag;
    IDE._diagLines = {};
    diag.forEach(d => {
        const prev = IDE._diagLines[d.line];
        if (!prev || d.sev === 'error') IDE._diagLines[d.line] = d.sev;
    });
    ideUpdateGutter();
    ideUpdateHighlight(); // re-render highlight with error token spans
}


function ideJumpToLine(ln) {
    const ta = document.getElementById('ide-textarea');
    if (!ta) return;
    const lines = ta.value.split('\n');
    let offset = 0;
    for (let i = 0; i < Math.min(ln - 1, lines.length); i++) offset += lines[i].length + 1;
    ta.focus();
    ta.setSelectionRange(offset, offset + (lines[ln-1]||'').length);
    // Scroll line into view
    const lineH = parseFloat(getComputedStyle(ta).lineHeight) || 22;
    ta.scrollTop = Math.max(0, (ln - 4) * lineH);
    const hl = document.getElementById('ide-highlight');
    const gt = document.getElementById('ide-gutter');
    if (hl) hl.scrollTop = ta.scrollTop;
    if (gt) gt.scrollTop = ta.scrollTop;
    // Open problems panel if not already visible
    ideOpenProblems();
}

function _setIndicator(type, items) {
    const el    = document.getElementById(`ide-ind-${type}`);
    const count = document.getElementById(`ide-ind-${type}-count`);
    if (!el) return;
    el.style.display = items.length ? 'flex' : 'none';
    if (count) count.textContent = items.length;
}

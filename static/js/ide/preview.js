// ── Architex Mini App Preview ─────────────────────────────────
// Парсит .arx код и рендерит интерактивный UI в iframe-подобной панели

let _previewDebounce = null;
let _previewState = {};      // реактивные переменные (~var)
let _previewScreens = {};    // распарсенные экраны
let _previewCurrentScreen = null;
let _previewHistory = [];    // навигация назад
let _previewTheme = {};      // @theme цвета
let _previewConsoleLog = []; // логи send() и т.д.

// ── Публичные функции ────────────────────────────────────────

function ideShowPreview() {
    const panel = document.getElementById('ide-preview');
    const btn = document.getElementById('ide-preview-toggle');
    if (panel) panel.style.display = 'flex';
    if (btn) btn.classList.add('active');
    IDE.previewVisible = true;
    _previewRefreshFromEditor();
}

function ideHidePreview() {
    const panel = document.getElementById('ide-preview');
    const btn = document.getElementById('ide-preview-toggle');
    if (panel) panel.style.display = 'none';
    if (btn) btn.classList.remove('active');
    IDE.previewVisible = false;
}

function ideTogglePreview() {
    if (IDE.previewVisible) ideHidePreview();
    else ideShowPreview();
}

function ideUpdatePreview(code, filename) {
    if (!filename || !filename.endsWith('.arx')) return;
    if (!IDE.previewVisible) return;
    clearTimeout(_previewDebounce);
    _previewDebounce = setTimeout(() => _previewRender(code), 500);
}

// Вызывается при смене файла / input
function _previewRefreshFromEditor() {
    if (!IDE.previewVisible) return;
    const file = IDE.activeFile || '';
    if (!file.endsWith('.arx')) {
        _previewShowPlaceholder();
        return;
    }
    const code = IDE.current?.files[file] || '';
    _previewRender(code);
}

// ── Парсер Architex ──────────────────────────────────────────

function _previewParse(code) {
    const lines = code.split('\n');
    const screens = {};
    const theme = {};
    let currentScreen = null;
    let indentStack = []; // стек виджетов по отступу

    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const trimmed = raw.trim();
        if (!trimmed || trimmed.startsWith('//')) continue;

        // @theme блок
        const themeMatch = trimmed.match(/^@theme\s*$/);
        if (themeMatch) {
            // Читаем следующие строки с отступом
            for (let j = i + 1; j < lines.length; j++) {
                const tl = lines[j].trim();
                if (!tl || tl.startsWith('//')) continue;
                if (!lines[j].match(/^\s+/)) break;
                const kvMatch = tl.match(/^(\w+)\s*[:=]\s*(.+)$/);
                if (kvMatch) theme[kvMatch[1]] = kvMatch[2].trim();
                i = j;
            }
            continue;
        }

        // @screen Name
        const screenMatch = trimmed.match(/^@screen\s+(\w+)/);
        if (screenMatch) {
            currentScreen = screenMatch[1];
            screens[currentScreen] = { name: currentScreen, vars: {}, computed: {}, widgets: [], conditions: [] };
            indentStack = [];
            continue;
        }

        // @component Name (обрабатываем как экран пока)
        const compMatch = trimmed.match(/^@component\s+(\w+)/);
        if (compMatch) {
            currentScreen = '__comp_' + compMatch[1];
            screens[currentScreen] = { name: compMatch[1], vars: {}, computed: {}, widgets: [], isComponent: true };
            indentStack = [];
            continue;
        }

        if (!currentScreen) continue;
        const screen = screens[currentScreen];

        // Реактивная переменная: ~name = value  или  ~name := expr
        const rxMatch = trimmed.match(/^~(\w+)\s*(:?=)\s*(.+)$/);
        if (rxMatch) {
            const [, varName, op, val] = rxMatch;
            if (op === ':=') {
                screen.computed[varName] = val;
            } else {
                screen.vars[varName] = _parseValue(val);
            }
            continue;
        }

        // @if / @else условия
        const ifMatch = trimmed.match(/^@if\s+(.+)$/);
        if (ifMatch) {
            const condWidget = { type: '__if', condition: ifMatch[1], children: [], elseChildren: [], indent: _getIndent(raw) };
            _addWidget(screen, indentStack, condWidget, _getIndent(raw));
            indentStack.push({ widget: condWidget, indent: _getIndent(raw), target: 'children' });
            continue;
        }
        if (trimmed === '@else') {
            // Найти последний @if в стеке
            for (let s = indentStack.length - 1; s >= 0; s--) {
                if (indentStack[s].widget.type === '__if') {
                    indentStack[s].target = 'elseChildren';
                    break;
                }
            }
            continue;
        }

        // Виджеты: type content :: modifiers
        const widgetMatch = trimmed.match(/^(\w+)\s*(.*?)(?:\s*::\s*(.*))?$/);
        if (widgetMatch) {
            const [, wType, wContent, wMods] = widgetMatch;
            const widget = _parseWidget(wType, wContent.trim(), wMods || '', i + 1);
            if (!widget) continue;

            const indent = _getIndent(raw);

            // Обработчик => на следующей строке или inline
            _checkHandler(widget, lines, i);

            _addWidget(screen, indentStack, widget, indent);

            // Контейнеры: col, row, stack, list, grid, scroll
            if (['col', 'row', 'stack', 'list', 'grid', 'scroll'].includes(widget.type)) {
                indentStack.push({ widget, indent, target: 'children' });
            }
        }
    }

    return { screens, theme };
}

function _getIndent(line) {
    const m = line.match(/^(\s*)/);
    return m ? m[1].length : 0;
}

function _addWidget(screen, indentStack, widget, indent) {
    // Убираем из стека все элементы с отступом >= текущего
    while (indentStack.length > 0 && indentStack[indentStack.length - 1].indent >= indent) {
        indentStack.pop();
    }

    if (indentStack.length > 0) {
        const parent = indentStack[indentStack.length - 1];
        const target = parent.target || 'children';
        if (!parent.widget[target]) parent.widget[target] = [];
        parent.widget[target].push(widget);
    } else {
        screen.widgets.push(widget);
    }
}

function _checkHandler(widget, lines, lineIdx) {
    // Проверяем следующую строку на => handler
    for (let j = lineIdx + 1; j < lines.length; j++) {
        const nextTrimmed = lines[j].trim();
        if (!nextTrimmed || nextTrimmed.startsWith('//')) continue;
        if (nextTrimmed.startsWith('=>')) {
            widget.handler = nextTrimmed.substring(2).trim();
        }
        break;
    }
}

function _parseWidget(type, content, modsStr, line) {
    const knownTypes = [
        'col', 'row', 'stack', 'list', 'grid', 'scroll',
        'text', 'header', 'button', 'input', 'image', 'card',
        'spacer', 'divider', 'label', 'icon', 'badge', 'avatar',
        'switch', 'slider', 'progressbar', 'chip',
        'tabs', 'tab', 'video', 'audio', 'table'
    ];
    if (!knownTypes.includes(type.toLowerCase())) return null;

    const mods = _parseModifiers(modsStr);
    const isReactive = content.startsWith('~');

    return {
        type: type.toLowerCase(),
        content: content.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1'),
        reactive: isReactive ? content.replace(/^~/, '') : null,
        mods,
        children: [],
        handler: null,
        line
    };
}

function _parseModifiers(str) {
    if (!str) return {};
    const mods = {};
    // pad(24) gap(16) center bold size(22) color(#4f8ef7) bg(#fff) radius(8) border(#ccc) italic
    const re = /(\w+)(?:\(([^)]*)\))?/g;
    let m;
    while ((m = re.exec(str)) !== null) {
        const [, name, val] = m;
        mods[name] = val !== undefined ? val : true;
    }
    return mods;
}

function _parseValue(str) {
    str = str.trim();
    if (str === 'true') return true;
    if (str === 'false') return false;
    if (/^-?\d+(\.\d+)?$/.test(str)) return parseFloat(str);
    // Строка в кавычках
    if ((str.startsWith('"') && str.endsWith('"')) || (str.startsWith("'") && str.endsWith("'")))
        return str.slice(1, -1);
    return str;
}

// ── Рендер ───────────────────────────────────────────────────

function _previewRender(code) {
    const parsed = _previewParse(code);
    _previewScreens = parsed.screens;
    _previewTheme = parsed.theme;

    // Инициализируем state из всех экранов
    _previewState = {};
    for (const [, scr] of Object.entries(_previewScreens)) {
        for (const [k, v] of Object.entries(scr.vars)) {
            _previewState[k] = v;
        }
    }

    // Определяем первый экран
    const screenNames = Object.keys(_previewScreens).filter(n => !n.startsWith('__comp_'));
    if (screenNames.length === 0) {
        _previewShowPlaceholder();
        return;
    }

    if (!_previewCurrentScreen || !_previewScreens[_previewCurrentScreen]) {
        _previewCurrentScreen = screenNames[0];
    }

    _previewRedraw();
}

function _previewRedraw() {
    const content = document.getElementById('ide-preview-content');
    if (!content) return;

    const screen = _previewScreens[_previewCurrentScreen];
    if (!screen) {
        content.innerHTML = '<div class="arx-empty">No screen to display</div>';
        return;
    }

    // Пересчитываем computed
    for (const [k, expr] of Object.entries(screen.computed || {})) {
        _previewState[k] = _evalComputed(expr);
    }

    // Обновляем заголовок экрана
    const titleEl = document.getElementById('ide-preview-screen-title');
    if (titleEl) titleEl.textContent = screen.name;

    // Обновляем навигационные табы
    _renderPreviewTabs();

    content.innerHTML = '';
    const el = _renderWidgets(screen.widgets);
    content.appendChild(el);
}

function _renderPreviewTabs() {
    const nav = document.getElementById('ide-preview-nav');
    if (!nav) return;
    const screenNames = Object.keys(_previewScreens).filter(n => !n.startsWith('__comp_'));
    if (screenNames.length <= 1) {
        nav.style.display = 'none';
        return;
    }
    nav.style.display = 'flex';
    nav.innerHTML = '';
    screenNames.forEach(name => {
        const tab = document.createElement('div');
        tab.className = 'arx-nav-tab' + (name === _previewCurrentScreen ? ' active' : '');
        tab.textContent = name;
        tab.onclick = () => _previewNavigate(name);
        nav.appendChild(tab);
    });
}

function _renderWidgets(widgets) {
    const frag = document.createDocumentFragment();
    for (const w of widgets) {
        const el = _renderWidget(w);
        if (el) frag.appendChild(el);
    }
    return frag;
}

function _renderWidget(w) {
    if (w.type === '__if') return _renderCondition(w);

    const el = document.createElement('div');
    el.className = 'arx-widget arx-' + w.type;

    // Применяем стили из модификаторов
    _applyMods(el, w.mods);

    switch (w.type) {
        case 'col':
            el.style.display = 'flex';
            el.style.flexDirection = 'column';
            if (w.mods.gap) el.style.gap = w.mods.gap + 'px';
            if (w.mods.center) { el.style.alignItems = 'center'; }
            el.appendChild(_renderWidgets(w.children || []));
            break;

        case 'row':
            el.style.display = 'flex';
            el.style.flexDirection = 'row';
            el.style.flexWrap = 'wrap';
            if (w.mods.gap) el.style.gap = w.mods.gap + 'px';
            if (w.mods.center) { el.style.justifyContent = 'center'; el.style.alignItems = 'center'; }
            el.appendChild(_renderWidgets(w.children || []));
            break;

        case 'stack':
            el.style.position = 'relative';
            (w.children || []).forEach(c => {
                const child = _renderWidget(c);
                if (child) { child.style.position = 'absolute'; el.appendChild(child); }
            });
            break;

        case 'list':
        case 'scroll':
            el.style.display = 'flex';
            el.style.flexDirection = 'column';
            el.style.overflowY = 'auto';
            if (w.mods.gap) el.style.gap = w.mods.gap + 'px';
            el.appendChild(_renderWidgets(w.children || []));
            break;

        case 'grid':
            el.style.display = 'grid';
            el.style.gridTemplateColumns = 'repeat(' + (w.mods.cols || 2) + ', 1fr)';
            if (w.mods.gap) el.style.gap = w.mods.gap + 'px';
            el.appendChild(_renderWidgets(w.children || []));
            break;

        case 'text':
        case 'label':
            el.textContent = _resolveContent(w);
            if (w.mods.bold) el.style.fontWeight = '700';
            if (w.mods.italic) el.style.fontStyle = 'italic';
            if (w.mods.center) el.style.textAlign = 'center';
            break;

        case 'header':
            el.textContent = _resolveContent(w);
            el.style.fontWeight = '800';
            if (!w.mods.size) el.style.fontSize = '20px';
            break;

        case 'button': {
            el.className = 'arx-widget arx-button';
            el.textContent = _resolveContent(w);
            el.style.cursor = 'pointer';
            el.style.textAlign = 'center';
            el.style.fontWeight = '600';
            if (!w.mods.pad) { el.style.padding = '10px 16px'; }
            if (!w.mods.radius) { el.style.borderRadius = '8px'; }
            if (!w.mods.bg) { el.style.background = 'rgba(124,58,237,.15)'; el.style.color = '#7c3aed'; }
            if (w.handler) {
                el.onclick = () => _execHandler(w.handler);
            }
            break;
        }

        case 'input': {
            const inp = document.createElement('input');
            inp.className = 'arx-input-field';
            inp.type = 'text';
            const varName = w.reactive;
            if (varName && _previewState[varName] !== undefined) {
                inp.value = _previewState[varName];
            }
            if (w.mods.placeholder) inp.placeholder = w.mods.placeholder;
            _applyMods(inp, w.mods);
            inp.oninput = (e) => {
                if (varName) {
                    _previewState[varName] = e.target.value;
                    _previewRedraw();
                }
            };
            el.appendChild(inp);
            break;
        }

        case 'image': {
            const img = document.createElement('img');
            const src = _resolveContent(w);
            img.src = src || 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="60" fill="%23334155"><rect width="100" height="60" rx="8"/><text x="50" y="35" text-anchor="middle" fill="%2394a3b8" font-size="12">Image</text></svg>';
            img.style.maxWidth = '100%';
            img.style.borderRadius = w.mods.radius ? w.mods.radius + 'px' : '8px';
            img.onerror = () => { img.style.display = 'none'; };
            el.appendChild(img);
            break;
        }

        case 'card':
            el.style.background = 'rgba(255,255,255,.06)';
            el.style.borderRadius = '12px';
            el.style.padding = '14px';
            el.style.border = '1px solid rgba(255,255,255,.1)';
            el.appendChild(_renderWidgets(w.children || []));
            break;

        case 'spacer':
            el.style.height = (w.mods.size || '16') + 'px';
            break;

        case 'divider':
            el.style.height = '1px';
            el.style.background = 'rgba(255,255,255,.12)';
            el.style.margin = '8px 0';
            el.style.width = '100%';
            break;

        case 'switch': {
            el.className = 'arx-widget arx-switch-wrap';
            const varName = w.reactive;
            const isOn = varName ? !!_previewState[varName] : false;
            const lbl = document.createElement('span');
            lbl.className = 'arx-switch-label';
            lbl.textContent = _resolveContent(w) || '';
            el.appendChild(lbl);

            const sw = document.createElement('div');
            sw.className = 'arx-switch' + (isOn ? ' on' : '');
            sw.innerHTML = '<div class="arx-switch-thumb"></div>';
            sw.onclick = () => {
                if (varName) {
                    _previewState[varName] = !_previewState[varName];
                    _previewRedraw();
                }
            };
            el.appendChild(sw);
            break;
        }

        case 'slider': {
            const varName = w.reactive;
            const val = varName ? (_previewState[varName] || 0) : 50;
            const range = document.createElement('input');
            range.type = 'range';
            range.className = 'arx-slider';
            range.min = w.mods.min || 0;
            range.max = w.mods.max || 100;
            range.value = val;
            range.oninput = (e) => {
                if (varName) {
                    _previewState[varName] = parseInt(e.target.value);
                    _previewRedraw();
                }
            };
            el.appendChild(range);
            break;
        }

        case 'badge':
            el.textContent = _resolveContent(w);
            el.style.display = 'inline-flex';
            el.style.padding = '3px 10px';
            el.style.borderRadius = '12px';
            el.style.fontSize = '11px';
            el.style.fontWeight = '700';
            if (!w.mods.bg) el.style.background = 'rgba(124,58,237,.2)';
            if (!w.mods.color) el.style.color = '#c4b5fd';
            break;

        case 'avatar': {
            const size = w.mods.size || '40';
            el.style.width = size + 'px';
            el.style.height = size + 'px';
            el.style.borderRadius = '50%';
            el.style.background = 'linear-gradient(135deg, #7c3aed, #4f46e5)';
            el.style.display = 'flex';
            el.style.alignItems = 'center';
            el.style.justifyContent = 'center';
            el.style.color = '#fff';
            el.style.fontWeight = '700';
            el.style.fontSize = (parseInt(size) / 2.5) + 'px';
            const text = _resolveContent(w);
            el.textContent = text ? text.charAt(0).toUpperCase() : 'U';
            break;
        }

        case 'icon':
            el.textContent = _resolveContent(w) || '\u25CF';
            el.style.fontSize = (w.mods.size || '20') + 'px';
            break;

        case 'progressbar': {
            const val = w.reactive ? (_previewState[w.reactive] || 0) : parseInt(w.content) || 50;
            el.className = 'arx-widget arx-progressbar';
            const track = document.createElement('div');
            track.className = 'arx-progressbar-track';
            const fill = document.createElement('div');
            fill.className = 'arx-progressbar-fill';
            fill.style.width = Math.min(100, Math.max(0, val)) + '%';
            track.appendChild(fill);
            el.appendChild(track);
            break;
        }

        case 'chip':
            el.textContent = _resolveContent(w);
            el.style.display = 'inline-flex';
            el.style.padding = '5px 12px';
            el.style.borderRadius = '16px';
            el.style.fontSize = '12px';
            el.style.fontWeight = '600';
            el.style.border = '1px solid rgba(255,255,255,.15)';
            el.style.cursor = 'pointer';
            if (w.handler) el.onclick = () => _execHandler(w.handler);
            break;

        default:
            el.textContent = _resolveContent(w);
    }

    // Клик-обработчик для неинтерактивных виджетов
    if (w.handler && !['button', 'chip', 'switch'].includes(w.type)) {
        el.style.cursor = 'pointer';
        el.onclick = () => _execHandler(w.handler);
    }

    return el;
}

function _renderCondition(w) {
    const result = _evalCondition(w.condition);
    const children = result ? w.children : w.elseChildren;
    if (!children || children.length === 0) return null;

    const frag = document.createDocumentFragment();
    children.forEach(c => {
        const el = _renderWidget(c);
        if (el) frag.appendChild(el);
    });
    const wrapper = document.createElement('div');
    wrapper.appendChild(frag);
    return wrapper;
}

// ── Модификаторы ─> CSS ──────────────────────────────────────

function _applyMods(el, mods) {
    if (mods.pad || mods.padding) el.style.padding = (mods.pad || mods.padding) + 'px';
    if (mods.margin) el.style.margin = mods.margin + 'px';
    if (mods.bg || mods.background) el.style.background = mods.bg || mods.background;
    if (mods.radius || mods.cornerRadius) el.style.borderRadius = (mods.radius || mods.cornerRadius) + 'px';
    if (mods.border) el.style.border = '1px solid ' + mods.border;
    if (mods.shadow) el.style.boxShadow = '0 2px 8px rgba(0,0,0,.2)';
    if (mods.opacity) el.style.opacity = mods.opacity;
    if (mods.size) el.style.fontSize = mods.size + 'px';
    if (mods.width) el.style.width = mods.width + 'px';
    if (mods.height) el.style.height = mods.height + 'px';
    if (mods.maxWidth) el.style.maxWidth = mods.maxWidth + 'px';
    if (mods.maxHeight) el.style.maxHeight = mods.maxHeight + 'px';
    if (mods.color) el.style.color = mods.color;
    if (mods.font) el.style.fontFamily = mods.font;
    if (mods.bold) el.style.fontWeight = '700';
    if (mods.italic) el.style.fontStyle = 'italic';
    if (mods.center) el.style.textAlign = 'center';
    if (mods.align) {
        if (mods.align === 'center') el.style.textAlign = 'center';
        else if (mods.align === 'right' || mods.align === 'end') el.style.textAlign = 'right';
    }
}

// ── Резолв контента и реактивных переменных ──────────────────

function _resolveContent(w) {
    if (w.reactive) {
        const val = _previewState[w.reactive];
        return val !== undefined ? String(val) : '';
    }
    let str = w.content || '';
    // Интерполяция {~varName}
    str = str.replace(/\{~(\w+)\}/g, (_, name) => {
        const val = _previewState[name];
        return val !== undefined ? String(val) : '';
    });
    return str;
}

function _evalComputed(expr) {
    // Простая интерполяция: "Hello, {~name}!"
    let result = expr.replace(/^"(.*)"$/, '$1');
    result = result.replace(/\{~(\w+)\}/g, (_, name) => {
        const val = _previewState[name];
        return val !== undefined ? String(val) : '';
    });
    return result;
}

function _evalCondition(cond) {
    // Простые условия: ~var > N, ~var < N, ~var == N, ~var != N
    const m = cond.match(/^~(\w+)\s*(>|<|>=|<=|==|!=)\s*(.+)$/);
    if (!m) return false;
    const [, varName, op, rawVal] = m;
    const left = _previewState[varName];
    const right = _parseValue(rawVal);

    switch (op) {
        case '>':  return left > right;
        case '<':  return left < right;
        case '>=': return left >= right;
        case '<=': return left <= right;
        case '==': return left == right;
        case '!=': return left != right;
    }
    return false;
}

// ── Обработчики действий ─────────────────────────────────────

function _execHandler(handler) {
    if (!handler) return;

    // ~var += N, ~var -= N, ~var = N
    const assignMatch = handler.match(/^~(\w+)\s*(\+?=|-?=)\s*(.+)$/);
    if (assignMatch) {
        const [, varName, op, rawVal] = assignMatch;
        const val = _parseValue(rawVal);
        if (op === '+=') _previewState[varName] = (_previewState[varName] || 0) + val;
        else if (op === '-=') _previewState[varName] = (_previewState[varName] || 0) - val;
        else _previewState[varName] = val;
        _previewRedraw();
        return;
    }

    // send(...)
    const sendMatch = handler.match(/^send\s*\((.+)\)$/);
    if (sendMatch) {
        const payload = sendMatch[1];
        // Резолвим реактивные переменные в payload
        const resolved = payload.replace(/~(\w+)/g, (_, name) => {
            const val = _previewState[name];
            return val !== undefined ? String(val) : name;
        });
        _previewLog('send', 'send(' + resolved + ')');
        _previewToast('Sent: ' + resolved);
        return;
    }

    // navigate(ScreenName)
    const navMatch = handler.match(/^navigate\s*\((\w+)\)$/);
    if (navMatch) {
        _previewNavigate(navMatch[1]);
        return;
    }

    // back()
    if (handler.match(/^back\s*\(\)$/)) {
        _previewBack();
        return;
    }

    // Если ничего не подошло — показать toast
    _previewToast(handler);
}

function _previewNavigate(screenName) {
    if (_previewScreens[screenName]) {
        _previewHistory.push(_previewCurrentScreen);
        _previewCurrentScreen = screenName;
        _previewRedraw();
    }
}

function _previewBack() {
    if (_previewHistory.length > 0) {
        _previewCurrentScreen = _previewHistory.pop();
        _previewRedraw();
    }
}

function _previewLog(type, msg) {
    _previewConsoleLog.push({ type, msg, time: new Date().toLocaleTimeString() });
    // Обновляем лог-панель в preview
    const logEl = document.getElementById('ide-preview-log');
    if (!logEl) return;
    const line = document.createElement('div');
    line.className = 'arx-log-line arx-log-' + type;
    line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
}

function _previewToast(msg) {
    const container = document.getElementById('ide-preview-content');
    if (!container) return;

    // Удаляем предыдущий тост
    const old = container.querySelector('.arx-toast');
    if (old) old.remove();

    const toast = document.createElement('div');
    toast.className = 'arx-toast arx-toast-show';
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.classList.remove('arx-toast-show'), 2000);
    setTimeout(() => toast.remove(), 2500);
}

function _previewShowPlaceholder() {
    const content = document.getElementById('ide-preview-content');
    if (!content) return;
    content.innerHTML =
        '<div class="arx-placeholder">' +
            '<svg width="36" height="36" fill="rgba(124,58,237,.4)" viewBox="0 0 24 24">' +
                '<path d="M17 1.01L7 1c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-1.99-2-1.99zM17 19H7V5h10v14z"/>' +
            '</svg>' +
            '<span>Open an .arx file to preview</span>' +
        '</div>';
}

function idePreviewClearLog() {
    const logEl = document.getElementById('ide-preview-log');
    if (logEl) logEl.innerHTML = '';
    _previewConsoleLog = [];
}

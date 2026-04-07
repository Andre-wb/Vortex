// static/js/chat/search.js — client-side message search + server search

let _searchMatches  = [];   // массив элементов <mark> с совпадениями
let _searchCurrent  = -1;   // индекс текущего выделенного совпадения

/** Убирает все подсветки из DOM */
function _clearSearchHighlights() {
    document.querySelectorAll('mark.search-highlight').forEach(mark => {
        const parent = mark.parentNode;
        parent.replaceChild(document.createTextNode(mark.textContent), mark);
        parent.normalize();   // склеивает соседние текстовые узлы
    });
    _searchMatches = [];
    _searchCurrent = -1;
}

/** Подсвечивает совпадения query внутри textNode-ов элемента el */
function _highlightText(el, query) {
    const lowerQ = query.toLowerCase();
    const walker  = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null);
    const nodes   = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);

    for (const node of nodes) {
        const text = node.textContent;
        const lower = text.toLowerCase();
        let idx = lower.indexOf(lowerQ);
        if (idx === -1) continue;

        const frag = document.createDocumentFragment();
        let last = 0;
        while (idx !== -1) {
            if (idx > last) frag.appendChild(document.createTextNode(text.slice(last, idx)));
            const mark = document.createElement('mark');
            mark.className = 'search-highlight';
            mark.textContent = text.slice(idx, idx + query.length);
            frag.appendChild(mark);
            last = idx + query.length;
            idx = lower.indexOf(lowerQ, last);
        }
        if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
        node.parentNode.replaceChild(frag, node);
    }
}

function _updateMatchCounter() {
    const el = document.getElementById('search-match-count');
    if (!el) return;
    if (_searchMatches.length === 0) {
        const input = document.getElementById('chat-search-input');
        el.textContent = (input && input.value.trim()) ? t('chat.noMatches') : '';
    } else {
        el.textContent = t('chat.matchCounter').replace('{current}', _searchCurrent + 1).replace('{total}', _searchMatches.length);
    }
}

function _scrollToCurrentMatch() {
    if (_searchCurrent < 0 || _searchCurrent >= _searchMatches.length) return;
    // Снимаем .current у предыдущего
    _searchMatches.forEach(m => m.classList.remove('current'));
    const cur = _searchMatches[_searchCurrent];
    cur.classList.add('current');
    cur.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

window.searchMessages = function(query) {
    _clearSearchHighlights();

    const groups = document.querySelectorAll('.msg-group');

    if (!query || !query.trim()) {
        // Сбрасываем: показываем все сообщения и разделители
        groups.forEach(g => g.style.display = '');
        document.querySelectorAll('.date-divider').forEach(d => d.style.display = '');
        _updateMatchCounter();
        return;
    }

    const lowerQ = query.toLowerCase();

    groups.forEach(g => {
        const bubble = g.querySelector('.msg-bubble');
        if (!bubble) { g.style.display = ''; return; }
        const text = bubble.textContent.toLowerCase();
        const match = text.includes(lowerQ);
        g.style.display = match ? '' : 'none';
        if (match) _highlightText(bubble, query);
    });

    // Скрываем разделители дат при поиске
    document.querySelectorAll('.date-divider').forEach(d => d.style.display = 'none');

    // Собираем все mark-элементы
    _searchMatches = Array.from(document.querySelectorAll('mark.search-highlight'));
    _searchCurrent = _searchMatches.length > 0 ? 0 : -1;
    _updateMatchCounter();
    if (_searchCurrent >= 0) _scrollToCurrentMatch();
};

/** Навигация между совпадениями: direction = 1 (вниз) или -1 (вверх) */
window.searchNavigate = function(direction) {
    if (_searchMatches.length === 0) return;
    _searchCurrent = (_searchCurrent + direction + _searchMatches.length) % _searchMatches.length;
    _updateMatchCounter();
    _scrollToCurrentMatch();
};

/** Обработка клавиш в поле поиска: Enter — следующее, Shift+Enter — предыдущее */
window.handleSearchKey = function(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        window.searchNavigate(e.shiftKey ? -1 : 1);
    } else if (e.key === 'Escape') {
        e.preventDefault();
        window.toggleChatSearch();
    }
};

window.toggleChatSearch = function() {
    const bar = document.getElementById('chat-search-bar');
    if (!bar) return;
    const isVisible = bar.style.display !== 'none';
    bar.style.display = isVisible ? 'none' : 'flex';
    if (!isVisible) {
        const input = document.getElementById('chat-search-input');
        if (input) { input.value = ''; input.focus(); }
        window.searchMessages('');
    } else {
        _clearSearchHighlights();
        window.searchMessages('');
        const panel = document.getElementById('server-search-results');
        if (panel) panel.style.display = 'none';
    }
};

// =============================================================================
// Серверный поиск сообщений (файлы, метаданные)
// =============================================================================

window.serverSearchMessages = async function() {
    const S = window.AppState;
    const roomId = S.currentRoom?.id;
    if (!roomId) return;

    const input = document.getElementById('chat-search-input');
    const q = input?.value?.trim() || '';
    const panel = document.getElementById('server-search-results');
    const list = document.getElementById('server-search-list');
    const status = document.getElementById('server-search-status');
    if (!panel || !list || !status) return;

    panel.style.display = 'block';
    list.innerHTML = '';
    status.textContent = 'Поиск...';

    try {
        const params = new URLSearchParams();
        if (q) params.set('q', q);
        params.set('limit', '50');

        const data = await window.api('GET', `/api/rooms/${roomId}/messages/search?${params}`);
        const msgs = data.messages || [];
        status.textContent = msgs.length
            ? `Найдено: ${data.total} (показано ${msgs.length})`
            : 'Ничего не найдено';

        msgs.forEach(m => {
            const div = document.createElement('div');
            div.style.cssText = 'padding:4px 0; border-bottom:1px solid var(--border, #eee); cursor:pointer;';
            const date = m.created_at ? new Date(m.created_at).toLocaleString() : '';
            const sender = m.sender_name || 'Unknown';
            const type = m.msg_type || 'text';
            const fileName = m.file_name ? ` — ${m.file_name}` : '';
            div.textContent = `[${date}] ${sender} (${type})${fileName}`;
            div.onclick = () => {
                // Scroll to message if it's loaded in DOM
                const msgEl = document.querySelector(`[data-msg-id="${m.id}"]`);
                if (msgEl) {
                    msgEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    msgEl.style.outline = '2px solid var(--accent, #4a90d9)';
                    setTimeout(() => { msgEl.style.outline = ''; }, 2000);
                }
            };
            list.appendChild(div);
        });
    } catch (e) {
        status.textContent = 'Ошибка поиска: ' + (e.message || e);
    }
};

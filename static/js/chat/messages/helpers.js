// static/js/chat/messages.js
// =============================================================================
// Модуль рендеринга сообщений в чате.
// Отвечает за отображение текстовых сообщений, файлов, изображений, голосовых,
// контекстные меню, анимацию удаления, обновление текста при редактировании,
// а также интеграцию с liquid-glass для стеклянного эффекта.
// =============================================================================

import { esc, fmtTime, fmtDate, fmtSize } from '../../utils.js';
import { initLiquidGlass, createReplyQuote } from '../liquid-glass.js';
import { loadEncryptedImage, downloadAndDecryptFile } from '../file-upload.js';


// =========================================================================
// Link preview (OG meta) — cache and helpers
// =========================================================================
const _linkPreviewCache = new Map();
const _URL_RE = /https?:\/\/[^\s<>"']+/g;

/**
 * Detects the first non-special URL in message text and fetches its OG preview.
 * Appends a preview card inside the bubble element.
 * @param {string} text  - raw message text
 * @param {HTMLElement} bubble - the .msg-bubble element to append the card to
 */
function _maybeAttachLinkPreview(text, bubble) {
    if (!text) return;

    // Skip GIF and location messages (already have special rendering)
    if (text.startsWith('[GIF] ') || text.startsWith('[STICKER] ') || text.startsWith('[PAY] ') || text.includes('maps.google.com/maps?q=')) return;

    const urls = text.match(_URL_RE);
    if (!urls || urls.length === 0) return;

    // Take first URL, skip if it looks like a direct image/gif
    const url = urls[0].replace(/[).,;:!?\]]+$/, ''); // trim trailing punctuation
    if (/\.(gif|png|jpg|jpeg|webp|svg|mp4|webm|mp3|ogg|wav)(\?.*)?$/i.test(url)) return;

    // Check JS-side cache
    if (_linkPreviewCache.has(url)) {
        const data = _linkPreviewCache.get(url);
        if (data && data.title) {
            bubble.appendChild(_buildPreviewCard(data));
        }
        return;
    }

    // Fetch preview asynchronously
    fetch(`/api/link-preview?url=${encodeURIComponent(url)}`, { credentials: 'include' })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (!data) return;
            _linkPreviewCache.set(url, data);
            if (data.title) {
                bubble.appendChild(_buildPreviewCard(data));
            }
        })
        .catch(() => { /* silently ignore preview failures */ });
}

/**
 * Builds the link preview card DOM element.
 * @param {Object} data - {title, description, image, site_name, url}
 * @returns {HTMLElement}
 */
function _buildPreviewCard(data) {
    const card = document.createElement('div');
    card.className = 'link-preview';

    let html = '';
    if (data.site_name) {
        html += `<div class="link-preview-site">${esc(data.site_name)}</div>`;
    }
    html += `<a class="link-preview-title" href="${esc(data.url)}" target="_blank" rel="noopener noreferrer">${esc(data.title)}</a>`;
    if (data.description) {
        html += `<div class="link-preview-desc">${esc(data.description)}</div>`;
    }
    if (data.image) {
        html += `<img class="link-preview-image" src="${esc(data.image)}" alt="" loading="lazy" onerror="this.style.display='none'">`;
    }

    card.innerHTML = html;
    return card;
}

// =========================================================================
// Bot message markdown renderer
// Supports: **bold**, _italic_, `code`, [text](url), newlines
// =========================================================================
function _renderBotMarkdown(text) {
    if (!text) return '';
    let s = esc(text);
    // Fenced code blocks ```lang\n...\n``` (must run before inline code)
    s = s.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, lang, code) => {
        const cls = lang ? ` class="language-${lang}"` : '';
        return `<pre><code${cls}>${code}</code></pre>`;
    });
    // Inline code (to avoid inner formatting)
    s = s.replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.06);padding:1px 4px;border-radius:3px;font-family:var(--mono);font-size:12px;">$1</code>');
    // Bold
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // Italic
    s = s.replace(/(?<!\w)_(.+?)_(?!\w)/g, '<em>$1</em>');
    // Links [text](url)
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" style="color:var(--accent2);text-decoration:underline;">$1</a>');
    // Standalone URLs
    s = s.replace(/(?<![">])(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener" style="color:var(--accent2);text-decoration:underline;">$1</a>');
    // Newlines
    s = s.replace(/\n/g, '<br>');
    return s;
}

// =========================================================================
// @mention detection and rendering
// =========================================================================
const _MENTION_RE = /@(\w{3,30})/g;

/**
 * Renders text with @username mentions highlighted.
 * Matches current user's username get an extra .me class.
 * @param {HTMLElement} el - target element
 * @param {string} text - raw plaintext
 * @param {boolean} isOwn - whether this is our own message
 */
function _renderTextWithMentions(el, text, isOwn) {
    if (!text) { el.textContent = ''; return; }

    const S = window.AppState;
    const myUsername = (S.user?.username || '').toLowerCase();

    // Check if text contains any mention at all (fast path)
    if (!text.includes('@')) {
        el.textContent = text;
        return;
    }

    // Split text by @mention pattern, interleave plain text and mention spans
    let lastIndex = 0;
    let match;
    const frag = document.createDocumentFragment();
    const re = new RegExp(_MENTION_RE.source, 'g');

    while ((match = re.exec(text)) !== null) {
        // Plain text before this match
        if (match.index > lastIndex) {
            frag.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
        }
        const username = match[1];
        const span = document.createElement('span');
        const isMe = username.toLowerCase() === myUsername;
        span.className = 'mention' + (isMe ? ' me' : '');
        span.textContent = '@' + username;
        span.title = username;
        frag.appendChild(span);

        // If this mention is for the current user, trigger notification
        if (isMe && !isOwn) {
            _notifyMention();
        }

        lastIndex = re.lastIndex;
    }
    // Remaining text after last match
    if (lastIndex < text.length) {
        frag.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    el.appendChild(frag);
}

/** Play a subtle notification sound for @mention of current user */
let _lastMentionSound = 0;
function _notifyMention() {
    const now = Date.now();
    if (now - _lastMentionSound < 3000) return; // debounce 3s
    _lastMentionSound = now;
    try {
        const actx = new AudioContext();
        const osc = actx.createOscillator();
        const gain = actx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, actx.currentTime);
        osc.frequency.setValueAtTime(1100, actx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.15, actx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, actx.currentTime + 0.25);
        osc.connect(gain).connect(actx.destination);
        osc.start();
        osc.stop(actx.currentTime + 0.25);
    } catch {}
}

/**
 * Extracts @mentioned usernames from text.
 * @param {string} text
 * @returns {string[]} list of usernames (without @)
 */
function extractMentions(text) {
    if (!text || !text.includes('@')) return [];
    const mentions = [];
    const re = new RegExp(_MENTION_RE.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) mentions.push(m[1]);
    return [...new Set(mentions)];
}

// =========================================================================
// Swipe-to-reply gesture (mobile)
// =========================================================================
const _SWIPE_THRESHOLD   = 80;  // px to trigger reply
const _SWIPE_SHOW_ARROW  = 50;  // px to show arrow indicator
const _SWIPE_MAX         = 120; // max translate distance
const _VERTICAL_CANCEL   = 30;  // vertical tolerance before cancelling swipe

/**
 * Attaches swipe-to-reply touch handlers on a .msg-group element.
 * @param {HTMLElement} groupEl - the msg-group wrapper
 * @param {Object} msg - the full message object (passed to setReplyTo)
 */
function _attachSwipeReply(groupEl, msg) {
    let startX = 0, startY = 0, swiping = false, cancelled = false;

    // Create reply arrow indicator (hidden by default)
    const arrow = document.createElement('div');
    arrow.className = 'swipe-reply-arrow';
    arrow.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 24 24"><path d="M10 9V5l-7 7 7 7v-4.1c5 0 8.5 1.6 11 5.1-1-5-4-10-11-11z"/></svg>';
    groupEl.appendChild(arrow);

    groupEl.addEventListener('touchstart', (e) => {
        const touch = e.touches[0];
        startX    = touch.clientX;
        startY    = touch.clientY;
        swiping   = false;
        cancelled = false;
        groupEl.style.transition = 'none';
        arrow.style.transition   = 'none';
    }, { passive: true });

    groupEl.addEventListener('touchmove', (e) => {
        if (cancelled) return;
        const touch = e.touches[0];
        const dx = touch.clientX - startX;
        const dy = touch.clientY - startY;

        // Cancel if vertical movement exceeds tolerance
        if (!swiping && Math.abs(dy) > _VERTICAL_CANCEL) {
            cancelled = true;
            _resetSwipe(groupEl, arrow);
            return;
        }

        // Only track rightward swipe
        if (dx < 10) return;

        // Once horizontal movement is dominant, lock the swipe
        if (!swiping && dx > 10 && Math.abs(dx) > Math.abs(dy)) {
            swiping = true;
        }

        if (!swiping) return;

        // Prevent vertical scroll while swiping
        e.preventDefault();

        const clamped = Math.min(dx, _SWIPE_MAX);
        groupEl.style.transform = `translateX(${clamped}px)`;

        // Counter-translate arrow so it stays fixed at the left edge
        arrow.style.left = `${4 - clamped}px`;

        // Show/scale arrow indicator
        if (dx >= _SWIPE_SHOW_ARROW) {
            arrow.classList.add('visible');
            const progress = Math.min((dx - _SWIPE_SHOW_ARROW) / (_SWIPE_THRESHOLD - _SWIPE_SHOW_ARROW), 1);
            arrow.style.transform = `scale(${0.5 + progress * 0.5})`;
            arrow.style.opacity   = `${0.4 + progress * 0.6}`;
        } else {
            arrow.classList.remove('visible');
        }
    }, { passive: false });

    groupEl.addEventListener('touchend', () => {
        if (cancelled) return;

        const currentX = parseFloat(groupEl.style.transform?.replace(/[^\d.-]/g, '')) || 0;

        // Animate snap-back
        groupEl.style.transition = 'transform 0.25s ease';
        arrow.style.transition   = 'opacity 0.2s ease, transform 0.2s ease, left 0.25s ease';
        groupEl.style.transform  = '';
        arrow.classList.remove('visible');
        arrow.style.transform    = '';
        arrow.style.opacity      = '';
        arrow.style.left         = '';

        if (swiping && currentX >= _SWIPE_THRESHOLD) {
            // Haptic feedback if available
            if (navigator.vibrate) navigator.vibrate(15);
            window.setReplyTo(msg);
        }

        swiping = false;
    }, { passive: true });

    groupEl.addEventListener('touchcancel', () => {
        _resetSwipe(groupEl, arrow);
        swiping   = false;
        cancelled = false;
    }, { passive: true });
}

function _resetSwipe(groupEl, arrow) {
    groupEl.style.transition = 'transform 0.2s ease';
    groupEl.style.transform  = '';
    arrow.classList.remove('visible');
    arrow.style.transform    = '';
    arrow.style.opacity      = '';
    arrow.style.left         = '';
}

// Пути к иконкам для контекстного меню
const _ICON_REPLY  = '/static/elements/reply-svgrepo-com.svg';
const _ICON_EDIT   = '/static/elements/edit-svgrepo-com.svg';
const _ICON_DELETE = '/static/elements/delete-2-svgrepo-com.svg';
const _ICON_SAVE   = '/static/elements/edit-svgrepo-com.svg'; // reuse edit icon for save/bookmark

/**
 * Renders avatar HTML: photo if avatar_url exists, otherwise emoji fallback.
 * Clicking the avatar opens the user profile modal (for non-own messages).
 */
function _avatarHtml(msg) {
    const S = window.AppState;
    const isOwn = msg.sender_id && S?.user && (msg.sender_id === S.user.user_id || msg.sender_id === S.user.id);
    const clickAttr = (!isOwn && msg.sender_id)
        ? ` style="cursor:pointer;" onclick="window.openUserProfile(${msg.sender_id})"`
        : '';
    if (msg.avatar_url) {
        return `<div class="msg-avatar"${clickAttr}><img src="${esc(msg.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;"></div>`;
    }
    return `<div class="msg-avatar"${clickAttr}>${esc(msg.avatar_emoji || '\u{1F464}')}</div>`;
}

/**
 * Translate a message via /api/translate and show the result below the original text.
 */
async function _translateMessage(msg) {
    const msgEl = document.querySelector(`.msg-group[data-msg-id="${msg.msg_id}"]`);
    if (!msgEl) return;

    // Don't translate twice
    if (msgEl.querySelector('.msg-translation')) return;

    const textEl = msgEl.querySelector('.msg-text');
    if (!textEl) return;

    const rawText = msg.text || textEl.textContent || '';
    if (!rawText.trim()) return;

    const locale = (typeof window.getLocale === 'function' ? window.getLocale() : 'en').split('-')[0] || 'en';

    try {
        const resp = await fetch('/api/translate', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: rawText, source: 'auto', target: locale }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        const div = document.createElement('div');
        div.className = 'msg-translation';
        div.textContent = data.translatedText || '';
        const label = document.createElement('span');
        label.className = 'msg-translation-label';
        label.textContent = '\uD83C\uDF10 ' + (t('ctx.translationLabel') || 'Перевод');
        div.prepend(label, document.createTextNode(' '));

        // Insert after the text element inside the bubble
        const bubble = textEl.closest('.msg-bubble');
        if (bubble) {
            bubble.appendChild(div);
        }
    } catch (err) {
        console.warn('Translation failed:', err);
    }
}



// =============================================================================
// Вспомогательные функции для контекстного меню
// =============================================================================

/**
 * Гарантирует, что стили для контекстного меню присутствуют в head.
 * Также инициализирует liquid-glass (если ещё не).
 */
function _ensureContextMenuStyles() {
    if (document.getElementById('ctx-menu-style')) return;
    initLiquidGlass();

    const s = document.createElement('style');
    s.id = 'ctx-menu-style';
    s.textContent = `
    .ctx-backdrop {
        position: fixed;
        inset: 0;
        z-index: 9990;
        background: transparent;
    }

    .ctx-menu {
        position: fixed;
        z-index: 9999;
        min-width: 180px;
        border-radius: 14px;
        padding: 6px 0;
        overflow: hidden;
        animation: ctxFadeIn .14s ease;
    }
    @keyframes ctxFadeIn {
        from { opacity: 0; transform: scale(.92) translateY(-6px); }
        to   { opacity: 1; transform: scale(1)  translateY(0); }
    }

    .ctx-item {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 11px 16px;
        cursor: pointer;
        transition: background .12s;
        position: relative;
        z-index: 3;
        user-select: none;
        font-size: 14px;
        font-weight: 500;
        color: rgba(255, 255, 255, 0.88);
        letter-spacing: 0.01em;
    }
    .ctx-item:hover {
        background: rgba(255, 255, 255, 0.08);
    }
    .ctx-item:active {
        background: rgba(255, 255, 255, 0.14);
    }
    .ctx-item.danger {
        color: rgba(255, 90, 90, 0.90);
    }
    .ctx-item img {
        width: 18px;
        height: 18px;
        opacity: 0.78;
        filter: invert(1) brightness(1.2);
        flex-shrink: 0;
    }
    .ctx-item.danger img {
        filter: invert(35%) sepia(90%) saturate(500%) hue-rotate(320deg) brightness(1.1);
    }
    .ctx-divider {
        height: 1px;
        margin: 4px 12px;
        background: rgba(255, 255, 255, 0.10);
        position: relative;
        z-index: 3;
    }

    .msg-bubble {
        user-select: text;
        border-radius: 14px;
        padding: 10px 14px;
        max-width: 480px;
        width: fit-content;
        cursor: pointer;
    }
    .msg-bubble.own {
        margin-left: auto;
    }

    .msg-bubble .lg-reply {
        margin-bottom: 6px;
    }
    `;
    document.head.appendChild(s);
}

/**
 * Отображает контекстное меню для сообщения.
 *
 * @param {Event} e - событие, вызвавшее меню
 * @param {Object} msg - данные сообщения
 * @param {boolean} isOwn - является ли сообщение отправленным текущим пользователем
 */
function _showContextMenu(e, msg, isOwn) {
    e.stopPropagation();

    _closeContextMenu();

    const menu = document.createElement('div');
    menu.className = 'ctx-menu lg';

    const grain = document.createElement('div');
    grain.className = 'lg-grain';
    menu.appendChild(grain);

    const items = [];

    // Быстрые реакции (6 дефолтных + часто используемые + кнопка "+")
    const defaultEmojis = ['\uD83D\uDC4D', '\u2764\uFE0F', '\uD83D\uDE02', '\uD83D\uDE2E', '\uD83D\uDE22', '\uD83D\uDD25'];
    const recentReactions = _getRecentReactions();
    // Merge: recent first (up to 3), then fill with defaults to total 6
    const merged = [...new Set([...recentReactions.slice(0, 3), ...defaultEmojis])].slice(0, 6);
    items.push({
        type: 'reactions',
        emojis: merged,
        msgId: msg.msg_id,
    });

    items.push({ icon: _ICON_REPLY, label: t('ctx.reply'), danger: false, action: () => window.setReplyTo(msg) });

    // Тред
    if (msg.msg_id) {
        items.push({ icon: _ICON_REPLY, label: t('ctx.thread'), danger: false, action: () => window.openThread(msg.msg_id) });
    }

    // Переслать
    items.push({ icon: _ICON_REPLY, label: t('ctx.forward'), danger: false, action: () => window.showForwardModal(msg.msg_id) });

    // Перевести
    if (msg.text && localStorage.getItem('vortex_translate_enabled') === 'true') {
        items.push({ icon: _ICON_EDIT, label: '\uD83C\uDF10 ' + (t('ctx.translate') || 'Перевести'), danger: false, action: () => _translateMessage(msg) });
    }

    // В избранное (toggle)
    if (msg.msg_id) {
        items.push({ icon: _ICON_SAVE, label: '\u2B50 ' + t('ctx.addToSaved'), danger: false, action: () => window.toggleSavedMessage(msg.msg_id) });
    }

    // Закрепить (если есть msg_id)
    if (msg.msg_id) {
        items.push({ icon: _ICON_EDIT, label: t('ctx.pin'), danger: false, action: () => {
            const S = window.AppState;
            if (S.ws?.readyState === WebSocket.OPEN) {
                S.ws.send(JSON.stringify({action: 'pin_message', msg_id: msg.msg_id}));
            }
        }});
    }

    if (isOwn && (!msg.msg_type || msg.msg_type === 'text')) {
        items.push({ icon: _ICON_EDIT, label: t('ctx.edit'), danger: false, action: () => window.startEditMessage(msg) });
    }

    if (isOwn) {
        items.push({ divider: true });
        items.push({ icon: _ICON_DELETE, label: t('ctx.delete'), danger: true, action: () => window.deleteMessage(msg.msg_id) });
    }

    // Напомнить
    if (msg.msg_id) {
        items.push({ icon: _ICON_SAVE, label: '🔔 ' + (t('ctx.remind') || 'Напомнить'), danger: false, action: () => _showReminderModal(msg) });
    }

    // Report button (for messages from other users)
    if (!isOwn && msg.sender_id) {
        items.push({ divider: true });
        items.push({
            icon: _ICON_DELETE,
            label: t('ctx.report'),
            danger: true,
            action: () => {
                if (typeof window.showReportModal === 'function') {
                    window.showReportModal(msg.sender_id, msg.msg_id);
                }
            },
        });
    }

    items.forEach(item => {
        if (item.divider) {
            const d = document.createElement('div');
            d.className = 'ctx-divider';
            menu.appendChild(d);
            return;
        }
        if (item.type === 'reactions') {
            const row = document.createElement('div');
            row.className = 'ctx-reactions-row';
            row.style.cssText = 'display:flex;gap:4px;padding:8px 12px;justify-content:center;position:relative;z-index:3;align-items:center;';
            item.emojis.forEach(emoji => {
                const eb = document.createElement('span');
                eb.className = 'ctx-react-btn';
                eb.textContent = emoji;
                eb.style.cssText = 'font-size:20px;cursor:pointer;padding:4px 6px;border-radius:8px;transition:all .12s;';
                eb.onmouseenter = () => { eb.style.background = 'rgba(255,255,255,0.1)'; eb.style.transform = 'scale(1.25)'; };
                eb.onmouseleave = () => { eb.style.background = ''; eb.style.transform = ''; };
                eb.addEventListener('click', (ev) => {
                    ev.stopPropagation();
                    _closeContextMenu();
                    _sendReaction(item.msgId, emoji);
                });
                row.appendChild(eb);
            });

            // "+" button → opens full emoji picker for custom reaction
            const plusBtn = document.createElement('span');
            plusBtn.className = 'ctx-react-plus';
            plusBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>';
            plusBtn.title = t('ctx.moreEmoji');
            plusBtn.addEventListener('click', (ev) => {
                ev.stopPropagation();
                _closeContextMenu();
                _openReactionPicker(item.msgId);
            });
            row.appendChild(plusBtn);

            menu.appendChild(row);
            const d = document.createElement('div');
            d.className = 'ctx-divider';
            menu.appendChild(d);
            return;
        }
        const btn = document.createElement('div');
        btn.className = `ctx-item${item.danger ? ' danger' : ''}`;
        btn.innerHTML = `<img src="${item.icon}" alt=""><span>${item.label}</span>`;
        btn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            _closeContextMenu();
            item.action();
        });
        menu.appendChild(btn);
    });

    document.body.appendChild(menu);

    const bubbleEl = e.currentTarget || e.target.closest('.msg-bubble') || e.target;
    const rect = bubbleEl.getBoundingClientRect
        ? bubbleEl.getBoundingClientRect()
        : { left: e.clientX, top: e.clientY, right: e.clientX, bottom: e.clientY };

    const mw = 190, mh = items.length * 44;
    let x, y;

    if (isOwn) {
        x = rect.left - mw - 8;
        if (x < 8) x = rect.right + 8;
    } else {
        x = rect.right + 8;
        if (x + mw > window.innerWidth - 8) x = rect.left - mw - 8;
    }

    y = rect.top;
    if (y + mh > window.innerHeight - 8) y = window.innerHeight - mh - 8;
    if (y < 8) y = 8;

    menu.style.left = x + 'px';
    menu.style.top  = y + 'px';

    const backdrop = document.createElement('div');
    backdrop.className = 'ctx-backdrop';
    backdrop.id = 'ctx-backdrop';
    backdrop.addEventListener('click', _closeContextMenu);
    document.body.insertBefore(backdrop, menu);
}

/**
 * Закрывает контекстное меню (удаляет backdrop и все меню).
 */
function _closeContextMenu() {
    document.getElementById('ctx-backdrop')?.remove();
    document.querySelectorAll('.ctx-menu').forEach(m => m.remove());
}

// =============================================================================
// Reminder (напоминание о сообщении)
// =============================================================================

const _REMINDER_KEY = 'vortex_reminders';

function _loadReminders() {
    try { return JSON.parse(localStorage.getItem(_REMINDER_KEY) || '[]'); } catch { return []; }
}
function _saveReminders(list) {
    localStorage.setItem(_REMINDER_KEY, JSON.stringify(list));
}

function _showReminderModal(msg) {
    document.getElementById('vx-reminder-modal')?.remove();

    const presets = [
        { label: 'Через 20 минут', mins: 20 },
        { label: 'Через 1 час',    mins: 60 },
        { label: 'Через 2 часа',   mins: 120 },
        { label: 'Через 4 часа',   mins: 240 },
        { label: 'Завтра утром',   mins: null, special: 'tomorrow' },
    ];

    const overlay = document.createElement('div');
    overlay.id = 'vx-reminder-modal';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.45);backdrop-filter:blur(4px);';

    const box = document.createElement('div');
    box.className = 'lg';
    box.style.cssText = 'min-width:280px;max-width:340px;width:90%;border-radius:16px;padding:20px;position:relative;';
    box.innerHTML = '<div class="lg-grain"></div>';

    const title = document.createElement('div');
    title.style.cssText = 'font-weight:600;font-size:15px;margin-bottom:14px;position:relative;z-index:2;';
    title.textContent = '🔔 Напомнить о сообщении';
    box.appendChild(title);

    const preview = document.createElement('div');
    preview.style.cssText = 'font-size:12px;color:var(--text2);margin-bottom:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%;position:relative;z-index:2;';
    preview.textContent = msg.text ? msg.text.slice(0, 60) + (msg.text.length > 60 ? '…' : '') : '(медиа-сообщение)';
    box.appendChild(preview);

    presets.forEach(p => {
        const btn = document.createElement('button');
        btn.className = 'btn btn-secondary';
        btn.style.cssText = 'width:100%;margin-bottom:8px;text-align:left;position:relative;z-index:2;';
        btn.textContent = p.label;
        btn.onclick = () => {
            let remindAt;
            if (p.special === 'tomorrow') {
                const d = new Date(); d.setDate(d.getDate() + 1); d.setHours(9, 0, 0, 0);
                remindAt = d.getTime();
            } else {
                remindAt = Date.now() + p.mins * 60 * 1000;
            }
            _scheduleReminder(msg, remindAt);
            overlay.remove();
        };
        box.appendChild(btn);
    });

    // Своё время
    const customRow = document.createElement('div');
    customRow.style.cssText = 'display:flex;gap:8px;margin-top:4px;position:relative;z-index:2;';
    const customInput = document.createElement('input');
    customInput.type = 'datetime-local';
    customInput.className = 'form-input';
    customInput.style.cssText = 'flex:1;font-size:13px;';
    const now = new Date(); now.setMinutes(now.getMinutes() + 30);
    customInput.value = now.toISOString().slice(0, 16);
    const customBtn = document.createElement('button');
    customBtn.className = 'btn btn-primary';
    customBtn.textContent = 'OK';
    customBtn.onclick = () => {
        const ts = new Date(customInput.value).getTime();
        if (!ts || ts <= Date.now()) { customInput.style.borderColor = 'var(--red)'; return; }
        _scheduleReminder(msg, ts);
        overlay.remove();
    };
    customRow.appendChild(customInput);
    customRow.appendChild(customBtn);
    box.appendChild(customRow);

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-ghost';
    cancelBtn.style.cssText = 'width:100%;margin-top:10px;position:relative;z-index:2;';
    cancelBtn.textContent = 'Отмена';
    cancelBtn.onclick = () => overlay.remove();
    box.appendChild(cancelBtn);

    overlay.appendChild(box);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);
}

function _scheduleReminder(msg, remindAt) {
    const reminders = _loadReminders();
    const entry = {
        id: `r_${msg.msg_id}_${Date.now()}`,
        msg_id: msg.msg_id,
        room_id: window.AppState?.currentRoom?.id,
        text: msg.text ? msg.text.slice(0, 100) : '(медиа)',
        remind_at: remindAt,
    };
    reminders.push(entry);
    _saveReminders(reminders);

    const delay = remindAt - Date.now();
    setTimeout(() => _fireReminder(entry.id), delay);

    // Показать тост с подтверждением
    const d = new Date(remindAt);
    const label = d.toLocaleString('ru', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    if (window.showToast) window.showToast(`🔔 Напомним ${label}`);
}

function _fireReminder(reminderId) {
    const reminders = _loadReminders();
    const entry = reminders.find(r => r.id === reminderId);
    if (!entry) return;
    _saveReminders(reminders.filter(r => r.id !== reminderId));

    // Web Notification
    const notify = () => {
        new Notification('🔔 Напоминание — Vortex', {
            body: entry.text,
            icon: '/static/icons/icon-192.png',
            tag: reminderId,
        });
    };

    if (Notification.permission === 'granted') {
        notify();
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(p => { if (p === 'granted') notify(); });
    }

    // In-app баннер
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);z-index:9999;' +
        'background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 18px;' +
        'box-shadow:0 4px 24px rgba(0,0,0,.3);display:flex;align-items:center;gap:12px;max-width:360px;cursor:pointer;';
    banner.innerHTML = `<span style="font-size:22px;">🔔</span><div><div style="font-weight:600;font-size:13px;">Напоминание</div><div style="font-size:12px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:260px;">${entry.text}</div></div>`;
    banner.onclick = () => {
        banner.remove();
        // Перейти к комнате если доступно
        if (entry.room_id && window.openRoomById) window.openRoomById(entry.room_id);
        if (entry.msg_id) {
            const el = document.getElementById(`msg-${entry.msg_id}`);
            if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.style.animation = 'msg-highlight 1.5s ease'; }
        }
    };
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 8000);
}

// Восстановить напоминания после перезагрузки страницы
(function _restoreReminders() {
    const reminders = _loadReminders();
    const now = Date.now();
    const still = [];
    reminders.forEach(r => {
        const delay = r.remind_at - now;
        if (delay > 0) {
            setTimeout(() => _fireReminder(r.id), delay);
            still.push(r);
        } else if (delay > -3600000) {
            // Пропущенное за последний час — показать сразу
            _fireReminder(r.id);
        }
    });
    _saveReminders(still);
})();

// =============================================================================
// История редактирования сообщений
// =============================================================================

async function _showEditHistory(msgId, roomId) {
    if (!roomId) return;
    document.getElementById('vx-edit-history-modal')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'vx-edit-history-modal';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.45);backdrop-filter:blur(4px);';

    const box = document.createElement('div');
    box.className = 'lg';
    box.style.cssText = 'min-width:300px;max-width:420px;width:92%;border-radius:16px;padding:20px;position:relative;max-height:80vh;overflow-y:auto;';
    box.innerHTML = '<div class="lg-grain"></div>';

    const title = document.createElement('div');
    title.style.cssText = 'font-weight:600;font-size:15px;margin-bottom:14px;position:relative;z-index:2;';
    title.textContent = '📋 История изменений';
    box.appendChild(title);

    const loading = document.createElement('div');
    loading.style.cssText = 'color:var(--text2);font-size:13px;position:relative;z-index:2;';
    loading.textContent = 'Загрузка...';
    box.appendChild(loading);

    overlay.appendChild(box);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);

    try {
        const resp = await fetch(`/api/rooms/${roomId}/messages/${msgId}/history`, { credentials: 'include' });
        if (!resp.ok) throw new Error('Ошибка ' + resp.status);
        const data = await resp.json();
        loading.remove();

        const versions = [...(data.history || []), { ciphertext_hex: data.current?.ciphertext_hex, edited_at: data.current?.edited_at, is_current: true }];

        if (versions.length === 1 && !data.history?.length) {
            const empty = document.createElement('div');
            empty.style.cssText = 'color:var(--text2);font-size:13px;position:relative;z-index:2;';
            empty.textContent = 'История изменений пуста.';
            box.appendChild(empty);
        } else {
            versions.reverse().forEach((v, i) => {
                const row = document.createElement('div');
                row.style.cssText = 'position:relative;z-index:2;margin-bottom:10px;padding:10px;border-radius:10px;background:rgba(255,255,255,0.05);border:1px solid var(--border);';

                const label = document.createElement('div');
                label.style.cssText = 'font-size:11px;color:var(--text3);margin-bottom:4px;display:flex;justify-content:space-between;';
                const timeStr = v.edited_at ? new Date(v.edited_at).toLocaleString('ru', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';
                label.innerHTML = `<span>${v.is_current ? '✅ Текущая версия' : `Версия ${versions.length - i}`}</span><span>${timeStr}</span>`;
                row.appendChild(label);

                const cipher = document.createElement('div');
                cipher.style.cssText = 'font-size:11px;font-family:var(--mono);color:var(--text2);word-break:break-all;overflow:hidden;max-height:60px;';
                cipher.textContent = v.ciphertext_hex ? v.ciphertext_hex.slice(0, 120) + (v.ciphertext_hex.length > 120 ? '…' : '') : '(зашифровано)';
                cipher.title = 'Зашифрованный текст (E2E). Расшифровка на стороне клиента.';
                row.appendChild(cipher);

                box.appendChild(row);
            });
        }
    } catch (e) {
        loading.textContent = 'Ошибка загрузки: ' + e.message;
    }

    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn btn-ghost';
    closeBtn.style.cssText = 'width:100%;margin-top:10px;position:relative;z-index:2;';
    closeBtn.textContent = 'Закрыть';
    closeBtn.onclick = () => overlay.remove();
    box.appendChild(closeBtn);
}

// =============================================================================
// Вспомогательная функция для создания блока цитаты (reply)
// =============================================================================

/**
 * Создаёт элемент-цитату с помощью liquid-glass.
 *
 * @param {string} replyToId - ID цитируемого сообщения
 * @param {string} replyToText - текст цитируемого сообщения
 * @param {string} replyToSender - отправитель цитаты
 * @param {boolean} isOwn - флаг «своё» сообщение (для цвета)
 * @returns {HTMLElement} - элемент цитаты
 */
function _buildReplyQuote(replyToId, replyToText, replyToSender, isOwn = false) {
    const quote = createReplyQuote(
        replyToSender || '?',
        _truncate(replyToText, 80),
        isOwn,
        () => _scrollToMsg(replyToId)
    );
    return quote;
}

// =============================================================================
// Публичные функции для управления сообщениями
// =============================================================================

/**
 * Сбрасывает состояние группировки (дата, автор) и очищает карту элементов.
 */

export {
    _maybeAttachLinkPreview, _buildPreviewCard, _renderBotMarkdown,
    _renderTextWithMentions, _notifyMention, extractMentions,
    _attachSwipeReply, _resetSwipe, _avatarHtml, _translateMessage,
    _ensureContextMenuStyles, _showContextMenu, _closeContextMenu,
    _loadReminders, _saveReminders, _showReminderModal, _scheduleReminder,
    _fireReminder, _showEditHistory, _buildReplyQuote,
};

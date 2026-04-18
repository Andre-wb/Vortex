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
import { _getRecentReactions, _openReactionPicker, _sendReaction } from './reactions.js';


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

// Инлайновые SVG-иконки для контекстного меню
const _SVG = (d, size = 18) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;

const _ICON_REPLY    = _SVG('<polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>');
const _ICON_COPY     = _SVG('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>');
const _ICON_THREAD   = _SVG('<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>');
const _ICON_FORWARD  = _SVG('<polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>');
const _ICON_QUOTE    = _SVG('<path d="M3 21c3 0 7-1 7-8V5c0-1.25-.756-2.017-2-2H4c-1.25 0-2 .75-2 1.972V11c0 1.25.75 2 2 2 1 0 1 0 1 1v1c0 1-1 2-2 2s-1 .008-1 1.031V21z"/><path d="M15 21c3 0 7-1 7-8V5c0-1.25-.757-2.017-2-2h-4c-1.25 0-2 .75-2 1.972V11c0 1.25.75 2 2 2h.75c0 2.25.25 4-2.75 5v3z"/>');
const _ICON_SAVE     = _SVG('<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>');
const _ICON_PIN      = _SVG('<path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16h14v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 2-2H6a2 2 0 0 0 2 2 1 1 0 0 1 1 1z"/>');
const _ICON_EDIT     = _SVG('<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>');
const _ICON_DELETE   = _SVG('<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>');
const _ICON_TRANSLATE = _SVG('<path d="M5 8l6 10"/><path d="M4 14h6"/><path d="M2 5h12"/><path d="M7 2v3"/><path d="M22 22l-5-10-5 10"/><path d="M14 18h6"/>');
const _ICON_REMIND   = _SVG('<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>');
const _ICON_REPORT   = _SVG('<path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86L7.86 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>');
const _ICON_SELECT   = _SVG('<polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>');
const _ICON_TASK     = _SVG('<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>');
const _ICON_TAG      = _SVG('<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>');

// Legacy — для совместимости
const _ICON_REPLY_PATH = '/static/elements/reply-svgrepo-com.svg';
const _ICON_EDIT_PATH  = '/static/elements/edit-svgrepo-com.svg';
const _ICON_DELETE_PATH = '/static/elements/delete-2-svgrepo-com.svg';

/**
 * Renders avatar HTML: photo if avatar_url exists, otherwise emoji fallback.
 * Clicking the avatar opens the user profile modal.
 * If the user has active stories, a blue ring is shown around the avatar.
 */
function _avatarHtml(msg) {
    const clickAttr = msg.sender_id
        ? ` style="cursor:pointer;" onclick="window.openUserProfile(${msg.sender_id})"`
        : '';
    // Story ring: check if this sender has active stories
    const hasStory = msg.sender_id && window._storyUserIds?.has(msg.sender_id);
    const ringClass = hasStory ? ' msg-avatar-story' : '';
    if (msg.avatar_url) {
        return `<div class="msg-avatar${ringClass}"${clickAttr}><img src="${esc(msg.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;"></div>`;
    }
    return `<div class="msg-avatar${ringClass}"${clickAttr}>${esc(msg.avatar_emoji || '\u{1F464}')}</div>`;
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
        label.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:2px;"><path d="M5 8l6 10M4 14h6M2 5h12M7 2v3M22 22l-5-10-5 10M14 18h6"/></svg>' + t('chat.translation');
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

// Translate modal — выбор языка
const _TRANSLATE_LANGS = [
    { code: 'ru', flag: '🇷🇺', name: 'Русский' },
    { code: 'en', flag: '🇬🇧', name: 'English' },
    { code: 'es', flag: '🇪🇸', name: 'Español' },
    { code: 'fr', flag: '🇫🇷', name: 'Français' },
    { code: 'de', flag: '🇩🇪', name: 'Deutsch' },
    { code: 'zh', flag: '🇨🇳', name: '中文' },
    { code: 'ja', flag: '🇯🇵', name: '日本語' },
    { code: 'ko', flag: '🇰🇷', name: '한국어' },
    { code: 'ar', flag: '🇸🇦', name: 'العربية' },
    { code: 'pt', flag: '🇧🇷', name: 'Português' },
    { code: 'it', flag: '🇮🇹', name: 'Italiano' },
    { code: 'tr', flag: '🇹🇷', name: 'Türkçe' },
    { code: 'hi', flag: '🇮🇳', name: 'हिन्दी' },
    { code: 'uk', flag: '🇺🇦', name: 'Українська' },
];

function _showTranslateModal(msg) {
    // Убираем старую модалку
    document.getElementById('translate-lang-modal')?.remove();

    const backdrop = document.createElement('div');
    backdrop.id = 'translate-lang-modal';
    backdrop.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;animation:vxFadeIn .15s ease;';

    const box = document.createElement('div');
    box.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:20px;min-width:280px;max-width:360px;width:90vw;box-shadow:0 16px 48px rgba(0,0,0,.4);animation:vxSlideUp .2s ease;';

    const title = document.createElement('div');
    title.style.cssText = 'font-size:15px;font-weight:600;color:var(--text);margin-bottom:14px;display:flex;align-items:center;gap:8px;';
    title.textContent = t('chat.translate');

    const grid = document.createElement('div');
    grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:6px;max-height:50vh;overflow-y:auto;';

    const lastLang = localStorage.getItem('vortex_translate_lang') || 'en';

    for (const lang of _TRANSLATE_LANGS) {
        const btn = document.createElement('button');
        const isActive = lang.code === lastLang;
        btn.style.cssText = `display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:10px;border:1px solid ${isActive ? 'var(--accent)' : 'transparent'};background:${isActive ? 'rgba(124,58,237,.12)' : 'var(--bg3)'};cursor:pointer;color:var(--text);font-size:13px;transition:all .12s;`;
        btn.onmouseenter = () => { btn.style.background = 'rgba(124,58,237,.15)'; };
        btn.onmouseleave = () => { btn.style.background = isActive ? 'rgba(124,58,237,.12)' : 'var(--bg3)'; };
        btn.textContent = `${lang.flag} ${lang.name}`;
        btn.addEventListener('click', () => {
            localStorage.setItem('vortex_translate_lang', lang.code);
            backdrop.remove();
            _translateMessageToLang(msg, lang.code, lang.name);
        });
        grid.appendChild(btn);
    }

    box.append(title, grid);
    backdrop.appendChild(box);
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
    document.body.appendChild(backdrop);
}

async function _translateMessageToLang(msg, langCode, langName) {
    const msgEl = document.querySelector(`.msg-group[data-msg-id="${msg.msg_id}"]`);
    if (!msgEl) return;

    msgEl.querySelector('.msg-translation')?.remove();

    const textEl = msgEl.querySelector('.msg-text');
    if (!textEl) return;
    const rawText = msg.text || textEl.textContent || '';
    if (!rawText.trim()) return;

    const loader = document.createElement('div');
    loader.className = 'msg-translation';
    loader.style.cssText = 'opacity:0.5;';
    loader.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite;vertical-align:middle;margin-right:4px;"><path d="M21 12a9 9 0 11-6.22-8.56"/></svg>' + t('chat.translation') + '...';
    const bubble = textEl.closest('.msg-bubble');
    if (bubble) bubble.appendChild(loader);

    try {
        const resp = await fetch('/api/translate', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: rawText, source: 'auto', target: langCode }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        // Красивая анимация появления перевода
        loader.style.transition = 'all 0.3s ease';
        loader.style.opacity = '0';
        setTimeout(() => {
            loader.textContent = '';
            const label = document.createElement('span');
            label.className = 'msg-translation-label';
            label.textContent = `→ ${langName}`;
            loader.appendChild(label);
            loader.appendChild(document.createTextNode(' ' + (data.translatedText || data.translated_text || '')));
            loader.style.opacity = '1';
        }, 200);
    } catch (err) {
        loader.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' + (err.message || t('errors.translationFailed'));
        loader.style.color = 'var(--red)';
        setTimeout(() => loader.remove(), 3000);
    }
}


// Chat-wide translate language picker (called from translate bar)
window._showChatTranslateLangPicker = function(roomId, bar) {
    document.getElementById('translate-lang-modal')?.remove();

    const backdrop = document.createElement('div');
    backdrop.id = 'translate-lang-modal';
    backdrop.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;animation:vxFadeIn .15s ease;';

    const box = document.createElement('div');
    box.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:20px;min-width:280px;max-width:360px;width:90vw;box-shadow:0 16px 48px rgba(0,0,0,.4);animation:vxSlideUp .2s ease;';

    const title = document.createElement('div');
    title.style.cssText = 'font-size:15px;font-weight:600;color:var(--text);margin-bottom:14px;';
    title.textContent = t('chat.translateTo');

    const grid = document.createElement('div');
    grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:6px;max-height:50vh;overflow-y:auto;';

    const lastLang = localStorage.getItem('vortex_translate_lang') || 'en';

    for (const lang of _TRANSLATE_LANGS) {
        const btn = document.createElement('button');
        const isLast = lang.code === lastLang;
        btn.style.cssText = 'display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:10px;border:1px solid ' + (isLast ? 'var(--accent)' : 'transparent') + ';background:' + (isLast ? 'rgba(124,58,237,.12)' : 'var(--bg3)') + ';cursor:pointer;color:var(--text);font-size:13px;transition:all .12s;';
        btn.textContent = lang.flag + ' ' + lang.name;
        btn.addEventListener('click', () => {
            localStorage.setItem('vortex_translate_lang', lang.code);
            localStorage.setItem('vortex_translate_active_' + roomId, '1');
            if (bar) bar.classList.add('active');
            backdrop.remove();
            window.showToast?.(t('chat.translationEnabled', {lang: lang.name}), 'success');
        });
        grid.appendChild(btn);
    }

    box.append(title, grid);
    backdrop.appendChild(box);
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
    document.body.appendChild(backdrop);
};

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
        gap: 10px;
        padding: 9px 14px;
        cursor: pointer;
        transition: background .12s;
        position: relative;
        z-index: 3;
        user-select: none;
        font-size: 13px;
        font-weight: 500;
        color: rgba(255, 255, 255, 0.85);
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
    .ctx-item .ctx-icon {
        width: 18px;
        height: 18px;
        flex-shrink: 0;
        opacity: 0.7;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .ctx-item .ctx-icon svg {
        color: rgba(255, 255, 255, 0.8);
    }
    .ctx-item.danger .ctx-icon svg {
        color: rgba(255, 90, 90, 0.85);
    }
    /* Legacy img icons */
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
        margin: 3px 12px;
        background: rgba(255, 255, 255, 0.08);
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

    .ctx-reactions-row {
        display: flex;
        gap: 2px;
        padding: 6px 10px;
        justify-content: center;
        position: relative;
        z-index: 3;
        align-items: center;
    }
    .ctx-react-btn {
        font-size: 22px;
        cursor: pointer;
        padding: 4px 5px;
        border-radius: 8px;
        transition: all .12s;
        line-height: 1;
    }
    .ctx-react-btn:hover {
        background: rgba(255,255,255,0.1);
        transform: scale(1.3);
    }
    .ctx-react-plus {
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        padding: 4px;
        margin-left: 2px;
        border-radius: 50%;
        color: rgba(255,255,255,0.5);
        transition: all .15s;
    }
    .ctx-react-plus:hover {
        background: rgba(255,255,255,0.1);
        color: rgba(255,255,255,0.8);
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
    const _isStickerMsg = msg.text && msg.text.startsWith('[STICKER] ');
    const _isGifMsg = msg.text && msg.text.startsWith('[GIF] ');
    const _isMediaOnly = _isStickerMsg || _isGifMsg;

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

    items.push({ svg: _ICON_REPLY, label: t('ctx.reply'), action: () => window.setReplyTo(msg) });

    // Копировать текст (not for stickers/GIF)
    if (msg.text && !_isMediaOnly) {
        items.push({ svg: _ICON_COPY, label: t('ctx.copy'), action: () => {
            navigator.clipboard.writeText(msg.text).then(() => {
                if (typeof window.showToast === 'function') window.showToast(t('ctx.copied') || 'Copied', 'success');
            }).catch(() => {});
        }});
    }

    // Цитировать выделенный текст (not for stickers/GIF)
    if (!_isMediaOnly) {
        const _sel = window.getSelection();
        const _selectedText = _sel && _sel.toString().trim();
        if (_selectedText) {
            items.push({ svg: _ICON_QUOTE, label: t('ctx.quote'), action: () => {
                window.setReplyTo(msg, _selectedText);
            }});
        }
    }

    // Тред (not for stickers/GIF)
    if (msg.msg_id && !_isMediaOnly) {
        items.push({ svg: _ICON_THREAD, label: t('ctx.thread'), action: () => window.openThread(msg.msg_id) });
    }

    // Переслать
    items.push({ svg: _ICON_FORWARD, label: t('ctx.forward'), action: () => window.showForwardModal(msg.msg_id) });

    // Добавить в GIF (для gif файлов)
    if (msg.file_name && msg.file_name.toLowerCase().endsWith('.gif') && msg.download_url) {
        items.push({
            svg: _SVG('<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>'),
            label: t('ctx.addToGif'),
            action: async () => {
                const url = msg.download_url;
                try {
                    // Decrypt the GIF
                    const resp = await fetch(url, { credentials: 'include' });
                    let data = await resp.arrayBuffer();
                    const { getRoomKey, decryptFile } = await import('../../crypto.js');
                    const rk = getRoomKey(window.AppState?.currentRoom?.id);
                    if (rk && data.byteLength > 28) {
                        try { data = await decryptFile(data, rk); } catch {}
                    }
                    // Upload decrypted GIF to server saved collection
                    const blob = new Blob([data], { type: 'image/gif' });
                    const fd = new FormData();
                    fd.append('file', blob, 'saved.gif');
                    const csrf = window.AppState?.csrfToken;
                    const headers = {};
                    if (csrf) headers['X-CSRF-Token'] = csrf;
                    const saveResp = await fetch('/api/gifs/saved', { method: 'POST', credentials: 'include', headers, body: fd });
                    if (saveResp.ok) {
                        window.showToast?.(t('chat.gifSaved'), 'success');
                    } else {
                        const err = await saveResp.json().catch(() => ({}));
                        window.showToast?.(err.detail || t('errors.saveFailed'), 'error');
                    }
                } catch (e) {
                    console.warn('Save GIF error:', e);
                    window.showToast?.(t('errors.gifSaveFailed'), 'error');
                }
            },
        });
    }

    // Добавить в стикеры (для изображений)
    if (msg.download_url && msg.mime_type && msg.mime_type.startsWith('image/')) {
        items.push({
            svg: _SVG('<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>'),
            label: t('ctx.addToStickers'),
            action: () => window.addImageToStickers?.(msg.download_url, msg.file_name),
        });
    }

    // Перевести (not for stickers/GIF)
    if (msg.text && !_isMediaOnly) {
        items.push({ svg: _ICON_TRANSLATE, label: t('ctx.translate'), action: () => _showTranslateModal(msg) });
    }

    // В избранное / Убрать из избранного (not for stickers/GIF)
    if (msg.msg_id && !_isMediaOnly) {
        const _savedSet = window._savedMsgIds || new Set();
        const _isSaved = _savedSet.has(msg.msg_id);
        items.push({
            svg: _isSaved ? _SVG('<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" fill="currentColor" stroke="currentColor"/>') : _ICON_SAVE,
            label: _isSaved ? t('ctx.removeFromSaved') : t('ctx.addToSaved'),
            action: () => {
                window.toggleSavedMessage(msg.msg_id);
                if (_isSaved) _savedSet.delete(msg.msg_id); else _savedSet.add(msg.msg_id);
            }
        });
    }

    // Закрепить (not for stickers/GIF)
    if (msg.msg_id && !_isMediaOnly) {
        items.push({ svg: _ICON_PIN, label: t('ctx.pin'), action: () => {
            const S = window.AppState;
            if (S.ws?.readyState === WebSocket.OPEN) {
                S.ws.send(JSON.stringify({action: 'pin_message', msg_id: msg.msg_id}));
            }
        }});
    }

    if (isOwn && (!msg.msg_type || msg.msg_type === 'text') && !_isMediaOnly) {
        items.push({ svg: _ICON_EDIT, label: t('ctx.edit'), action: () => window.startEditMessage(msg) });
    }

    // Напомнить (not for stickers/GIF)
    if (msg.msg_id && !_isMediaOnly) {
        items.push({ svg: _ICON_REMIND, label: t('ctx.remind'), action: () => _showReminderModal(msg) });
    }

    // Add Task (admin/owner only, for text messages)
    {
        const _roomTask = window.AppState?.currentRoom;
        const isAdminOrOwner = _roomTask?.my_role === 'owner'
            || _roomTask?.my_role === 'admin'
            || _roomTask?.is_owner
            || _roomTask?.is_admin;
        if (isAdminOrOwner && msg.msg_id && !_isMediaOnly) {
            items.push({ svg: _ICON_TASK, label: t('ctx.addTask'), action: () => {
                window._addTaskFromMessage?.(msg);
            }});
        }
        // Set Tag (admin/owner — assign a visible tag/badge to the message sender)
        if (isAdminOrOwner && msg.sender_id) {
            items.push({ svg: _ICON_TAG, label: t('ctx.setTag'), action: () => {
                window._showTagPicker?.(msg.sender_id, msg.tag, msg.tag_color);
            }});
        }
    }

    items.push({ divider: true });

    // Delete
    const _room = window.AppState?.currentRoom;
    const canDelete = isOwn
        || _room?.my_role === 'owner'
        || _room?.my_role === 'admin'
        || _room?.is_owner
        || _room?.is_admin;
    if (canDelete) {
        items.push({ svg: _ICON_DELETE, label: t('ctx.delete'), danger: true, action: () => window.deleteMessage(msg.msg_id) });
    }

    // Пожаловаться
    if (!isOwn && msg.sender_id) {
        items.push({
            svg: _ICON_REPORT,
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
            item.emojis.forEach(emoji => {
                const eb = document.createElement('span');
                eb.className = 'ctx-react-btn';
                eb.textContent = emoji;
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
        if (item.svg) {
            // SVG icons are static constants, safe to use innerHTML
            btn.innerHTML = `<span class="ctx-icon">${item.svg}</span><span>${item.label}</span>`;
        } else if (item.icon) {
            btn.innerHTML = `<img src="${item.icon}" alt=""><span>${item.label}</span>`;
        } else {
            btn.textContent = item.label;
        }
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
        { label: t('reminder.in20min'), mins: 20 },
        { label: t('reminder.in1hour'),    mins: 60 },
        { label: t('reminder.in2hours'),   mins: 120 },
        { label: t('reminder.in4hours'),   mins: 240 },
        { label: t('reminder.tomorrowMorning'),   mins: null, special: 'tomorrow' },
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
    title.textContent = t('reminder.remindAboutMessage');
    box.appendChild(title);

    const preview = document.createElement('div');
    preview.style.cssText = 'font-size:12px;color:var(--text2);margin-bottom:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%;position:relative;z-index:2;';
    preview.textContent = msg.text ? msg.text.slice(0, 60) + (msg.text.length > 60 ? '…' : '') : t('chat.mediaMessage');
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
    customBtn.textContent = (typeof t==='function'?t('app.ok'):'OK');
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
    cancelBtn.textContent = t('common.cancel');
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
        text: msg.text ? msg.text.slice(0, 100) : t('chat.media'),
        remind_at: remindAt,
    };
    reminders.push(entry);
    _saveReminders(reminders);

    const delay = remindAt - Date.now();
    setTimeout(() => _fireReminder(entry.id), delay);

    // Показать тост с подтверждением
    const d = new Date(remindAt);
    const label = d.toLocaleString('ru', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    if (window.showToast) window.showToast(t('reminder.willRemind', {time: label}));
}

function _fireReminder(reminderId) {
    const reminders = _loadReminders();
    const entry = reminders.find(r => r.id === reminderId);
    if (!entry) return;
    _saveReminders(reminders.filter(r => r.id !== reminderId));

    // Web Notification
    const notify = () => {
        new Notification(t('reminder.notificationTitle'), {
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
    banner.innerHTML = `<span style="font-size:22px;">🔔</span><div><div style="font-weight:600;font-size:13px;">${t('reminder.reminder')}</div><div style="font-size:12px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:260px;">${entry.text}</div></div>`;
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
    title.textContent = t('chat.editHistory');
    box.appendChild(title);

    const loading = document.createElement('div');
    loading.style.cssText = 'color:var(--text2);font-size:13px;position:relative;z-index:2;';
    loading.textContent = t('common.loading');
    box.appendChild(loading);

    overlay.appendChild(box);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);

    try {
        const resp = await fetch(`/api/rooms/${roomId}/messages/${msgId}/history`, { credentials: 'include' });
        if (!resp.ok) throw new Error(t('errors.errorWithStatus', {status: resp.status}));
        const data = await resp.json();
        loading.remove();

        const versions = [...(data.history || []), { ciphertext_hex: data.current?.ciphertext_hex, edited_at: data.current?.edited_at, is_current: true }];

        if (versions.length === 1 && !data.history?.length) {
            const empty = document.createElement('div');
            empty.style.cssText = 'color:var(--text2);font-size:13px;position:relative;z-index:2;';
            empty.textContent = t('chat.editHistoryEmpty');
            box.appendChild(empty);
        } else {
            versions.reverse().forEach((v, i) => {
                const row = document.createElement('div');
                row.style.cssText = 'position:relative;z-index:2;margin-bottom:10px;padding:10px;border-radius:10px;background:rgba(255,255,255,0.05);border:1px solid var(--border);';

                const label = document.createElement('div');
                label.style.cssText = 'font-size:11px;color:var(--text3);margin-bottom:4px;display:flex;justify-content:space-between;';
                const timeStr = v.edited_at ? new Date(v.edited_at).toLocaleString('ru', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';
                label.innerHTML = `<span>${v.is_current ? t('chat.currentVersion') : t('chat.versionNumber', {num: versions.length - i})}</span><span>${timeStr}</span>`;
                row.appendChild(label);

                const cipher = document.createElement('div');
                cipher.style.cssText = 'font-size:11px;font-family:var(--mono);color:var(--text2);word-break:break-all;overflow:hidden;max-height:60px;';
                cipher.textContent = v.ciphertext_hex ? v.ciphertext_hex.slice(0, 120) + (v.ciphertext_hex.length > 120 ? '…' : '') : t('chat.encrypted');
                cipher.title = t('chat.encryptedTooltip');
                row.appendChild(cipher);

                box.appendChild(row);
            });
        }
    } catch (e) {
        loading.textContent = t('errors.loadingError', {message: e.message});
    }

    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn btn-ghost';
    closeBtn.style.cssText = 'width:100%;margin-top:10px;position:relative;z-index:2;';
    closeBtn.textContent = t('common.close');
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
        replyToText?.length > 80 ? replyToText.slice(0, 80) + '\u2026' : (replyToText || ''),
        isOwn,
        () => _scrollToMsg(replyToId)
    );
    if (replyToId) quote.dataset.replyId = replyToId;
    return quote;
}

// =============================================================================
// Публичные функции для управления сообщениями
// =============================================================================

/**
 * Сбрасывает состояние группировки (дата, автор) и очищает карту элементов.
 */

/**
 * Attaches mobile long-press (400ms) to a bubble element to show the context menu.
 * Fires before the selection-mode timer (500ms on group) and stops propagation.
 */
function _attachMobileLongPress(bubble, msg, isOwn) {
    let _ctxTimer = null;
    let _ctxMoved = false;
    bubble.addEventListener('touchstart', (te) => {
        _ctxMoved = false;
        _ctxTimer = setTimeout(() => {
            if (_ctxMoved) return;
            te.stopPropagation();
            if (navigator.vibrate) navigator.vibrate(20);
            _showContextMenu(te, msg, isOwn);
        }, 400);
    }, { passive: true });
    bubble.addEventListener('touchmove',   () => { _ctxMoved = true; clearTimeout(_ctxTimer); }, { passive: true });
    bubble.addEventListener('touchend',    () => clearTimeout(_ctxTimer), { passive: true });
    bubble.addEventListener('touchcancel', () => clearTimeout(_ctxTimer), { passive: true });
}

export {
    _maybeAttachLinkPreview, _buildPreviewCard, _renderBotMarkdown,
    _renderTextWithMentions, _notifyMention, extractMentions,
    _attachSwipeReply, _resetSwipe, _avatarHtml, _translateMessage,
    _ensureContextMenuStyles, _showContextMenu, _closeContextMenu,
    _loadReminders, _saveReminders, _showReminderModal, _scheduleReminder,
    _fireReminder, _showEditHistory, _buildReplyQuote,
    _attachMobileLongPress,
    _showTagPicker,
};

/* ── Tag Picker (mini modal for setting member tags) ──────────────── */
function _showTagPicker(targetUserId, currentTag, currentColor) {
    // Remove any existing picker
    document.getElementById('tag-picker-overlay')?.remove();

    const TAG_COLORS = [
        '#10b981', '#3b82f6', '#8b5cf6', '#ef4444', '#f59e0b',
        '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
    ];

    const overlay = document.createElement('div');
    overlay.id = 'tag-picker-overlay';
    overlay.className = 'tag-picker-overlay';
    overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

    let selectedColor = currentColor || TAG_COLORS[0];

    const card = document.createElement('div');
    card.className = 'tag-picker-card';
    card.innerHTML = `
        <div class="tag-picker-title">${t('ctx.setTag') || 'Set Tag'}</div>
        <input class="tag-picker-input" id="tag-picker-text" type="text"
               placeholder="${t('tags.placeholder') || 'Tag text (e.g. Admin, VIP, Mod)'}"
               value="${esc(currentTag || '')}" maxlength="30" autofocus>
        <div class="tag-picker-preview-wrap">
            <span class="msg-bubble-tag" id="tag-picker-preview"
                  style="background:${selectedColor}22;color:${selectedColor};border-color:${selectedColor}44">
                ${esc(currentTag || 'Preview')}
            </span>
        </div>
        <div class="tag-picker-colors" id="tag-picker-colors">
            ${TAG_COLORS.map(c =>
                `<button class="tag-picker-color${c === selectedColor ? ' active' : ''}"
                         style="background:${c}" data-color="${c}"></button>`
            ).join('')}
        </div>
        <div class="tag-picker-actions">
            <button class="tag-picker-btn tag-picker-btn-remove" id="tag-picker-remove">
                ${t('tags.remove') || 'Remove tag'}
            </button>
            <button class="tag-picker-btn tag-picker-btn-save" id="tag-picker-save">
                ${t('tags.save') || 'Save'}
            </button>
        </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('active'));

    const input = document.getElementById('tag-picker-text');
    const preview = document.getElementById('tag-picker-preview');
    const colorsEl = document.getElementById('tag-picker-colors');

    // Update preview on input
    input.addEventListener('input', () => {
        preview.textContent = input.value || 'Preview';
    });

    // Color selection
    colorsEl.addEventListener('click', e => {
        const btn = e.target.closest('.tag-picker-color');
        if (!btn) return;
        selectedColor = btn.dataset.color;
        colorsEl.querySelectorAll('.tag-picker-color').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        preview.style.background = selectedColor + '22';
        preview.style.color = selectedColor;
        preview.style.borderColor = selectedColor + '44';
    });

    // Save
    document.getElementById('tag-picker-save').onclick = async () => {
        const text = input.value.trim();
        const S = window.AppState;
        if (!S.currentRoom) return;
        try {
            const headers = { 'Content-Type': 'application/json' };
            if (S.csrfToken) headers['X-CSRF-Token'] = S.csrfToken;
            const r = await fetch(`/api/rooms/${S.currentRoom.id}/members/${targetUserId}/tag`, {
                method: 'PUT', headers, credentials: 'include',
                body: JSON.stringify({ tag: text || null, tag_color: text ? selectedColor : null }),
            });
            if (!r.ok) throw new Error('Failed');
            overlay.remove();
            // Update all existing messages from this user in DOM
            _updateTagsInDOM(targetUserId, text || null, text ? selectedColor : null);
            if (typeof window.showToast === 'function') {
                window.showToast(t('tags.saved') || 'Tag saved', 'success');
            }
        } catch (err) {
            console.error('setTag error:', err);
            if (typeof window.showToast === 'function') {
                window.showToast(t('tags.error') || 'Failed to set tag', 'error');
            }
        }
    };

    // Remove tag
    document.getElementById('tag-picker-remove').onclick = async () => {
        const S = window.AppState;
        if (!S.currentRoom) return;
        try {
            const headers = { 'Content-Type': 'application/json' };
            if (S.csrfToken) headers['X-CSRF-Token'] = S.csrfToken;
            await fetch(`/api/rooms/${S.currentRoom.id}/members/${targetUserId}/tag`, {
                method: 'PUT', headers, credentials: 'include',
                body: JSON.stringify({ tag: null, tag_color: null }),
            });
            overlay.remove();
            _updateTagsInDOM(targetUserId, null, null);
            if (typeof window.showToast === 'function') {
                window.showToast(t('tags.removed') || 'Tag removed', 'success');
            }
        } catch (err) {
            console.error('removeTag error:', err);
        }
    };

    input.focus();
}

/**
 * Update tag badges on ALL messages from a given user in the current chat.
 * Adds, updates, or removes .msg-bubble-tag on every msg-group with matching sender_id.
 */
function _updateTagsInDOM(userId, tagText, tagColor) {
    document.querySelectorAll(`.msg-group[data-sender-id="${userId}"]`).forEach(group => {
        // Update tag in author header (.msg-tag)
        const authorTag = group.querySelector('.msg-tag');
        if (tagText) {
            if (authorTag) {
                authorTag.textContent = tagText;
                if (tagColor) {
                    authorTag.style.background = tagColor + '22';
                    authorTag.style.color = tagColor;
                    authorTag.style.borderColor = tagColor + '44';
                }
            }
            // Could insert new .msg-tag if not present, but author block may not exist for all messages
        } else if (authorTag) {
            authorTag.remove();
        }

        // Update tag badge on bubble (.msg-bubble-tag)
        group.querySelectorAll('.msg-bubble').forEach(bubble => {
            let badge = bubble.querySelector('.msg-bubble-tag');
            if (tagText) {
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'msg-bubble-tag';
                    bubble.insertBefore(badge, bubble.firstChild);
                }
                badge.textContent = tagText;
                if (tagColor) {
                    badge.style.background = tagColor + '22';
                    badge.style.color = tagColor;
                    badge.style.borderColor = tagColor + '44';
                } else {
                    badge.style.cssText = '';
                }
            } else if (badge) {
                badge.remove();
            }
        });
    });
}

// Expose for context menu
window._showTagPicker = _showTagPicker;

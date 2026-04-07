import { _buildReplyQuote, _showContextMenu } from './helpers.js';
import { _msgElements } from './shared.js';

const _SVG_PLAY  = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" width="20" height="20"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><path d="M15.5 12L10 15.5V8.5L15.5 12Z" fill="currentColor"/></svg>`;
const _SVG_PAUSE = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" width="20" height="20"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><rect x="9" y="8" width="2.2" height="8" rx="1" fill="currentColor"/><rect x="12.8" y="8" width="2.2" height="8" rx="1" fill="currentColor"/></svg>`;

// =============================================================================
// Голосовые сообщения (визуализация и управление)
// =============================================================================

/**
 * Вставляет стили для голосового плеера, если ещё не.
 */
function _ensureVoiceStyles() {
    if (document.getElementById('vb-style')) return;
    const s = document.createElement('style');
    s.id = 'vb-style';
    s.textContent = `
    /* Layout голосового пузыря — стекло от .lg из liquid-glass */
    .vb-wrap {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 10px 14px;
        border-radius: 16px;
        max-width: 300px;
        min-width: 230px;
        width: fit-content;
    }
    .vb-wrap.own {
        margin-left: auto;
    }
    .vb-wrap > * { position: relative; z-index: 4; }
    .vb-row { display: flex; align-items: center; gap: 12px; }
    .vb-play {
        width: 40px; height: 40px; border-radius: 50%; border: none; flex-shrink: 0;
        display: flex; align-items: center; justify-content: center;
        background: rgba(255, 255, 255, 0.14); color: #fff; cursor: pointer;
        box-shadow: 0 2px 8px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.22);
        transition: transform .12s;
        position: relative; z-index: 4;
    }
    .vb-play:hover  { transform: scale(1.08); }
    .vb-play:active { transform: scale(.94); }
    .vb-play.played { background: rgba(180,180,195,0.18); color: rgba(255,255,255,0.45); }
    .vb-wrap.own .vb-play { background: rgba(195,160,255,0.20); }
    .vb-speed {
        font-family: monospace; font-size: 11px; border: none; cursor: pointer;
        padding: 2px 6px; background: var(--bg3, rgba(255,255,255,0.12));
        border-radius: var(--radius, 6px); color: #fff; flex-shrink: 0;
        transition: opacity .12s;
    }
    .vb-speed:hover { opacity: .75; }

    .vb-right { flex: 1; display: flex; flex-direction: column; gap: 5px; min-width: 0; position: relative; z-index: 4; }
    .vb-bars  { display: flex; align-items: center; gap: 2px; height: 32px; cursor: pointer; }
    .vb-bar   {
        flex: 1; border-radius: 2px; min-width: 2px;
        background: rgba(200, 215, 240, 0.22);
        transition: background .1s;
    }
    .vb-bar.played { background: rgba(200, 215, 240, 0.72); }
    .vb-bar.done   { background: rgba(175, 180, 195, 0.20); }
    .vb-wrap.own .vb-bar        { background: rgba(195, 168, 255, 0.22); }
    .vb-wrap.own .vb-bar.played { background: rgba(210, 190, 255, 0.72); }
    .vb-wrap.own .vb-bar.done   { background: rgba(175, 170, 195, 0.20); }
    .vb-time {
        font-size: 11px;
        font-family: var(--mono, monospace);
        color: rgba(255, 255, 255, 0.38);
        align-self: flex-end;
        position: relative; z-index: 4;
    }
    `;
    document.head.appendChild(s);
}

/**
 * Нормализует массив пиков громкости (0..1) для отображения в виде столбиков.
 * Если peaks нет, генерирует случайные значения.
 *
 * @param {number[]|null} peaks - исходные пики
 * @param {number} N - желаемое количество столбиков
 * @returns {number[]} - нормализованные значения (0..1)
 */
function _normPeaks(peaks, N) {
    if (!peaks?.length) {
        return Array.from({ length: N }, (_, i) => 0.2 + (((i * 7 + 3) % 17) / 17) * 0.65);
    }
    const out = [];
    for (let i = 0; i < N; i++) {
        const s = Math.floor(i * peaks.length / N);
        const e = Math.max(s + 1, Math.floor((i + 1) * peaks.length / N));
        let mx = 0;
        for (let j = s; j < e; j++) mx = Math.max(mx, peaks[j] || 0);
        out.push(mx);
    }
    const max = Math.max(...out, 0.01);
    return out.map(v => v / max);
}

/**
 * Создаёт DOM-элемент голосового сообщения (пузырёк с кнопкой, столбиками и временем).
 *
 * @param {Object} msg - данные сообщения
 * @param {boolean} isOwn - своё/чужое
 * @returns {HTMLElement} - обёртка .vb-wrap
 */
export function _buildVoiceBubble(msg, isOwn) {
    _ensureVoiceStyles();

    let peaks = null;
    if (msg.file_name) {
        try { peaks = JSON.parse(sessionStorage.getItem('vp:' + msg.file_name) || 'null'); } catch {}
    }

    const BARS      = 40;
    const normPeaks = _normPeaks(peaks, BARS);

    const wrap = document.createElement('div');
    wrap.className   = `vb-wrap lg${isOwn ? ' lg-own own' : ''}`;
    wrap.dataset.src = msg.download_url;

    const grain = document.createElement('div');
    grain.className = 'lg-grain';
    wrap.appendChild(grain);

    if (msg.reply_to_id && msg.reply_to_text) {
        wrap.appendChild(_buildReplyQuote(msg.reply_to_id, msg.reply_to_text, msg.reply_to_sender, isOwn));
    }

    const row = document.createElement('div');
    row.className = 'vb-row';

    const playBtn = document.createElement('button');
    playBtn.className = 'vb-play';
    playBtn.innerHTML = _SVG_PLAY;

    const right = document.createElement('div');
    right.className = 'vb-right';

    const barsEl = document.createElement('div');
    barsEl.className = 'vb-bars';
    normPeaks.forEach(h => {
        const b = document.createElement('div');
        b.className  = 'vb-bar';
        b.style.height = Math.max(12, h * 100) + '%';
        barsEl.appendChild(b);
    });

    const timeEl = document.createElement('span');
    timeEl.className   = 'vb-time';
    timeEl.textContent = '0:00';

    right.appendChild(barsEl);
    right.appendChild(timeEl);
    const speedBtn = document.createElement('button');
    speedBtn.className   = 'vb-speed';
    speedBtn.textContent = '1x';

    row.appendChild(playBtn);
    row.appendChild(speedBtn);
    row.appendChild(right);
    wrap.appendChild(row);

    wrap._playBtn  = playBtn;
    wrap._barsEl   = barsEl;
    wrap._timeEl   = timeEl;
    wrap._speedBtn = speedBtn;

    wrap.addEventListener('click', (e) => {
        if (e.target.closest('.vb-play') || e.target.closest('.vb-bars') || e.target.closest('.vb-speed') || e.target.closest('.lg-reply')) return;
        _showContextMenu(e, msg, isOwn);
    });

    return wrap;
}

/**
 * Инициализирует голосовой плеер: подключает Audio, обработчики событий.
 *
 * @param {HTMLElement} el - элемент .vb-wrap
 */
export async function _initVoiceBubble(el) {
    if (!el?.dataset?.src) return;

    const barNodes = el._barsEl ? Array.from(el._barsEl.children) : [];
    const N        = barNodes.length;
    let   done     = false;

    // E2E: загружаем и расшифровываем аудио перед воспроизведением
    let audioSrc = el.dataset.src;
    try {
        const { getRoomKey } = await import('../crypto.js');
        const roomKey = getRoomKey(window.AppState?.currentRoom?.id);
        if (roomKey) {
            const resp = await fetch(el.dataset.src, { credentials: 'include' });
            if (resp.ok) {
                let data = await resp.arrayBuffer();
                if (data.byteLength > 12) {
                    try {
                        const { decryptFile } = await import('../crypto.js');
                        data = await decryptFile(data, roomKey);
                    } catch {
                        // Legacy — используем как есть
                    }
                }
                const blob = new Blob([data]);
                audioSrc = URL.createObjectURL(blob);
            }
        }
    } catch (e) {
        console.warn('[E2E] Не удалось расшифровать голосовое:', e);
    }

    const audio    = new Audio(audioSrc);
    el._audio      = audio;

    audio.addEventListener('loadedmetadata', () => {
        if (el._timeEl) el._timeEl.textContent = _fmtDur(audio.duration);
    });
    audio.addEventListener('timeupdate', () => {
        if (done) return;
        const pct    = audio.duration ? audio.currentTime / audio.duration : 0;
        const played = Math.round(pct * N);
        barNodes.forEach((b, i) => b.classList.toggle('played', i < played));
        if (el._timeEl) el._timeEl.textContent = _fmtDur(audio.currentTime);
    });
    audio.addEventListener('ended', () => {
        done = true;
        if (el._playBtn) { el._playBtn.innerHTML = _SVG_PLAY; el._playBtn.classList.add('played'); }
        barNodes.forEach(b => { b.classList.remove('played'); b.classList.add('done'); });
        if (el._timeEl && audio.duration) el._timeEl.textContent = _fmtDur(audio.duration);
    });

    if (el._barsEl) {
        el._barsEl.addEventListener('click', e => {
            if (!audio.duration) return;
            const r = el._barsEl.getBoundingClientRect();
            audio.currentTime = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * audio.duration;
            if (done) {
                done = false;
                if (el._playBtn) el._playBtn.classList.remove('played');
                barNodes.forEach(b => b.classList.remove('done'));
            }
        });
    }

    if (el._speedBtn) {
        const speeds = [1, 1.5, 2, 0.5];
        let si = 0;
        el._speedBtn.onclick = () => {
            si = (si + 1) % speeds.length;
            audio.playbackRate = speeds[si];
            el._speedBtn.textContent = speeds[si] + 'x';
        };
    }

    if (el._playBtn) {
        el._playBtn.onclick = () => {
            if (audio.paused) {
                // Останавливаем другие плееры
                document.querySelectorAll('.vb-wrap').forEach(b => {
                    if (b !== el && b._audio && !b._audio.paused) {
                        b._audio.pause();
                        if (b._playBtn) b._playBtn.innerHTML = _SVG_PLAY;
                    }
                });
                if (done) {
                    done = false;
                    el._playBtn.classList.remove('played');
                    barNodes.forEach(b => b.classList.remove('done'));
                }
                audio.play().catch(() => {});
                el._playBtn.innerHTML = _SVG_PAUSE;
            } else {
                audio.pause();
                el._playBtn.innerHTML = _SVG_PLAY;
            }
        };
    }
}

// Заглушка для глобальной функции (не используется)
window.toggleVoicePlay = () => {};

// =============================================================================
// Вспомогательные функции
// =============================================================================

/**
 * Плавно прокручивает к сообщению по ID и подсвечивает его.
 *
 * @param {string} msgId
 */
export function _scrollToMsg(msgId) {
    const el = _msgElements.get(msgId);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('msg-highlight');
    setTimeout(() => el.classList.remove('msg-highlight'), 1500);
}
window._scrollToMsg = _scrollToMsg; // делаем доступной глобально для обработчиков

/**
 * Усечение строки.
 */
export function _truncate(str, n) { return str?.length > n ? str.slice(0, n) + '…' : str || ''; }

/**
 * Форматирование длительности (секунды → MM:SS).
 */
export function _fmtDur(s) {
    if (!isFinite(s) || s < 0) return '0:00';
    const m = Math.floor(s / 60), sec = Math.floor(s % 60);
    return `${m}:${String(sec).padStart(2, '0')}`;
}

/**
 * Извлекает download_url из текста сообщения (если файл был вложен в текстовое сообщение).
 */
export function _extractDownloadUrl(text) {
    if (!text) return null;
    const m = text.match(/\[file:(\d+):/);
    return m ? `/api/files/download/${m[1]}` : null;
}

/**
 * Угадывает MIME-тип по расширению имени файла.
 */
export function _guessMimeFromName(name) {
    if (!name) return null;
    const ext = name.split('.').pop().toLowerCase();
    return {
        jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
        gif: 'image/gif',  webp: 'image/webp',
        mp4: 'video/mp4',  webm: 'audio/webm',
        mp3: 'audio/mpeg', ogg: 'audio/ogg',  wav: 'audio/wav',
        m4a: 'audio/mp4',
    }[ext] || null;
}

/**
 * Угадывает MIME-тип из текста сообщения (если там ссылка на файл).
 */
export function _guessMimeFromText(text) {
    if (!text) return null;
    const m = text.match(/\[file:\d+:(.+?)\]/);
    if (!m) return null;
    return _guessMimeFromName(m[1]);
}

/**
 * static/js/chat/media-viewer.js — Universal media viewer module.
 *
 * Viewers:
 *  - VideoNote: circular viewer with ring seek, speed control
 *  - Video: standard player modal
 *  - Audio: player with progress, speed
 *  - Document: PDF, SVG, text, images, download fallback
 */
import { $, esc, fmtSize } from '../utils.js';
import { t } from '../i18n.js';

// ── State ────────────────────────────────────────────────────────────────────
let _activeViewer = null;

function _close() {
    if (_activeViewer) {
        _activeViewer.remove();
        _activeViewer = null;
    }
}

function _onKey(e) {
    if (e.key === 'Escape') _close();
}

function _backdrop() {
    const el = document.createElement('div');
    el.className = 'mv-backdrop';
    el.addEventListener('click', (e) => { if (e.target === el) _close(); });
    document.addEventListener('keydown', _onKey);
    _activeViewer = el;
    document.body.appendChild(el);
    return el;
}

function _header(parent, title, extra) {
    const hdr = document.createElement('div');
    hdr.className = 'mv-header';

    const name = document.createElement('span');
    name.className = 'mv-title';
    name.textContent = title || '';
    hdr.appendChild(name);

    if (extra) hdr.appendChild(extra);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'mv-close';
    closeBtn.textContent = '\u2715';
    closeBtn.addEventListener('click', _close);
    hdr.appendChild(closeBtn);

    parent.appendChild(hdr);
    return hdr;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
const _fmtSec = s => {
    const m = Math.floor(s / 60);
    return m + ':' + String(Math.floor(s % 60)).padStart(2, '0');
};

const SPEEDS = [0.5, 0.75, 1, 1.25, 1.5, 2];

function _speedBtn(mediaEl) {
    const btn = document.createElement('button');
    btn.className = 'mv-speed-btn';
    btn.textContent = '1x';
    let idx = 2; // starts at 1x
    btn.addEventListener('click', () => {
        idx = (idx + 1) % SPEEDS.length;
        mediaEl.playbackRate = SPEEDS[idx];
        btn.textContent = SPEEDS[idx] + 'x';
    });
    return btn;
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. VIDEO NOTE — circular viewer with SVG ring seek
// ══════════════════════════════════════════════════════════════════════════════
export function openVideoNoteViewer(url, fileName) {
    _close();
    const root = _backdrop();

    const card = document.createElement('div');
    card.className = 'mv-videonote';

    // Circular container
    const circle = document.createElement('div');
    circle.className = 'mv-vn-circle';

    const video = document.createElement('video');
    video.playsInline = true;
    video.preload = 'auto';
    circle.appendChild(video);

    // E2E decrypt if needed
    if (url.startsWith('blob:')) {
        video.src = url;
    } else {
        (async () => {
            try {
                const resp = await fetch(url, { credentials: 'include' });
                let data = await resp.arrayBuffer();
                try {
                    const { getRoomKey, decryptFile } = await import('../crypto.js');
                    const rk = getRoomKey(window.AppState?.currentRoom?.id);
                    if (rk && data.byteLength > 28) data = await decryptFile(data, rk);
                } catch {}
                video.src = URL.createObjectURL(new Blob([data], { type: 'video/mp4' }));
                video.play().catch(() => {});
            } catch { video.src = url; }
        })();
    }

    // SVG ring for progress + seek
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('class', 'mv-vn-ring');
    svg.setAttribute('viewBox', '0 0 200 200');

    const bgCircle = document.createElementNS(svgNS, 'circle');
    bgCircle.setAttribute('cx', '100');
    bgCircle.setAttribute('cy', '100');
    bgCircle.setAttribute('r', '96');
    bgCircle.setAttribute('class', 'mv-vn-ring-bg');
    svg.appendChild(bgCircle);

    const progressCircle = document.createElementNS(svgNS, 'circle');
    progressCircle.setAttribute('cx', '100');
    progressCircle.setAttribute('cy', '100');
    progressCircle.setAttribute('r', '96');
    progressCircle.setAttribute('class', 'mv-vn-ring-progress');
    const circumference = 2 * Math.PI * 96;
    progressCircle.style.strokeDasharray = circumference;
    progressCircle.style.strokeDashoffset = circumference;
    svg.appendChild(progressCircle);

    circle.appendChild(svg);

    // Play overlay
    const playBtn = document.createElement('div');
    playBtn.className = 'mv-vn-play';
    const playSvg = document.createElementNS(svgNS, 'svg');
    playSvg.setAttribute('width', '48');
    playSvg.setAttribute('height', '48');
    playSvg.setAttribute('viewBox', '0 0 24 24');
    playSvg.setAttribute('fill', '#fff');
    const playPath = document.createElementNS(svgNS, 'path');
    playPath.setAttribute('d', 'M8 5v14l11-7z');
    playSvg.appendChild(playPath);
    playBtn.appendChild(playSvg);
    circle.appendChild(playBtn);

    card.appendChild(circle);

    // Controls row
    const controls = document.createElement('div');
    controls.className = 'mv-vn-controls';

    const timeLabel = document.createElement('span');
    timeLabel.className = 'mv-vn-time';
    timeLabel.textContent = '0:00';
    controls.appendChild(timeLabel);

    controls.appendChild(_speedBtn(video));

    card.appendChild(controls);
    root.appendChild(card);

    // Behaviour
    video.addEventListener('timeupdate', () => {
        if (!video.duration) return;
        const pct = video.currentTime / video.duration;
        progressCircle.style.strokeDashoffset = circumference * (1 - pct);
        timeLabel.textContent = _fmtSec(video.currentTime) + ' / ' + _fmtSec(video.duration);
    });

    video.addEventListener('ended', () => {
        video.currentTime = 0;
        progressCircle.style.strokeDashoffset = circumference;
        circle.classList.remove('playing');
    });

    video.addEventListener('play', () => { circle.classList.add('playing'); playBtn.style.display = 'none'; });
    video.addEventListener('pause', () => { circle.classList.remove('playing'); playBtn.style.display = ''; });

    // Click to play/pause
    circle.addEventListener('click', (e) => {
        if (e.target.closest('.mv-vn-ring')) return;
        if (video.paused) video.play(); else video.pause();
    });

    // Seek by clicking ring
    svg.addEventListener('click', (e) => {
        if (!video.duration) return;
        const rect = svg.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        let angle = Math.atan2(e.clientY - cy, e.clientX - cx) + Math.PI / 2;
        if (angle < 0) angle += 2 * Math.PI;
        video.currentTime = (angle / (2 * Math.PI)) * video.duration;
    });

    // Auto-play is triggered after E2E decrypt (above)
    if (url.startsWith('blob:')) video.play().catch(() => {});
}


// ══════════════════════════════════════════════════════════════════════════════
// 2. VIDEO PLAYER — standard modal
// ══════════════════════════════════════════════════════════════════════════════
export function openVideoViewer(url, fileName) {
    _close();
    const root = _backdrop();

    const card = document.createElement('div');
    card.className = 'mv-video';

    _header(card, fileName || 'Video');

    // Skeleton loader
    const skeleton = document.createElement('div');
    skeleton.className = 'mv-video-skeleton';
    const skelBar = document.createElement('div');
    skelBar.className = 'mv-video-skeleton-bar';
    skeleton.appendChild(skelBar);
    const skelText = document.createElement('div');
    skelText.className = 'mv-video-skeleton-text';
    skelText.textContent = (typeof t==='function'?t('media.loadingVideo'):'Loading video...');
    skeleton.appendChild(skelText);
    card.appendChild(skeleton);

    const video = document.createElement('video');
    video.controls = true;
    video.autoplay = true;
    video.playsInline = true;
    video.className = 'mv-video-el';
    video.style.display = 'none';
    card.appendChild(video);

    const bar = document.createElement('div');
    bar.className = 'mv-video-bar';
    bar.appendChild(_speedBtn(video));
    card.appendChild(bar);

    root.appendChild(card);

    // If blob: URL (cached) — show immediately
    if (url.startsWith('blob:')) {
        video.src = url;
        video.style.display = '';
        skeleton.remove();
    } else {
        // Fetch with progress → decrypt → play
        _fetchWithProgress(url, (pct) => {
            skelBar.style.width = pct + '%';
            skelText.textContent = pct < 100 ? 'Loading ' + pct + '%' : 'Decrypting...';
        }).then(async (buf) => {
            // Decrypt
            try {
                const { getRoomKey, decryptFile } = await import('../crypto.js');
                const rk = getRoomKey(window.AppState?.currentRoom?.id);
                if (rk && buf.byteLength > 28) {
                    const dec = await decryptFile(new Uint8Array(buf).buffer, rk);
                    if (dec && dec.byteLength > 0) buf = dec;
                }
            } catch (_) {}
            const blob = new Blob([buf], { type: 'video/mp4' });
            const blobUrl = URL.createObjectURL(blob);
            video.src = blobUrl;
            video.style.display = '';
            skeleton.remove();
        }).catch(() => {
            skelText.textContent = (typeof t==='function'?t('media.failedVideo'):'Failed to load video');
            skelBar.style.width = '0%';
        });
    }
}

/** Fetch with download progress tracking */
async function _fetchWithProgress(url, onProgress) {
    const resp = await fetch(url, { credentials: 'include' });
    const total = parseInt(resp.headers.get('content-length') || '0', 10);
    if (!total || !resp.body) {
        // Fallback: no streaming, just load
        onProgress(50);
        const buf = await resp.arrayBuffer();
        onProgress(100);
        return buf;
    }
    const reader = resp.body.getReader();
    const chunks = [];
    let loaded = 0;
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        loaded += value.length;
        onProgress(Math.min(99, Math.round(loaded / total * 100)));
    }
    onProgress(100);
    const result = new Uint8Array(loaded);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    return result.buffer;
}


// ══════════════════════════════════════════════════════════════════════════════
// 3. AUDIO PLAYER
// ══════════════════════════════════════════════════════════════════════════════
export function openAudioViewer(url, fileName) {
    _close();
    const root = _backdrop();

    const card = document.createElement('div');
    card.className = 'mv-audio';

    _header(card, fileName || 'Audio');

    const audio = document.createElement('audio');
    audio.src = url;
    audio.preload = 'auto';

    // Progress bar
    const progressWrap = document.createElement('div');
    progressWrap.className = 'mv-audio-progress';
    const progressFill = document.createElement('div');
    progressFill.className = 'mv-audio-fill';
    progressWrap.appendChild(progressFill);
    card.appendChild(progressWrap);

    // Seek
    progressWrap.addEventListener('click', (e) => {
        if (!audio.duration) return;
        const rect = progressWrap.getBoundingClientRect();
        audio.currentTime = ((e.clientX - rect.left) / rect.width) * audio.duration;
    });

    // Controls
    const ctrls = document.createElement('div');
    ctrls.className = 'mv-audio-controls';

    const playBtn = document.createElement('button');
    playBtn.className = 'mv-audio-play';
    playBtn.textContent = '\u25B6';
    playBtn.addEventListener('click', () => {
        if (audio.paused) audio.play(); else audio.pause();
    });
    ctrls.appendChild(playBtn);

    const timeLabel = document.createElement('span');
    timeLabel.className = 'mv-audio-time';
    timeLabel.textContent = '0:00';
    ctrls.appendChild(timeLabel);

    ctrls.appendChild(_speedBtn(audio));
    card.appendChild(ctrls);

    root.appendChild(card);

    audio.addEventListener('timeupdate', () => {
        if (!audio.duration) return;
        progressFill.style.width = (audio.currentTime / audio.duration * 100) + '%';
        timeLabel.textContent = _fmtSec(audio.currentTime) + ' / ' + _fmtSec(audio.duration);
    });
    audio.addEventListener('play', () => { playBtn.textContent = '\u23F8'; });
    audio.addEventListener('pause', () => { playBtn.textContent = '\u25B6'; });
    audio.addEventListener('ended', () => { playBtn.textContent = '\u25B6'; progressFill.style.width = '0'; });

    audio.play().catch(() => {});
}


// ══════════════════════════════════════════════════════════════════════════════
// 4. DOCUMENT VIEWER — PDF, SVG, text, images, fallback download
// ══════════════════════════════════════════════════════════════════════════════
/**
 * Fetch file, attempt E2E decryption, return ArrayBuffer.
 */
async function _fetchAndDecrypt(url) {
    const resp = await fetch(url, { credentials: 'include' });
    const buf = await resp.arrayBuffer();
    // E2E: try to decrypt (files encrypted with AES-256-GCM at upload)
    try {
        const { getRoomKey, decryptFile } = await import('../crypto.js');
        const rk = getRoomKey(window.AppState?.currentRoom?.id);
        if (rk && buf.byteLength > 28) { // nonce(12) + tag(16) minimum
            const dec = await decryptFile(new Uint8Array(buf).buffer, rk);
            if (dec && dec.byteLength > 0) return dec;
        }
    } catch (_) { /* not encrypted or wrong key — return as-is */ }
    return buf;
}

/** Check if buffer looks like readable text (not encrypted binary garbage). */
function _isReadableText(buf) {
    const bytes = new Uint8Array(buf).slice(0, 256);
    if (bytes.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        // Printable ASCII, common UTF-8 lead bytes, whitespace
        if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13 || b >= 0xC0) printable++;
    }
    return printable / bytes.length > 0.7;
}

/**
 * Simple markdown → HTML (headers, bold, italic, code, links, lists).
 */
function _renderMarkdown(text) {
    // 1. Extract code blocks to protect them from further processing
    const codeBlocks = [];
    let src = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
        codeBlocks.push('<pre class="mv-md-code"><code>' + code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</code></pre>');
        return '\x00CB' + (codeBlocks.length - 1) + '\x00';
    });

    // 2. Escape HTML in remaining text
    src = src.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // 3. Tables — detect and convert pipe tables
    src = src.replace(/((?:^\|.+\|[ \t]*$\n?)+)/gm, (block) => {
        const rows = block.trim().split('\n').filter(r => r.trim());
        if (rows.length < 2) return block;
        // Check if row 2 is separator (|---|---|)
        const isSep = r => /^\|[\s\-:|]+\|$/.test(r.trim());
        let html = '<table class="mv-md-table">';
        rows.forEach((row, i) => {
            if (isSep(row)) return; // skip separator row
            const cells = row.split('|').slice(1, -1).map(c => c.trim());
            const tag = (i === 0 && rows.length > 1 && isSep(rows[1])) ? 'th' : 'td';
            const wrap = tag === 'th' ? 'thead' : (i === 2 || (i === 1 && !isSep(rows[1])) ? 'tbody' : '');
            if (i === 0 && tag === 'th') html += '<thead>';
            if (i === 2 && isSep(rows[1])) html += '<tbody>';
            html += '<tr>' + cells.map(c => '<' + tag + '>' + c + '</' + tag + '>').join('') + '</tr>';
            if (i === 0 && tag === 'th') html += '</thead>';
        });
        if (rows.length > 2 && isSep(rows[1])) html += '</tbody>';
        html += '</table>';
        return html;
    });

    // 4. Inline formatting
    src = src
        .replace(/`([^`]+)`/g, '<code class="mv-md-inline">$1</code>')
        .replace(/^#### (.+)$/gm, '<h4>$1</h4>')
        .replace(/^### (.+)$/gm, '<h3>$1</h3>')
        .replace(/^## (.+)$/gm, '<h2>$1</h2>')
        .replace(/^# (.+)$/gm, '<h1>$1</h1>')
        .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
        .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
        .replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
        .replace(/^---$/gm, '<hr>')
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>');

    // 5. Wrap lists
    src = src.replace(/((?:<li>.*?<\/li>(?:<br>)?)+)/g, '<ul>$1</ul>');
    // Merge adjacent blockquotes
    src = src.replace(/<\/blockquote>(?:<br>)?<blockquote>/g, '<br>');

    // 6. Restore code blocks
    src = src.replace(/\x00CB(\d+)\x00/g, (_, i) => codeBlocks[i]);

    return '<p>' + src + '</p>';
}

export function openDocViewer(url, fileName, mimeType) {
    _close();
    const root = _backdrop();

    const card = document.createElement('div');
    card.className = 'mv-doc';

    const dlBtn = document.createElement('a');
    dlBtn.href = url;
    dlBtn.download = fileName || '';
    dlBtn.className = 'mv-doc-dl';
    dlBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    _header(card, fileName || 'Document', dlBtn);

    const mime = (mimeType || '').toLowerCase();
    const ext = (fileName || '').split('.').pop().toLowerCase();

    const TEXT_EXTS = ['txt', 'json', 'xml', 'csv', 'yaml', 'yml', 'toml', 'ini', 'cfg',
        'js', 'ts', 'py', 'rs', 'go', 'java', 'c', 'cpp', 'h', 'hpp', 'rb', 'swift', 'kt',
        'html', 'css', 'scss', 'less', 'sql', 'sh', 'bash', 'zsh', 'ps1', 'rtf'];
    const MD_EXTS = ['md', 'markdown', 'mdx'];
    const LOG_EXTS = ['log'];

    if (mime === 'application/pdf' || ext === 'pdf') {
        // PDF: fetch → decrypt → render with PDF.js (canvas per page)
        const pdfContainer = document.createElement('div');
        pdfContainer.className = 'mv-pdf-container';
        pdfContainer.textContent = (typeof t==='function'?t('media.loadingPdf'):'Loading PDF...');
        pdfContainer.style.cssText = 'flex:1;overflow:auto;text-align:center;padding:8px;';
        card.appendChild(pdfContainer);

        _fetchAndDecrypt(url).then(async buf => {
            try {
                const pdfjsLib = await import('/static/js/lib/pdf.min.mjs');
                pdfjsLib.GlobalWorkerOptions.workerSrc = '/static/js/lib/pdf.worker.min.mjs';
                const pdf = await pdfjsLib.getDocument({ data: new Uint8Array(buf) }).promise;
                pdfContainer.textContent = '';

                // Page navigation bar
                let currentScale = 1.5;
                const devicePixelRatio = window.devicePixelRatio || 1;

                for (let i = 1; i <= pdf.numPages; i++) {
                    const page = await pdf.getPage(i);
                    const viewport = page.getViewport({ scale: currentScale * devicePixelRatio });

                    const canvas = document.createElement('canvas');
                    canvas.width = viewport.width;
                    canvas.height = viewport.height;
                    canvas.style.cssText = `width:${viewport.width / devicePixelRatio}px;height:${viewport.height / devicePixelRatio}px;margin:0 auto 8px;display:block;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.3);`;

                    const ctx = canvas.getContext('2d');
                    await page.render({ canvasContext: ctx, viewport }).promise;
                    pdfContainer.appendChild(canvas);
                }

                // Page count label
                const info = document.createElement('div');
                info.style.cssText = 'text-align:center;color:var(--text3);font-size:12px;padding:8px 0 16px;';
                info.textContent = pdf.numPages + ' page' + (pdf.numPages !== 1 ? 's' : '');
                pdfContainer.appendChild(info);
            } catch (e) {
                pdfContainer.textContent = (typeof t==='function'?t('media.failedRenderPdf'):'Failed to render PDF: ') + e.message;
                pdfContainer.style.cssText += 'color:var(--text3);display:flex;align-items:center;justify-content:center;';
            }
        }).catch(() => {
            pdfContainer.textContent = (typeof t==='function'?t('media.failedPdf'):'Failed to load PDF');
        });
    } else if (MD_EXTS.includes(ext)) {
        // Markdown: rendered view + raw toggle
        let _rawText = '';
        let _isRaw = false;

        // Insert toggle into existing header (before close button)
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'mv-md-toggle';
        toggleBtn.textContent = '</> Raw';
        const hdr = card.querySelector('.mv-header');
        if (hdr) {
            const closeBtn = hdr.querySelector('.mv-close');
            hdr.insertBefore(toggleBtn, closeBtn);
        }

        const rendered = document.createElement('div');
        rendered.className = 'mv-doc-md';
        rendered.textContent = (typeof t==='function'?t('media.loading'):'Loading...');
        card.appendChild(rendered);

        const raw = document.createElement('pre');
        raw.className = 'mv-doc-text';
        raw.style.display = 'none';
        card.appendChild(raw);

        toggleBtn.addEventListener('click', () => {
            _isRaw = !_isRaw;
            rendered.style.display = _isRaw ? 'none' : '';
            raw.style.display = _isRaw ? '' : 'none';
            toggleBtn.innerHTML = _isRaw ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg> Rendered' : '&lt;/&gt; Raw';
        });

        _fetchAndDecrypt(url).then(buf => {
            _rawText = new TextDecoder().decode(buf);
            rendered.textContent = '';
            const safeHtml = _renderMarkdown(_rawText);
            const temp = document.createElement('div');
            temp.innerHTML = safeHtml;
            rendered.appendChild(temp);
            raw.textContent = _rawText;
        }).catch(() => { rendered.textContent = (typeof t==='function'?t('media.failedFile'):'Failed to load file'); });
    } else if (LOG_EXTS.includes(ext)) {
        // Log files: fetch → decrypt → styled log viewer with line numbers
        const pre = document.createElement('pre');
        pre.className = 'mv-doc-text mv-doc-log';
        pre.textContent = (typeof t==='function'?t('media.loading'):'Loading...');
        card.appendChild(pre);
        _fetchAndDecrypt(url).then(buf => {

            const text = new TextDecoder().decode(buf);
            pre.textContent = '';
            const lines = text.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const ln = document.createElement('span');
                ln.className = 'mv-log-num';
                ln.textContent = String(i + 1);
                pre.appendChild(ln);
                // Colorize log levels
                const line = lines[i];
                const span = document.createElement('span');
                if (/\b(ERROR|FATAL|CRITICAL)\b/i.test(line)) span.className = 'mv-log-error';
                else if (/\bWARN(ING)?\b/i.test(line)) span.className = 'mv-log-warn';
                else if (/\bINFO\b/i.test(line)) span.className = 'mv-log-info';
                else if (/\bDEBUG\b/i.test(line)) span.className = 'mv-log-debug';
                span.textContent = line + '\n';
                pre.appendChild(span);
            }
        }).catch(() => { pre.textContent = (typeof t==='function'?t('media.failedFile'):'Failed to load file'); });
    } else if (mime === 'image/svg+xml' || ext === 'svg') {
        const obj = document.createElement('object');
        obj.data = url;
        obj.type = 'image/svg+xml';
        obj.className = 'mv-doc-svg';
        card.appendChild(obj);
    } else if (mime.startsWith('image/')) {
        const img = document.createElement('img');
        img.src = url;
        img.className = 'mv-doc-img';
        card.appendChild(img);
    } else if (mime.startsWith('text/') || TEXT_EXTS.includes(ext)) {
        // Code/text: fetch → decrypt → pre with line numbers
        const pre = document.createElement('pre');
        pre.className = 'mv-doc-text';
        pre.textContent = (typeof t==='function'?t('media.loading'):'Loading...');
        card.appendChild(pre);
        _fetchAndDecrypt(url).then(buf => {

            pre.textContent = new TextDecoder().decode(buf);
        }).catch(() => { pre.textContent = (typeof t==='function'?t('media.failedFile'):'Failed to load file'); });
    } else {
        // Fallback: icon + download prompt
        const fallback = document.createElement('div');
        fallback.className = 'mv-doc-fallback';

        const icon = document.createElement('div');
        icon.className = 'mv-doc-icon';
        icon.textContent = '\uD83D\uDCC4';
        fallback.appendChild(icon);

        const label = document.createElement('div');
        label.className = 'mv-doc-label';
        label.textContent = fileName || 'File';
        fallback.appendChild(label);

        const dlBtn2 = document.createElement('a');
        dlBtn2.href = url;
        dlBtn2.download = fileName || '';
        dlBtn2.className = 'mv-doc-dl-btn';
        dlBtn2.textContent = '\u2193 ' + (t('chat.download') || 'Download');
        fallback.appendChild(dlBtn2);

        card.appendChild(fallback);
    }

    root.appendChild(card);
}


// ══════════════════════════════════════════════════════════════════════════════
// 5. Live Photo support helper
// ══════════════════════════════════════════════════════════════════════════════
export function openLivePhoto(imageUrl, videoUrl, fileName) {
    _close();
    const root = _backdrop();

    const card = document.createElement('div');
    card.className = 'mv-livephoto';

    _header(card, fileName || 'Live Photo');

    const wrap = document.createElement('div');
    wrap.className = 'mv-lp-wrap';

    const img = document.createElement('img');
    img.src = imageUrl;
    img.className = 'mv-lp-img';
    wrap.appendChild(img);

    const video = document.createElement('video');
    video.src = videoUrl;
    video.loop = true;
    video.muted = true;
    video.playsInline = true;
    video.className = 'mv-lp-video';
    wrap.appendChild(video);

    const badge = document.createElement('div');
    badge.className = 'mv-lp-badge';
    badge.textContent = 'LIVE';
    wrap.appendChild(badge);

    // Long-press to play video
    let pressTimer = null;
    wrap.addEventListener('pointerdown', () => {
        pressTimer = setTimeout(() => {
            img.style.opacity = '0';
            video.style.opacity = '1';
            video.currentTime = 0;
            video.play().catch(() => {});
            badge.classList.add('active');
        }, 200);
    });
    const stopLive = () => {
        clearTimeout(pressTimer);
        img.style.opacity = '1';
        video.style.opacity = '0';
        video.pause();
        badge.classList.remove('active');
    };
    wrap.addEventListener('pointerup', stopLive);
    wrap.addEventListener('pointercancel', stopLive);
    wrap.addEventListener('pointerleave', stopLive);

    card.appendChild(wrap);
    root.appendChild(card);
}

// ── Close export ─────────────────────────────────────────────────────────────
export function closeMediaViewer() { _close(); }

// ── Global window exports ────────────────────────────────────────────────────
window.openVideoNoteViewer = openVideoNoteViewer;
window.openVideoViewer = openVideoViewer;
window.openAudioViewer = openAudioViewer;
window.openDocViewer = openDocViewer;
window.openLivePhoto = openLivePhoto;
window.closeMediaViewer = closeMediaViewer;

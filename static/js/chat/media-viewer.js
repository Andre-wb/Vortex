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
    video.src = url;
    video.playsInline = true;
    video.preload = 'auto';
    circle.appendChild(video);

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

    video.play().catch(() => {});
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

    const video = document.createElement('video');
    video.src = url;
    video.controls = true;
    video.autoplay = true;
    video.playsInline = true;
    video.className = 'mv-video-el';
    card.appendChild(video);

    const bar = document.createElement('div');
    bar.className = 'mv-video-bar';
    bar.appendChild(_speedBtn(video));
    card.appendChild(bar);

    root.appendChild(card);
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
export function openDocViewer(url, fileName, mimeType) {
    _close();
    const root = _backdrop();

    const card = document.createElement('div');
    card.className = 'mv-doc';

    const dlBtn = document.createElement('a');
    dlBtn.href = url;
    dlBtn.download = fileName || '';
    dlBtn.className = 'mv-doc-dl';
    dlBtn.textContent = '\u2193 ' + (t('chat.download') || 'Download');
    _header(card, fileName || 'Document', dlBtn);

    const mime = (mimeType || '').toLowerCase();
    const ext = (fileName || '').split('.').pop().toLowerCase();

    if (mime === 'application/pdf' || ext === 'pdf') {
        const iframe = document.createElement('iframe');
        iframe.src = url;
        iframe.className = 'mv-doc-frame';
        card.appendChild(iframe);
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
    } else if (mime.startsWith('text/') || ['txt', 'md', 'json', 'xml', 'csv', 'log', 'yaml', 'yml', 'toml', 'ini', 'cfg',
        'js', 'ts', 'py', 'rs', 'go', 'java', 'c', 'cpp', 'h', 'hpp', 'rb', 'swift', 'kt',
        'html', 'css', 'scss', 'less', 'sql', 'sh', 'bash', 'zsh', 'ps1'].includes(ext)) {
        const pre = document.createElement('pre');
        pre.className = 'mv-doc-text';
        pre.textContent = t('chat.loading') || 'Loading...';
        card.appendChild(pre);
        fetch(url, { credentials: 'include' })
            .then(r => r.text())
            .then(txt => { pre.textContent = txt; })
            .catch(() => { pre.textContent = 'Failed to load file'; });
    } else {
        // Fallback: icon + download prompt
        const fallback = document.createElement('div');
        fallback.className = 'mv-doc-fallback';

        const icon = document.createElement('div');
        icon.className = 'mv-doc-icon';
        icon.textContent = '\uD83D\uDCC4'; // 📄
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

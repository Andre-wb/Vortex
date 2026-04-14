/**
 * video-editor.js — Vortex Video Editor (50 features)
 *
 * Tabs: Edit | Adjust | Text | Overlay | Audio | Export | Cover
 *
 * Features: Trim, Multi-cut, Speed, Reverse, Freeze, Loop, Merge, Keyframes,
 *   Crop, Rotate, Filters, LUTs, Vignette, Grain, Blur-bg, Tilt-shift,
 *   Duotone, Chroma aberration, Glitch, RGB curves, Multi-text layers,
 *   Fonts, Text animation, Text bg, Subtitles, Auto-subs, Watermark,
 *   Stickers, Drawing, Shapes, Volume, Fade in/out, 5-band EQ, Pitch,
 *   Noise gate, Replace audio, Voiceover, Music library, Mix levels,
 *   Resolution, Format, GIF, Quality, Frame export, Before/After,
 *   WebCodecs, Undo/Redo, Hotkeys, Autosave, Frame navigation,
 *   Presets, Drag text, Pinch-zoom timeline, Compare view.
 *
 * NOTE: innerHTML usage is safe — only static SVG/HTML literals, never user input.
 */

/* ═══════════════════════════════════════════════════════════════
   CONSTANTS
   ═══════════════════════════════════════════════════════════════ */

const LUTS = [
    { n: 'None', f: '' },
    { n: 'Cinema', f: 'contrast(1.1) saturate(1.3) sepia(.1) brightness(.9)' },
    { n: 'Vintage', f: 'sepia(.4) contrast(.9) brightness(1.1) saturate(.8)' },
    { n: 'B&W', f: 'grayscale(1) contrast(1.2)' },
    { n: 'Cold', f: 'saturate(.8) brightness(1.05) hue-rotate(10deg)' },
    { n: 'Warm', f: 'saturate(1.2) brightness(1.05) hue-rotate(-10deg) sepia(.15)' },
    { n: 'Neon', f: 'saturate(2) contrast(1.3) brightness(1.1)' },
    { n: 'Fade', f: 'saturate(.6) contrast(.8) brightness(1.2)' },
    { n: 'Dramatic', f: 'contrast(1.5) saturate(.8) brightness(.85)' },
    { n: 'Pastel', f: 'saturate(.7) brightness(1.15) contrast(.85)' },
    { n: 'Noir', f: 'grayscale(1) contrast(1.4) brightness(.8)' },
    { n: 'Sunset', f: 'saturate(1.4) hue-rotate(-20deg) brightness(1.05) sepia(.2)' },
    { n: 'Ocean', f: 'saturate(.9) hue-rotate(30deg) contrast(1.1)' },
];
const FONTS = [
    'sans-serif', 'serif', 'monospace', "'Syne',sans-serif", "'Space Mono',monospace",
    'cursive', 'Impact,sans-serif', 'Georgia,serif', "'Courier New',monospace", 'system-ui',
];
const FONT_NAMES = ['Sans', 'Serif', 'Mono', 'Syne', 'Space', 'Cursive', 'Impact', 'Georgia', 'Courier', 'System'];
const ANIMS = ['none', 'fadeIn', 'typewriter', 'slideUp', 'bounce', 'pulse', 'glow', 'shake'];
const MUSIC = [
    { n: 'Chill Lo-Fi', d: '2:34', bpm: 85 }, { n: 'Upbeat Pop', d: '3:12', bpm: 120 },
    { n: 'Ambient Piano', d: '4:01', bpm: 70 }, { n: 'Cinematic Epic', d: '2:55', bpm: 100 },
    { n: 'Acoustic Guitar', d: '3:30', bpm: 95 }, { n: 'Electronic', d: '3:15', bpm: 140 },
    { n: 'Jazz Smooth', d: '4:22', bpm: 90 }, { n: 'Hip-Hop Beat', d: '2:48', bpm: 85 },
];
const STICKERS = {
    Faces: '😀😂🥰😎🤔😱🥳😴🤯😈🥺😤🤩😏🥹🤓🫠🫡',
    Hands: '👍👎👋🤝👏✌️🤞🤙👊✊🫶🙌🤌🫰🤟💪👆👇',
    Items: '❤️⭐🔥💯🎉🎵💡🚀💎🏆⚡🌈🎯✨💫🦋🍀🫧',
    Arrows: '➡️⬅️⬆️⬇️↗️↘️↙️↖️🔄↩️⤴️⤵️↕️↔️🔀🔁',
};
const COLORS = ['#ffffff','#000000','#ef4444','#22c55e','#3b82f6','#eab308','#a855f7','#ec4899','#14b8a6','#f97316'];
const EQ_FREQS = [60, 230, 910, 3600, 14000];
const EQ_LABELS = ['60', '230', '910', '3.6k', '14k'];

let _editor = null;
export function openVideoEditor(file, onDone, onCancel) {
    if (_editor) _editor.destroy();
    _editor = new VideoEditor(file, onDone, onCancel);
}
export function closeVideoEditor() { if (_editor) { _editor.destroy(); _editor = null; } }

/* ═══════════════════════════════════════════════════════════════
   VIDEO EDITOR CLASS
   ═══════════════════════════════════════════════════════════════ */

class VideoEditor {
constructor(file, onDone, onCancel) {
    this.file = file; this.onDone = onDone; this.onCancel = onCancel;
    this.objUrl = URL.createObjectURL(file);
    /* Edit */ this.trimStart = 0; this.trimEnd = 1; this.cuts = []; this.speed = 1;
    this.deletedSegs = []; this._selSeg = -1; // deleted segment indices, selected segment
    this.reversed = false; this.freezes = []; this.loopSeg = null;
    this.mergeFiles = []; this.keyframes = []; this.timecodes = [];
    /* Adjust */ this.crop = { x: 0, y: 0, w: 1, h: 1, aspect: 'free' };
    this.rotation = 0; this.flipH = false; this.flipV = false;
    this.brightness = 100; this.contrast = 100; this.saturation = 100;
    this.lut = null; this.vignette = 0; this.grain = 0; this.blurBg = 0;
    this.tiltShift = 0; this.tiltPos = 50;
    this.duotone = null; this.chromaAb = 0; this.glitch = 0;
    this.rgbR = 0; this.rgbG = 0; this.rgbB = 0;
    /* Text */ this.textLayers = []; this.subs = []; this.watermark = null;
    /* Overlay */ this.stickers = []; this.strokes = []; this.shapes = [];
    /* Audio */ this.volume = 1; this.fadeIn = 0; this.fadeOut = 0;
    this.eq = [0,0,0,0,0]; this.pitch = 0;
    this.noiseGate = false; this.noiseThr = -40;
    this.replUrl = null; this.replName = null;
    this.voiceUrl = null; this.voiceName = null;
    this.musicIdx = -1; this.mixOrig = 100; this.mixOver = 100;
    /* Export */ this.exRes = 'original'; this.exFmt = 'mp4'; this.exQual = 80;
    /* Cover */ this.thumbnail = null;
    /* UI */ this.duration = 0; this.activeTab = 'edit'; this.activeTool = 'trim';
    this._us = []; this._rs = []; // undo/redo stacks
    this._audioCtx = null; this._srcNode = null; this._eqN = null; this._gainN = null;
    this._replAudio = null; this._voiceAudio = null;
    this._drawing = false; this._curStroke = null;
    this._thumbVid = null; this._grainRAF = null; this._selText = null; this._selSticker = null;
    this._recorder = null; this._compare = false; this._tlZoom = 1;
    this._presets = JSON.parse(localStorage.getItem('ved_presets') || '[]');
    this._build(); this._bindKeys(); this._loadDraft();
    this._saveTimer = setInterval(() => this._saveDraft(), 5000);
}

destroy() {
    this.root?.remove();
    if (this.video) { this.video.pause(); this.video.src = ''; }
    if (this._thumbVid) this._thumbVid.src = '';
    if (this._replAudio) { this._replAudio.pause(); this._replAudio = null; }
    if (this._voiceAudio) { this._voiceAudio.pause(); this._voiceAudio = null; }
    URL.revokeObjectURL(this.objUrl);
    [this.replUrl, this.voiceUrl, this.watermark?.url].forEach(u => u && URL.revokeObjectURL(u));
    this.mergeFiles.forEach(f => URL.revokeObjectURL(f.url));
    if (this._audioCtx) this._audioCtx.close().catch(() => {});
    document.removeEventListener('keydown', this._kh);
    clearInterval(this._saveTimer);
    cancelAnimationFrame(this._grainRAF);
    _editor = null;
}

/* ─── BUILD ──────────────────────────────────────────────── */

_build() {
    const R = this.root = document.createElement('div');
    R.className = 'ved-root'; R.tabIndex = -1;

    // Header
    const h = document.createElement('div'); h.className = 'ved-header';
    const canc = this._btn('ved-header-btn', 'Cancel', () => { this.destroy(); this.onCancel?.(); });
    const undo = this._iconBtn('ved-hdr-icon', 'M3 10h10a5 5 0 015 5v2 M3 10l4-4m-4 4l4 4', () => this._undo());
    const redo = this._iconBtn('ved-hdr-icon', 'M21 10H11a5 5 0 00-5 5v2 M21 10l-4-4m4 4l-4 4', () => this._redo());
    this._undoEl = undo; this._redoEl = redo;
    const title = document.createElement('div'); title.className = 'ved-title'; title.textContent = (window.t?.('videoEditor.title')||'Video Editor');
    const done = this._btn('ved-header-btn ved-done', 'Done', () => this._finish());
    h.append(canc, undo, redo, title, done);
    R.appendChild(h);

    // Player
    const pw = document.createElement('div'); pw.className = 'ved-player'; this.playerEl = pw;
    this.video = document.createElement('video');
    Object.assign(this.video, { src: this.objUrl, playsInline: true, preload: 'auto', className: 'ved-video' });
    pw.appendChild(this.video);

    // Effect overlays
    this.vignetteEl = this._el('div', 'ved-vignette-ov'); pw.appendChild(this.vignetteEl);
    this.grainCvs = document.createElement('canvas'); this.grainCvs.className = 'ved-grain-ov'; pw.appendChild(this.grainCvs);
    this.tiltEl = this._el('div', 'ved-tilt-ov'); pw.appendChild(this.tiltEl);
    this.overlayBox = this._el('div', 'ved-ov-box'); pw.appendChild(this.overlayBox);
    this.drawCvs = document.createElement('canvas'); this.drawCvs.className = 'ved-draw-cvs'; pw.appendChild(this.drawCvs);
    this.subEl = this._el('div', 'ved-sub-display'); pw.appendChild(this.subEl);
    this.cropEl = this._el('div', 'ved-crop-ov'); pw.appendChild(this.cropEl);
    this.compareLine = this._el('div', 'ved-compare-line'); pw.appendChild(this.compareLine);

    const playOv = this._el('div', 'ved-play-overlay');
    playOv.innerHTML = '<svg width="56" height="56" viewBox="0 0 24 24" fill="white" opacity=".8"><path d="M8 5v14l11-7z"/></svg>';
    pw.appendChild(playOv); this.playOv = playOv;
    pw.addEventListener('click', e => {
        if (this._drawing || e.target.closest('.ved-ov-layer,.ved-crop-handle')) return;
        this._togglePlay();
    });
    R.appendChild(pw);

    // Content
    this.content = this._el('div', 'ved-content'); R.appendChild(this.content);

    // Tabs
    const tbar = this._el('div', 'ved-tabs');
    const T = [
        ['edit','M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21H3v-3.5L16.732 3.732z','Edit'],
        ['adjust','M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707 M12 8a4 4 0 100 8 4 4 0 000-8z','Adjust'],
        ['text','M4 7V4h16v3 M9 20h6 M12 4v16','Text'],
        ['overlay','M12 2L2 7l10 5 10-5-10-5z M2 17l10 5 10-5 M2 12l10 5 10-5','Overlay'],
        ['audio','M11 5L6 9H2v6h4l5 4V5z M19.07 4.93a10 10 0 010 14.14 M15.54 8.46a5 5 0 010 7.07','Audio'],
        ['export','M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M7 10l5 5 5-5 M12 15V3','Export'],
        ['cover','M3 3h18a2 2 0 012 2v14a2 2 0 01-2 2H3a2 2 0 01-2-2V5c0-1.1.9-2 2-2z M8.5 8.5a1.5 1.5 0 100-3 1.5 1.5 0 000 3z M21 15l-5-5L5 21','Cover'],
    ];
    T.forEach(([id, icon, label]) => {
        const t = this._mkTab(id, icon, label);
        tbar.appendChild(t); this['_tab_' + id] = t;
    });
    R.appendChild(tbar);
    document.body.appendChild(R);

    this.video.addEventListener('loadedmetadata', () => { this.duration = this.video.duration; this._resizeCvs(); this._showTab('edit'); });
    this.video.addEventListener('timeupdate', () => this._onTime());
    this.video.addEventListener('play', () => playOv.classList.add('hidden'));
    this.video.addEventListener('pause', () => playOv.classList.remove('hidden'));
    new ResizeObserver(() => this._resizeCvs()).observe(pw);
}

/* ─── TAB SYSTEM ─────────────────────────────────────────── */

_mkTab(id, pathD, label) {
    const t = document.createElement('button');
    t.className = 'ved-tab' + (id === 'edit' ? ' active' : '');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '18'); svg.setAttribute('height', '18');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '1.5');
    svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
    pathD.split(' M').forEach((d, i) => {
        const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        p.setAttribute('d', (i ? 'M' : '') + d); svg.appendChild(p);
    });
    t.appendChild(svg);
    const s = document.createElement('span'); s.textContent = label; t.appendChild(s);
    t.addEventListener('click', () => this._showTab(id));
    return t;
}

_showTab(id) {
    this.activeTab = id;
    document.querySelectorAll('.ved-tab').forEach(t => t.classList.remove('active'));
    this['_tab_' + id]?.classList.add('active');
    this.content.textContent = '';
    this._drawing = false; this.drawCvs.classList.remove('active');
    this.cropEl.classList.remove('active');
    this._compare = false; this.compareLine.style.display = 'none';
    // Overlays only interactive on text/overlay tabs
    const ovInteractive = (id === 'text' || id === 'overlay');
    this.overlayBox.querySelectorAll('.ved-ov-layer').forEach(el => {
        el.style.pointerEvents = ovInteractive ? 'auto' : 'none';
        el.style.cursor = ovInteractive ? 'grab' : 'default';
    });
    // Hide crop overlay on non-adjust tabs
    if (id !== 'adjust') this.video.style.clipPath = '';
    this['_tab_build_' + id]?.();
}

_tab_build_edit() { this._buildSubtools('edit', [
    ['trim','M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21H3v-3.5L16.732 3.732z','Trim'],
    ['speed','M13 2L3 14h9l-1 8 10-12h-9l1-8z','Speed'],
    ['reverse','M1 4v6h6 M23 20v-6h-6 M20.49 9A9 9 0 005.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 013.51 15','Reverse'],
    ['freeze','M12 2v4m0 12v4 M2 12h4m12 0h4 M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83 M19.07 4.93l-2.83 2.83m-8.48 8.48l-2.83 2.83','Freeze'],
    ['loop','M17 1l4 4-4 4 M3 11V9a4 4 0 014-4h14 M7 23l-4-4 4-4 M21 13v2a4 4 0 01-4 4H3','Loop'],
    ['merge','M12 5v14 M5 12h14','Merge'],
    ['keyframe','M12 2a10 10 0 100 20 10 10 0 000-20z M12 6v6l4 2','Keyframes'],
    ['timecodes','M3 3h18v18H3z M3 9h18 M3 15h18 M9 3v18','Timecodes'],
]); }

_tab_build_adjust() { this._buildSubtools('adjust', [
    ['crop','M6.13 1L6 16a2 2 0 002 2h15 M1 6.13L16 6a2 2 0 012 2v15','Crop'],
    ['rotate','M23 4v6h-6 M1 20v-6h6 M3.51 9a9 9 0 0114.85-3.36L23 10 M1 14l4.64 4.36A9 9 0 0020.49 15','Rotate'],
    ['filters','M12 3v1m0 16v1m9-9h-1M4 12H3 M12 8a4 4 0 100 8 4 4 0 000-8z','Filters'],
    ['luts','M20 7l-8 5-8-5m16 0l-8 5m8-5v10l-8 5m0-10L4 7m8 5v10M4 7v10l8 5','LUTs'],
    ['vignette','M12 2a10 10 0 100 20 10 10 0 000-20z','Vignette'],
    ['grain','M4 4h16v16H4z','Grain'],
    ['blurbg','M1 12s4-8 11-8 7 0 11 8 11 8s-4 8-11 8-11-8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z','Blur BG'],
    ['tiltshift','M1 3h22 M1 21h22 M5 12h14','Tilt-Shift'],
    ['duotone','M12 2a10 10 0 100 20 10 10 0 000-20z M12 2v20','Duotone'],
    ['chroma','M12 2a10 10 0 100 20 10 10 0 000-20z','Chroma'],
    ['glitch','M2 12h6l3-9 4 18 3-9h4','Glitch'],
    ['rgb','M12 2a10 10 0 100 20 10 10 0 000-20z M2 12h20 M12 2a15 15 0 014 10 15 15 0 01-4 10 M12 2a15 15 0 00-4 10 15 15 0 004 10','RGB'],
    ['presets','M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z M17 21v-8H7v8 M7 3v5h8','Presets'],
]); }

_tab_build_text() { this._buildSubtools('text', [
    ['textlayers','M4 7V4h16v3 M9 20h6 M12 4v16','Layers'],
    ['subtitles','M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2v10z','Subtitles'],
    ['autosubs','M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z M19 10v2a7 7 0 01-14 0v-2 M12 19v4 M8 23h8','Auto-Subs'],
    ['watermark','M3 3h18v18H3z M8.5 8.5a1.5 1.5 0 100-3 1.5 1.5 0 000 3z M21 15l-5-5L5 21','Watermark'],
]); }

_tab_build_overlay() { this._buildSubtools('overlay', [
    ['stickers','M14.828 14.828a4 4 0 01-5.656 0 M9 10h.01 M15 10h.01 M21 12a9 9 0 11-18 0 9 9 0 0118 0z','Stickers'],
    ['draw','M17 3a2.83 2.83 0 114 4L7.5 20.5 2 22l1.5-5.5L17 3z','Draw'],
    ['shapes','M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M17.5 14a3.5 3.5 0 100 7 3.5 3.5 0 000-7z','Shapes'],
]); }

_tab_build_audio() { this._buildSubtools('audio', [
    ['volume','M11 5L6 9H2v6h4l5 4V5z M19.07 4.93a10 10 0 010 14.14','Volume'],
    ['fade','M2 12c2-4 4-8 10-8s8 4 10 8','Fade'],
    ['eq','M4 21v-7 M4 10V3 M12 21v-9 M12 8V3 M20 21v-5 M20 12V3 M1 14h6 M9 8h6 M17 16h6','EQ'],
    ['pitch','M2 20h20 M6 16l4-8 4 4 4-12','Pitch'],
    ['noisegate','M1 12s4-8 11-8 7 0 11 8 11 8 M1 1l22 22','Noise Gate'],
    ['replace','M9 18V5l12-2v13 M9 18a3 3 0 11-6 0 3 3 0 016 0z M21 16a3 3 0 11-6 0 3 3 0 016 0z','Replace'],
    ['voiceover','M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z M19 10v2a7 7 0 01-14 0v-2','Record'],
    ['music','M9 18V5l12-2v13','Music'],
    ['mix','M4 21v-7 M12 21v-9 M20 21v-5 M1 14h6 M9 12h6 M17 16h6','Mix'],
]); }

_tab_build_export() { this._buildSubtools('export', [
    ['resolution','M3 3h18v18H3z M9 3v18 M15 3v18 M3 9h18 M3 15h18','Resolution'],
    ['format','M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z M14 2v6h6 M12 18v-6 M9 15l3 3 3-3','Format'],
    ['gif','M21 12a9 9 0 11-18 0 9 9 0 0118 0z M10 8l6 4-6 4V8z','GIF'],
    ['quality','M4 21v-7 M8 21v-5 M12 21v-9 M16 21v-6 M20 21v-10','Quality'],
    ['snapshot','M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2v11z M12 13a4 4 0 100-8 4 4 0 000 8z','Snapshot'],
    ['compare','M12 3v18 M3 12h18','Compare'],
]); }

_tab_build_cover() { this._buildCover(); }

_buildSubtools(tab, tools) {
    // Reset activeTool if it doesn't belong to this tab
    if (!tools.some(([id]) => id === this.activeTool)) {
        this.activeTool = tools[0][0];
    }
    const w = this._el('div', 'ved-edit');
    const bar = this._el('div', 'ved-toolbar');
    tools.forEach(([id, icon, label]) => {
        const btn = document.createElement('button');
        btn.className = 'ved-tool' + (this.activeTool === id ? ' active' : '');
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('width', '16'); svg.setAttribute('height', '16');
        svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '2');
        svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
        icon.split(' M').forEach((d, i) => {
            const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            p.setAttribute('d', (i ? 'M' : '') + d); svg.appendChild(p);
        });
        btn.appendChild(svg);
        const s = document.createElement('span'); s.textContent = label; btn.appendChild(s);
        btn.addEventListener('click', () => { this.activeTool = id; this._showTab(tab); });
        bar.appendChild(btn);
    });
    w.appendChild(bar);
    const tc = this._el('div', 'ved-tool-content');
    if (this['_t_' + this.activeTool]) this['_t_' + this.activeTool](tc);
    w.appendChild(tc);
    this.content.appendChild(w);
}

/* ═══════════════════════════════════════════════════════════════
   EDIT TAB TOOLS
   ═══════════════════════════════════════════════════════════════ */

/* ── Trim ─────────────────────────────────────────────────── */
_t_trim(c) {
    const tl = this._el('div', 'ved-timeline');
    tl.style.transform = 'scaleX(' + this._tlZoom + ')';
    const strip = this._el('div', 'ved-strip');
    tl.appendChild(strip); this._genStrip(strip);
    const region = this._el('div', 'ved-trim-region');
    const dimL = this._el('div', 'ved-dim ved-dim-l');
    const dimR = this._el('div', 'ved-dim ved-dim-r');
    const hL = this._el('div', 'ved-handle ved-handle-l');
    const hR = this._el('div', 'ved-handle ved-handle-r');
    const az = this._el('div', 'ved-active-zone');
    region.append(dimL, hL, az, hR, dimR); tl.appendChild(region);

    // Clickable segments between cuts
    const segBounds = this._getSegments();
    segBounds.forEach((seg, i) => {
        const segEl = this._el('div', 'ved-seg');
        segEl.style.left = (seg.start * 100) + '%';
        segEl.style.width = ((seg.end - seg.start) * 100) + '%';
        if (this.deletedSegs.includes(i)) segEl.classList.add('deleted');
        if (this._selSeg === i) segEl.classList.add('selected');
        segEl.addEventListener('click', e => {
            e.stopPropagation();
            this._selSeg = (this._selSeg === i ? -1 : i);
            this._showTab('edit');
        });
        tl.appendChild(segEl);
    });

    // Cut markers
    this.cuts.forEach((pos, i) => {
        const m = this._el('div', 'ved-cut-mark');
        m.style.left = (pos * 100) + '%';
        m.title = 'Cut #' + (i + 1) + ' \u2014 click to remove';
        m.addEventListener('click', e => { e.stopPropagation(); this._saveSnap(); this.cuts.splice(i, 1); this.deletedSegs = []; this._selSeg = -1; this._showTab('edit'); });
        tl.appendChild(m);
    });
    // Freeze markers
    this.freezes.forEach((f, i) => {
        const m = this._el('div', 'ved-freeze-mark');
        m.style.left = (f.pos * 100) + '%';
        m.title = 'Freeze ' + f.dur + 's \u2014 click to remove';
        m.addEventListener('click', e => { e.stopPropagation(); this._saveSnap(); this.freezes.splice(i, 1); this._showTab('edit'); });
        tl.appendChild(m);
    });
    // Keyframe dots
    this.keyframes.forEach((kf, i) => {
        const m = this._el('div', 'ved-kf-mark');
        m.style.left = (kf.pos * 100) + '%';
        m.title = 'Keyframe \u2014 click to remove';
        m.addEventListener('click', e => { e.stopPropagation(); this._saveSnap(); this.keyframes.splice(i, 1); this._showTab('edit'); });
        tl.appendChild(m);
    });
    // Timecode markers
    this.timecodes.forEach(tc => {
        const m = this._el('div', 'ved-tc-mark');
        m.style.left = (this.duration ? tc.time / this.duration * 100 : 0) + '%';
        m.title = tc.label;
        m.addEventListener('click', e => { e.stopPropagation(); this.video.currentTime = tc.time; });
        tl.appendChild(m);
    });
    const ph = this._el('div', 'ved-playhead');
    tl.appendChild(ph); this.playhead = ph;
    this._trimEls = { hL, hR, az, dimL, dimR };
    this._setupDrag(hL, 'start', tl); this._setupDrag(hR, 'end', tl);
    tl.addEventListener('click', e => {
        if (e.target.closest('.ved-handle,.ved-cut-mark,.ved-freeze-mark,.ved-kf-mark,.ved-seg')) return;
        const r = tl.getBoundingClientRect();
        this.video.currentTime = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * this.duration;
    });
    // Pinch-to-zoom on timeline
    tl.addEventListener('wheel', e => {
        e.preventDefault();
        this._tlZoom = Math.max(1, Math.min(5, this._tlZoom + (e.deltaY > 0 ? -0.2 : 0.2)));
        tl.style.transform = 'scaleX(' + this._tlZoom + ')';
    }, { passive: false });
    c.appendChild(tl);

    // Segment info + delete button
    if (this._selSeg >= 0 && segBounds[this._selSeg]) {
        const seg = segBounds[this._selSeg];
        const isDeleted = this.deletedSegs.includes(this._selSeg);
        const segInfo = this._el('div', 'ved-seg-info');
        const segLabel = this._el('span', 'ved-seg-label');
        segLabel.textContent = 'Segment ' + (this._selSeg + 1) + ': ' + this._fmt(seg.start * this.duration) + ' \u2192 ' + this._fmt(seg.end * this.duration);
        const segAction = this._btn(
            isDeleted ? 'ved-ctrl ved-seg-restore' : 'ved-ctrl ved-seg-delete',
            isDeleted ? (window.t?.('videoEditor.restore')||'Restore') : (window.t?.('videoEditor.deleteSegment')||'Delete segment'),
            () => {
                this._saveSnap();
                if (isDeleted) {
                    this.deletedSegs = this.deletedSegs.filter(s => s !== this._selSeg);
                } else {
                    // Don't allow deleting all segments
                    if (this.deletedSegs.length >= segBounds.length - 1) return;
                    this.deletedSegs.push(this._selSeg);
                }
                this._showTab('edit');
            }
        );
        segInfo.append(segLabel, segAction);
        c.appendChild(segInfo);
    }

    const tr = this._el('div', 'ved-time-row');
    this.elTS = this._el('span'); this.elTC = this._el('span', 'ved-time-c'); this.elTE = this._el('span');
    tr.append(this.elTS, this.elTC, this.elTE); c.appendChild(tr);

    // Controls: frame back, play, frame forward, duration, split button
    const row = this._el('div', 'ved-controls');
    const fb = this._iconBtn('ved-ctrl-sm', 'M19 12H5 M12 19l-7-7 7-7', () => this._frameStep(-1));
    const pb = document.createElement('button'); pb.className = 'ved-ctrl-play';
    pb.innerHTML = '<svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>';
    pb.addEventListener('click', () => this._togglePlay());
    const ff = this._iconBtn('ved-ctrl-sm', 'M5 12h14 M12 5l7 7-7 7', () => this._frameStep(1));
    const dur = this._el('div', 'ved-dur');
    dur.textContent = this._fmt((this.trimEnd - this.trimStart) * this.duration);
    const splitBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.splitHere')||'Split here'), () => {
        this._saveSnap();
        const pos = this.video.currentTime / this.duration;
        if (pos > 0.01 && pos < 0.99 && !this.cuts.some(c => Math.abs(c - pos) < 0.01)) {
            this.cuts.push(pos); this.cuts.sort((a, b) => a - b);
            this.deletedSegs = []; this._selSeg = -1;
        }
        this._showTab('edit');
    });
    row.append(fb, pb, ff, dur, splitBtn); c.appendChild(row);
    this._updTrim();
}

/* ── Speed ────────────────────────────────────────────────── */
_t_speed(c) {
    const speeds = [0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 3];
    const g = this._el('div', 'ved-speed-grid');
    speeds.forEach(s => {
        const b = document.createElement('button');
        b.className = 'ved-speed-btn' + (this.speed === s ? ' active' : '');
        b.textContent = s + 'x';
        b.addEventListener('click', () => { this._saveSnap(); this.speed = s; this.video.playbackRate = s; this._showTab('edit'); });
        g.appendChild(b);
    }); c.appendChild(g);
}

/* ── Reverse ──────────────────────────────────────────────── */
_t_reverse(c) {
    const toggle = this._toggle((window.t?.('videoEditor.reversePlayback')||'Reverse playback'), this.reversed, v => { this._saveSnap(); this.reversed = v; });
    c.appendChild(toggle);
    c.appendChild(this._note('Video will be reversed on export. Preview plays forward.'));
}

/* ── Freeze Frame ─────────────────────────────────────────── */
_t_freeze(c) {
    const addBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.freezeCurrentFrame')||'Freeze current frame'), () => {
        this._saveSnap();
        const pos = this.video.currentTime / this.duration;
        this.freezes.push({ pos, dur: 2 });
        this._showTab('edit');
    });
    addBtn.style.cssText = 'width:100%;justify-content:center';
    c.appendChild(addBtn);
    c.appendChild(this._slider('Duration (s)', 0.5, 10, this.freezes.length ? this.freezes[this.freezes.length-1].dur : 2, 's', v => {
        if (this.freezes.length) this.freezes[this.freezes.length-1].dur = v;
    }));
    if (this.freezes.length) {
        const list = this._el('div', 'ved-layer-list');
        this.freezes.forEach((f, i) => {
            const row = this._el('div', 'ved-layer-item');
            row.textContent = 'Freeze at ' + this._fmt(f.pos * this.duration) + ' — ' + f.dur + 's';
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => { this._saveSnap(); this.freezes.splice(i, 1); this._showTab('edit'); });
            row.appendChild(del); list.appendChild(row);
        }); c.appendChild(list);
    }
}

/* ── Loop Segment ─────────────────────────────────────────── */
_t_loop(c) {
    const toggle = this._toggle((window.t?.('videoEditor.loopSegment')||'Loop segment'), !!this.loopSeg, v => {
        this._saveSnap();
        if (v) this.loopSeg = { start: this.trimStart, end: this.trimEnd, count: 2 };
        else this.loopSeg = null;
        this._showTab('edit');
    });
    c.appendChild(toggle);
    if (this.loopSeg) {
        c.appendChild(this._slider('Repeat count', 2, 10, this.loopSeg.count, 'x', v => { this.loopSeg.count = v; }));
        c.appendChild(this._note('Loops ' + this._fmt(this.loopSeg.start * this.duration) + ' → ' + this._fmt(this.loopSeg.end * this.duration)));
    }
}

/* ── Merge ────────────────────────────────────────────────── */
_t_merge(c) {
    const addBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.addVideoClip')||'Add video clip...'), () => {
        const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'video/*';
        inp.addEventListener('change', () => {
            if (!inp.files?.[0]) return;
            this._saveSnap();
            const f = inp.files[0];
            this.mergeFiles.push({ file: f, url: URL.createObjectURL(f), name: f.name });
            this._showTab('edit');
        }); inp.click();
    });
    addBtn.style.cssText = 'width:100%;justify-content:center';
    c.appendChild(addBtn);
    if (this.mergeFiles.length) {
        const list = this._el('div', 'ved-layer-list');
        this.mergeFiles.forEach((mf, i) => {
            const row = this._el('div', 'ved-layer-item');
            row.textContent = (i + 2) + '. ' + mf.name;
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => {
                this._saveSnap(); URL.revokeObjectURL(mf.url); this.mergeFiles.splice(i, 1); this._showTab('edit');
            });
            row.appendChild(del); list.appendChild(row);
        }); c.appendChild(list);
    }
    c.appendChild(this._note('Clips will be concatenated in order on export.'));
}

/* ── Keyframes ────────────────────────────────────────────── */
_t_keyframe(c) {
    const addBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.addKeyframe')||'Add keyframe at current time'), () => {
        this._saveSnap();
        const pos = this.video.currentTime / this.duration;
        this.keyframes.push({ pos, zoom: 1, panX: 0, panY: 0 });
        this.keyframes.sort((a, b) => a.pos - b.pos);
        this._showTab('edit');
    });
    addBtn.style.cssText = 'width:100%;justify-content:center';
    c.appendChild(addBtn);
    if (this.keyframes.length) {
        const list = this._el('div', 'ved-layer-list');
        this.keyframes.forEach((kf, i) => {
            const row = this._el('div', 'ved-layer-item ved-kf-row');
            const lbl = this._el('span'); lbl.textContent = this._fmt(kf.pos * this.duration);
            lbl.style.minWidth = '40px';
            const zSlider = this._miniSlider('Zoom', 0.5, 3, kf.zoom, v => { kf.zoom = v; this._applyKeyframe(); });
            const xSlider = this._miniSlider('X', -100, 100, kf.panX, v => { kf.panX = v; this._applyKeyframe(); });
            const ySlider = this._miniSlider('Y', -100, 100, kf.panY, v => { kf.panY = v; this._applyKeyframe(); });
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => { this._saveSnap(); this.keyframes.splice(i, 1); this._showTab('edit'); });
            row.append(lbl, zSlider, xSlider, ySlider, del); list.appendChild(row);
        }); c.appendChild(list);
    }
    c.appendChild(this._note('Zoom and pan animate between keyframes during playback.'));
}

/* ── Timecodes ────────────────────────────────────────────── */
_t_timecodes(c) {
    // ── Mini player / scrubber ──
    const playerBox = this._el('div', 'ved-tc-player');

    // Scrub bar with existing timecode markers
    const scrubWrap = this._el('div', 'ved-tc-scrub');
    const scrubFill = this._el('div', 'ved-tc-scrub-fill');
    const scrubThumb = this._el('div', 'ved-tc-scrub-thumb');
    scrubWrap.append(scrubFill, scrubThumb);
    // Timecode markers on scrub bar
    this.timecodes.forEach(tc => {
        const m = this._el('div', 'ved-tc-scrub-mark');
        m.style.left = (this.duration ? tc.time / this.duration * 100 : 0) + '%';
        m.title = tc.label;
        scrubWrap.appendChild(m);
    });

    const updateScrub = () => {
        if (!this.duration) return;
        const pct = this.video.currentTime / this.duration * 100;
        scrubFill.style.width = pct + '%';
        scrubThumb.style.left = pct + '%';
        timeDisplay.textContent = this._fmt(this.video.currentTime) + ' / ' + this._fmt(this.duration);
    };
    // Drag to seek
    let dragging = false;
    const seekFromEvent = (e) => {
        const r = scrubWrap.getBoundingClientRect();
        const pct = Math.max(0, Math.min(1, ((e.touches ? e.touches[0].clientX : e.clientX) - r.left) / r.width));
        this.video.currentTime = pct * this.duration;
        updateScrub();
    };
    scrubWrap.addEventListener('mousedown', e => { dragging = true; this.video.pause(); seekFromEvent(e); document.addEventListener('mousemove', onDrag); document.addEventListener('mouseup', onUp); });
    scrubWrap.addEventListener('touchstart', e => { dragging = true; this.video.pause(); seekFromEvent(e); document.addEventListener('touchmove', onDrag, { passive: false }); document.addEventListener('touchend', onUp); }, { passive: false });
    const onDrag = e => { if (dragging) { e.preventDefault?.(); seekFromEvent(e); } };
    const onUp = () => { dragging = false; document.removeEventListener('mousemove', onDrag); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchmove', onDrag); document.removeEventListener('touchend', onUp); };

    playerBox.appendChild(scrubWrap);

    // Controls row: frame back, play/pause, frame forward, time
    const ctrlRow = this._el('div', 'ved-tc-ctrls');
    const PLAY_SVG = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>';
    const PAUSE_SVG = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>';
    const fbBtn = this._iconBtn('ved-ctrl-sm', 'M19 12H5 M12 19l-7-7 7-7', () => { this.video.currentTime = Math.max(0, this.video.currentTime - 1 / 30); updateScrub(); });
    const playPauseBtn = document.createElement('button'); playPauseBtn.className = 'ved-ctrl-play'; playPauseBtn.style.cssText = 'width:36px;height:36px;';
    playPauseBtn.innerHTML = PLAY_SVG;
    playPauseBtn.addEventListener('click', () => {
        if (this.video.paused) this.video.play(); else this.video.pause();
    });
    this.video.addEventListener('play', () => { playPauseBtn.innerHTML = PAUSE_SVG; });
    this.video.addEventListener('pause', () => { playPauseBtn.innerHTML = PLAY_SVG; });
    const ffBtn = this._iconBtn('ved-ctrl-sm', 'M5 12h14 M12 5l7 7-7 7', () => { this.video.currentTime = Math.min(this.duration, this.video.currentTime + 1 / 30); updateScrub(); });
    // -5s / +5s buttons
    const back5 = this._btn('ved-ctrl-sm-txt', '-5s', () => { this.video.currentTime = Math.max(0, this.video.currentTime - 5); updateScrub(); });
    const fwd5 = this._btn('ved-ctrl-sm-txt', '+5s', () => { this.video.currentTime = Math.min(this.duration, this.video.currentTime + 5); updateScrub(); });
    const timeDisplay = this._el('div', 'ved-tc-time-display');
    timeDisplay.textContent = this._fmt(this.video.currentTime) + ' / ' + this._fmt(this.duration);
    ctrlRow.append(back5, fbBtn, playPauseBtn, ffBtn, fwd5, timeDisplay);
    playerBox.appendChild(ctrlRow);
    c.appendChild(playerBox);

    // Update scrub on video timeupdate
    this._tcUpdateScrub = () => updateScrub();
    this.video.addEventListener('timeupdate', this._tcUpdateScrub);
    updateScrub();

    // ── Add timecode row ──
    const addBox = this._el('div', 'ved-tc-add-box');
    const nameInp = document.createElement('input'); nameInp.type = 'text';
    nameInp.className = 'ved-text-input'; nameInp.placeholder = (window.t?.('videoEditor.chapterName')||'Chapter name...');
    nameInp.style.flex = '1';
    const addBtn = this._btn('ved-ctrl ved-tc-add-btn', '+ Add at ' + this._fmt(this.video.currentTime), () => {
        const label = nameInp.value.trim() || 'Chapter ' + (this.timecodes.length + 1);
        this._saveSnap();
        this.timecodes.push({ time: this.video.currentTime, label });
        this.timecodes.sort((a, b) => a.time - b.time);
        this.video.removeEventListener('timeupdate', this._tcUpdateScrub);
        this._showTab('edit');
    });
    // Update button text as video plays
    const updateAddBtn = () => { addBtn.textContent = '+ Add at ' + this._fmt(this.video.currentTime); };
    this.video.addEventListener('timeupdate', updateAddBtn);
    addBox.append(nameInp, addBtn);
    c.appendChild(addBox);

    // ── Timecodes list ──
    if (this.timecodes.length) {
        const list = this._el('div', 'ved-layer-list');
        this.timecodes.forEach((tc, i) => {
            const row = this._el('div', 'ved-tc-item');
            const timeBadge = this._el('span', 'ved-tc-time');
            timeBadge.textContent = this._fmt(tc.time);
            timeBadge.addEventListener('click', e => { e.stopPropagation(); this.video.currentTime = tc.time; updateScrub(); });
            const labelInp = document.createElement('input'); labelInp.type = 'text';
            labelInp.className = 'ved-tc-label'; labelInp.value = tc.label;
            labelInp.addEventListener('change', () => { tc.label = labelInp.value.trim() || tc.label; });
            const del = this._btn('ved-ctrl-xs', '\u00D7', e => {
                e.stopPropagation(); this._saveSnap();
                this.timecodes.splice(i, 1);
                this.video.removeEventListener('timeupdate', this._tcUpdateScrub);
                this._showTab('edit');
            });
            row.append(timeBadge, labelInp, del);
            row.addEventListener('click', () => { this.video.currentTime = tc.time; updateScrub(); });
            list.appendChild(row);
        });
        c.appendChild(list);

        const copyBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.copyTimecodes')||'Copy timecodes'), () => {
            const text = this.timecodes.map(tc => this._fmt(tc.time) + ' \u2014 ' + tc.label).join('\n');
            navigator.clipboard.writeText(text).then(() => {
                copyBtn.textContent = (window.t?.('ui.copied')||'Copied!');
                setTimeout(() => { copyBtn.textContent = (window.t?.('videoEditor.copyTimecodes')||'Copy timecodes'); }, 1500);
            });
        });
        copyBtn.style.cssText = 'width:100%;justify-content:center;margin-top:6px';
        c.appendChild(copyBtn);
    }

    c.appendChild(this._note('Scrub the video to find the right moment, then add a chapter.'));
}

/* ═══════════════════════════════════════════════════════════════
   ADJUST TAB TOOLS
   ═══════════════════════════════════════════════════════════════ */

/* ── Crop ─────────────────────────────────────────────────── */
_t_crop(c) {
    const aspects = ['free', '16:9', '9:16', '4:3', '3:4', '1:1'];
    const g = this._el('div', 'ved-speed-grid');
    aspects.forEach(a => {
        const b = document.createElement('button');
        b.className = 'ved-speed-btn' + (this.crop.aspect === a ? ' active' : '');
        b.textContent = a === 'free' ? 'Free' : a;
        b.addEventListener('click', () => {
            this._saveSnap(); this.crop.aspect = a;
            if (a !== 'free') {
                const [rw, rh] = a.split(':').map(Number);
                const r = rw / rh; const vr = (this.video.videoWidth || 16) / (this.video.videoHeight || 9);
                if (r > vr) { this.crop.w = 1; this.crop.h = vr / r; }
                else { this.crop.h = 1; this.crop.w = r / vr; }
                this.crop.x = (1 - this.crop.w) / 2; this.crop.y = (1 - this.crop.h) / 2;
            } else { this.crop.x = 0; this.crop.y = 0; this.crop.w = 1; this.crop.h = 1; }
            this._applyCrop(); this._showTab('adjust');
        });
        g.appendChild(b);
    }); c.appendChild(g);
    this._applyCrop();
    const resetBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.resetCrop')||'Reset crop'), () => {
        this._saveSnap(); this.crop = { x: 0, y: 0, w: 1, h: 1, aspect: 'free' };
        this._applyCrop(); this._showTab('adjust');
    });
    resetBtn.style.cssText = 'width:100%;justify-content:center;margin-top:6px';
    c.appendChild(resetBtn);
}

/* ── Rotate ───────────────────────────────────────────────── */
_t_rotate(c) {
    const row = this._el('div', 'ved-rotate-grid');
    [['90\u00B0', () => this.rotation = (this.rotation + 90) % 360],
     ['-90\u00B0', () => this.rotation = (this.rotation + 270) % 360],
     ['Flip H', () => this.flipH = !this.flipH],
     ['Flip V', () => this.flipV = !this.flipV],
     [(window.t?.('ui.reset')||'Reset'), () => { this.rotation = 0; this.flipH = false; this.flipV = false; }],
    ].forEach(([label, fn]) => {
        const b = this._btn('ved-ctrl', label, () => { this._saveSnap(); fn(); this._applyTransform(); this._showTab('adjust'); });
        row.appendChild(b);
    }); c.appendChild(row);
    c.appendChild(this._note('Rotation: ' + this.rotation + '\u00B0' + (this.flipH ? ' | Flip H' : '') + (this.flipV ? ' | Flip V' : '')));
}

/* ── Filters ──────────────────────────────────────────────── */
_t_filters(c) {
    c.appendChild(this._slider('Brightness', 0, 200, this.brightness, '%', v => { this._saveSnap(); this.brightness = v; this._applyFilters(); }));
    c.appendChild(this._slider('Contrast', 0, 200, this.contrast, '%', v => { this._saveSnap(); this.contrast = v; this._applyFilters(); }));
    c.appendChild(this._slider('Saturation', 0, 200, this.saturation, '%', v => { this._saveSnap(); this.saturation = v; this._applyFilters(); }));
    const rb = this._btn('ved-ctrl', (window.t?.('ui.reset')||'Reset'), () => {
        this._saveSnap(); this.brightness = this.contrast = this.saturation = 100;
        this._applyFilters(); this._showTab('adjust');
    });
    rb.style.cssText = 'width:100%;justify-content:center;margin-top:4px'; c.appendChild(rb);
}

/* ── LUTs ─────────────────────────────────────────────────── */
_t_luts(c) {
    const g = this._el('div', 'ved-lut-grid');
    LUTS.forEach((l, i) => {
        const item = document.createElement('button');
        item.className = 'ved-lut-item' + (this.lut === i ? ' active' : '');
        item.textContent = l.n;
        item.addEventListener('click', () => { this._saveSnap(); this.lut = (this.lut === i ? null : i); this._applyFilters(); this._showTab('adjust'); });
        g.appendChild(item);
    }); c.appendChild(g);
}

/* ── Vignette ─────────────────────────────────────────────── */
_t_vignette(c) {
    c.appendChild(this._slider('Amount', 0, 100, this.vignette, '%', v => {
        this.vignette = v;
        this.vignetteEl.style.background = v ? 'radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,' + (v / 100 * 0.8) + ') 100%)' : 'none';
    }));
}

/* ── Film Grain ───────────────────────────────────────────── */
_t_grain(c) {
    c.appendChild(this._slider('Amount', 0, 100, this.grain, '%', v => {
        this._saveSnap(); this.grain = v;
        cancelAnimationFrame(this._grainRAF);
        if (v > 0) this._animGrain();
        else this.grainCvs.style.opacity = '0';
    }));
}

/* ── Blur Background ──────────────────────────────────────── */
_t_blurbg(c) {
    c.appendChild(this._slider('Blur', 0, 30, this.blurBg, 'px', v => { this._saveSnap(); this.blurBg = v; this._applyFilters(); }));
    c.appendChild(this._note('Applies background blur behind the video for vertical content.'));
}

/* ── Tilt-Shift ───────────────────────────────────────────── */
_t_tiltshift(c) {
    c.appendChild(this._slider('Blur amount', 0, 20, this.tiltShift, 'px', v => { this.tiltShift = v; this._applyTiltShift(); }));
    c.appendChild(this._slider('Focus position', 0, 100, this.tiltPos, '%', v => { this.tiltPos = v; this._applyTiltShift(); }));
}

/* ── Duotone ──────────────────────────────────────────────── */
_t_duotone(c) {
    const toggle = this._toggle((window.t?.('videoEditor.enableDuotone')||'Enable duotone'), !!this.duotone, v => {
        this._saveSnap();
        this.duotone = v ? { light: '#7c3aed', dark: '#0a0a12' } : null;
        this._applyFilters(); this._showTab('adjust');
    });
    c.appendChild(toggle);
    if (this.duotone) {
        c.appendChild(this._colorPicker('Light', this.duotone.light, v => { this.duotone.light = v; this._applyFilters(); }));
        c.appendChild(this._colorPicker('Dark', this.duotone.dark, v => { this.duotone.dark = v; this._applyFilters(); }));
    }
}

/* ── Chromatic Aberration ─────────────────────────────────── */
_t_chroma(c) {
    c.appendChild(this._slider('Amount', 0, 20, this.chromaAb, 'px', v => {
        this._saveSnap(); this.chromaAb = v;
        this.video.style.textShadow = v ? v + 'px 0 rgba(255,0,0,.3), -' + v + 'px 0 rgba(0,0,255,.3)' : '';
        this.video.style.filter = this._buildFilter();
    }));
    c.appendChild(this._note('RGB channel offset. Full quality on export.'));
}

/* ── Glitch ───────────────────────────────────────────────── */
_t_glitch(c) {
    c.appendChild(this._slider('Intensity', 0, 100, this.glitch, '%', v => { this._saveSnap(); this.glitch = v; }));
    c.appendChild(this._note('Glitch effect is applied during playback and on export.'));
}

/* ── RGB Curves ───────────────────────────────────────────── */
_t_rgb(c) {
    c.appendChild(this._slider('Red', -100, 100, this.rgbR, '', v => { this._saveSnap(); this.rgbR = v; this._applyFilters(); }));
    c.appendChild(this._slider('Green', -100, 100, this.rgbG, '', v => { this._saveSnap(); this.rgbG = v; this._applyFilters(); }));
    c.appendChild(this._slider('Blue', -100, 100, this.rgbB, '', v => { this._saveSnap(); this.rgbB = v; this._applyFilters(); }));
    const rb = this._btn('ved-ctrl', (window.t?.('ui.reset')||'Reset'), () => {
        this._saveSnap(); this.rgbR = this.rgbG = this.rgbB = 0;
        this._applyFilters(); this._showTab('adjust');
    });
    rb.style.cssText = 'width:100%;justify-content:center;margin-top:4px'; c.appendChild(rb);
}

/* ── Presets ───────────────────────────────────────────────── */
_t_presets(c) {
    const saveBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.savePreset')||'Save current as preset'), () => {
        const name = prompt('Preset name:');
        if (!name) return;
        this._presets.push({ name, data: this._getAdjustState() });
        localStorage.setItem('ved_presets', JSON.stringify(this._presets));
        this._showTab('adjust');
    });
    saveBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(saveBtn);
    if (this._presets.length) {
        const list = this._el('div', 'ved-layer-list');
        this._presets.forEach((p, i) => {
            const row = this._el('div', 'ved-layer-item');
            const lbl = this._el('span'); lbl.textContent = p.name; lbl.style.flex = '1';
            const apply = this._btn('ved-ctrl-xs', '\u2713', () => { this._saveSnap(); this._applyAdjustState(p.data); this._showTab('adjust'); });
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => { this._presets.splice(i, 1); localStorage.setItem('ved_presets', JSON.stringify(this._presets)); this._showTab('adjust'); });
            row.append(lbl, apply, del); list.appendChild(row);
        }); c.appendChild(list);
    } else c.appendChild(this._note((window.t?.('videoEditor.noPresets')||'No saved presets yet.')));
}

/* ═══════════════════════════════════════════════════════════════
   TEXT TAB TOOLS
   ═══════════════════════════════════════════════════════════════ */

/* ── Text Layers ──────────────────────────────────────────── */
_t_textlayers(c) {
    const addBtn = this._btn('ved-ctrl', '+ Add text layer', () => {
        this._saveSnap();
        this.textLayers.push({
            id: Date.now(), text: 'Text', x: 50, y: 50, size: 24,
            color: '#ffffff', font: 'sans-serif', anim: 'none', hasBg: false
        });
        this._selText = this.textLayers[this.textLayers.length - 1].id;
        this._renderOverlays(); this._showTab('text');
    });
    addBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(addBtn);

    if (this.textLayers.length) {
        const list = this._el('div', 'ved-layer-list');
        this.textLayers.forEach((tl, i) => {
            const row = this._el('div', 'ved-layer-item' + (this._selText === tl.id ? ' selected' : ''));
            row.addEventListener('click', () => { this._selText = tl.id; this._showTab('text'); });
            const lbl = this._el('span'); lbl.textContent = tl.text.substring(0, 20) || '(empty)'; lbl.style.flex = '1';
            const del = this._btn('ved-ctrl-xs', '\u00D7', e => { e.stopPropagation(); this._saveSnap(); this.textLayers.splice(i, 1); this._renderOverlays(); this._showTab('text'); });
            row.append(lbl, del); list.appendChild(row);
        }); c.appendChild(list);

        const sel = this.textLayers.find(t => t.id === this._selText);
        if (sel) {
            const inp = document.createElement('input'); inp.type = 'text'; inp.className = 'ved-text-input';
            inp.value = sel.text; inp.placeholder = 'Enter text...';
            inp.addEventListener('input', () => { sel.text = inp.value; this._renderOverlays(); });
            c.appendChild(inp);
            c.appendChild(this._slider('Size', 12, 120, sel.size, 'px', v => { sel.size = v; this._renderOverlays(); }));
            // Font
            const fontRow = this._el('div', 'ved-speed-grid'); fontRow.style.gridTemplateColumns = 'repeat(5,1fr)';
            FONTS.forEach((f, fi) => {
                const b = document.createElement('button');
                b.className = 'ved-speed-btn' + (sel.font === f ? ' active' : '');
                b.textContent = FONT_NAMES[fi]; b.style.fontFamily = f; b.style.fontSize = '11px';
                b.addEventListener('click', () => { this._saveSnap(); sel.font = f; this._renderOverlays(); this._showTab('text'); });
                fontRow.appendChild(b);
            }); c.appendChild(fontRow);
            // Color
            const colorRow = this._el('div', 'ved-color-row');
            COLORS.forEach(col => {
                const sw = document.createElement('button');
                sw.className = 'ved-swatch' + (sel.color === col ? ' active' : '');
                sw.style.background = col;
                sw.addEventListener('click', () => { this._saveSnap(); sel.color = col; this._renderOverlays(); this._showTab('text'); });
                colorRow.appendChild(sw);
            }); c.appendChild(colorRow);
            // Animation
            const animRow = this._el('div', 'ved-speed-grid'); animRow.style.gridTemplateColumns = 'repeat(4,1fr)';
            ANIMS.forEach(a => {
                const b = document.createElement('button');
                b.className = 'ved-speed-btn' + (sel.anim === a ? ' active' : '');
                b.textContent = a;
                b.addEventListener('click', () => { this._saveSnap(); sel.anim = a; this._renderOverlays(); this._showTab('text'); });
                animRow.appendChild(b);
            }); c.appendChild(animRow);
            // Background
            c.appendChild(this._toggle((window.t?.('videoEditor.textBackground')||'Text background'), sel.hasBg, v => { this._saveSnap(); sel.hasBg = v; this._renderOverlays(); }));
        }
    }
    c.appendChild(this._note('Drag text on the video to reposition.'));
}

/* ── Subtitles ────────────────────────────────────────────── */
_t_subtitles(c) {
    const addBtn = this._btn('ved-ctrl', '+ Add subtitle', () => {
        this._saveSnap();
        const ct = this.video.currentTime;
        this.subs.push({ start: ct, end: Math.min(ct + 3, this.duration), text: 'Subtitle' });
        this._showTab('text');
    });
    addBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(addBtn);
    if (this.subs.length) {
        const list = this._el('div', 'ved-layer-list');
        this.subs.forEach((s, i) => {
            const row = this._el('div', 'ved-sub-item');
            const time = this._el('span', 'ved-sub-time');
            time.textContent = this._fmt(s.start) + ' → ' + this._fmt(s.end);
            const inp = document.createElement('input'); inp.type = 'text'; inp.className = 'ved-sub-input';
            inp.value = s.text;
            inp.addEventListener('input', () => { s.text = inp.value; });
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => { this._saveSnap(); this.subs.splice(i, 1); this._showTab('text'); });
            row.append(time, inp, del); list.appendChild(row);
        }); c.appendChild(list);
    }
}

/* ── Auto-Subtitles ───────────────────────────────────────── */
_t_autosubs(c) {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { c.appendChild(this._note('Speech Recognition not available in this browser.')); return; }
    const btn = this._btn('ved-ctrl ved-record-btn', 'Auto-detect subtitles', () => {
        this._saveSnap();
        const recognition = new SR();
        recognition.continuous = true; recognition.interimResults = false; recognition.lang = 'ru-RU';
        const audio = document.createElement('audio'); audio.src = this.objUrl;
        let lastTime = 0;
        recognition.onresult = (e) => {
            for (let i = e.resultIndex; i < e.results.length; i++) {
                if (e.results[i].isFinal) {
                    const text = e.results[i][0].transcript.trim();
                    if (text) {
                        const now = audio.currentTime || lastTime;
                        this.subs.push({ start: Math.max(0, now - 3), end: now, text });
                        lastTime = now;
                    }
                }
            }
        };
        recognition.onend = () => { this._showTab('text'); };
        // Play audio to capture speech
        const stream = audio.captureStream ? audio.captureStream() : null;
        if (stream) {
            recognition.start(); audio.play();
            setTimeout(() => { recognition.stop(); audio.pause(); }, Math.min(this.duration * 1000, 60000));
        } else {
            recognition.start();
            setTimeout(() => recognition.stop(), 10000);
        }
        btn.textContent = (window.t?.('videoEditor.listening')||'Listening...'); btn.disabled = true;
    });
    btn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(btn);
    c.appendChild(this._note('Plays audio and detects speech. Best with clear voice.'));
}

/* ── Watermark ────────────────────────────────────────────── */
_t_watermark(c) {
    if (this.watermark) {
        const info = this._el('div', 'ved-audio-info');
        info.textContent = this.watermark.name;
        c.appendChild(info);
        c.appendChild(this._slider('Opacity', 10, 100, Math.round((this.watermark.opacity || 0.5) * 100), '%', v => {
            this.watermark.opacity = v / 100; this._renderOverlays();
        }));
        const posRow = this._el('div', 'ved-speed-grid');
        ['top-left','top-right','bottom-left','bottom-right','center'].forEach(pos => {
            const b = document.createElement('button');
            b.className = 'ved-speed-btn' + (this.watermark.pos === pos ? ' active' : '');
            b.textContent = pos.replace('-', ' ');
            b.addEventListener('click', () => { this._saveSnap(); this.watermark.pos = pos; this._renderOverlays(); this._showTab('text'); });
            posRow.appendChild(b);
        }); c.appendChild(posRow);
        const removeBtn = this._btn('ved-ctrl ved-ctrl-remove', (window.t?.('videoEditor.removeWatermark')||'Remove watermark'), () => {
            this._saveSnap(); URL.revokeObjectURL(this.watermark.url); this.watermark = null;
            this._renderOverlays(); this._showTab('text');
        }); c.appendChild(removeBtn);
    } else {
        const uploadBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.uploadWatermark')||'Upload watermark image...'), () => {
            const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
            inp.addEventListener('change', () => {
                if (!inp.files?.[0]) return;
                this._saveSnap();
                this.watermark = { url: URL.createObjectURL(inp.files[0]), name: inp.files[0].name, pos: 'bottom-right', opacity: 0.5 };
                this._renderOverlays(); this._showTab('text');
            }); inp.click();
        });
        uploadBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(uploadBtn);
    }
}

/* ═══════════════════════════════════════════════════════════════
   OVERLAY TAB TOOLS
   ═══════════════════════════════════════════════════════════════ */

/* ── Stickers ─────────────────────────────────────────────── */
_t_stickers(c) {
    const cats = Object.keys(STICKERS);
    const tabs = this._el('div', 'ved-sticker-tabs');
    const grid = this._el('div', 'ved-sticker-grid');
    let activeCat = cats[0];
    const renderGrid = () => {
        grid.textContent = '';
        [...STICKERS[activeCat]].forEach(emoji => {
            const b = document.createElement('button'); b.className = 'ved-sticker-item';
            b.textContent = emoji;
            b.addEventListener('click', () => {
                this._saveSnap();
                this.stickers.push({ id: Date.now(), emoji, x: 50, y: 50, size: 48 });
                this._renderOverlays();
                this._showTab('overlay');
            });
            grid.appendChild(b);
        });
    };
    cats.forEach(cat => {
        const t = document.createElement('button');
        t.className = 'ved-sticker-tab' + (cat === activeCat ? ' active' : '');
        t.textContent = cat;
        t.addEventListener('click', () => { activeCat = cat; tabs.querySelectorAll('.ved-sticker-tab').forEach(x => x.classList.remove('active')); t.classList.add('active'); renderGrid(); });
        tabs.appendChild(t);
    });
    c.appendChild(tabs); c.appendChild(grid); renderGrid();
    if (this.stickers.length) {
        const list = this._el('div', 'ved-layer-list');
        this.stickers.forEach((s, i) => {
            const row = this._el('div', 'ved-layer-item');
            row.textContent = s.emoji;
            const sz = this._miniSlider('Size', 16, 120, s.size, v => { s.size = v; this._renderOverlays(); });
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => { this._saveSnap(); this.stickers.splice(i, 1); this._renderOverlays(); this._showTab('overlay'); });
            row.append(sz, del); list.appendChild(row);
        }); c.appendChild(list);
    }
    c.appendChild(this._note('Drag stickers on the video to reposition.'));
}

/* ── Drawing ──────────────────────────────────────────────── */
_t_draw(c) {
    const toggle = this._toggle((window.t?.('videoEditor.drawingMode')||'Drawing mode'), this._drawing, v => {
        this._drawing = v;
        this.drawCvs.classList.toggle('active', v);
    });
    c.appendChild(toggle);
    this._drawColor = this._drawColor || '#ef4444';
    this._drawWidth = this._drawWidth || 3;
    c.appendChild(this._slider('Brush size', 1, 20, this._drawWidth, 'px', v => { this._drawWidth = v; }));
    const colorRow = this._el('div', 'ved-color-row');
    COLORS.forEach(col => {
        const sw = document.createElement('button');
        sw.className = 'ved-swatch' + (this._drawColor === col ? ' active' : '');
        sw.style.background = col;
        sw.addEventListener('click', () => { this._drawColor = col; this._showTab('overlay'); });
        colorRow.appendChild(sw);
    }); c.appendChild(colorRow);
    const clearBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.clearStrokes')||'Clear all strokes'), () => {
        this._saveSnap(); this.strokes = [];
        const ctx = this.drawCvs.getContext('2d');
        ctx.clearRect(0, 0, this.drawCvs.width, this.drawCvs.height);
        this._showTab('overlay');
    });
    clearBtn.style.cssText = 'width:100%;justify-content:center;margin-top:6px'; c.appendChild(clearBtn);
    if (!this._drawBound) { this._initDrawing(); this._drawBound = true; }
    c.appendChild(this._note('Enable drawing mode, then paint on the video.'));
}

/* ── Shapes ───────────────────────────────────────────────── */
_t_shapes(c) {
    const types = [
        ['rect', 'Rectangle'], ['circle', 'Circle'], ['arrow', 'Arrow'], ['line', 'Line']
    ];
    this._shapeColor = this._shapeColor || '#3b82f6';
    this._shapeStroke = this._shapeStroke || 3;
    const row = this._el('div', 'ved-speed-grid');
    types.forEach(([type, label]) => {
        const b = this._btn('ved-speed-btn', label, () => {
            this._saveSnap();
            this.shapes.push({ id: Date.now(), type, x: 30, y: 30, w: 40, h: 30, color: this._shapeColor, strokeW: this._shapeStroke });
            this._renderOverlays(); this._showTab('overlay');
        });
        row.appendChild(b);
    }); c.appendChild(row);
    c.appendChild(this._slider('Stroke', 1, 10, this._shapeStroke, 'px', v => { this._shapeStroke = v; }));
    const colorRow = this._el('div', 'ved-color-row');
    COLORS.forEach(col => {
        const sw = document.createElement('button');
        sw.className = 'ved-swatch' + (this._shapeColor === col ? ' active' : '');
        sw.style.background = col;
        sw.addEventListener('click', () => { this._shapeColor = col; this._showTab('overlay'); });
        colorRow.appendChild(sw);
    }); c.appendChild(colorRow);
    if (this.shapes.length) {
        const list = this._el('div', 'ved-layer-list');
        this.shapes.forEach((s, i) => {
            const row2 = this._el('div', 'ved-layer-item');
            row2.textContent = s.type;
            const del = this._btn('ved-ctrl-xs', '\u00D7', () => { this._saveSnap(); this.shapes.splice(i, 1); this._renderOverlays(); this._showTab('overlay'); });
            row2.appendChild(del); list.appendChild(row2);
        }); c.appendChild(list);
    }
}

/* ═══════════════════════════════════════════════════════════════
   AUDIO TAB TOOLS
   ═══════════════════════════════════════════════════════════════ */

/* ── Volume ───────────────────────────────────────────────── */
_t_volume(c) {
    c.appendChild(this._slider('Volume', 0, 200, Math.round(this.volume * 100), '%', v => {
        this._saveSnap(); this.volume = v / 100;
        this.video.volume = Math.min(1, this.volume);
        this._initAudio(); if (this._gainN) this._gainN.gain.value = this.volume;
    }));
    if (this.volume === 0) c.appendChild(this._note('Audio is muted (0%)'));
}

/* ── Fade In/Out ──────────────────────────────────────────── */
_t_fade(c) {
    c.appendChild(this._slider('Fade In', 0, 10, this.fadeIn, 's', v => { this._saveSnap(); this.fadeIn = v; }));
    c.appendChild(this._slider('Fade Out', 0, 10, this.fadeOut, 's', v => { this._saveSnap(); this.fadeOut = v; }));
    c.appendChild(this._note('Audio fades are applied during playback and on export.'));
}

/* ── EQ ───────────────────────────────────────────────────── */
_t_eq(c) {
    this._initAudio();
    const eqBox = this._el('div', 'ved-eq-box');
    EQ_FREQS.forEach((freq, i) => {
        const band = this._el('div', 'ved-eq-band');
        const val = this._el('div', 'ved-eq-val'); val.textContent = this.eq[i] + 'dB';
        const slider = document.createElement('input');
        slider.type = 'range'; slider.className = 'ved-eq-slider';
        slider.min = '-12'; slider.max = '12'; slider.value = String(this.eq[i]);
        slider.addEventListener('input', () => {
            this.eq[i] = parseInt(slider.value);
            val.textContent = this.eq[i] + 'dB';
            if (this._eqN?.[i]) this._eqN[i].gain.value = this.eq[i];
        });
        const lbl = this._el('div', 'ved-eq-label'); lbl.textContent = EQ_LABELS[i];
        band.append(val, slider, lbl); eqBox.appendChild(band);
    }); c.appendChild(eqBox);
    const rb = this._btn('ved-ctrl', 'Flat', () => {
        this._saveSnap(); this.eq = [0,0,0,0,0];
        this.eq.forEach((v, i) => { if (this._eqN?.[i]) this._eqN[i].gain.value = 0; });
        this._showTab('audio');
    });
    rb.style.cssText = 'width:100%;justify-content:center;margin-top:4px'; c.appendChild(rb);
}

/* ── Pitch ────────────────────────────────────────────────── */
_t_pitch(c) {
    c.appendChild(this._slider('Pitch shift', -12, 12, this.pitch, ' st', v => {
        this._saveSnap(); this.pitch = v;
        // Preview via playbackRate approximation: each semitone ≈ 5.95%
        if (!this.reversed) this.video.playbackRate = this.speed * Math.pow(2, v / 12);
    }));
    c.appendChild(this._note('Semitone shift. Full quality on export via audio processing.'));
}

/* ── Noise Gate ───────────────────────────────────────────── */
_t_noisegate(c) {
    c.appendChild(this._toggle((window.t?.('videoEditor.enableNoiseGate')||'Enable noise gate'), this.noiseGate, v => { this._saveSnap(); this.noiseGate = v; }));
    c.appendChild(this._slider('Threshold', -60, 0, this.noiseThr, 'dB', v => { this._saveSnap(); this.noiseThr = v; }));
    c.appendChild(this._note('Silences audio below the threshold level.'));
}

/* ── Replace Audio ────────────────────────────────────────── */
_t_replace(c) {
    if (this.replName) {
        const info = this._el('div', 'ved-audio-info'); info.textContent = '\u266B ' + this.replName; c.appendChild(info);
        const removeBtn = this._btn('ved-ctrl ved-ctrl-remove', 'Remove', () => {
            this._saveSnap(); URL.revokeObjectURL(this.replUrl); this.replUrl = null; this.replName = null;
            if (this._replAudio) { this._replAudio.pause(); this._replAudio = null; }
            this.video.muted = false; this._showTab('audio');
        }); c.appendChild(removeBtn);
    } else {
        const uploadBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.replaceAudio')||'Replace audio from file...'), () => {
            const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'audio/*';
            inp.addEventListener('change', () => {
                if (!inp.files?.[0]) return;
                this._saveSnap();
                if (this.replUrl) URL.revokeObjectURL(this.replUrl);
                this.replUrl = URL.createObjectURL(inp.files[0]);
                this.replName = inp.files[0].name;
                this._replAudio = new Audio(this.replUrl);
                this._showTab('audio');
            }); inp.click();
        });
        uploadBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(uploadBtn);
    }
}

/* ── Voiceover ────────────────────────────────────────────── */
_t_voiceover(c) {
    if (this.voiceName) {
        const info = this._el('div', 'ved-audio-info'); info.textContent = '\u{1F3A4} ' + this.voiceName; c.appendChild(info);
        const removeBtn = this._btn('ved-ctrl ved-ctrl-remove', (window.t?.('videoEditor.removeVoiceover')||'Remove voiceover'), () => {
            this._saveSnap(); URL.revokeObjectURL(this.voiceUrl); this.voiceUrl = null; this.voiceName = null;
            if (this._voiceAudio) { this._voiceAudio.pause(); this._voiceAudio = null; }
            this._showTab('audio');
        }); c.appendChild(removeBtn);
    } else {
        const recBtn = this._btn('ved-ctrl ved-record-btn', (window.t?.('videoEditor.recordVoiceover')||'Record voiceover'), () => {
            if (this._recorder) { this._recorder.stop(); return; }
            navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
                this._recorder = new MediaRecorder(stream);
                const chunks = [];
                this._recorder.ondataavailable = e => chunks.push(e.data);
                this._recorder.onstop = () => {
                    stream.getTracks().forEach(t => t.stop());
                    const blob = new Blob(chunks, { type: 'audio/webm' });
                    this._saveSnap();
                    if (this.voiceUrl) URL.revokeObjectURL(this.voiceUrl);
                    this.voiceUrl = URL.createObjectURL(blob);
                    this.voiceName = 'Recording ' + new Date().toLocaleTimeString();
                    this._voiceAudio = new Audio(this.voiceUrl);
                    this._recorder = null; this._showTab('audio');
                };
                this._recorder.start(); recBtn.textContent = (window.t?.('videoEditor.stopRecording')||'Stop recording');
                recBtn.classList.add('recording');
            }).catch(() => { c.appendChild(this._note('Microphone access denied.')); });
        });
        recBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(recBtn);
    }
}

/* ── Music Library ────────────────────────────────────────── */
_t_music(c) {
    const list = this._el('div', 'ved-music-list');
    MUSIC.forEach((m, i) => {
        const row = this._el('div', 'ved-music-item' + (this.musicIdx === i ? ' active' : ''));
        const info = this._el('div', 'ved-music-info');
        info.innerHTML = '<strong>' + m.n + '</strong><br><span style="font-size:11px;color:var(--text3)">' + m.d + ' \u2022 ' + m.bpm + ' BPM</span>';
        row.appendChild(info);
        row.addEventListener('click', () => { this._saveSnap(); this.musicIdx = (this.musicIdx === i ? -1 : i); this._showTab('audio'); });
        list.appendChild(row);
    }); c.appendChild(list);
    c.appendChild(this._note('Music tracks will be mixed with the video audio on export.'));
}

/* ── Mix Levels ───────────────────────────────────────────── */
_t_mix(c) {
    c.appendChild(this._slider('Original audio', 0, 100, this.mixOrig, '%', v => { this._saveSnap(); this.mixOrig = v; }));
    c.appendChild(this._slider('Overlay audio', 0, 100, this.mixOver, '%', v => { this._saveSnap(); this.mixOver = v; }));
    c.appendChild(this._note('Controls the balance between original and added audio.'));
}

/* ═══════════════════════════════════════════════════════════════
   EXPORT TAB TOOLS
   ═══════════════════════════════════════════════════════════════ */

/* ── Resolution ───────────────────────────────────────────── */
_t_resolution(c) {
    const opts = ['original', '1080p', '720p', '480p', '360p'];
    const g = this._el('div', 'ved-speed-grid');
    opts.forEach(o => {
        const b = document.createElement('button');
        b.className = 'ved-speed-btn' + (this.exRes === o ? ' active' : '');
        b.textContent = o === 'original' ? 'Original' : o;
        b.addEventListener('click', () => { this._saveSnap(); this.exRes = o; this._showTab('export'); });
        g.appendChild(b);
    }); c.appendChild(g);
}

/* ── Format ───────────────────────────────────────────────── */
_t_format(c) {
    const opts = ['mp4', 'webm', 'gif'];
    const g = this._el('div', 'ved-speed-grid');
    opts.forEach(o => {
        const b = document.createElement('button');
        b.className = 'ved-speed-btn' + (this.exFmt === o ? ' active' : '');
        b.textContent = o.toUpperCase();
        b.addEventListener('click', () => { this._saveSnap(); this.exFmt = o; this._showTab('export'); });
        g.appendChild(b);
    }); c.appendChild(g);
}

/* ── GIF Settings ─────────────────────────────────────────── */
_t_gif(c) {
    if (this.exFmt !== 'gif') {
        c.appendChild(this._note('Select GIF format in the Format tool first.'));
        return;
    }
    this._gifFps = this._gifFps || 10;
    this._gifWidth = this._gifWidth || 480;
    c.appendChild(this._slider('FPS', 5, 30, this._gifFps, '', v => { this._gifFps = v; }));
    c.appendChild(this._slider('Width', 160, 1280, this._gifWidth, 'px', v => { this._gifWidth = v; }));
    c.appendChild(this._note('Lower FPS and width = smaller file size.'));
}

/* ── Quality ──────────────────────────────────────────────── */
_t_quality(c) {
    c.appendChild(this._slider('Quality', 10, 100, this.exQual, '%', v => { this._saveSnap(); this.exQual = v; }));
    const labels = { 10: 'Lowest', 30: 'Low', 50: 'Medium', 70: 'Good', 90: 'High', 100: 'Maximum' };
    const nearest = Object.keys(labels).reduce((p, k) => Math.abs(k - this.exQual) < Math.abs(p - this.exQual) ? k : p);
    c.appendChild(this._note(labels[nearest] + ' quality — ' + (this.exQual > 70 ? 'larger file' : 'smaller file')));
}

/* ── Snapshot ─────────────────────────────────────────────── */
_t_snapshot(c) {
    const captureBtn = this._btn('ved-ctrl', (window.t?.('videoEditor.captureFrame')||'Capture current frame as PNG'), () => {
        const cvs = document.createElement('canvas');
        cvs.width = this.video.videoWidth; cvs.height = this.video.videoHeight;
        cvs.getContext('2d').drawImage(this.video, 0, 0);
        const link = document.createElement('a');
        link.download = 'frame_' + this._fmt(this.video.currentTime).replace(':', '-') + '.png';
        link.href = cvs.toDataURL('image/png');
        link.click();
    });
    captureBtn.style.cssText = 'width:100%;justify-content:center'; c.appendChild(captureBtn);
    c.appendChild(this._note('Saves the current video frame at full resolution.'));
}

/* ── Compare Before/After ─────────────────────────────────── */
_t_compare(c) {
    const toggle = this._toggle((window.t?.('videoEditor.compareMode')||'Compare mode'), this._compare, v => {
        this._compare = v;
        this.compareLine.style.display = v ? 'block' : 'none';
        if (v) {
            this.video.style.clipPath = 'inset(0 50% 0 0)';
            this.compareLine.style.left = '50%';
            // Drag the compare line
            let dragging = false;
            const move = e => { if (!dragging) return; const r = this.playerEl.getBoundingClientRect(); const pct = Math.max(5, Math.min(95, (e.clientX - r.left) / r.width * 100)); this.compareLine.style.left = pct + '%'; this.video.style.clipPath = 'inset(0 ' + (100 - pct) + '% 0 0)'; };
            const up = () => { dragging = false; document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
            this.compareLine.onmousedown = () => { dragging = true; document.addEventListener('mousemove', move); document.addEventListener('mouseup', up); };
        } else {
            this.video.style.clipPath = '';
        }
    });
    c.appendChild(toggle);
    c.appendChild(this._note('Drag the divider to compare original vs edited.'));
}

/* ═══════════════════════════════════════════════════════════════
   COVER TAB (Thumbnail)
   ═══════════════════════════════════════════════════════════════ */

_buildCover() {
    // Cleanup previous thumbnail video
    if (this._thumbVid) { this._thumbVid.pause(); this._thumbVid.src = ''; this._thumbVid = null; }

    const w = this._el('div', 'ved-thumb');

    // Video player preview
    const tv = document.createElement('video');
    tv.src = this.objUrl; tv.muted = true; tv.preload = 'auto';
    tv.playsInline = true; tv.className = 'ved-thumb-preview ved-thumb-video';
    this._thumbVid = tv;
    w.appendChild(tv);

    // Hidden canvas for frame capture
    const cvs = document.createElement('canvas');
    cvs.style.display = 'none';

    // Time label
    const timeLabel = this._el('span', 'ved-thumb-time'); timeLabel.textContent = '0:00';

    // Time slider row
    const row = this._el('div', 'ved-thumb-row');
    const slider = document.createElement('input');
    slider.type = 'range'; slider.min = '0';
    slider.max = String(this.duration || 1);
    slider.step = '0.01'; slider.value = '0'; slider.className = 'ved-thumb-slider';
    row.append(slider, timeLabel);
    w.appendChild(row);

    // Playback controls
    const controls = this._el('div', 'ved-controls');
    const ICON_PLAY = '<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>';
    const ICON_PAUSE = '<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>';
    const playBtn = document.createElement('button'); playBtn.className = 'ved-ctrl-play';
    playBtn.innerHTML = ICON_PLAY;
    playBtn.addEventListener('click', () => { tv.paused ? tv.play() : tv.pause(); });
    tv.addEventListener('play', () => { playBtn.innerHTML = ICON_PAUSE; });
    tv.addEventListener('pause', () => { playBtn.innerHTML = ICON_PLAY; });
    tv.addEventListener('ended', () => { playBtn.innerHTML = ICON_PLAY; });
    controls.appendChild(playBtn);
    w.appendChild(controls);

    // Capture + Upload buttons
    const btnRow = this._el('div', 'ved-thumb-actions');
    const captureBtn = this._btn('ved-ctrl', '', () => {
        tv.pause();
        cvs.width = tv.videoWidth || 640; cvs.height = tv.videoHeight || 360;
        cvs.getContext('2d').drawImage(tv, 0, 0, cvs.width, cvs.height);
        this.thumbnail = cvs.toDataURL('image/jpeg', 0.92);
        captureBtn.textContent = '';
        captureBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg><span style="margin-left:6px">Captured at ' + this._fmt(tv.currentTime) + '</span>';
    });
    captureBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2v11z"/><circle cx="12" cy="13" r="4"/></svg><span style="margin-left:6px">Use this frame</span>';
    captureBtn.style.flex = '1';

    const uploadBtn = this._btn('ved-ctrl', '', () => {
        const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
        inp.addEventListener('change', () => {
            if (!inp.files?.[0]) return;
            const reader = new FileReader();
            reader.onload = ev => {
                const img = new Image(); img.onload = () => {
                    cvs.width = img.naturalWidth; cvs.height = img.naturalHeight;
                    cvs.getContext('2d').drawImage(img, 0, 0);
                    this.thumbnail = cvs.toDataURL('image/jpeg', 0.92);
                    captureBtn.textContent = '';
                    captureBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg><span style="margin-left:6px">Custom image set</span>';
                }; img.src = ev.target.result;
            };
            reader.readAsDataURL(inp.files[0]);
        }); inp.click();
    });
    uploadBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg><span style="margin-left:6px">Upload image</span>';
    uploadBtn.style.flex = '1';
    btnRow.append(captureBtn, uploadBtn);
    w.appendChild(btnRow);

    this.content.appendChild(w);

    // Video events
    tv.addEventListener('timeupdate', () => {
        if (tv.duration) {
            slider.value = String(tv.currentTime);
            timeLabel.textContent = this._fmt(tv.currentTime);
        }
    });
    tv.addEventListener('loadeddata', () => {
        slider.max = String(tv.duration);
        slider.value = String(Math.min(0.5, tv.duration));
        tv.currentTime = parseFloat(slider.value);
    }, { once: true });
    slider.addEventListener('input', () => {
        tv.pause();
        tv.currentTime = parseFloat(slider.value);
    });
}

/* ═══════════════════════════════════════════════════════════════
   SYSTEMS
   ═══════════════════════════════════════════════════════════════ */

/* ── Undo / Redo ──────────────────────────────────────────── */

_getSnap() {
    return JSON.stringify({
        trimStart: this.trimStart, trimEnd: this.trimEnd, cuts: this.cuts.slice(), deletedSegs: this.deletedSegs.slice(),
        speed: this.speed, reversed: this.reversed, freezes: JSON.parse(JSON.stringify(this.freezes)),
        loopSeg: this.loopSeg ? {...this.loopSeg} : null, keyframes: JSON.parse(JSON.stringify(this.keyframes)),
        timecodes: JSON.parse(JSON.stringify(this.timecodes)),
        crop: {...this.crop}, rotation: this.rotation, flipH: this.flipH, flipV: this.flipV,
        brightness: this.brightness, contrast: this.contrast, saturation: this.saturation,
        lut: this.lut, vignette: this.vignette, grain: this.grain, blurBg: this.blurBg,
        tiltShift: this.tiltShift, tiltPos: this.tiltPos, duotone: this.duotone ? {...this.duotone} : null,
        chromaAb: this.chromaAb, glitch: this.glitch, rgbR: this.rgbR, rgbG: this.rgbG, rgbB: this.rgbB,
        textLayers: JSON.parse(JSON.stringify(this.textLayers)), subs: JSON.parse(JSON.stringify(this.subs)),
        stickers: JSON.parse(JSON.stringify(this.stickers)), shapes: JSON.parse(JSON.stringify(this.shapes)),
        volume: this.volume, fadeIn: this.fadeIn, fadeOut: this.fadeOut, eq: this.eq.slice(),
        pitch: this.pitch, noiseGate: this.noiseGate, noiseThr: this.noiseThr,
        musicIdx: this.musicIdx, mixOrig: this.mixOrig, mixOver: this.mixOver,
        exRes: this.exRes, exFmt: this.exFmt, exQual: this.exQual,
    });
}

_saveSnap() {
    this._us.push(this._getSnap());
    if (this._us.length > 50) this._us.shift();
    this._rs = [];
    this._updUndoUI();
}

_applySnap(json) {
    const s = JSON.parse(json);
    Object.keys(s).forEach(k => {
        if (k === 'crop' || k === 'duotone') this[k] = s[k];
        else this[k] = s[k];
    });
    this._applyFilters(); this._applyTransform(); this._renderOverlays();
}

_undo() {
    if (!this._us.length) return;
    this._rs.push(this._getSnap());
    this._applySnap(this._us.pop());
    this._updUndoUI(); this._showTab(this.activeTab);
}

_redo() {
    if (!this._rs.length) return;
    this._us.push(this._getSnap());
    this._applySnap(this._rs.pop());
    this._updUndoUI(); this._showTab(this.activeTab);
}

_updUndoUI() {
    this._undoEl?.classList.toggle('disabled', !this._us.length);
    this._redoEl?.classList.toggle('disabled', !this._rs.length);
}

/* ── Hotkeys ──────────────────────────────────────────────── */

_bindKeys() {
    this._kh = e => {
        if (!this.root?.isConnected) return;
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
        const k = e.key.toLowerCase();
        if (k === ' ') { e.preventDefault(); this._togglePlay(); }
        else if (k === 'arrowleft') { e.preventDefault(); this._frameStep(e.shiftKey ? -10 : -1); }
        else if (k === 'arrowright') { e.preventDefault(); this._frameStep(e.shiftKey ? 10 : 1); }
        else if (k === 'j') { this.video.currentTime = Math.max(0, this.video.currentTime - 5); }
        else if (k === 'l') { this.video.currentTime = Math.min(this.duration, this.video.currentTime + 5); }
        else if (k === 'k') { this._togglePlay(); }
        else if (k === 'z' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); e.shiftKey ? this._redo() : this._undo(); }
        else if (k === 'y' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); this._redo(); }
        else if (k === 's' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); this._saveDraft(); }
        else if (k === 'escape') { this.destroy(); this.onCancel?.(); }
    };
    document.addEventListener('keydown', this._kh);
}

/* ── Autosave ─────────────────────────────────────────────── */

_saveDraft() {
    try {
        const data = this._getSnap();
        localStorage.setItem('ved_draft_' + this.file.name, data);
    } catch { /* quota exceeded — ignore */ }
}

_loadDraft() {
    try {
        const raw = localStorage.getItem('ved_draft_' + this.file.name);
        if (raw) this._applySnap(raw);
    } catch { /* corrupt data — ignore */ }
}

/* ── Audio Engine ─────────────────────────────────────────── */

_initAudio() {
    if (this._audioCtx) return;
    try {
        this._audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        this._srcNode = this._audioCtx.createMediaElementSource(this.video);
        this._eqN = EQ_FREQS.map(f => {
            const n = this._audioCtx.createBiquadFilter();
            n.type = 'peaking'; n.frequency.value = f; n.Q.value = 1; n.gain.value = 0;
            return n;
        });
        this._gainN = this._audioCtx.createGain();
        this._gainN.gain.value = this.volume;
        let prev = this._srcNode;
        this._eqN.forEach((n, i) => { prev.connect(n); n.gain.value = this.eq[i]; prev = n; });
        prev.connect(this._gainN);
        this._gainN.connect(this._audioCtx.destination);
    } catch { /* audio init failed */ }
}

/* ── Effects ──────────────────────────────────────────────── */

_buildFilter() {
    let f = 'brightness(' + this.brightness + '%) contrast(' + this.contrast + '%) saturate(' + this.saturation + '%)';
    if (this.lut != null && LUTS[this.lut]?.f) f += ' ' + LUTS[this.lut].f;
    if (this.duotone) f += ' grayscale(1)';
    if (this.blurBg) f += ' blur(' + this.blurBg + 'px)';
    if (this.rgbR || this.rgbG || this.rgbB) {
        const hue = Math.atan2(this.rgbG - this.rgbB, this.rgbR - (this.rgbG + this.rgbB) / 2) * 180 / Math.PI;
        f += ' hue-rotate(' + (hue || 0).toFixed(1) + 'deg)';
    }
    return f;
}

_applyFilters() { this.video.style.filter = this._buildFilter(); }
_applyTransform() {
    const t = [];
    if (this.rotation) t.push('rotate(' + this.rotation + 'deg)');
    if (this.flipH) t.push('scaleX(-1)');
    if (this.flipV) t.push('scaleY(-1)');
    this.video.style.transform = t.join(' ') || '';
}
_applyCrop() {
    if (this.crop.w >= 1 && this.crop.h >= 1) {
        this.video.style.clipPath = ''; this.cropEl.classList.remove('active');
    } else {
        const l = this.crop.x * 100, t = this.crop.y * 100;
        const r = (1 - this.crop.x - this.crop.w) * 100, b = (1 - this.crop.y - this.crop.h) * 100;
        this.video.style.clipPath = 'inset(' + t + '% ' + r + '% ' + b + '% ' + l + '%)';
    }
}
_applyTiltShift() {
    if (!this.tiltShift) { this.tiltEl.style.backdropFilter = ''; this.tiltEl.style.mask = ''; return; }
    this.tiltEl.style.backdropFilter = 'blur(' + this.tiltShift + 'px)';
    this.tiltEl.style.webkitBackdropFilter = 'blur(' + this.tiltShift + 'px)';
    const p = this.tiltPos;
    this.tiltEl.style.mask = 'linear-gradient(to bottom, black 0%, transparent ' + (p - 15) + '%, transparent ' + (p + 15) + '%, black 100%)';
    this.tiltEl.style.webkitMask = this.tiltEl.style.mask;
}
_applyKeyframe() {
    if (!this.keyframes.length) { this.video.style.transform = this._baseTransform(); return; }
    const pos = this.duration ? this.video.currentTime / this.duration : 0;
    let kf = this.keyframes[0];
    for (let i = 1; i < this.keyframes.length; i++) {
        if (this.keyframes[i].pos <= pos) kf = this.keyframes[i];
        else {
            const prev = this.keyframes[i - 1], next = this.keyframes[i];
            const t = (pos - prev.pos) / (next.pos - prev.pos);
            kf = { zoom: prev.zoom + (next.zoom - prev.zoom) * t, panX: prev.panX + (next.panX - prev.panX) * t, panY: prev.panY + (next.panY - prev.panY) * t };
            break;
        }
    }
    this.video.style.transform = this._baseTransform() + ' scale(' + (kf.zoom || 1) + ') translate(' + (kf.panX || 0) + 'px,' + (kf.panY || 0) + 'px)';
}
_baseTransform() {
    const t = [];
    if (this.rotation) t.push('rotate(' + this.rotation + 'deg)');
    if (this.flipH) t.push('scaleX(-1)');
    if (this.flipV) t.push('scaleY(-1)');
    return t.join(' ');
}

/* ── Grain Animation ──────────────────────────────────────── */

_animGrain() {
    if (!this.grain) return;
    const ctx = this.grainCvs.getContext('2d');
    const w = this.grainCvs.width || 200, h = this.grainCvs.height || 200;
    const img = ctx.createImageData(w, h);
    const d = img.data;
    for (let i = 0; i < d.length; i += 4) {
        const v = Math.random() * 255 | 0;
        d[i] = d[i + 1] = d[i + 2] = v; d[i + 3] = 255;
    }
    ctx.putImageData(img, 0, 0);
    this.grainCvs.style.opacity = String(this.grain / 100 * 0.35);
    this._grainRAF = requestAnimationFrame(() => this._animGrain());
}

/* ── Drawing System ───────────────────────────────────────── */

_initDrawing() {
    const cvs = this.drawCvs;
    const getPos = e => {
        const r = cvs.getBoundingClientRect();
        const x = (e.touches ? e.touches[0].clientX : e.clientX) - r.left;
        const y = (e.touches ? e.touches[0].clientY : e.clientY) - r.top;
        return { x: x / r.width * cvs.width, y: y / r.height * cvs.height };
    };
    const ctx = cvs.getContext('2d');
    const start = e => {
        if (!this._drawing) return;
        e.preventDefault();
        const p = getPos(e);
        this._curStroke = { points: [p], color: this._drawColor || '#ef4444', width: this._drawWidth || 3 };
        ctx.beginPath(); ctx.moveTo(p.x, p.y);
        ctx.strokeStyle = this._curStroke.color; ctx.lineWidth = this._curStroke.width;
        ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    };
    const move = e => {
        if (!this._curStroke) return;
        e.preventDefault();
        const p = getPos(e);
        this._curStroke.points.push(p);
        ctx.lineTo(p.x, p.y); ctx.stroke();
    };
    const end = () => {
        if (this._curStroke) {
            this._saveSnap();
            this.strokes.push(this._curStroke);
            this._curStroke = null;
        }
    };
    cvs.addEventListener('mousedown', start); cvs.addEventListener('mousemove', move); cvs.addEventListener('mouseup', end);
    cvs.addEventListener('touchstart', start, { passive: false }); cvs.addEventListener('touchmove', move, { passive: false }); cvs.addEventListener('touchend', end);
}

_resizeCvs() {
    const r = this.playerEl.getBoundingClientRect();
    this.drawCvs.width = r.width; this.drawCvs.height = r.height;
    this.grainCvs.width = Math.min(r.width / 2, 200); this.grainCvs.height = Math.min(r.height / 2, 200);
    this._redrawStrokes();
}

_redrawStrokes() {
    const ctx = this.drawCvs.getContext('2d');
    ctx.clearRect(0, 0, this.drawCvs.width, this.drawCvs.height);
    this.strokes.forEach(s => {
        if (s.points.length < 2) return;
        ctx.beginPath(); ctx.moveTo(s.points[0].x, s.points[0].y);
        s.points.forEach(p => ctx.lineTo(p.x, p.y));
        ctx.strokeStyle = s.color; ctx.lineWidth = s.width;
        ctx.lineCap = 'round'; ctx.lineJoin = 'round';
        ctx.stroke();
    });
}

/* ── Overlay Rendering ────────────────────────────────────── */

_renderOverlays() {
    this.overlayBox.textContent = '';
    // Text layers
    this.textLayers.forEach(tl => {
        const el = this._el('div', 'ved-ov-layer ved-ov-text');
        el.textContent = tl.text;
        el.style.cssText = 'left:' + tl.x + '%;top:' + tl.y + '%;font-size:' + tl.size + 'px;color:' + tl.color + ';font-family:' + tl.font + ';transform:translate(-50%,-50%);position:absolute;cursor:grab;user-select:none;text-shadow:0 2px 6px rgba(0,0,0,.7);font-weight:700;white-space:nowrap;pointer-events:auto;z-index:2;';
        if (tl.hasBg) el.style.background = 'rgba(0,0,0,.5)'; el.style.padding = tl.hasBg ? '4px 10px' : '0';
        el.style.borderRadius = tl.hasBg ? '6px' : '0';
        if (tl.anim && tl.anim !== 'none') el.classList.add('ved-anim-' + tl.anim);
        if (this._selText === tl.id) el.style.outline = '2px dashed var(--accent)';
        this._makeDraggable(el, (x, y) => { tl.x = x; tl.y = y; });
        el.addEventListener('click', e => { e.stopPropagation(); this._selText = tl.id; this._showTab('text'); });
        this.overlayBox.appendChild(el);
    });
    // Stickers
    this.stickers.forEach(s => {
        const el = this._el('div', 'ved-ov-layer ved-ov-sticker');
        el.textContent = s.emoji;
        el.style.cssText = 'left:' + s.x + '%;top:' + s.y + '%;font-size:' + s.size + 'px;transform:translate(-50%,-50%);position:absolute;cursor:grab;user-select:none;pointer-events:auto;z-index:2;line-height:1;';
        this._makeDraggable(el, (x, y) => { s.x = x; s.y = y; });
        this.overlayBox.appendChild(el);
    });
    // Shapes (SVG overlay)
    if (this.shapes.length) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('class', 'ved-ov-shapes');
        svg.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:1;';
        this.shapes.forEach(s => {
            let el;
            if (s.type === 'rect') {
                el = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                el.setAttribute('x', s.x + '%'); el.setAttribute('y', s.y + '%');
                el.setAttribute('width', s.w + '%'); el.setAttribute('height', s.h + '%');
            } else if (s.type === 'circle') {
                el = document.createElementNS('http://www.w3.org/2000/svg', 'ellipse');
                el.setAttribute('cx', (s.x + s.w / 2) + '%'); el.setAttribute('cy', (s.y + s.h / 2) + '%');
                el.setAttribute('rx', s.w / 2 + '%'); el.setAttribute('ry', s.h / 2 + '%');
            } else if (s.type === 'line') {
                el = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                el.setAttribute('x1', s.x + '%'); el.setAttribute('y1', s.y + '%');
                el.setAttribute('x2', (s.x + s.w) + '%'); el.setAttribute('y2', (s.y + s.h) + '%');
            } else if (s.type === 'arrow') {
                el = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                el.setAttribute('x1', s.x + '%'); el.setAttribute('y1', (s.y + s.h) + '%');
                el.setAttribute('x2', (s.x + s.w) + '%'); el.setAttribute('y2', s.y + '%');
                el.setAttribute('marker-end', 'url(#ved-arrowhead)');
            }
            if (el) {
                el.setAttribute('stroke', s.color); el.setAttribute('stroke-width', s.strokeW);
                el.setAttribute('fill', 'none'); svg.appendChild(el);
            }
        });
        // Arrow marker
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        defs.innerHTML = '<marker id="ved-arrowhead" markerWidth="10" markerHeight="7" refX="0" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="currentColor"/></marker>';
        svg.appendChild(defs);
        this.overlayBox.appendChild(svg);
    }
    // Watermark
    if (this.watermark) {
        const img = document.createElement('img');
        img.src = this.watermark.url; img.className = 'ved-ov-watermark';
        const pos = this.watermark.pos || 'bottom-right';
        const styles = { 'top-left': 'top:8px;left:8px', 'top-right': 'top:8px;right:8px', 'bottom-left': 'bottom:8px;left:8px', 'bottom-right': 'bottom:8px;right:8px', 'center': 'top:50%;left:50%;transform:translate(-50%,-50%)' };
        img.style.cssText = 'position:absolute;max-width:20%;max-height:20%;pointer-events:none;opacity:' + (this.watermark.opacity || 0.5) + ';z-index:3;' + (styles[pos] || styles['bottom-right']);
        this.overlayBox.appendChild(img);
    }
}

_makeDraggable(el, onMove) {
    let dragging = false, startX, startY, startLeft, startTop;
    const down = e => {
        e.stopPropagation(); e.preventDefault(); dragging = true;
        const touch = e.touches ? e.touches[0] : e;
        startX = touch.clientX; startY = touch.clientY;
        const r = this.playerEl.getBoundingClientRect();
        startLeft = parseFloat(el.style.left); startTop = parseFloat(el.style.top);
        el.style.cursor = 'grabbing';
    };
    const move = e => {
        if (!dragging) return; e.preventDefault();
        const touch = e.touches ? e.touches[0] : e;
        const r = this.playerEl.getBoundingClientRect();
        const dx = (touch.clientX - startX) / r.width * 100;
        const dy = (touch.clientY - startY) / r.height * 100;
        const nx = Math.max(0, Math.min(100, startLeft + dx));
        const ny = Math.max(0, Math.min(100, startTop + dy));
        el.style.left = nx + '%'; el.style.top = ny + '%';
        onMove(nx, ny);
    };
    const up = () => { dragging = false; el.style.cursor = 'grab'; document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); document.removeEventListener('touchmove', move); document.removeEventListener('touchend', up); };
    el.addEventListener('mousedown', e => { down(e); document.addEventListener('mousemove', move); document.addEventListener('mouseup', up); });
    el.addEventListener('touchstart', e => { down(e); document.addEventListener('touchmove', move, { passive: false }); document.addEventListener('touchend', up); }, { passive: false });
}

/* ── Playback ─────────────────────────────────────────────── */

_togglePlay() {
    if (this.video.paused) {
        const ct = this.video.currentTime / this.duration;
        if (ct < this.trimStart || ct >= this.trimEnd) this.video.currentTime = this.trimStart * this.duration;
        this.video.volume = Math.min(1, this.volume);
        this.video.playbackRate = this.speed * (this.pitch ? Math.pow(2, this.pitch / 12) : 1);
        if (this.replUrl) { this.video.muted = true; this._replAudio?.play(); }
        if (this._voiceAudio) this._voiceAudio.play();
        if (this._audioCtx?.state === 'suspended') this._audioCtx.resume();
        this.video.play();
    } else {
        this.video.pause();
        this._replAudio?.pause();
        this._voiceAudio?.pause();
    }
}

_frameStep(n) {
    const fps = 30;
    this.video.currentTime = Math.max(0, Math.min(this.duration, this.video.currentTime + n / fps));
}

_onTime() {
    if (!this.duration) return;
    const f = this.video.currentTime / this.duration;
    if (this.playhead) this.playhead.style.left = (f * 100) + '%';
    if (this.elTC) this.elTC.textContent = this._fmt(this.video.currentTime);
    if (f >= this.trimEnd) this.video.currentTime = this.trimStart * this.duration;
    // Skip deleted segments during playback
    if (this.deletedSegs.length && !this.video.paused) {
        const segs = this._getSegments();
        for (const idx of this.deletedSegs) {
            const seg = segs[idx];
            if (seg && f >= seg.start && f < seg.end) {
                // Jump to next non-deleted segment
                let jumped = false;
                for (let j = idx + 1; j < segs.length; j++) {
                    if (!this.deletedSegs.includes(j)) {
                        this.video.currentTime = segs[j].start * this.duration;
                        jumped = true; break;
                    }
                }
                if (!jumped) this.video.currentTime = this.trimStart * this.duration;
                break;
            }
        }
    }
    // Sync replace audio
    if (this._replAudio && !this.video.paused) {
        if (Math.abs(this._replAudio.currentTime - this.video.currentTime) > 0.3)
            this._replAudio.currentTime = this.video.currentTime;
    }
    // Audio fade
    if (this._gainN && (this.fadeIn || this.fadeOut)) {
        const ct = this.video.currentTime;
        const end = this.trimEnd * this.duration;
        let vol = this.volume;
        if (this.fadeIn && ct < this.fadeIn) vol *= ct / this.fadeIn;
        if (this.fadeOut && ct > end - this.fadeOut) vol *= (end - ct) / this.fadeOut;
        this._gainN.gain.value = Math.max(0, vol);
    }
    // Subtitle display
    const ct = this.video.currentTime;
    const activeSub = this.subs.find(s => ct >= s.start && ct <= s.end);
    if (activeSub) {
        this.subEl.textContent = activeSub.text;
        this.subEl.style.display = 'block';
    } else this.subEl.style.display = 'none';
    // Keyframe animation
    if (this.keyframes.length) this._applyKeyframe();
}

/* ── Trim Helpers ─────────────────────────────────────────── */

_genStrip(container) {
    for (let i = 0; i < 10; i++) {
        const cv = document.createElement('canvas');
        cv.width = 54; cv.height = 36; cv.className = 'ved-frame';
        container.appendChild(cv);
        const t = (i / 10) * (this.duration || 1);
        const v = document.createElement('video');
        v.src = this.objUrl; v.preload = 'auto'; v.muted = true;
        v.addEventListener('loadeddata', () => { v.currentTime = t; }, { once: true });
        v.addEventListener('seeked', () => { cv.getContext('2d').drawImage(v, 0, 0, cv.width, cv.height); v.src = ''; }, { once: true });
    }
}

_setupDrag(handle, side, tl) {
    let a = false;
    const mv = e => {
        if (!a) return;
        const r = tl.getBoundingClientRect();
        const x = e.touches ? e.touches[0].clientX : e.clientX;
        let f = Math.max(0, Math.min(1, (x - r.left) / r.width));
        if (side === 'start') this.trimStart = Math.min(f, this.trimEnd - 0.02);
        else this.trimEnd = Math.max(f, this.trimStart + 0.02);
        this._updTrim();
        // Sync video to handle position in real-time
        this.video.currentTime = (side === 'start' ? this.trimStart : this.trimEnd) * this.duration;
    };
    const up = () => { a = false; document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); document.removeEventListener('touchmove', mv); document.removeEventListener('touchend', up); };
    handle.addEventListener('mousedown', e => { e.stopPropagation(); a = true; this.video.pause(); document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up); });
    handle.addEventListener('touchstart', e => { e.stopPropagation(); a = true; this.video.pause(); document.addEventListener('touchmove', mv, { passive: true }); document.addEventListener('touchend', up); }, { passive: true });
}

_updTrim() {
    const { hL, hR, az, dimL, dimR } = this._trimEls || {};
    if (!hL) return;
    const s = this.trimStart * 100, e = this.trimEnd * 100;
    hL.style.left = s + '%'; hR.style.left = e + '%';
    az.style.left = s + '%'; az.style.width = (e - s) + '%';
    dimL.style.width = s + '%'; dimR.style.left = e + '%'; dimR.style.width = (100 - e) + '%';
    if (this.elTS) this.elTS.textContent = this._fmt(this.trimStart * this.duration);
    if (this.elTE) this.elTE.textContent = this._fmt(this.trimEnd * this.duration);
}

/* ── Adjust State (for presets) ───────────────────────────── */

/* ── Segments (regions between cuts within trim bounds) ──── */

_getSegments() {
    const pts = [this.trimStart, ...this.cuts.filter(c => c > this.trimStart && c < this.trimEnd), this.trimEnd];
    const segs = [];
    for (let i = 0; i < pts.length - 1; i++) segs.push({ start: pts[i], end: pts[i + 1] });
    return segs;
}

_getAdjustState() {
    return { brightness: this.brightness, contrast: this.contrast, saturation: this.saturation, lut: this.lut, vignette: this.vignette, grain: this.grain, blurBg: this.blurBg, tiltShift: this.tiltShift, tiltPos: this.tiltPos, duotone: this.duotone ? {...this.duotone} : null, chromaAb: this.chromaAb, glitch: this.glitch, rgbR: this.rgbR, rgbG: this.rgbG, rgbB: this.rgbB, rotation: this.rotation, flipH: this.flipH, flipV: this.flipV, crop: {...this.crop} };
}

_applyAdjustState(s) {
    Object.keys(s).forEach(k => {
        if (k === 'crop') this.crop = {...s.crop};
        else if (k === 'duotone') this.duotone = s.duotone ? {...s.duotone} : null;
        else this[k] = s[k];
    });
    this._applyFilters(); this._applyTransform(); this._applyCrop();
}

/* ═══════════════════════════════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════════════════════════════ */

_el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

_btn(cls, text, fn) {
    const b = document.createElement('button'); b.className = cls; b.textContent = text;
    if (fn) b.addEventListener('click', fn); return b;
}

_iconBtn(cls, pathD, fn) {
    const b = document.createElement('button'); b.className = cls;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '18'); svg.setAttribute('height', '18');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
    pathD.split(' M').forEach((d, i) => {
        const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        p.setAttribute('d', (i ? 'M' : '') + d); svg.appendChild(p);
    });
    b.appendChild(svg);
    if (fn) b.addEventListener('click', fn);
    return b;
}

_slider(label, min, max, val, unit, onChange) {
    const row = this._el('div', 'ved-slider-row');
    const lbl = this._el('span', 'ved-slider-label'); lbl.textContent = label;
    const valEl = this._el('span', 'ved-slider-val'); valEl.textContent = val + unit;
    const sl = document.createElement('input');
    sl.type = 'range'; sl.min = min; sl.max = max; sl.value = val; sl.step = (max - min > 100 ? 1 : 0.1);
    sl.className = 'ved-slider';
    sl.addEventListener('input', () => { valEl.textContent = (Number(sl.value) % 1 ? Number(sl.value).toFixed(1) : sl.value) + unit; onChange(parseFloat(sl.value)); });
    row.append(lbl, sl, valEl); return row;
}

_miniSlider(label, min, max, val, onChange) {
    const w = this._el('span', 'ved-mini-slider');
    const lbl = this._el('span', 'ved-mini-label'); lbl.textContent = label;
    const sl = document.createElement('input');
    sl.type = 'range'; sl.min = min; sl.max = max; sl.value = val; sl.step = 0.1;
    sl.className = 'ved-slider'; sl.style.width = '60px';
    sl.addEventListener('input', () => onChange(parseFloat(sl.value)));
    w.append(lbl, sl); return w;
}

_toggle(label, value, onChange) {
    const row = this._el('div', 'ved-toggle-row');
    const lbl = this._el('span', 'ved-toggle-label'); lbl.textContent = label;
    const sw = this._el('button', 'ved-toggle' + (value ? ' active' : ''));
    sw.innerHTML = '<span class="ved-toggle-knob"></span>';
    sw.addEventListener('click', () => { const nv = !sw.classList.contains('active'); sw.classList.toggle('active', nv); onChange(nv); });
    row.append(lbl, sw); return row;
}

_colorPicker(label, value, onChange) {
    const row = this._el('div', 'ved-slider-row');
    const lbl = this._el('span', 'ved-slider-label'); lbl.textContent = label;
    const inp = document.createElement('input');
    inp.type = 'color'; inp.value = value; inp.className = 'ved-color-input';
    inp.addEventListener('input', () => onChange(inp.value));
    row.append(lbl, inp); return row;
}

_note(text) { const n = this._el('div', 'ved-note'); n.textContent = text; return n; }

_fmt(s) {
    if (!s || isNaN(s)) return '0:00';
    const m = Math.floor(s / 60);
    return m + ':' + String(Math.floor(s % 60)).padStart(2, '0');
}

/* ── Finish ───────────────────────────────────────────────── */

_finish() {
    localStorage.removeItem('ved_draft_' + this.file.name);
    // Auto-generate thumbnail from main video if user didn't pick one
    if (!this.thumbnail && this.video.videoWidth) {
        try {
            const cvs = document.createElement('canvas');
            cvs.width = this.video.videoWidth; cvs.height = this.video.videoHeight;
            cvs.getContext('2d').drawImage(this.video, 0, 0, cvs.width, cvs.height);
            this.thumbnail = cvs.toDataURL('image/jpeg', 0.92);
        } catch (_) {}
    }
    this.onDone?.({
        file: this.file,
        thumbnail: this.thumbnail,
        trimStart: this.trimStart * this.duration,
        trimEnd: this.trimEnd * this.duration,
        cuts: this.cuts.map(c => c * this.duration),
        deletedSegments: this.deletedSegs.slice(),
        keepSegments: this._getSegments().filter((_, i) => !this.deletedSegs.includes(i)).map(s => ({ start: s.start * this.duration, end: s.end * this.duration })),
        speed: this.speed,
        reversed: this.reversed,
        freezes: this.freezes.map(f => ({ time: f.pos * this.duration, dur: f.dur })),
        loopSeg: this.loopSeg ? { start: this.loopSeg.start * this.duration, end: this.loopSeg.end * this.duration, count: this.loopSeg.count } : null,
        mergeFiles: this.mergeFiles.map(f => f.file),
        keyframes: this.keyframes.map(kf => ({ time: kf.pos * this.duration, zoom: kf.zoom, panX: kf.panX, panY: kf.panY })),
        timecodes: this.timecodes.map(tc => ({ time: tc.time, label: tc.label })),
        crop: this.crop,
        rotation: this.rotation, flipH: this.flipH, flipV: this.flipV,
        brightness: this.brightness, contrast: this.contrast, saturation: this.saturation,
        lut: this.lut != null ? LUTS[this.lut]?.n : null,
        vignette: this.vignette, grain: this.grain, blurBg: this.blurBg,
        tiltShift: this.tiltShift, tiltPos: this.tiltPos,
        duotone: this.duotone, chromaAb: this.chromaAb, glitch: this.glitch,
        rgbR: this.rgbR, rgbG: this.rgbG, rgbB: this.rgbB,
        textLayers: this.textLayers,
        subtitles: this.subs,
        watermark: this.watermark ? { pos: this.watermark.pos, opacity: this.watermark.opacity } : null,
        stickers: this.stickers,
        shapes: this.shapes,
        strokes: this.strokes,
        volume: this.volume, muted: this.volume === 0,
        fadeIn: this.fadeIn, fadeOut: this.fadeOut,
        eq: this.eq, pitch: this.pitch,
        noiseGate: this.noiseGate, noiseThr: this.noiseThr,
        replaceAudioName: this.replName,
        voiceoverName: this.voiceName,
        musicTrack: this.musicIdx >= 0 ? MUSIC[this.musicIdx]?.n : null,
        mixOrig: this.mixOrig, mixOver: this.mixOver,
        exportRes: this.exRes, exportFmt: this.exFmt, exportQuality: this.exQual,
    });
    this.destroy();
}

} // end class

window.openVideoEditor = openVideoEditor;
window.closeVideoEditor = closeVideoEditor;

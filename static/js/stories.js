// static/js/stories.js — Stories (Instagram/Telegram style)
import { api, esc } from './utils.js';

// ── State ────────────────────────────────────────────────────────────────────
let _groups = [];          // story groups from API
let _gi = 0;               // current group index
let _si = 0;               // story index within group
let _progress = 0;         // 0..100
let _raf = null;           // requestAnimationFrame handle
let _lastTs = null;        // last frame timestamp
let _paused = false;
let _holdTimer = null;     // long-press detect timer
let _camStream = null;     // camera MediaStream
let _camRecorder = null;
let _camChunks = [];
let _isRecording = false;
let _scType = null;        // current creator type
let _scFile = null;        // selected media File
let _scMusicFile = null;
let _scTextColor = '#ffffff';
let _scBg = 'linear-gradient(135deg,#667eea 0%,#764ba2 100%)';
let _expanded = false;     // stories strip expanded state

// ── Public: set of user IDs that have active stories ─────────────────────────
export const storyUserIds = new Set();

// ── Load & render strip ───────────────────────────────────────────────────────
export async function loadStories() {
    try {
        const data = await api('GET', '/api/stories');
        _groups = data.story_groups || [];
    } catch {
        _groups = [];
    }
    storyUserIds.clear();
    for (const g of _groups) {
        if (g.user_id && g.stories?.length) storyUserIds.add(g.user_id);
    }
    renderStoriesStrip();
}

export function renderStoriesStrip() {
    const track = document.getElementById('stories-track');
    if (!track) return;

    const S = window.AppState;
    const myId = S.user?.id;

    // Always show "Add story" (self) first
    let html = '';

    // Self bubble: если есть истории → открыть просмотр, иначе → создать
    const selfGroup = _groups.find(g => g.is_self);
    const selfIdx = selfGroup ? _groups.indexOf(selfGroup) : -1;
    const selfAction = selfGroup && selfGroup.stories.length > 0
        ? `window.openStories(${selfIdx})`
        : `window.showStoryCreator()`;
    html += `<button class="st-bubble st-self" onclick="${selfAction}" title="${window.t ? window.t('stories.myStory') : 'My Story'}">
        <div class="st-ring ${selfGroup && selfGroup.stories.length > 0 ? 'has-story' : ''}">
            <div class="st-avatar">${_avatarHtml(S.user?.avatar_url, S.user?.avatar_emoji || '👤')}</div>
            ${!selfGroup || selfGroup.stories.length === 0 ? '<div class="st-add-badge">+</div>' : ''}
        </div>
        <span class="st-label">${window.t ? window.t('stories.myStory') : 'My'}</span>
    </button>`;

    // Other users
    const others = _groups.filter(g => !g.is_self);
    const visible = _expanded ? others : others.slice(0, 3);

    for (const g of visible) {
        const idx = _groups.indexOf(g);
        html += `<button class="st-bubble" onclick="window.openStories(${idx})" title="${esc(g.display_name)}">
            <div class="st-ring${g.has_unseen !== false ? ' unseen' : ''}">
                <div class="st-avatar">${_avatarHtml(g.avatar_url, g.avatar_emoji || '👤')}</div>
            </div>
            <span class="st-label">${esc(g.display_name.split(' ')[0])}</span>
        </button>`;
    }

    // Show-all / collapse toggle
    if (others.length > 3) {
        if (!_expanded) {
            const showMoreLabel = window.t ? window.t('stories.showMore').replace('{n}', others.length - 3) : `+${others.length - 3}`;
            html += `<button class="st-bubble" onclick="window.expandStories()" title="${window.t ? window.t('stories.showAll') : 'Show all'}">
                <div class="st-ring" style="background:var(--bg3);">
                    <div class="st-avatar" style="display:flex;align-items:center;justify-content:center;font-size:18px;">›</div>
                </div>
                <span class="st-label">${showMoreLabel}</span>
            </button>`;
        } else {
            html += `<button class="st-bubble" onclick="window.collapseStories()" title="${window.t ? window.t('stories.collapse') : 'Collapse'}">
                <div class="st-ring" style="background:var(--bg3);">
                    <div class="st-avatar" style="display:flex;align-items:center;justify-content:center;font-size:18px;">‹</div>
                </div>
                <span class="st-label">${window.t ? window.t('stories.collapse') : 'Collapse'}</span>
            </button>`;
        }
    }

    track.innerHTML = html;

    const strip = document.getElementById('stories-strip');
    if (strip) strip.style.display = '';
}

function _avatarHtml(url, emoji) {
    if (url) return `<img src="${esc(url)}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
    return `<span style="font-size:20px;">${esc(emoji)}</span>`;
}

export function expandStories() { _expanded = true; renderStoriesStrip(); }
export function collapseStories() { _expanded = false; renderStoriesStrip(); }

// ── Viewer ────────────────────────────────────────────────────────────────────
export function openStories(groupIdx) {
    if (!_groups.length) return;
    _gi = Math.max(0, Math.min(groupIdx, _groups.length - 1));
    _si = 0;
    _paused = false;
    const viewer = document.getElementById('story-viewer');
    if (!viewer) return;
    viewer.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    _renderCurrent();
    _startProgress();
    // Mark viewed
    _markViewed();
}

export function closeStoryViewer() {
    _stopProgress();
    const viewer = document.getElementById('story-viewer');
    if (viewer) viewer.style.display = 'none';
    document.body.style.overflow = '';
    // Stop video/audio
    const vid = document.getElementById('sv-video');
    if (vid) { vid.pause(); vid.src = ''; }
    const aud = document.getElementById('sv-audio');
    if (aud) { aud.pause(); aud.src = ''; }
    _stopCamera();
}

function _renderCurrent() {
    const group = _groups[_gi];
    if (!group) { closeStoryViewer(); return; }
    const story = group.stories[_si];
    if (!story) { closeStoryViewer(); return; }

    const S = window.AppState;

    // User info
    document.getElementById('sv-username').textContent = group.display_name;
    document.getElementById('sv-time').textContent = _timeAgo(story.created_at);
    const avatarEl = document.getElementById('sv-avatar');
    avatarEl.innerHTML = '';
    if (group.avatar_url) {
        avatarEl.innerHTML = `<img src="${esc(group.avatar_url)}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;">`;
    } else {
        avatarEl.textContent = group.avatar_emoji || '👤';
    }

    // Add + Delete buttons for own stories
    const addBtn = document.getElementById('sv-add-btn');
    if (addBtn) addBtn.style.display = group.is_self ? 'flex' : 'none';
    const delBtn = document.getElementById('sv-delete-btn');
    if (delBtn) delBtn.style.display = group.is_self ? 'flex' : 'none';

    // Views counter
    const viewsEl = document.getElementById('sv-views');
    const viewsCount = document.getElementById('sv-views-count');
    if (group.is_self) {
        viewsEl.style.display = 'flex';
        viewsCount.textContent = story.views_count || 0;
    } else {
        viewsEl.style.display = 'none';
    }

    // Media
    const img = document.getElementById('sv-img');
    const vid = document.getElementById('sv-video');
    const textSlide = document.getElementById('sv-text-slide');
    const content = document.getElementById('sv-content');

    img.style.display = 'none';
    vid.style.display = 'none';
    textSlide.style.display = 'none';

    if (story.media_type === 'photo' && story.media_url) {
        img.src = story.media_url;
        img.style.display = 'block';
        content.style.background = '#000';
    } else if (story.media_type === 'video' && story.media_url) {
        vid.src = story.media_url;
        vid.style.display = 'block';
        vid.muted = false;
        vid.play().catch(() => {});
        content.style.background = '#000';
    } else {
        // text story
        textSlide.style.display = 'flex';
        textSlide.style.background = story.bg_color || 'linear-gradient(135deg,#667eea 0%,#764ba2 100%)';
        const p = document.getElementById('sv-text-content');
        p.textContent = story.text || '';
        p.style.color = story.text_color || '#fff';
        content.style.background = 'transparent';
    }

    // Music
    const musicBadge = document.getElementById('sv-music-badge');
    const audio = document.getElementById('sv-audio');
    if (story.music_url || story.music_title) {
        musicBadge.style.display = 'flex';
        document.getElementById('sv-music-title').textContent = story.music_title || '♫';
        if (story.music_url) {
            audio.src = story.music_url;
            audio.play().catch(() => {});
        }
    } else {
        musicBadge.style.display = 'none';
        audio.pause();
        audio.src = '';
    }

    // Progress bars
    _buildProgressBars(group.stories.length);
}

function _buildProgressBars(count) {
    const row = document.getElementById('sv-progress-row');
    if (!row) return;
    let html = '';
    for (let i = 0; i < count; i++) {
        const pct = i < _si ? 100 : (i === _si ? 0 : 0);
        html += `<div class="sv-prog-bar"><div class="sv-prog-fill" id="sv-prog-${i}" style="width:${pct}%"></div></div>`;
    }
    row.innerHTML = html;
}

function _startProgress() {
    _stopProgress();
    _progress = 0;
    _lastTs = null;
    const group = _groups[_gi];
    if (!group) return;
    const story = group.stories[_si];
    const dur = (story?.media_type === 'video' ? (story.duration || 15) : (story?.duration || 5)) * 1000;

    const animate = (ts) => {
        if (_paused) { _raf = requestAnimationFrame(animate); return; }
        if (_lastTs === null) _lastTs = ts;
        const delta = ts - _lastTs;
        _lastTs = ts;
        _progress = Math.min(100, _progress + (delta / dur) * 100);

        const fill = document.getElementById(`sv-prog-${_si}`);
        if (fill) fill.style.width = _progress + '%';

        if (_progress >= 100) {
            _nextStory();
            return;
        }
        _raf = requestAnimationFrame(animate);
    };
    _raf = requestAnimationFrame(animate);
}

function _stopProgress() {
    if (_raf) { cancelAnimationFrame(_raf); _raf = null; }
}

function _nextStory() {
    _stopProgress();
    const group = _groups[_gi];
    if (!group) { closeStoryViewer(); return; }
    if (_si < group.stories.length - 1) {
        _si++;
        _progress = 0;
        _renderCurrent();
        _startProgress();
        _markViewed();
    } else if (_gi < _groups.length - 1) {
        _gi++;
        _si = 0;
        _progress = 0;
        _renderCurrent();
        _startProgress();
        _markViewed();
    } else {
        closeStoryViewer();
    }
}

function _prevStory() {
    _stopProgress();
    if (_si > 0) {
        _si--;
    } else if (_gi > 0) {
        _gi--;
        _si = _groups[_gi].stories.length - 1;
    }
    _progress = 0;
    _renderCurrent();
    _startProgress();
}

function _markViewed() {
    const group = _groups[_gi];
    if (!group || group.is_self) return;
    const story = group.stories[_si];
    if (!story) return;
    api('POST', `/api/stories/${story.id}/view`).catch(() => {});
}

// Hold to pause
window._svTapStart = function(e, side) {
    e.preventDefault();
    _holdTimer = setTimeout(() => {
        _paused = true;
        _holdTimer = null;
    }, 150);
};

window._svTapEnd = function(e, side) {
    e.preventDefault();
    if (_holdTimer) {
        clearTimeout(_holdTimer);
        _holdTimer = null;
        // Short tap → navigate
        if (side === 'right') _nextStory();
        else _prevStory();
    } else {
        // Was holding → resume
        _paused = false;
    }
};

window.closeStoryViewer = closeStoryViewer;
window.openStories = openStories;

window._deleteCurrentStory = async function() {
    const group = _groups[_gi];
    if (!group || !group.is_self) return;
    const story = group.stories[_si];
    if (!story) return;
    try {
        await api('DELETE', `/api/stories/${story.id}`);
        group.stories.splice(_si, 1);
        if (!group.stories.length) {
            _groups.splice(_gi, 1);
            if (!_groups.length) { closeStoryViewer(); renderStoriesStrip(); return; }
            _gi = Math.min(_gi, _groups.length - 1);
            _si = 0;
        } else {
            _si = Math.min(_si, group.stories.length - 1);
        }
        _renderCurrent();
        _startProgress();
        renderStoriesStrip();
    } catch (e) {
        alert(e.message);
    }
};

function _timeAgo(iso) {
    if (!iso) return '';
    const d = new Date(/Z$|[+-]\d{2}/.test(iso) ? iso : iso + 'Z');
    const diff = Math.round((Date.now() - d.getTime()) / 60000);
    const _t = window.t || ((k) => k);
    if (diff < 1) return _t('time.justNow');
    if (diff < 60) return diff + ' ' + _t('time.minShort');
    if (diff < 1440) return Math.round(diff / 60) + ' ' + _t('time.hShort');
    return Math.round(diff / 1440) + ' ' + _t('time.dShort');
}

// ── Story Creator ─────────────────────────────────────────────────────────────
export function showStoryCreator() {
    _scFile = null;
    _scMusicFile = null;
    _scType = null;
    const modal = document.getElementById('story-create-modal');
    if (!modal) return;
    modal.style.display = 'flex';
    document.getElementById('sc-step-type').style.display = '';
    document.getElementById('sc-step-editor').style.display = 'none';
}

export function closeStoryCreator() {
    const modal = document.getElementById('story-create-modal');
    if (modal) modal.style.display = 'none';
    _stopCamera();
    _scFile = null;
    _scMusicFile = null;
}

window.showStoryCreator = showStoryCreator;
window.closeStoryCreator = closeStoryCreator;
window.expandStories = expandStories;
window.collapseStories = collapseStories;

window._scBack = function() {
    _stopCamera();
    document.getElementById('sc-step-type').style.display = '';
    document.getElementById('sc-step-editor').style.display = 'none';
};

window._scSelectType = async function(type) {
    _scType = type;
    document.getElementById('sc-step-type').style.display = 'none';
    document.getElementById('sc-step-editor').style.display = '';

    // Reset all editor sections
    ['sc-camera-wrap','sc-preview-wrap','sc-text-editor','sc-duration-group','sc-overlay-group'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });
    const _t = window.t || ((k) => k);
    document.getElementById('sc-editor-title').textContent = {
        photo: _t('stories.editorPhoto'),
        video: _t('stories.editorVideo'),
        text:  _t('stories.editorText'),
        music: _t('stories.editorMusic'),
        'camera-photo': _t('stories.editorCamera'),
        'camera-video': _t('stories.editorCamera'),
    }[type] || _t('stories.editor');

    if (type === 'photo') {
        document.getElementById('sc-photo-file').click();
        document.getElementById('sc-overlay-group').style.display = '';
        document.getElementById('sc-duration-group').style.display = '';
    } else if (type === 'video') {
        document.getElementById('sc-video-file').click();
    } else if (type === 'text') {
        document.getElementById('sc-text-editor').style.display = '';
        document.getElementById('sc-duration-group').style.display = '';
        _scUpdateTextPreview();
    } else if (type === 'music') {
        document.getElementById('sc-text-editor').style.display = '';
        document.getElementById('sc-duration-group').style.display = '';
        _scUpdateTextPreview();
    } else if (type === 'camera-photo' || type === 'camera-video') {
        document.getElementById('sc-camera-wrap').style.display = '';
        document.getElementById('sc-overlay-group').style.display = '';
        if (type === 'camera-photo') document.getElementById('sc-duration-group').style.display = '';
        await _startCamera();
        // Show/hide record vs capture buttons
        document.getElementById('sc-capture-btn').style.display = type === 'camera-photo' ? '' : 'none';
        document.getElementById('sc-record-btn').style.display  = type === 'camera-video' ? '' : 'none';
    }
};

// Camera
async function _startCamera() {
    try {
        _camStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' }, audio: true });
        const v = document.getElementById('sc-camera-stream');
        if (v) { v.srcObject = _camStream; }
    } catch {
        alert(window.t ? window.t('stories.noCamera') : 'No camera access');
    }
}

function _stopCamera() {
    if (_camStream) { _camStream.getTracks().forEach(t => t.stop()); _camStream = null; }
    if (_camRecorder) { try { _camRecorder.stop(); } catch {} _camRecorder = null; }
    _isRecording = false;
}

window._scCapture = function() {
    const video = document.getElementById('sc-camera-stream');
    const canvas = document.getElementById('sc-canvas');
    if (!video || !canvas) return;
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob(blob => {
        _scFile = new File([blob], 'story.jpg', { type: 'image/jpeg' });
        _scType = 'photo';
        _stopCamera();
        document.getElementById('sc-camera-wrap').style.display = 'none';
        document.getElementById('sc-preview-wrap').style.display = '';
        const img = document.getElementById('sc-preview-img');
        img.src = URL.createObjectURL(blob);
        img.style.display = 'block';
    }, 'image/jpeg', 0.9);
};

window._scToggleCamRecord = function() {
    if (!_isRecording) {
        _camChunks = [];
        const mime = MediaRecorder.isTypeSupported('video/webm;codecs=vp9') ? 'video/webm;codecs=vp9' : 'video/webm';
        _camRecorder = new MediaRecorder(_camStream, { mimeType: mime });
        _camRecorder.ondataavailable = e => { if (e.data.size > 0) _camChunks.push(e.data); };
        _camRecorder.onstop = () => {
            const blob = new Blob(_camChunks, { type: 'video/webm' });
            _scFile = new File([blob], 'story.webm', { type: 'video/webm' });
            _scType = 'video';
            _stopCamera();
            document.getElementById('sc-camera-wrap').style.display = 'none';
            document.getElementById('sc-preview-wrap').style.display = '';
            const vid = document.getElementById('sc-preview-video');
            vid.src = URL.createObjectURL(blob);
            vid.style.display = 'block';
        };
        _camRecorder.start();
        _isRecording = true;
        document.getElementById('sc-record-btn').textContent = '⏹ ' + (window.t ? window.t('stories.stopRecording') : 'Stop');
        document.getElementById('sc-record-btn').style.background = 'var(--red)';
    } else {
        _camRecorder.stop();
        _isRecording = false;
        document.getElementById('sc-record-btn').textContent = '⏺ ' + (window.t ? window.t('stories.startRecording') : 'Record');
        document.getElementById('sc-record-btn').style.background = '';
    }
};

window._scMediaFileChange = function(input, type) {
    const file = input.files?.[0];
    if (!file) return;
    _scFile = file;
    _scType = type;
    document.getElementById('sc-preview-wrap').style.display = '';
    const url = URL.createObjectURL(file);
    if (type === 'photo') {
        const img = document.getElementById('sc-preview-img');
        img.src = url; img.style.display = 'block';
        document.getElementById('sc-preview-video').style.display = 'none';
    } else {
        const vid = document.getElementById('sc-preview-video');
        vid.src = url; vid.style.display = 'block';
        document.getElementById('sc-preview-img').style.display = 'none';
    }
};

window._scMusicFileChange = function(input) {
    const file = input.files?.[0];
    if (!file) return;
    _scMusicFile = file;
    const prev = document.getElementById('sc-music-preview');
    prev.textContent = '♫ ' + file.name;
    prev.style.display = '';
};

window._scUpdateTextPreview = function() {
    const text = document.getElementById('sc-text-input')?.value || '';
    const p = document.getElementById('sc-text-preview-content');
    if (p) { p.textContent = text; p.style.color = _scTextColor; }
    const preview = document.getElementById('sc-text-preview');
    if (preview) preview.style.background = _scBg;
};

window._scSetTextColor = function(color, btn) {
    _scTextColor = color;
    document.querySelectorAll('#sc-text-colors .sc-color-dot').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    _scUpdateTextPreview();
};

window._scSetBg = function(bg, btn) {
    _scBg = bg;
    document.querySelectorAll('#sc-bg-colors .sc-bg-dot').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    _scUpdateTextPreview();
};

window._scPublish = async function() {
    const btn = document.getElementById('sc-publish-btn');
    btn.disabled = true;
    btn.textContent = window.t ? window.t('stories.publishing') : 'Publishing...';
    try {
        const fd = new FormData();
        const mediaType = ['camera-photo','photo'].includes(_scType) ? 'photo'
            : ['camera-video','video'].includes(_scType) ? 'video' : 'text';
        fd.append('media_type', mediaType);

        if (_scFile) fd.append('file', _scFile);
        if (_scMusicFile) fd.append('music_file', _scMusicFile);

        const musicTitle = document.getElementById('sc-music-title')?.value.trim();
        if (musicTitle) fd.append('music_title', musicTitle);

        const overlayText = document.getElementById('sc-overlay-text')?.value.trim();
        const mainText = document.getElementById('sc-text-input')?.value.trim();
        fd.append('text', overlayText || mainText || '');
        fd.append('text_color', _scTextColor);
        fd.append('bg_color', _scBg);

        const dur = document.getElementById('sc-duration-input')?.value || '5';
        fd.append('duration', dur);

        const csrf = window.AppState?.csrfToken || '';
        const resp = await fetch('/api/stories', {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrf },
            body: fd,
            credentials: 'include',
        });
        if (!resp.ok) throw new Error(await resp.text());
        const story = await resp.json();

        // Add to own group
        let selfGroup = _groups.find(g => g.is_self);
        if (!selfGroup) {
            const S = window.AppState;
            selfGroup = {
                user_id: S.user?.id,
                username: S.user?.username,
                display_name: S.user?.display_name || S.user?.username,
                avatar_emoji: S.user?.avatar_emoji,
                avatar_url: S.user?.avatar_url,
                is_self: true,
                stories: [],
                has_unseen: false,
            };
            _groups.unshift(selfGroup);
        }
        selfGroup.stories.push(story);

        closeStoryCreator();
        renderStoriesStrip();
    } catch (e) {
        const errMsg = window.t ? window.t('stories.publishError').replace('{error}', e.message) : ('Error: ' + e.message);
        alert(errMsg);
    } finally {
        btn.disabled = false;
        btn.textContent = window.t ? window.t('stories.publish') : 'Publish';
    }
};

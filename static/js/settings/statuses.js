// ══════════════════════════════════════════════════════════════════════════════
// FEATURE: Statuses (24-hour ephemeral posts)
// ══════════════════════════════════════════════════════════════════════════════

window.openStatusModal = function() {
    var ta = document.getElementById('status-text');
    if (ta) ta.value = '';
    if (window.openModal) window.openModal('status-modal');
};

window.postStatus = async function() {
    var text = (document.getElementById('status-text')?.value || '').trim();
    if (!text) return;
    try {
        await window.api('POST', '/api/statuses', { text: text });
        if (window.closeModal) window.closeModal('status-modal');
        window.loadStatuses();
    } catch(e) { alert(e.message); }
};

window.loadStatuses = async function() {
    try {
        var data = await window.api('GET', '/api/statuses');
        var el = document.getElementById('status-list');
        if (!el) return;
        if (!data.users || !data.users.length) { el.innerHTML = ''; return; }

        el.innerHTML = data.users.map(function(u) {
            var avatar;
            if (u.avatar_url) {
                avatar = '<img src="' + u.avatar_url + '" style="width:36px;height:36px;border-radius:50%;object-fit:cover;border:2px solid var(--accent);">';
            } else {
                avatar = '<div style="width:36px;height:36px;border-radius:50%;border:2px solid var(--accent);display:flex;align-items:center;justify-content:center;font-size:18px;background:var(--bg3);">' + (u.avatar_emoji || '\u{1F464}') + '</div>';
            }
            var latest = u.statuses[0];
            var previewText = latest && latest.text ? latest.text : '';
            if (previewText.length > 40) previewText = previewText.substring(0, 40) + '...';
            return '<div style="display:flex;align-items:center;gap:8px;padding:6px 4px;cursor:pointer;border-radius:8px;transition:background 0.1s;" ' +
                'onmouseover="this.style.background=\'var(--bg3)\'" onmouseout="this.style.background=\'\'" ' +
                'onclick="viewStatus(' + u.user_id + ')">' +
                avatar +
                '<div style="flex:1;min-width:0;">' +
                    '<div style="font-weight:700;font-size:12px;">' + (u.display_name || u.username) + '</div>' +
                    '<div style="font-size:11px;color:var(--text3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + previewText + '</div>' +
                '</div>' +
            '</div>';
        }).join('');
    } catch(e) { console.warn('loadStatuses error:', e); }
};

window._statusData = null;

window.viewStatus = async function(userId) {
    try {
        var data = await window.api('GET', '/api/statuses');
        var userEntry = (data.users || []).find(function(u) { return u.user_id === userId; });
        if (!userEntry || !userEntry.statuses.length) {
            alert(t('settings.noActiveStatuses'));
            return;
        }
        var title = document.getElementById('status-viewer-title');
        if (title) title.textContent = t('statuses.title') + ' \u2014 ' + (userEntry.display_name || userEntry.username);
        var list = document.getElementById('status-viewer-list');
        if (list) {
            list.innerHTML = userEntry.statuses.map(function(s) {
                var createdAt = s.created_at ? new Date(s.created_at).toLocaleString('ru') : '';
                return '<div style="padding:12px;margin-bottom:8px;background:var(--bg3);border-radius:var(--radius);border-left:3px solid var(--accent);">' +
                    '<div style="font-size:14px;margin-bottom:4px;">' + (s.text || '') + '</div>' +
                    '<div style="font-size:10px;color:var(--text3);font-family:var(--mono);">' + createdAt + '</div>' +
                '</div>';
            }).join('');
        }
        if (window.openModal) window.openModal('status-viewer-modal');
    } catch(e) { alert(e.message); }
};

// ── Media Gallery ──
window._galleryFiles = [];
window._galleryTab = 'photo';

window.openGallery = async function() {
    var S = window.AppState;
    if (!S || !S.currentRoom) return;
    if (window.openModal) window.openModal('gallery-modal');
    var grid = document.getElementById('gallery-grid');
    grid.innerHTML = '<div class="gallery-empty">' + t('common.loading') + '</div>';
    // Reset tab to photo
    window._galleryTab = 'photo';
    document.querySelectorAll('.gallery-tab').forEach(function(t) {
        t.classList.toggle('active', t.dataset.galleryTab === 'photo');
    });
    try {
        var data = await window.api('GET', '/api/files/room/' + S.currentRoom.id);
        window._galleryFiles = data.files || [];
        renderGallery();
    } catch(e) {
        grid.innerHTML = '<div class="gallery-empty">' + t('errors.loadingError') + '</div>';
    }
};

window.switchGalleryTab = function(tab) {
    window._galleryTab = tab;
    document.querySelectorAll('.gallery-tab').forEach(function(t) {
        t.classList.toggle('active', t.dataset.galleryTab === tab);
    });
    renderGallery();
};

function renderGallery() {
    var grid = document.getElementById('gallery-grid');
    var tab = window._galleryTab;
    var files = window._galleryFiles;
    var filtered;

    if (tab === 'photo') {
        filtered = files.filter(function(f) { return f.mime_type && f.mime_type.startsWith('image/'); });
    } else if (tab === 'video') {
        filtered = files.filter(function(f) { return f.mime_type && f.mime_type.startsWith('video/'); });
    } else {
        filtered = files.filter(function(f) {
            return !f.mime_type || (!f.mime_type.startsWith('image/') && !f.mime_type.startsWith('video/'));
        });
    }

    if (!filtered.length) {
        var labels = { photo: t('gallery.noPhotos'), video: t('gallery.noVideos'), files: t('gallery.noFiles') };
        grid.innerHTML = '<div class="gallery-empty">' + (labels[tab] || t('ui.empty')) + '</div>';
        return;
    }

    if (tab === 'photo') {
        grid.className = 'gallery-grid gallery-grid-media';
        grid.innerHTML = filtered.map(function(f) {
            var safeName = (f.file_name || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
            return '<div class="gallery-thumb" onclick="closeModal(\'gallery-modal\');window.openImageViewer(\'' + f.download_url + '\',\'' + safeName + '\')">' +
                '<img src="' + f.download_url + '" alt="' + safeName + '" loading="lazy">' +
            '</div>';
        }).join('');
    } else if (tab === 'video') {
        grid.className = 'gallery-grid gallery-grid-media';
        grid.innerHTML = filtered.map(function(f) {
            var safeName = (f.file_name || '').replace(/"/g, '&quot;');
            return '<div class="gallery-thumb gallery-thumb-video" onclick="openGalleryVideo(\'' + f.download_url + '\',\'' + safeName + '\')">' +
                '<video src="' + f.download_url + '" preload="metadata" muted></video>' +
                '<div class="gallery-play-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="white" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>' +
            '</div>';
        }).join('');
    } else {
        grid.className = 'gallery-grid gallery-grid-files';
        grid.innerHTML = filtered.map(function(f) {
            var size = f.size_bytes;
            var sizeStr;
            if (size < 1024) sizeStr = size + ' ' + t('files.bytes');
            else if (size < 1024 * 1024) sizeStr = (size / 1024).toFixed(1) + ' ' + t('files.kb');
            else sizeStr = (size / 1024 / 1024).toFixed(1) + ' ' + t('files.mb');
            var safeName = (f.file_name || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return '<a href="' + f.download_url + '" download class="gallery-file-item">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11z"/></svg>' +
                '<div class="gallery-file-info">' +
                    '<div class="gallery-file-name">' + safeName + '</div>' +
                    '<div class="gallery-file-meta">' + sizeStr + (f.uploader ? ' \u00B7 ' + f.uploader : '') + '</div>' +
                '</div>' +
            '</a>';
        }).join('');
    }
}

window.openGalleryVideo = function(url, name) {
    // Close gallery and open a fullscreen video player using the image viewer overlay approach
    closeModal('gallery-modal');
    var overlay = document.getElementById('image-viewer-overlay');
    var img = document.getElementById('image-viewer-img');
    var nameEl = document.getElementById('image-viewer-name');
    // Replace img with video temporarily
    var video = document.createElement('video');
    video.src = url;
    video.controls = true;
    video.autoplay = true;
    video.style.cssText = 'max-width:90vw;max-height:80vh;border-radius:8px;outline:none;';
    video.id = 'gallery-video-player';
    img.style.display = 'none';
    img.parentNode.insertBefore(video, img.nextSibling);
    nameEl.textContent = name;
    overlay.classList.add('show');

    // Clean up when overlay closes
    var obs = new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
            if (!overlay.classList.contains('show')) {
                var vp = document.getElementById('gallery-video-player');
                if (vp) { vp.pause(); vp.remove(); }
                img.style.display = '';
                obs.disconnect();
            }
        });
    });
    obs.observe(overlay, { attributes: true, attributeFilter: ['class'] });
};


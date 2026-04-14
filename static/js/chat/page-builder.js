/**
 * page-builder.js — Собирает HTML/CSS/JS файлы в одну страницу.
 * Просмотр через sandbox iframe без allow-same-origin — полная изоляция.
 */

import { getRoomKey, encryptFile } from '../crypto.js';

// ── Page Builder Modal ──────────────────────────────────────────────────────

let _pageFiles = { html: null, css: null, js: null };

export function openPageBuilder() {
    _pageFiles = { html: null, css: null, js: null };
    document.getElementById('page-builder-modal')?.remove();

    const backdrop = document.createElement('div');
    backdrop.id = 'page-builder-modal';
    backdrop.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;animation:vxFadeIn .15s ease;';

    const box = document.createElement('div');
    box.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:24px;width:90vw;max-width:400px;box-shadow:0 16px 48px rgba(0,0,0,.4);animation:vxSlideUp .2s ease;';

    // Build modal content using DOM (not innerHTML with user data)
    const header = document.createElement('div');
    header.style.cssText = 'font-size:16px;font-weight:700;color:var(--text);margin-bottom:4px;display:flex;align-items:center;gap:8px;';
    const iconWrap = document.createElement('div');
    iconWrap.style.cssText = 'width:28px;height:28px;border-radius:8px;background:#7c3aed;display:flex;align-items:center;justify-content:center;';
    iconWrap.textContent = '</>';
    iconWrap.style.color = '#fff';
    iconWrap.style.fontSize = '11px';
    iconWrap.style.fontWeight = '700';
    header.appendChild(iconWrap);
    header.appendChild(document.createTextNode(t('chat.pageBuilderTitle')));

    const desc = document.createElement('div');
    desc.style.cssText = 'font-size:12px;color:var(--text3);margin-bottom:12px;';
    desc.textContent = t('pageBuilder.dropHint');

    // Dropzone
    const dropzone = document.createElement('div');
    dropzone.style.cssText = 'border:2px dashed var(--border);border-radius:14px;padding:24px 16px;text-align:center;cursor:pointer;transition:all .15s;margin-bottom:12px;position:relative;';

    const dropInput = document.createElement('input');
    dropInput.type = 'file';
    dropInput.multiple = true;
    dropInput.accept = '.html,.htm,.css,.js,.mjs';
    dropInput.style.cssText = 'position:absolute;inset:0;opacity:0;cursor:pointer;';
    dropInput.addEventListener('change', () => _distributeFiles(dropInput.files, statusList));

    const dropLabel = document.createElement('div');
    dropLabel.style.cssText = 'color:var(--text3);font-size:13px;pointer-events:none;';
    dropLabel.textContent = 'HTML + CSS + JS';

    dropzone.append(dropInput, dropLabel);
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.style.borderColor = 'var(--accent)'; dropzone.style.background = 'rgba(124,58,237,0.05)'; });
    dropzone.addEventListener('dragleave', () => { dropzone.style.borderColor = 'var(--border)'; dropzone.style.background = ''; });
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.style.borderColor = 'var(--border)';
        dropzone.style.background = '';
        _distributeFiles(e.dataTransfer.files, statusList);
    });

    // Status indicators
    const statusList = document.createElement('div');
    statusList.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';

    function _distributeFiles(files, container) {
        for (const f of files) {
            const ext = f.name.split('.').pop().toLowerCase();
            if (ext === 'html' || ext === 'htm') _pageFiles.html = f;
            else if (ext === 'css') _pageFiles.css = f;
            else if (ext === 'js' || ext === 'mjs') _pageFiles.js = f;
        }
        // Update status
        container.textContent = '';
        const types = [
            { key: 'html', color: '#ea580c' },
            { key: 'css', color: '#2563eb' },
            { key: 'js', color: '#eab308' },
        ];
        for (const t of types) {
            const file = _pageFiles[t.key];
            const chip = document.createElement('span');
            chip.style.cssText = `padding:4px 10px;border-radius:8px;font-size:11px;font-weight:600;color:#fff;background:${file ? t.color : 'var(--bg3)'};${file ? '' : 'color:var(--text3);'}`;
            chip.textContent = file ? `${t.key.toUpperCase()}: ${file.name}` : t.key.toUpperCase();
            container.appendChild(chip);
        }
    }

    const slots = document.createElement('div');
    slots.append(dropzone, statusList);

    const nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.id = 'pb-page-name';
    nameInput.placeholder = t('pageBuilder.pageName');
    nameInput.style.cssText = 'width:100%;padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:var(--bg3);color:var(--text);font-size:13px;outline:none;box-sizing:border-box;margin-top:12px;';

    const btns = document.createElement('div');
    btns.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;margin-top:16px;';

    const cancelBtn = document.createElement('button');
    cancelBtn.style.cssText = 'padding:8px 20px;border-radius:10px;border:none;cursor:pointer;background:var(--bg3);color:var(--text2);font-size:13px;';
    cancelBtn.textContent = t('app.cancel');
    cancelBtn.onclick = () => backdrop.remove();

    const sendBtn = document.createElement('button');
    sendBtn.style.cssText = 'padding:8px 20px;border-radius:10px;border:none;cursor:pointer;background:var(--accent);color:#fff;font-size:13px;font-weight:600;';
    sendBtn.textContent = t('pageBuilder.buildAndSend');
    sendBtn.onclick = () => _buildAndSend(sendBtn, backdrop);

    btns.append(cancelBtn, sendBtn);
    box.append(header, desc, slots, nameInput, btns);
    backdrop.appendChild(box);
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
    document.body.appendChild(backdrop);
}

async function _buildAndSend(btn, backdrop) {
    if (!_pageFiles.html && !_pageFiles.css && !_pageFiles.js) {
        window.showToast?.(t('pageBuilder.uploadAtLeastOne'), 'error');
        return;
    }
    btn.disabled = true;
    btn.textContent = t('pageBuilder.building');

    try {
        const htmlContent = _pageFiles.html ? await _pageFiles.html.text() : '';
        const cssContent = _pageFiles.css ? await _pageFiles.css.text() : '';
        const jsContent = _pageFiles.js ? await _pageFiles.js.text() : '';
        const pageName = document.getElementById('pb-page-name')?.value?.trim() || 'Page';

        const builtHtml = _buildPage(htmlContent, cssContent, jsContent, pageName);
        const blob = new Blob([builtHtml], { type: 'text/html' });
        const fileName = pageName.replace(/[^a-zA-Z0-9а-яА-Я_-]/g, '_') + '.vxpage.html';

        const S = window.AppState;
        if (!S?.currentRoom?.id) return;

        let uploadBlob = blob;
        const roomKey = getRoomKey(S.currentRoom.id);
        if (roomKey) {
            try {
                const buf = await blob.arrayBuffer();
                const encrypted = await encryptFile(buf, roomKey);
                uploadBlob = new Blob([encrypted], { type: 'application/octet-stream' });
            } catch {}
        }

        const formData = new FormData();
        formData.append('file', uploadBlob, fileName);
        const csrfToken = S.csrfToken || document.cookie.match(/csrf_token=([^;]+)/)?.[1] || '';

        const resp = await fetch(`/api/files/upload/${S.currentRoom.id}`, {
            method: 'POST', body: formData, credentials: 'include',
            headers: { 'X-CSRF-Token': csrfToken },
        });
        if (!resp.ok) throw new Error('Upload: ' + resp.status);

        backdrop.remove();
        window.showToast?.(t('pageBuilder.pageSent', {name: pageName}), 'success');
    } catch (e) {
        window.showToast?.(t('errors.generic') + ': ' + e.message, 'error');
        btn.disabled = false;
        btn.textContent = t('pageBuilder.buildAndSend');
    }
}

function _buildPage(html, css, js, title) {
    if (html && (html.includes('<head>') || html.includes('<body>'))) {
        if (css && html.includes('</head>')) {
            html = html.replace('</head>', '<style>\n' + css + '\n</style>\n</head>');
        } else if (css) {
            html = '<style>\n' + css + '\n</style>\n' + html;
        }
        if (js && html.includes('</body>')) {
            html = html.replace('</body>', '<script>\n' + js + '\n<\/script>\n</body>');
        } else if (js) {
            html += '\n<script>\n' + js + '\n<\/script>';
        }
        return html;
    }

    return '<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>'
        + title + '</title>\n'
        + (css ? '<style>\n' + css + '\n</style>\n' : '')
        + '</head>\n<body>\n'
        + (html || '')
        + (js ? '\n<script>\n' + js + '\n<\/script>' : '')
        + '\n</body>\n</html>';
}

// ── Page Viewer (sandbox iframe) ────────────────────────────────────────────

window.openPageViewer = async function(downloadUrl, fileName) {
    const overlay = document.getElementById('page-viewer-overlay');
    if (!overlay) return;

    const titleEl = document.getElementById('page-viewer-title');
    if (titleEl) titleEl.textContent = fileName || 'Page';

    const iframe = document.getElementById('page-viewer-iframe');
    if (!iframe) return;

    try {
        const resp = await fetch(downloadUrl, { credentials: 'include' });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        let data = await resp.arrayBuffer();

        const roomKey = getRoomKey(window.AppState?.currentRoom?.id);
        if (roomKey && data.byteLength > 12) {
            try {
                const { decryptFile } = await import('../crypto.js');
                data = await decryptFile(data, roomKey);
            } catch {}
        }

        iframe.srcdoc = new TextDecoder().decode(data);
    } catch (e) {
        iframe.srcdoc = '<body style="font-family:sans-serif;padding:20px;color:#999;"><h2>Error</h2><p>' + e.message + '</p></body>';
    }

    overlay.style.display = 'flex';
};

window.closePageViewer = function() {
    const overlay = document.getElementById('page-viewer-overlay');
    if (overlay) {
        overlay.style.display = 'none';
        const iframe = document.getElementById('page-viewer-iframe');
        if (iframe) iframe.srcdoc = '';
    }
};

window.openPageBuilder = openPageBuilder;

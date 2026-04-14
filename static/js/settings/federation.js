// ══════════════════════════════════════════════════════════════════════════════
// Federation Settings — управление федеративными узлами
// ══════════════════════════════════════════════════════════════════════════════

import { $, api } from '../utils.js';
import { t } from '../i18n.js';

let _refreshInterval = null;

const STATUS_COLORS = {
    active:    '#27ae60',
    verified:  '#3498db',
    pending:   '#f39c12',
    suspended: '#e74c3c',
    dead:      '#666',
};

// ════════════════════════════════════════════════════════════════════════════
// Public API
// ════════════════════════════════════════════════════════════════════════════

/**
 * Добавить федеративный узел по URL из поля ввода.
 */
export async function addFederatedNode() {
    const input = $('fed-node-url');
    const statusDiv = $('fed-add-status');
    if (!input) return;

    const url = input.value.trim();
    if (!url) {
        _showStatus(statusDiv, t('federation.enterUrl') || 'Enter server URL', 'red');
        return;
    }
    if (!/^https?:\/\/.+/i.test(url)) {
        _showStatus(statusDiv, t('federation.invalidUrl') || 'URL must start with http:// or https://', 'red');
        return;
    }

    const btn = input.nextElementSibling;
    const origText = btn ? btn.textContent : '';
    try {
        if (btn) {
            btn.disabled = true;
            btn.textContent = t('federation.adding') || 'Adding...';
        }
        const data = await api('POST', '/api/federation/nodes/add', { url });
        _showStatus(statusDiv, data.message || t('federation.nodeAdded') || 'Node added', '#27ae60');
        input.value = '';
        await loadFederatedNodes();
    } catch (e) {
        _showStatus(statusDiv, e.message || t('federation.addError') || 'Failed to add node', 'red');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = origText;
        }
    }
}

/**
 * Загрузить и отобразить список федеративных узлов.
 */
export async function loadFederatedNodes() {
    const container = $('fed-nodes-list');
    if (!container) return;

    try {
        const [nodesData, statusData] = await Promise.all([
            api('GET', '/api/federation/nodes'),
            api('GET', '/api/federation/nodes/status').catch(() => null),
        ]);

        // Очистить контейнер
        while (container.firstChild) container.removeChild(container.firstChild);

        // Сводка по сети
        if (statusData) {
            container.appendChild(_renderNetworkStatus(statusData));
        }

        const nodes = nodesData.nodes || [];
        if (nodes.length === 0) {
            const empty = document.createElement('div');
            empty.style.cssText = 'text-align:center;color:var(--text3);font-size:13px;padding:32px 0;';
            empty.textContent = t('federation.noNodes') || 'No servers connected';
            container.appendChild(empty);
            return;
        }

        for (const node of nodes) {
            container.appendChild(_renderNodeCard(node));
        }
    } catch (e) {
        while (container.firstChild) container.removeChild(container.firstChild);
        const err = document.createElement('div');
        err.style.cssText = 'text-align:center;color:var(--danger,#e74c3c);font-size:13px;padding:24px 0;';
        err.textContent = t('federation.loadError') || 'Failed to load nodes';
        container.appendChild(err);
    }
}

/**
 * Удалить федеративный узел после подтверждения.
 */
export async function removeFederatedNode(nodeId) {
    const msg = t('federation.confirmRemove') || 'Remove this node from federation?';
    if (!confirm(msg)) return;

    try {
        await api('DELETE', '/api/federation/nodes/' + nodeId);
        await loadFederatedNodes();
    } catch (e) {
        alert((t('federation.removeError') || 'Failed to remove node') + ': ' + (e.message || e));
    }
}

/**
 * Запустить ручную верификацию узла.
 */
export async function verifyFederatedNode(nodeId) {
    try {
        const data = await api('POST', '/api/federation/nodes/verify', { node_id: nodeId });
        const msg = data.verified
            ? (t('federation.verified') || 'Node verified successfully')
            : (t('federation.verifyFailed') || 'Verification failed');
        alert(msg);
        await loadFederatedNodes();
    } catch (e) {
        alert((t('federation.verifyError') || 'Verification error') + ': ' + (e.message || e));
    }
}

/**
 * Инициализировать секцию Federation в настройках.
 * Загружает список узлов и запускает авто-обновление.
 */
export function initFederationSettings() {
    cleanupFederationSettings();
    loadFederatedNodes();
    _refreshInterval = setInterval(() => {
        // Обновлять только если контейнер всё ещё в DOM
        if ($('fed-nodes-list')) {
            loadFederatedNodes();
        } else {
            cleanupFederationSettings();
        }
    }, 30000);
}

/**
 * Остановить авто-обновление при уходе из секции.
 */
export function cleanupFederationSettings() {
    if (_refreshInterval) {
        clearInterval(_refreshInterval);
        _refreshInterval = null;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Internal helpers
// ════════════════════════════════════════════════════════════════════════════

function _showStatus(el, text, color) {
    if (!el) return;
    el.textContent = text;
    el.style.color = color;
    el.style.display = '';
    setTimeout(() => {
        if (el.textContent === text) {
            el.style.display = 'none';
        }
    }, 5000);
}

function _statusColor(status) {
    return STATUS_COLORS[status] || STATUS_COLORS.dead;
}

function _statusLabel(status) {
    const labels = {
        active: t('federation.statusActive') || 'ACTIVE',
        verified: t('federation.statusVerified') || 'VERIFIED',
        pending: t('federation.statusPending') || 'PENDING',
        suspended: t('federation.statusSuspended') || 'SUSPENDED',
        dead: t('federation.statusDead') || 'OFFLINE',
    };
    return labels[status] || (status || 'unknown').toUpperCase();
}

/**
 * Форматирует ISO-дату в «N ago» вид.
 */
function _timeAgo(isoDate) {
    if (!isoDate) return t('federation.never') || 'never';
    const diff = Date.now() - new Date(isoDate).getTime();
    if (diff < 0) return t('federation.justNow') || 'just now';
    const sec = Math.floor(diff / 1000);
    if (sec < 60) return t('federation.justNow') || 'just now';
    const min = Math.floor(sec / 60);
    if (min < 60) return min + (t('federation.minAgo') || 'min ago');
    const hr = Math.floor(min / 60);
    if (hr < 24) return hr + (t('federation.hrAgo') || 'h ago');
    const days = Math.floor(hr / 24);
    return days + (t('federation.dayAgo') || 'd ago');
}

/**
 * Создаёт DOM-элемент полоски доверия (trust bar).
 */
function _createTrustBar(score) {
    const val = Math.max(0, Math.min(100, score || 0));
    let barColor;
    if (val < 30) barColor = '#e74c3c';
    else if (val < 60) barColor = '#f39c12';
    else barColor = '#27ae60';

    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'display:flex;align-items:center;gap:8px;margin:6px 0;';

    const label = document.createElement('span');
    label.style.cssText = 'font-size:11px;color:var(--text3);min-width:36px;';
    label.textContent = (t('federation.trust') || 'Trust') + ':';

    const track = document.createElement('div');
    track.style.cssText = 'flex:1;height:6px;background:var(--bg2,#2a2a2a);border-radius:3px;overflow:hidden;';

    const fill = document.createElement('div');
    fill.style.cssText = 'height:100%;border-radius:3px;transition:width .3s;'
        + 'width:' + val + '%;background:' + barColor + ';';

    track.appendChild(fill);

    const num = document.createElement('span');
    num.style.cssText = 'font-size:11px;color:var(--text2);min-width:40px;text-align:right;';
    num.textContent = val + '/100';

    wrapper.appendChild(label);
    wrapper.appendChild(track);
    wrapper.appendChild(num);
    return wrapper;
}

/**
 * Рендерит сводку по состоянию сети.
 */
function _renderNetworkStatus(status) {
    const bar = document.createElement('div');
    bar.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;align-items:center;'
        + 'padding:10px 14px;margin-bottom:12px;border-radius:8px;'
        + 'background:var(--bg3,#1e1e1e);font-size:12px;color:var(--text2);';

    const items = [
        { label: t('federation.total') || 'Nodes', value: status.total ?? '—' },
        { label: t('federation.active') || 'Active', value: status.active ?? '—' },
        { label: t('federation.avgTrust') || 'Avg trust', value: status.avg_trust != null ? Math.round(status.avg_trust) : '—' },
        { label: t('federation.health') || 'Health', value: status.network_health || '—' },
    ];

    for (const item of items) {
        const span = document.createElement('span');
        const lbl = document.createElement('span');
        lbl.style.color = 'var(--text3)';
        lbl.textContent = item.label + ': ';
        const val = document.createElement('span');
        val.style.fontWeight = '600';
        val.textContent = item.value;
        span.appendChild(lbl);
        span.appendChild(val);
        bar.appendChild(span);

        // Разделитель
        if (item !== items[items.length - 1]) {
            const sep = document.createElement('span');
            sep.style.color = 'var(--border,#444)';
            sep.textContent = '|';
            bar.appendChild(sep);
        }
    }
    return bar;
}

/**
 * Рендерит карточку узла через DOM API (без innerHTML).
 */
function _renderNodeCard(node) {
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--bg3,#1e1e1e);border-radius:10px;padding:14px;margin-bottom:10px;'
        + 'border:1px solid var(--border,#333);';

    // ── Header: имя + статус ──
    const header = document.createElement('div');
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;';

    const nameWrap = document.createElement('div');
    nameWrap.style.cssText = 'display:flex;align-items:center;gap:6px;';

    const icon = document.createElement('span');
    icon.textContent = '\uD83C\uDF10';
    icon.style.fontSize = '16px';

    const name = document.createElement('span');
    name.style.cssText = 'font-weight:700;font-size:14px;color:var(--text);';
    name.textContent = node.name || _shortenUrl(node.url);

    nameWrap.appendChild(icon);
    nameWrap.appendChild(name);

    const badge = document.createElement('span');
    const statusStr = node.status || 'dead';
    const sColor = _statusColor(statusStr);
    badge.style.cssText = 'font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:.5px;'
        + 'color:#fff;background:' + sColor + ';';
    badge.textContent = _statusLabel(statusStr);

    header.appendChild(nameWrap);
    header.appendChild(badge);
    card.appendChild(header);

    // ── URL ──
    const urlLine = document.createElement('div');
    urlLine.style.cssText = 'font-size:12px;color:var(--text3);margin-top:4px;font-family:var(--mono,monospace);'
        + 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
    urlLine.textContent = node.url || '';
    card.appendChild(urlLine);

    // ── Trust bar ──
    card.appendChild(_createTrustBar(node.trust_score));

    // ── Info row ──
    const info = document.createElement('div');
    info.style.cssText = 'display:flex;flex-wrap:wrap;gap:10px;font-size:11px;color:var(--text3);margin-top:2px;';

    if (node.version) {
        const ver = document.createElement('span');
        ver.textContent = (t('federation.version') || 'Version') + ': ' + node.version;
        info.appendChild(ver);
    }

    const lastSeen = document.createElement('span');
    lastSeen.textContent = (t('federation.lastSeen') || 'Last') + ': ' + _timeAgo(node.last_seen);
    info.appendChild(lastSeen);

    if (node.task_slots && node.task_slots.length) {
        const tasks = document.createElement('span');
        tasks.textContent = (t('federation.tasks') || 'Tasks') + ': ' + node.task_slots.join(', ');
        info.appendChild(tasks);
    }

    card.appendChild(info);

    // ── Token info (если есть) ──
    if (node.token_valid != null) {
        const tokenLine = document.createElement('div');
        tokenLine.style.cssText = 'font-size:11px;margin-top:6px;color:var(--text3);';
        const check = node.token_valid ? '\u2713' : '\u2717';
        const color = node.token_valid ? '#27ae60' : '#e74c3c';
        const tokenIcon = document.createElement('span');
        tokenIcon.style.color = color;
        tokenIcon.textContent = check + ' ';
        const tokenText = document.createElement('span');
        tokenText.textContent = 'Token: ' + (node.token_valid
            ? (t('federation.tokenValid') || 'Valid')
                + (node.token_expires ? ' (' + (t('federation.expires') || 'expires') + ' ' + _timeAgo(node.token_expires) + ')' : '')
            : (t('federation.tokenInvalid') || 'Invalid'));
        tokenLine.appendChild(tokenIcon);
        tokenLine.appendChild(tokenText);
        card.appendChild(tokenLine);
    }

    // ── Action buttons ──
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:8px;margin-top:10px;padding-top:10px;border-top:1px solid var(--border,#333);';

    const verifyBtn = document.createElement('button');
    verifyBtn.className = 'btn btn-secondary';
    verifyBtn.style.cssText = 'font-size:11px;padding:4px 12px;';
    verifyBtn.textContent = t('federation.verify') || 'Verify';
    verifyBtn.addEventListener('click', () => verifyFederatedNode(node.id));

    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn btn-secondary';
    removeBtn.style.cssText = 'font-size:11px;padding:4px 12px;color:var(--danger,#e74c3c);';
    removeBtn.textContent = t('federation.remove') || 'Remove';
    removeBtn.addEventListener('click', () => removeFederatedNode(node.id));

    actions.appendChild(verifyBtn);
    actions.appendChild(removeBtn);
    card.appendChild(actions);

    return card;
}

/**
 * Сокращает URL до хоста для отображения.
 */
function _shortenUrl(url) {
    if (!url) return 'Unknown';
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

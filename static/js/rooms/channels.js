// static/js/rooms/channels.js — channel autoposting (RSS feeds & webhooks)

import { $, api } from '../utils.js';

// ═══════════════════════════════════════════════════════════════════════════
// Channel Autoposting (RSS feeds & webhooks)
// ═══════════════════════════════════════════════════════════════════════════

window._channelAutopostRoomId = null;

window._channelLoadFeeds = async function(roomId) {
    const listEl = $('channel-feeds-list');
    const webhookEl = $('channel-webhook-url');
    if (!listEl) return;

    try {
        const data = await api('GET', `/api/channels/${roomId}/feeds`);
        const feeds = data.feeds || [];

        // Render feed list
        const rssFeeds = feeds.filter(f => f.feed_type === 'rss');
        if (rssFeeds.length === 0) {
            listEl.innerHTML = '<div style="font-size:12px;color:var(--text-secondary);">Нет активных RSS-лент</div>';
        } else {
            listEl.innerHTML = rssFeeds.map(f => `
                <div style="display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid var(--border);">
                    <span style="flex:1;font-size:12px;word-break:break-all;color:var(--text-primary);">${escapeHtml(f.url)}</span>
                    <span style="font-size:10px;color:var(--text-secondary);">${f.last_fetched ? new Date(f.last_fetched).toLocaleString() : 'не получено'}</span>
                    <button class="btn btn-danger" style="padding:2px 8px;font-size:11px;" onclick="window._channelDeleteFeed(${roomId},${f.id})">✕</button>
                </div>
            `).join('');
        }

        // Render webhook URL
        const webhookFeed = feeds.find(f => f.feed_type === 'webhook' && f.is_active);
        if (webhookFeed && webhookEl) {
            const base = window.location.origin;
            webhookEl.textContent = `${base}/api/channels/${roomId}/webhook?secret=${webhookFeed.url}`;
            webhookEl.dataset.secret = webhookFeed.url;
        } else if (webhookEl) {
            webhookEl.textContent = '— нет активного webhook';
            webhookEl.dataset.secret = '';
        }
    } catch(e) {
        if (listEl) listEl.innerHTML = `<div style="color:var(--red);font-size:12px;">${e.message}</div>`;
    }
};

window._channelAddRss = async function() {
    const roomId = window._channelAutopostRoomId;
    if (!roomId) return;
    const input = $('channel-rss-url-input');
    const url = input ? input.value.trim() : '';
    if (!url) { alert('Введите URL RSS-ленты'); return; }
    try {
        await api('POST', `/api/channels/${roomId}/feeds`, { type: 'rss', url });
        if (input) input.value = '';
        await window._channelLoadFeeds(roomId);
    } catch(e) {
        alert(e.message || 'Ошибка при добавлении RSS');
    }
};

window._channelDeleteFeed = async function(roomId, feedId) {
    if (!confirm('Удалить эту RSS-ленту?')) return;
    try {
        await api('DELETE', `/api/channels/${roomId}/feeds/${feedId}`);
        await window._channelLoadFeeds(roomId);
    } catch(e) {
        alert(e.message || 'Ошибка при удалении');
    }
};

window._channelCreateWebhook = async function() {
    const roomId = window._channelAutopostRoomId;
    if (!roomId) return;
    try {
        await api('POST', `/api/channels/${roomId}/feeds`, { type: 'webhook', url: '' });
        await window._channelLoadFeeds(roomId);
    } catch(e) {
        alert(e.message || 'Ошибка при создании webhook');
    }
};

window._channelCopyWebhook = function() {
    const el = $('channel-webhook-url');
    if (!el || !el.textContent || el.textContent === '—') return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        const orig = el.style.color;
        el.style.color = 'var(--green)';
        setTimeout(() => el.style.color = orig, 1000);
    });
};

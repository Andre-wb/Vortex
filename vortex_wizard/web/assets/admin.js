/* Vortex Admin Dashboard — local-only SPA
 *
 * Polls /api/wiz/admin/* every 5s. Zero outbound traffic. Every DOM write
 * uses safe DOM methods (createElement / textContent) — no innerHTML on
 * anything that came from an API.
 */

(() => {
    'use strict';

    const POLL_INTERVAL_MS = 5000;

    const $ = sel => document.querySelector(sel);

    // ── DOM helpers ────────────────────────────────────────────────────
    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

    function td(text, className) {
        const el = document.createElement('td');
        if (className) el.className = className;
        el.textContent = text ?? '';
        return el;
    }

    function toast(msg) {
        const t = $('#toast');
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 1800);
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            toast('Copied');
        } catch {
            const ta = document.createElement('textarea');
            ta.value = text; document.body.appendChild(ta); ta.select();
            document.execCommand('copy'); ta.remove(); toast('Copied');
        }
    }

    // ── Tab switching ──────────────────────────────────────────────────
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b === btn));
            document.querySelectorAll('.panel').forEach(p => {
                p.classList.toggle('active', p.id === 'panel-' + tab);
            });
            if (tab === 'logs') loadLogs();
            if (tab === 'earnings') loadEarnings();
        });
    });

    // Generic [data-copy="#selector"] handler for copy buttons (used by the
    // Earnings panel wallet address button, among others).
    document.querySelectorAll('[data-copy]').forEach(btn => {
        btn.addEventListener('click', () => {
            const sel = btn.getAttribute('data-copy');
            const target = sel ? document.querySelector(sel) : null;
            const text = (target && target.textContent || '').trim();
            if (text && text !== '—') copyText(text);
        });
    });

    // ── 1. Integrity ──────────────────────────────────────────────────
    async function loadIntegrity() {
        try {
            const r = await fetch('/api/wiz/admin/reverify', { method: 'POST' });
            const d = await r.json();
            renderIntegrity(d);
        } catch (e) {
            renderIntegrity({ status: 'unknown', message: 'Not available' });
        }
    }

    function renderIntegrity(d) {
        const badge = $('#integrity-badge');
        const badgeClasses = { verified: 'ok', tampered: 'err', bad_signature: 'err',
            wrong_key: 'err', no_manifest: 'warn', unknown: 'warn' };
        badge.className = 'card-badge ' + (badgeClasses[d.status] || 'warn');
        badge.textContent = d.status || '?';

        $('#integrity-matched').textContent = d.matched ?? '—';
        $('#integrity-message').textContent = d.message ?? '';
        $('#integrity-signed-by').textContent = (d.signed_by || '—').slice(0, 32) +
            (d.signed_by && d.signed_by.length > 32 ? '…' : '');
        $('#integrity-version').textContent = d.version ?? '—';
        $('#integrity-built-at').textContent = d.built_at
            ? new Date(d.built_at * 1000).toLocaleString() : '—';
        $('#integrity-mismatched').textContent =
            (d.mismatched?.length || 0) + (d.missing?.length ? ' + ' + d.missing.length + ' missing' : '');

        const diffCard = $('#integrity-diff');
        const diffList = $('#integrity-diff-list');
        clear(diffList);
        const all = [...(d.mismatched || []), ...(d.missing || []).map(p => '[MISSING] ' + p)];
        if (all.length) {
            diffCard.style.display = '';
            all.forEach(p => {
                const li = document.createElement('li');
                li.textContent = p;
                diffList.appendChild(li);
            });
        } else {
            diffCard.style.display = 'none';
        }
    }

    // ── 2. Identity ───────────────────────────────────────────────────
    async function loadIdentity() {
        const [id, ov] = await Promise.all([
            fetch('/api/wiz/admin/identity').then(r => r.json()),
            fetch('/api/wiz/admin/overview').then(r => r.json()),
        ]);
        $('#identity-pubkey').textContent = id.pubkey || id.message || '—';
        $('#identity-device').textContent = ov.device_name || '—';
        $('#identity-mode').textContent = ov.network_mode || '—';
        $('#identity-registered').textContent = ov.running ? 'Yes' : 'No';
        // On-chain seal — from migration-hint metadata if available
        const hint = ov.migration_hint || {};
        const selfPub = (hint.node?.pubkey || '').toLowerCase();
        // The node itself reports own metadata via the cursor; seal info is
        // fetched from the Solana registry when configured. Display best-effort.
        $('#identity-sealed').textContent = '—';
        $('#identity-code-hash').textContent = '—';
        $('#identity-checkin').textContent = '—';
    }

    // ── 3. Controller ─────────────────────────────────────────────────
    async function loadController() {
        const ov = await fetch('/api/wiz/admin/overview').then(r => r.json());
        $('#ctrl-url').textContent = ov.controller_url || '—';
        $('#ctrl-pubkey').textContent = ov.controller_pubkey || '—';
        $('#ctrl-last-sig').textContent = ov.running ? 'just now' : '—';
        $('#ctrl-sns').textContent = ov.controller_url ? 'check manually' : '—';

        const fb = $('#ctrl-fallbacks');
        clear(fb);
        const env = await fetch('/api/wiz/admin/env').then(r => r.json());
        const raw = env.CONTROLLER_FALLBACK_URLS || '';
        const items = raw.split(',').map(s => s.trim()).filter(Boolean);
        if (!items.length) {
            const p = document.createElement('span');
            p.className = 'card-desc';
            p.textContent = 'None configured';
            fb.appendChild(p);
        } else {
            items.forEach(u => {
                const r = document.createElement('div');
                r.className = 'card-row';
                const s = document.createElement('span');
                s.textContent = u;
                const tag = document.createElement('span');
                tag.className = 'verify-tag ctrl';
                tag.textContent = 'configured';
                r.appendChild(s); r.appendChild(tag);
                fb.appendChild(r);
            });
        }
    }

    // ── 4. Peers ──────────────────────────────────────────────────────
    async function loadPeers() {
        const d = await fetch('/api/wiz/admin/peers').then(r => r.json());
        const tbody = $('#peers-tbody');
        clear(tbody);
        const peers = d.peers || [];
        $('#peers-count').textContent = peers.length + ' peer' + (peers.length === 1 ? '' : 's');
        if (!peers.length) {
            const row = document.createElement('tr');
            const cell = td('No peers visible', 'empty');
            cell.colSpan = 5;
            row.appendChild(cell);
            tbody.appendChild(row);
            return;
        }
        peers.forEach(p => {
            const tr = document.createElement('tr');
            tr.appendChild(td((p.pubkey || '').slice(0, 16) + '…'));
            tr.appendChild(td(p.verification || 'unknown'));
            const vtd = document.createElement('td');
            const tag = document.createElement('span');
            const vtype = (p.metadata?.sealed || p.verification === 'solana+controller')
                ? 'solana' : 'ctrl';
            tag.className = 'verify-tag ' + vtype;
            tag.textContent = vtype === 'solana' ? '✓✓ dual' : '✓ ctrl';
            vtd.appendChild(tag);
            tr.appendChild(vtd);
            tr.appendChild(td((p.weight ?? 1.0).toFixed(2)));
            const age = p.last_seen ? Math.round((Date.now() / 1000 - p.last_seen) / 60) : '—';
            tr.appendChild(td(typeof age === 'number' ? age + ' min ago' : age));
            tbody.appendChild(tr);
        });
    }

    // ── 5. Traffic ────────────────────────────────────────────────────
    async function loadTraffic() {
        const d = await fetch('/api/wiz/admin/traffic').then(r => r.json());
        $('#traffic-ws').textContent = d.ws_active ?? 0;
        $('#traffic-rooms').textContent = d.rooms_active ?? 0;
        $('#traffic-mem').textContent = (d.memory_mb ?? 0) + ' MB';
        $('#traffic-cpu').textContent = (d.cpu_seconds ?? 0).toFixed(1) + ' s';
    }

    // ── 6. Certs & Keys ───────────────────────────────────────────────
    async function loadCerts() {
        const d = await fetch('/api/wiz/admin/certs').then(r => r.json());
        const ssl = d.ssl || {};
        $('#cert-subject').textContent = ssl.subject || '—';
        $('#cert-expiry').textContent = ssl.not_after
            ? new Date(ssl.not_after * 1000).toLocaleString() : '—';
        $('#cert-days').textContent = ssl.days_left != null ? ssl.days_left + ' days' : '—';
        $('#keys-jwt-age').textContent = d.jwt_secret_age_days != null
            ? d.jwt_secret_age_days + ' days' : '—';
        $('#keys-csrf-age').textContent = d.csrf_secret_age_days != null
            ? d.csrf_secret_age_days + ' days' : '—';
    }

    // ── 7. Logs ───────────────────────────────────────────────────────
    async function loadLogs() {
        const level = $('#logs-filter').value;
        const d = await fetch('/api/wiz/admin/logs?level=' + encodeURIComponent(level)).then(r => r.json());
        const out = $('#logs-output');
        out.textContent = (d.lines || []).join('\n') || '(no logs available)';
        out.scrollTop = out.scrollHeight;
    }

    // ── Node status (footer) ──────────────────────────────────────────
    async function loadNodeStatus() {
        try {
            const d = await fetch('/api/wiz/admin/check-node').then(r => r.json());
            $('#node-dot').className = 'status-dot ' + (d.running ? 'ok' : 'err');
            $('#node-status').textContent = d.running ? 'node online' : 'node offline';
            $('#node-version').textContent = d.url || '';
        } catch {
            $('#node-dot').className = 'status-dot err';
            $('#node-status').textContent = 'error';
        }
    }

    // ── Earnings ──────────────────────────────────────────────────────
    async function loadEarnings() {
        try {
            const r = await fetch('/api/wiz/admin/earnings');
            const d = await r.json();
            $('#earn-wallet').textContent      = d.wallet_pubkey || '—';
            $('#earn-monthly-sol').textContent = (d.estimated?.monthly_sol ?? 0);
            $('#earn-monthly-usd').textContent = (d.estimated?.monthly_usd ?? 0).toLocaleString();
            $('#earn-uptime').textContent      = d.uptime_pct ?? '—';
            $('#earn-users').textContent       = d.users_served ?? '—';
            $('#earn-stake').textContent       = d.stake_sol ?? 0;
            $('#earn-regfee').textContent      = d.register_fee_paid ? '✓ paid' : '— not yet';
            if (d.note) {
                $('#earn-note-text').textContent = d.note;
                $('#earn-note').style.display = '';
            }
        } catch (e) {
            $('#earn-wallet').textContent = 'error loading';
        }
    }

    // ── Bind actions ──────────────────────────────────────────────────
    $('#btn-reverify').addEventListener('click', loadIntegrity);
    $('#btn-copy-pubkey').addEventListener('click', () => {
        const t = $('#identity-pubkey').textContent || '';
        if (t && t !== '—') copyText(t);
    });
    $('#btn-refresh-logs').addEventListener('click', loadLogs);
    $('#logs-filter').addEventListener('change', loadLogs);
    $('#btn-copy-logs').addEventListener('click', () => {
        copyText($('#logs-output').textContent || '');
    });

    // ── Initial + polling ─────────────────────────────────────────────
    async function refreshAll() {
        try {
            await Promise.all([
                loadIdentity(),
                loadController(),
                loadPeers(),
                loadTraffic(),
                loadCerts(),
                loadNodeStatus(),
            ]);
        } catch (e) {
            console.warn('refresh failed:', e);
        }
    }

    (async () => {
        await loadIntegrity();
        await refreshAll();
        setInterval(refreshAll, POLL_INTERVAL_MS);
    })();
})();

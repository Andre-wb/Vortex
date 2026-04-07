// ── Helpers ─────────────────────────────────────────────────────────────────
// ── Helpers ───────────────────────────────────────────────────
function _esc(s) { const d = document.createElement('div'); d.textContent = s||''; return d.innerHTML; }
function _relTime(ts) {
    const diff = Date.now() - ts;
    if (diff < 60000)  return 'just now';
    if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
    return Math.floor(diff/86400000) + 'd ago';
}

// ── Shared modal helpers ─────────────────────────────────────────────────────
// ── Shared modal helpers ──────────────────────────────────────

function _ideShowModal(id, innerHTML) {
    let overlay = document.getElementById(id + '-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = id + '-overlay';
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:2000;';
        overlay.onclick = e => { if (e.target === overlay) _ideCloseModal(id); };
        document.body.appendChild(overlay);
    }
    let modal = document.getElementById(id);
    if (!modal) {
        modal = document.createElement('div');
        modal.id = id;
        modal.style.cssText = 'background:var(--bg2,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:20px;min-width:360px;max-width:90vw;max-height:80vh;overflow:auto;box-shadow:0 16px 48px rgba(0,0,0,.5);';
        overlay.appendChild(modal);
    }
    modal.innerHTML = innerHTML;
    overlay.style.display = 'flex';
}

function _ideCloseModal(id) {
    const overlay = document.getElementById(id + '-overlay');
    if (overlay) overlay.style.display = 'none';
}

/**
 * AI Text Assistant — Qwen3-8B powered text fix & rephrase.
 * Button next to msg-input with dropdown menu.
 */

function _initAiText() {
  'use strict';

  const btn   = document.getElementById('ai-text-btn');
  const menu  = document.getElementById('ai-text-menu');
  const input = document.getElementById('msg-input');
  if (!btn || !menu || !input) return;
  if (btn._aiInited) return;
  btn._aiInited = true;

  // Move menu to body to escape any overflow:hidden containers
  document.body.appendChild(menu);

  let _busy = false;

  /* ── Toggle menu ───────────────────────────────────────────── */
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (_busy) return;
    menu.classList.toggle('open');
    if (menu.classList.contains('open')) positionMenu();
  });

  function positionMenu() {
    if (!menu.classList.contains('open')) return;
    const vw = window.innerWidth;

    if (vw <= 600) {
      // Mobile: bottom sheet
      menu.classList.add('mobile');
      menu.style.left = '0';
      menu.style.right = '0';
      menu.style.bottom = '0';
      menu.style.top = 'auto';
    } else {
      // Desktop: above button
      menu.classList.remove('mobile');
      const r = btn.getBoundingClientRect();
      const menuW = menu.offsetWidth || 220;
      let left = r.left + r.width / 2 - menuW / 2;
      // Keep within viewport
      if (left < 8) left = 8;
      if (left + menuW > vw - 8) left = vw - 8 - menuW;
      menu.style.left = left + 'px';
      menu.style.bottom = (window.innerHeight - r.top + 8) + 'px';
      menu.style.top = 'auto';
      menu.style.right = 'auto';
    }
  }

  /* ── Close on outside click ──────────────────────────────── */
  document.addEventListener('click', (e) => {
    if (!menu.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {
      menu.classList.remove('open');
    }
  });

  /* ── Menu item handlers ──────────────────────────────────── */
  menu.querySelectorAll('.ai-text-menu-item').forEach((item) => {
    item.addEventListener('click', async () => {
      const action = item.dataset.action;
      const style  = item.dataset.style;
      const text   = input.value.trim();
      if (_busy) return;
      if (!text) {
        menu.classList.remove('open');
        window.showToast?.(t('ai.enterText'));
        return;
      }

      menu.classList.remove('open');
      _setBusy(true);

      try {
        let result;
        if (action === 'fix') {
          result = await apiFix(text);
        } else if (action === 'rephrase' && style) {
          result = await apiRephrase(text, style);
        }
        if (result) {
          showPreview(text, result);
        }
      } catch (err) {
        const msg = err?.message || String(err);
        window.showToast?.(t('errors.aiError') + ': ' + msg) || alert(t('errors.aiError') + ': ' + msg);
      } finally {
        _setBusy(false);
      }
    });
  });

  /* ── Busy state ──────────────────────────────────────────── */
  function _setBusy(v) {
    _busy = v;
    btn.classList.toggle('ai-loading', v);
    if (v) {
      btn.setAttribute('aria-busy', 'true');
    } else {
      btn.removeAttribute('aria-busy');
    }
  }

  /* ── API calls ───────────────────────────────────────────── */
  async function _aiRequest(url, body) {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    });
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = {}; }
    if (!resp.ok) {
      throw new Error(data.detail || `${resp.status}: ${resp.statusText}`);
    }
    return data.result;
  }

  function apiFix(text) {
    return _aiRequest('/api/ai/fix-text', { text });
  }

  function apiRephrase(text, style) {
    return _aiRequest('/api/ai/rephrase', { text, style });
  }

  /* ── Preview overlay ─────────────────────────────────────── */
  function showPreview(original, result) {
    // Remove existing preview
    document.getElementById('ai-preview')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'ai-preview';
    overlay.className = 'ai-preview';

    const card = document.createElement('div');
    card.className = 'ai-preview-card';

    // Header
    const header = document.createElement('div');
    header.className = 'ai-preview-header';
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('width', '18');
    icon.setAttribute('height', '18');
    icon.setAttribute('fill', 'currentColor');
    icon.setAttribute('viewBox', '0 0 24 24');
    const iconPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    iconPath.setAttribute('d', 'M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1.5a.5.5 0 0 1 0 1H21v1a7 7 0 0 1-7 7H10a7 7 0 0 1-7-7v-1H1.5a.5.5 0 0 1 0-1H3a7 7 0 0 1 7-7h1V5.73A2 2 0 0 1 12 2zm-2 7a5 5 0 0 0-5 5v1a5 5 0 0 0 5 5h4a5 5 0 0 0 5-5v-1a5 5 0 0 0-5-5h-4z');
    icon.appendChild(iconPath);
    header.appendChild(icon);
    const headerText = document.createElement('span');
    headerText.setAttribute('data-i18n', 'ai.result');
    headerText.textContent = t('ai.result');
    header.appendChild(headerText);

    // Text content (safe textContent)
    const textEl = document.createElement('div');
    textEl.className = 'ai-preview-text';
    textEl.textContent = result;

    // Action buttons
    const actions = document.createElement('div');
    actions.className = 'ai-preview-actions';

    const acceptBtn = document.createElement('button');
    acceptBtn.className = 'ai-preview-btn accept';
    acceptBtn.setAttribute('data-i18n', 'ai.accept');
    acceptBtn.textContent = t('ai.accept');

    const discardBtn = document.createElement('button');
    discardBtn.className = 'ai-preview-btn discard';
    discardBtn.setAttribute('data-i18n', 'ai.discard');
    discardBtn.textContent = t('ai.discard');

    actions.appendChild(acceptBtn);
    actions.appendChild(discardBtn);

    card.appendChild(header);
    card.appendChild(textEl);
    card.appendChild(actions);
    overlay.appendChild(card);

    // Insert above input-area
    const inputArea = document.getElementById('input-area');
    inputArea.parentNode.insertBefore(overlay, inputArea);

    acceptBtn.addEventListener('click', () => {
      input.value = result;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.style.height = 'auto';
      input.style.height = input.scrollHeight + 'px';
      overlay.remove();
    });

    discardBtn.addEventListener('click', () => {
      overlay.remove();
    });

    // Apply i18n if available
    if (typeof applyI18nTo === 'function') {
      applyI18nTo(overlay);
    }
  }
}

// Init on DOMContentLoaded + expose for SPA re-init
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _initAiText);
} else {
  _initAiText();
}
window._initAiText = _initAiText;

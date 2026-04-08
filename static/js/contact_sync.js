/**
 * static/js/contact_sync.js
 * ============================================================================
 * Синхронизация контактов с устройства.
 *
 * Использует Contact Picker API (Android Chrome 80+) или fallback
 * через input type=file для vCard (.vcf).
 * Номера хешируются SHA-256 на клиенте перед отправкой на сервер.
 * ============================================================================
 */

import { $, api } from './utils.js';
import { t }      from './i18n.js';

/* ── state ─────────────────────────────────────────────────────────────────── */
let _syncMatches   = [];
let _selectedIds   = new Set();
let _syncInProgress = false;

/* ── helpers ───────────────────────────────────────────────────────────────── */

function _normalizePhone(raw) {
    return raw.replace(/[^\d+]/g, '').trim();
}

async function _sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function _hashPhones(phones) {
    const unique = [...new Set(phones.map(_normalizePhone).filter(p => p.length >= 7))];
    return Promise.all(unique.map(p => _sha256(p)));
}

function _parsePhonesFromVcf(text) {
    const phones = [];
    const re = /TEL[^:]*:([^\r\n]+)/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
        const num = m[1].trim();
        if (num) phones.push(num);
    }
    return phones;
}

/* ── Contact Picker API ───────────────────────────────────────────────────── */

function _hasContactPicker() {
    return 'contacts' in navigator && 'ContactsManager' in window;
}

async function _pickContactsFromDevice() {
    if (!_hasContactPicker()) return null;
    try {
        const contacts = await navigator.contacts.select(['tel'], { multiple: true });
        const phones = [];
        for (const c of contacts) {
            if (c.tel) {
                for (const num of c.tel) phones.push(num);
            }
        }
        return phones;
    } catch (e) {
        console.warn('Contact Picker API error:', e);
        return null;
    }
}

/* ── vCard fallback ───────────────────────────────────────────────────────── */

function _pickVcfFile() {
    return new Promise(resolve => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.vcf,text/vcard';
        input.onchange = async () => {
            if (!input.files || !input.files.length) { resolve(null); return; }
            const text = await input.files[0].text();
            resolve(_parsePhonesFromVcf(text));
        };
        input.click();
    });
}

/* ── UI ───────────────────────────────────────────────────────────────────── */

function _show(id) { const el = $(id); if (el) el.classList.add('show'); }
function _hide(id) { const el = $(id); if (el) el.classList.remove('show'); }

function _renderStep(step) {
    const steps = ['cs-step-welcome', 'cs-step-progress', 'cs-step-results', 'cs-step-done'];
    steps.forEach(s => { const el = $(s); if (el) el.style.display = 'none'; });
    const target = $(step);
    if (target) target.style.display = '';
}

function _esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}

function _renderMatchList() {
    const list = $('cs-match-list');
    if (!list) return;

    if (_syncMatches.length === 0) {
        list.innerHTML = '<div class="cs-empty">' + t('contactSync.noMatches') + '</div>';
        const addAllBtn = $('cs-add-all-btn');
        if (addAllBtn) addAllBtn.style.display = 'none';
        return;
    }

    const addAllBtn = $('cs-add-all-btn');
    if (addAllBtn) addAllBtn.style.display = '';

    _selectedIds = new Set(_syncMatches.map(m => m.user_id));

    list.innerHTML = _syncMatches.map(m => {
        const av = m.avatar_url
            ? '<img src="' + _esc(m.avatar_url) + '" class="cs-avatar-img">'
            : '<span class="cs-avatar-emoji">' + (m.avatar_emoji || '\u{1F464}') + '</span>';
        return '<label class="cs-match-row" data-uid="' + m.user_id + '">'
            + '<input type="checkbox" checked onchange="toggleSyncContact(' + m.user_id + ', this.checked)">'
            + '<div class="cs-match-avatar">' + av + '</div>'
            + '<div class="cs-match-info">'
            +   '<div class="cs-match-name">' + _esc(m.display_name) + '</div>'
            +   '<div class="cs-match-username">@' + _esc(m.username) + '</div>'
            + '</div>'
            + '</label>';
    }).join('');
}

function _updateCount() {
    const el = $('cs-selected-count');
    if (el) el.textContent = t('contactSync.selectedCount', { n: _selectedIds.size });
}

/* ── Exported ─────────────────────────────────────────────────────────────── */

export function showContactSync() {
    _syncMatches = [];
    _selectedIds.clear();
    _renderStep('cs-step-welcome');
    _show('cs-overlay');
}

export function hideContactSync() {
    _hide('cs-overlay');
}

export function skipContactSync() {
    localStorage.setItem('vortex_contact_sync_skipped', '1');
    hideContactSync();
}

export function toggleSyncContact(userId, checked) {
    if (checked) _selectedIds.add(userId);
    else _selectedIds.delete(userId);
    _updateCount();
}

export async function startContactSync() {
    if (_syncInProgress) return;
    _syncInProgress = true;

    _renderStep('cs-step-progress');
    const statusEl = $('cs-progress-text');

    try {
        if (statusEl) statusEl.textContent = t('contactSync.readingContacts');

        let phones = null;
        if (_hasContactPicker()) {
            phones = await _pickContactsFromDevice();
        }
        if (!phones) {
            if (statusEl) statusEl.textContent = t('contactSync.selectFile');
            phones = await _pickVcfFile();
        }

        if (!phones || phones.length === 0) {
            _renderStep('cs-step-welcome');
            _syncInProgress = false;
            return;
        }

        if (statusEl) statusEl.textContent = t('contactSync.hashing', { n: phones.length });
        const hashes = await _hashPhones(phones);

        if (statusEl) statusEl.textContent = t('contactSync.searching');
        const resp = await api('POST', '/api/contacts/sync', { phone_hashes: hashes });

        _syncMatches = resp.matches || [];

        _renderStep('cs-step-results');
        _renderMatchList();
        _updateCount();

        const statsEl = $('cs-stats');
        if (statsEl) {
            statsEl.textContent = t('contactSync.stats', {
                checked: resp.total_checked,
                found:   _syncMatches.length,
            });
        }

    } catch (e) {
        console.error('Contact sync error:', e);
        _renderStep('cs-step-welcome');
    } finally {
        _syncInProgress = false;
    }
}

export async function addSyncedContacts() {
    if (_selectedIds.size === 0) {
        hideContactSync();
        return;
    }

    const btn = $('cs-add-all-btn');
    if (btn) { btn.disabled = true; btn.textContent = t('contactSync.adding'); }

    try {
        const resp = await api('POST', '/api/contacts/sync/add-all', {
            user_ids: [..._selectedIds],
        });

        _renderStep('cs-step-done');
        const doneText = $('cs-done-text');
        if (doneText) doneText.textContent = t('contactSync.doneCount', { n: resp.added });

        localStorage.setItem('vortex_contact_sync_done', '1');

        if (window.loadContacts) {
            await window.loadContacts();
        }
    } catch (e) {
        console.error('Add synced contacts error:', e);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('contactSync.addAll'); }
    }
}

export function shouldShowContactSync() {
    return !localStorage.getItem('vortex_contact_sync_done')
        && !localStorage.getItem('vortex_contact_sync_skipped');
}

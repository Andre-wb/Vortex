// static/js/user-profile.js
// =============================================================================
// Модуль превью профиля пользователя.
// Открывает боковую панель с фоном профиля, аватаром, статусом, ДР,
// общими медиа и общими группами.
// =============================================================================

import { api } from './utils.js';

const _MONTH_GEN = () => {
    const arr = t('time.monthsGen');
    return Array.isArray(arr) ? arr : ['January','February','March','April','May','June','July','August','September','October','November','December'];
};

/**
 * Открывает модал профиля для userId.
 * Если userId — текущий пользователь, ничего не делает.
 */
export async function openUserProfile(userId) {
    if (!userId) return;
    const S = window.AppState;

    const overlay = document.getElementById('user-profile-modal');
    if (!overlay) return;

    // Show overlay, activate loading skeleton
    overlay.style.display = 'flex';
    requestAnimationFrame(() => overlay.classList.add('upm-visible'));

    const loadingEl = document.getElementById('upm-loading');
    const bodyEl    = document.querySelector('.upm-body');
    if (loadingEl) loadingEl.style.display = 'flex';
    if (bodyEl)    bodyEl.style.opacity = '0';

    // Store userId for fingerprint section
    overlay.dataset.userId = userId;

    try {
        const data = await api('GET', `/api/users/profile/${userId}`);
        _renderUserProfile(data);
        if (bodyEl) bodyEl.style.opacity = '1';
    } catch (e) {
        console.error('[user-profile] load error:', e);
        closeUserProfile();
    } finally {
        if (loadingEl) loadingEl.style.display = 'none';
    }
}

/** Закрывает модал профиля. */
export function closeUserProfile() {
    const overlay = document.getElementById('user-profile-modal');
    if (!overlay) return;
    overlay.classList.remove('upm-visible');
    setTimeout(() => { overlay.style.display = 'none'; }, 240);
}

// =============================================================================
// Рендер данных профиля в DOM
// =============================================================================

function _renderUserProfile(data) {
    const { user, dm_room_id, common_groups, shared_media } = data;

    // ── Hero background ──────────────────────────────────────────────────────
    const hero = document.getElementById('upm-hero');
    if (hero) {
        hero.style.background = user.profile_bg
            || 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)';
    }

    // ── Hero icon (SVG on background) ─────────────────────────────────────────
    const heroIconWrap = document.getElementById('upm-hero-icon');
    const heroSvg      = document.getElementById('upm-hero-svg');
    if (heroIconWrap && heroSvg) {
        const iconPaths = user.profile_icon && window._PROFILE_ICONS
            ? window._PROFILE_ICONS[user.profile_icon]
            : null;
        if (iconPaths) {
            heroSvg.innerHTML      = iconPaths;
            heroIconWrap.style.display = '';
        } else {
            heroIconWrap.style.display = 'none';
        }
    }

    // ── Avatar ───────────────────────────────────────────────────────────────
    const avatarEl = document.getElementById('upm-avatar');
    if (avatarEl) {
        if (user.avatar_url) {
            avatarEl.innerHTML = `<img src="${_esc(user.avatar_url)}"
                style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
        } else {
            avatarEl.textContent = user.avatar_emoji || '👤';
        }
    }

    // ── Presence ring ─────────────────────────────────────────────────────────
    const ring = document.getElementById('upm-presence-ring');
    if (ring) {
        if (user.is_online) {
            ring.style.display = '';
            ring.dataset.presence = user.presence || 'online';
        } else {
            ring.style.display = 'none';
        }
    }

    // ── Name / username ───────────────────────────────────────────────────────
    const nameEl = document.getElementById('upm-name');
    if (nameEl) nameEl.textContent = user.display_name || user.username;

    const usernameEl = document.getElementById('upm-username');
    if (usernameEl) usernameEl.textContent = '@' + user.username;

    // ── Status line ───────────────────────────────────────────────────────────
    const statusLine = document.getElementById('upm-status-line');
    if (statusLine) {
        if (user.custom_status) {
            statusLine.style.display = '';
            statusLine.textContent   = (user.status_emoji ? user.status_emoji + '\u2009' : '') + user.custom_status;
        } else {
            statusLine.style.display = 'none';
        }
    }

    // ── Bio ───────────────────────────────────────────────────────────────────
    const bioEl = document.getElementById('upm-bio');
    if (bioEl) {
        if (user.bio) {
            bioEl.style.display = '';
            bioEl.textContent   = user.bio;
        } else {
            bioEl.style.display = 'none';
        }
    }

    // ── Action buttons ────────────────────────────────────────────────────────
    const writeBtn = document.getElementById('upm-write-btn');
    if (writeBtn) {
        writeBtn.style.display = dm_room_id ? '' : 'none';
        writeBtn.onclick = () => {
            closeUserProfile();
            window.openRoom?.(dm_room_id);
        };
    }
    const callBtn = document.getElementById('upm-call-btn');
    if (callBtn) {
        callBtn.style.display = dm_room_id ? '' : 'none';
        callBtn.onclick = () => {
            closeUserProfile();
            if (dm_room_id) {
                window.openRoom?.(dm_room_id);
                setTimeout(() => window.startCall?.(), 600);
            }
        };
    }

    // ── Birthday ──────────────────────────────────────────────────────────────
    const bdSection = document.getElementById('upm-birthday-section');
    if (bdSection) {
        if (user.birth_date) {
            bdSection.style.display = '';
            const bdVal = document.getElementById('upm-birthday-value');
            if (bdVal) bdVal.textContent = _formatBirthDate(user.birth_date);
        } else {
            bdSection.style.display = 'none';
        }
    }

    // ── Shared media ──────────────────────────────────────────────────────────
    const mediaSection = document.getElementById('upm-media-section');
    if (mediaSection) {
        if (shared_media && shared_media.length > 0) {
            mediaSection.style.display = '';
            const badge = document.getElementById('upm-media-badge');
            if (badge) badge.textContent = shared_media.length > 9 ? '9+' : shared_media.length;

            const grid = document.getElementById('upm-media-grid');
            if (grid) {
                grid.innerHTML = '';
                shared_media.slice(0, 9).forEach(f => {
                    const tile = document.createElement('div');
                    tile.className = 'upm-media-tile';
                    tile.title     = f.file_name || '';
                    tile.onclick   = () => {
                        closeUserProfile();
                        window.openRoom?.(f.room_id);
                    };

                    // Fallback icon
                    const icon = document.createElement('div');
                    icon.className = 'upm-media-icon';
                    icon.innerHTML = `<svg width="22" height="22" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/>
                    </svg>`;
                    tile.appendChild(icon);

                    // Try encrypted image load
                    if (typeof window.loadEncryptedImage === 'function') {
                        window.loadEncryptedImage(f.stored_name, f.room_id).then(url => {
                            if (url) {
                                const img = document.createElement('img');
                                img.src   = url;
                                img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:6px;';
                                icon.remove();
                                tile.prepend(img);
                            }
                        }).catch(() => {});
                    }

                    grid.appendChild(tile);
                });
            }

            const moreBtn = document.getElementById('upm-media-more');
            if (moreBtn) {
                if (dm_room_id) {
                    moreBtn.style.display = '';
                    moreBtn.onclick = () => {
                        closeUserProfile();
                        window.openRoom?.(dm_room_id);
                    };
                } else {
                    moreBtn.style.display = 'none';
                }
            }
        } else {
            mediaSection.style.display = 'none';
        }
    }

    // ── Common groups ─────────────────────────────────────────────────────────
    const groupsSection = document.getElementById('upm-groups-section');
    if (groupsSection) {
        if (common_groups && common_groups.length > 0) {
            groupsSection.style.display = '';
            const badge = document.getElementById('upm-groups-badge');
            if (badge) badge.textContent = common_groups.length;

            const list = document.getElementById('upm-groups-list');
            if (list) {
                list.textContent = '';
                common_groups.forEach(g => {
                    const item = document.createElement('div');
                    item.className = 'upm-group-item';
                    item.onclick   = () => {
                        closeUserProfile();
                        window.openRoom?.(g.id);
                    };

                    const avatar = document.createElement('div');
                    avatar.className = 'upm-group-avatar';
                    avatar.textContent = g.avatar_emoji || '\uD83D\uDCAC';
                    item.appendChild(avatar);

                    const name = document.createElement('span');
                    name.className = 'upm-group-name';
                    name.textContent = g.name;
                    item.appendChild(name);

                    const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                    arrow.setAttribute('class', 'upm-group-arrow');
                    arrow.setAttribute('width', '14');
                    arrow.setAttribute('height', '14');
                    arrow.setAttribute('fill', 'currentColor');
                    arrow.setAttribute('viewBox', '0 0 24 24');
                    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                    path.setAttribute('d', 'M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z');
                    arrow.appendChild(path);
                    item.appendChild(arrow);

                    list.appendChild(item);
                });
            }
        } else {
            groupsSection.style.display = 'none';
        }
    }

    // ── Fingerprint verification ──────────────────────────────────────────────
    const fpSection = document.getElementById('upm-fp-section');
    if (fpSection) {
        if (user.x25519_public_key) {
            fpSection.style.display = '';

            const fpIcon   = document.getElementById('upm-fp-icon');
            const fpStatus = document.getElementById('upm-fp-status');
            const verified = data.fingerprint_verified || false;

            if (fpIcon) {
                fpIcon.classList.toggle('fp-ok', verified);
                fpIcon.classList.toggle('fp-pending', !verified);
            }
            if (fpStatus) {
                fpStatus.textContent = verified ? t('fingerprint.verified') : t('upm.tapToVerify');
                fpStatus.classList.toggle('verified', verified);
            }

            // Find the contact entry for this user
            const S = window.AppState;
            const contacts = S?.contacts || [];
            const contact = contacts.find(c => c.user_id === user.id);

            const fpRow = document.getElementById('upm-fp-row');
            if (fpRow) {
                fpRow.onclick = () => {
                    window.openFingerprintModal?.({
                        userId:      user.id,
                        username:    user.username,
                        displayName: user.display_name || user.username,
                        contactId:   contact?.contact_id || null,
                        pubkey:      user.x25519_public_key,
                        verified:    verified,
                    });
                };
            }
        } else {
            fpSection.style.display = 'none';
        }
    }
}

// =============================================================================
// Вспомогательные функции
// =============================================================================

function _formatBirthDate(raw) {
    if (!raw) return '';
    if (raw.startsWith('--')) {
        // "--MM-DD"
        const parts = raw.slice(2).split('-');
        const m = parseInt(parts[0], 10) - 1;
        const d = parseInt(parts[1], 10);
        return `${d} ${_MONTH_GEN[m] || ''}`;
    }
    // "YYYY-MM-DD"
    const [yyyy, mm, dd] = raw.split('-');
    const m = parseInt(mm, 10) - 1;
    return `${parseInt(dd, 10)} ${_MONTH_GEN[m] || ''} ${yyyy}`;
}

function _esc(s) {
    if (!s) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * UX Enhancements — haptic feedback, swipe gestures, custom themes,
 *                    ripple effects, smooth transitions.
 */

// ══════════════════════════════════════════════════════════════════════════════
// 1. Haptic Feedback (vibration on actions)
// ══════════════════════════════════════════════════════════════════════════════

const Haptic = {
    /** Light tap — button press, toggle */
    light() {
        if (navigator.vibrate) navigator.vibrate(10);
    },
    /** Medium — send message, navigate */
    medium() {
        if (navigator.vibrate) navigator.vibrate(20);
    },
    /** Heavy — error, destructive action */
    heavy() {
        if (navigator.vibrate) navigator.vibrate([30, 10, 30]);
    },
    /** Success — message sent, action confirmed */
    success() {
        if (navigator.vibrate) navigator.vibrate([10, 50, 20]);
    },
    /** Selection changed */
    selection() {
        if (navigator.vibrate) navigator.vibrate(5);
    },
};

// Auto-attach haptic to common actions
document.addEventListener('click', e => {
    const btn = e.target.closest('button, .btn, .room-item, .input-btn');
    if (btn) Haptic.light();
});

window.Haptic = Haptic;


// ══════════════════════════════════════════════════════════════════════════════
// 2. Swipe Gestures (room list: swipe to archive/pin/mute)
// ══════════════════════════════════════════════════════════════════════════════

function initSwipeGestures() {
    let startX = 0, startY = 0, currentEl = null, swiping = false;
    const THRESHOLD = 60;

    document.addEventListener('touchstart', e => {
        const el = e.target.closest('.room-item');
        if (!el) return;
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
        currentEl = el;
        currentEl.classList.add('swipeable');
    }, { passive: true });

    document.addEventListener('touchmove', e => {
        if (!currentEl) return;
        const dx = e.touches[0].clientX - startX;
        const dy = e.touches[0].clientY - startY;

        // Horizontal swipe only (not scroll)
        if (Math.abs(dy) > Math.abs(dx)) {
            currentEl = null;
            return;
        }

        swiping = true;
        currentEl.classList.add('swiping');
        const clamped = Math.max(-100, Math.min(100, dx));
        currentEl.style.transform = `translateX(${clamped}px)`;

        if (dx > THRESHOLD) currentEl.classList.add('swiped-right');
        else currentEl.classList.remove('swiped-right');
        if (dx < -THRESHOLD) currentEl.classList.add('swiped-left');
        else currentEl.classList.remove('swiped-left');
    }, { passive: true });

    document.addEventListener('touchend', () => {
        if (!currentEl) return;
        currentEl.classList.remove('swiping');

        if (currentEl.classList.contains('swiped-right')) {
            Haptic.medium();
            const roomId = currentEl.dataset?.roomId;
            if (roomId && window.togglePinRoom) window.togglePinRoom(parseInt(roomId));
        } else if (currentEl.classList.contains('swiped-left')) {
            Haptic.medium();
            const roomId = currentEl.dataset?.roomId;
            if (roomId && window.toggleArchiveRoom) window.toggleArchiveRoom(parseInt(roomId));
        }

        currentEl.style.transform = '';
        currentEl.classList.remove('swiped-right', 'swiped-left', 'swipeable');
        currentEl = null;
        swiping = false;
    }, { passive: true });
}


// ══════════════════════════════════════════════════════════════════════════════
// 3. Custom Themes (accent color + background)
// ══════════════════════════════════════════════════════════════════════════════

const ThemeManager = {
    ACCENTS: ['purple', 'blue', 'green', 'red', 'orange', 'pink', 'cyan', 'yellow'],

    setAccent(color) {
        document.body.setAttribute('data-accent', color);
        localStorage.setItem('vortex_accent', color);
        Haptic.selection();
    },

    getAccent() {
        return localStorage.getItem('vortex_accent') || 'purple';
    },

    setBackgroundImage(url) {
        if (url) {
            document.body.style.setProperty('--bg-image', `url(${url})`);
            document.body.setAttribute('data-bg-image', 'true');
            localStorage.setItem('vortex_bg_image', url);
        } else {
            document.body.style.removeProperty('--bg-image');
            document.body.removeAttribute('data-bg-image');
            localStorage.removeItem('vortex_bg_image');
        }
    },

    init() {
        // Restore accent
        const accent = this.getAccent();
        if (accent !== 'purple') document.body.setAttribute('data-accent', accent);

        // Restore background
        const bg = localStorage.getItem('vortex_bg_image');
        if (bg) this.setBackgroundImage(bg);
    },
};

window.ThemeManager = ThemeManager;


// ══════════════════════════════════════════════════════════════════════════════
// 4. Ripple Effect (Material Design touch feedback)
// ══════════════════════════════════════════════════════════════════════════════

function initRipple() {
    document.addEventListener('pointerdown', e => {
        const el = e.target.closest('button, .btn, .room-item, .input-btn, .settings-tab');
        if (!el) return;

        el.classList.add('ripple-container');
        const ripple = document.createElement('span');
        ripple.className = 'ripple';

        const rect = el.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        ripple.style.width = ripple.style.height = size + 'px';
        ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
        ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';

        el.appendChild(ripple);
        setTimeout(() => ripple.remove(), 500);
    });
}


// ══════════════════════════════════════════════════════════════════════════════
// 5. Smooth Screen Transitions
// ══════════════════════════════════════════════════════════════════════════════

function transitionTo(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.classList.add('screen-entering');
    el.addEventListener('animationend', () => {
        el.classList.remove('screen-entering');
    }, { once: true });
}

window.transitionTo = transitionTo;


// ══════════════════════════════════════════════════════════════════════════════
// 6. Picture-in-Picture (for video calls)
// ══════════════════════════════════════════════════════════════════════════════

async function togglePiP(videoElement) {
    if (!videoElement) {
        videoElement = document.querySelector('video.call-video, #remote-video, #local-video');
    }
    if (!videoElement) return false;

    try {
        if (document.pictureInPictureElement) {
            await document.exitPictureInPicture();
            return false;
        } else if (videoElement.requestPictureInPicture) {
            await videoElement.requestPictureInPicture();
            return true;
        }
    } catch (e) {
        console.warn('PiP not available:', e);
    }
    return false;
}

window.togglePiP = togglePiP;


// ══════════════════════════════════════════════════════════════════════════════
// Init all enhancements
// ══════════════════════════════════════════════════════════════════════════════

function initUXEnhancements() {
    initSwipeGestures();
    initRipple();
    ThemeManager.init();
    console.log('[UX] Enhancements loaded: haptic, swipe, themes, ripple, PiP');
}

// Auto-init on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUXEnhancements);
} else {
    initUXEnhancements();
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. Bottom Tab Bar Navigation
// ══════════════════════════════════════════════════════════════════════════════

function switchBottomTab(tab) {
    // Update tab buttons
    document.querySelectorAll('.tab-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
        btn.setAttribute('aria-selected', String(btn.dataset.tab === tab));
    });

    Haptic.selection();

    const sidebar = document.getElementById('sidebar');
    const main = document.getElementById('main');
    const appContent = document.getElementById('app-content');

    // Show/hide sidebar based on tab
    // Sidebar only visible on "chats" tab
    if (tab === 'chats') {
        if (sidebar) sidebar.style.display = '';
        if (main) main.style.display = '';
        document.body.classList.remove('mobile-tab-other');
    } else {
        // Скрываем sidebar на всех не-chats табах
        document.body.classList.add('mobile-tab-other');
        if (window.innerWidth > 640) {
            if (sidebar) sidebar.style.display = 'none';
        }
    }

    // Hide/show the chats-area screens
    const chatScreen    = document.getElementById('chat-screen');
    const welcomeScreen = document.getElementById('welcome-screen');
    if (tab === 'chats') {
        const hasRoom = !!(window.AppState && window.AppState.currentRoom);
        if (chatScreen) chatScreen.style.display = hasRoom ? 'flex' : 'none';
        if (welcomeScreen) welcomeScreen.style.display = hasRoom ? 'none' : 'flex';
        // На мобильном: если нет открытого чата — показать sidebar
        if (!hasRoom) document.body.classList.remove('mobile-chat-open');
    } else {
        if (chatScreen)    chatScreen.style.display    = 'none';
        if (welcomeScreen) welcomeScreen.style.display = 'none';
    }

    // Show fullscreen tab views
    const callsView = document.getElementById('tab-view-calls');
    const contactsView = document.getElementById('tab-view-contacts');
    const botsView = document.getElementById('tab-view-bots');
    if (callsView) callsView.style.display = tab === 'calls' ? 'flex' : 'none';
    if (contactsView) contactsView.style.display = tab === 'contacts' ? 'flex' : 'none';
    if (botsView) botsView.style.display = tab === 'bots' ? 'flex' : 'none';
    const settingsView = document.getElementById('tab-view-settings');
    if (settingsView) settingsView.style.display = tab === 'settings' ? 'flex' : 'none';
    const ideView = document.getElementById('tab-view-ide');
    if (ideView) ideView.style.display = tab === 'ide' ? 'flex' : 'none';

    switch (tab) {
        case 'chats':
            break;
        case 'calls':
            loadRecentCalls();
            break;
        case 'contacts':
            loadContacts();
            break;
        case 'bots':
            loadBotStore();
            break;
        case 'settings':
            openSettingsView();
            break;
    }
}
window.switchBottomTab = switchBottomTab;


// ══════════════════════════════════════════════════════════════════════════════
// 8. Room Info Panel (click room name → slide-in info)
// ══════════════════════════════════════════════════════════════════════════════

// Save rooms.js version before we overwrite window.openRoomInfo below.
// main.js runs Object.assign(window, rooms, ...) before this module, so
// window.openRoomInfo is currently the full settings function from rooms.js.
const _roomsOpenRoomInfo = window.openRoomInfo;
window._roomsOpenRoomInfo = _roomsOpenRoomInfo;

function openRoomInfo() {
    const S = window.AppState;
    const room = S?.currentRoom;
    if (!room) return;

    // Для каналов: сразу открываем полные настройки вместо боковой панели
    if (room.is_channel && typeof window.openRoomSettings === 'function') {
        window.openRoomSettings();
        return;
    }

    const panel = document.getElementById('room-info-panel');
    if (!panel) return;

    const isChannel = !!room.is_channel;

    // Populate
    const avatar = document.getElementById('ri-avatar');
    const name = document.getElementById('ri-name');
    const meta = document.getElementById('ri-meta');
    const desc = document.getElementById('ri-description');
    const invite = document.getElementById('ri-invite-code');
    const inviteSection = document.getElementById('ri-invite-section');

    if (avatar) {
        if (room.avatar_url) {
            // Safe: avatar_url comes from our own server upload endpoint
            const img = document.createElement('img');
            img.src = room.avatar_url;
            img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:50%;';
            avatar.textContent = '';
            avatar.appendChild(img);
        } else {
            avatar.textContent = room.avatar_emoji || (isChannel ? '\u{1F4E2}' : '\u{1F4AC}');
        }
    }
    if (name) name.textContent = room.name || (isChannel ? 'Channel' : 'Room');
    if (meta) {
        const count = room.subscriber_count || room.member_count || 0;
        meta.textContent = isChannel
            ? `${count} подписчиков`
            : `${count} участников`;
    }
    if (desc) desc.textContent = room.description || '';

    // Для каналов: скрываем invite-код и меняем текст кнопок
    if (inviteSection) inviteSection.style.display = isChannel ? 'none' : '';
    if (invite && !isChannel) invite.textContent = room.invite_code || '';

    // Кнопка "Участники" → "Подписчики" для каналов
    const membersLabels = panel.querySelectorAll('[data-i18n="chat.members"], [data-i18n="roomInfo.members"]');
    membersLabels.forEach(el => {
        el.textContent = isChannel ? 'Подписчики' : el.getAttribute('data-i18n') === 'chat.members' ? 'Все участники' : 'Участники';
    });

    // Кнопка "Покинуть" → "Отписаться" для каналов
    const leaveBtn = panel.querySelector('[data-i18n="roomInfo.leave"]');
    if (leaveBtn) leaveBtn.textContent = isChannel ? 'Отписаться' : 'Покинуть комнату';

    // Sync mute button state
    const muteBtn   = document.getElementById('ri-mute-btn');
    const muteLabel = document.getElementById('ri-mute-label');
    if (muteBtn) {
        const muted = !!room.is_muted;
        muteBtn.classList.toggle('active', muted);
        if (muteLabel) muteLabel.textContent = muted ? 'Мьют' : 'Звук';
    }

    panel.classList.add('open');
    Haptic.light();
}

function closeRoomInfo() {
    const panel = document.getElementById('room-info-panel');
    if (panel) panel.classList.remove('open');
}

window.openRoomInfo = openRoomInfo;
window.closeRoomInfo = closeRoomInfo;


// ══════════════════════════════════════════════════════════════════════════════
// 9. Attachment Panel (скрепка → grid of options)
// ══════════════════════════════════════════════════════════════════════════════

function toggleAttachPanel() {
    const panel = document.getElementById('attach-panel');
    if (!panel) return;
    const opening = !panel.classList.contains('open');
    panel.classList.toggle('open');
    Haptic.light();
    if (opening) {
        // Close when the user taps anywhere outside the panel or the trigger button.
        const onOutside = e => {
            if (!panel.contains(e.target) && !e.target.closest('#attach-panel-btn')) {
                panel.classList.remove('open');
                document.removeEventListener('pointerdown', onOutside, true);
            }
        };
        // Delay one tick so the current pointerdown that opened the panel is ignored.
        setTimeout(() => document.addEventListener('pointerdown', onOutside, true), 0);
    }
}

window.toggleAttachPanel = toggleAttachPanel;

function toggleExprPanel() {
    const panel = document.getElementById('expr-panel');
    if (!panel) return;
    const opening = !panel.classList.contains('open');
    panel.classList.toggle('open');
    Haptic.light();
    if (opening) {
        const onOutside = e => {
            if (!panel.contains(e.target) && !e.target.closest('#expr-btn')) {
                panel.classList.remove('open');
                document.removeEventListener('pointerdown', onOutside, true);
            }
        };
        setTimeout(() => document.addEventListener('pointerdown', onOutside, true), 0);
    }
}
window.toggleExprPanel = toggleExprPanel;


// ══════════════════════════════════════════════════════════════════════════════
// 10. Recent Calls — load, render, filter
// ══════════════════════════════════════════════════════════════════════════════

let _callsFilter = 'all';

async function loadRecentCalls() {
    const container = document.getElementById('calls-items');
    const empty = document.getElementById('calls-empty');
    if (!container) return;

    try {
        const url = _callsFilter === 'missed' ? '/api/calls/missed' : '/api/calls/recent';
        const resp = await fetch(url, { credentials: 'include' });
        if (!resp.ok) { container.innerHTML = ''; if (empty) empty.style.display = 'flex'; return; }
        const data = await resp.json();
        const calls = data.calls || [];

        if (!calls.length) {
            container.innerHTML = '';
            if (empty) empty.style.display = 'flex';
            return;
        }
        if (empty) empty.style.display = 'none';

        // Group calls by date
        let html = '';
        let lastDateKey = '';

        calls.forEach(c => {
            const user = c.other_user || {};
            const name = user.display_name || user.username || t('calls.groupCall');
            const avatarInner = user.avatar_url
                ? `<img src="${_esc(user.avatar_url)}">`
                : (user.avatar_emoji ? _esc(user.avatar_emoji) : '<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>');
            const isVideo = c.call_type.includes('video');
            const isMissed = c.status === 'missed';
            const isDeclined = c.status === 'declined';
            const isBusy = c.status === 'busy';
            const statusClass = isMissed ? 'missed' : isDeclined ? 'declined' : isBusy ? 'busy' : 'answered';
            const dirIcon = c.direction === 'outgoing'
                ? '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M21 3H3v2h14.59L3 19.59 4.41 21 19 6.41V21h2V3z"/></svg>'
                : '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M21 19H6.41L21 4.41 19.59 3 5 17.59V3H3v18h18v-2z"/></svg>';
            const dur = c.duration > 0 ? _fmtCallDur(c.duration) : t('calls.' + c.status);
            const time = _fmtCallTime(c.started_at);
            const typeIcon = isVideo
                ? '<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>'
                : '<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M20.01 15.38c-1.23 0-2.42-.2-3.53-.56-.35-.12-.74-.03-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z"/></svg>';

            // Date group header
            const dateKey = _fmtCallDate(c.started_at);
            if (dateKey && dateKey !== lastDateKey) {
                html += `<div class="call-date-header">${dateKey}</div>`;
                lastDateKey = dateKey;
            }

            html += `<div class="call-item${isMissed ? ' missed' : ''}">
                <div class="call-avatar ${statusClass}">${avatarInner}</div>
                <div class="call-info">
                    <div class="call-name">${_esc(name)}</div>
                    <div class="call-meta ${statusClass}">
                        <span class="call-direction-icon">${dirIcon}</span>
                        <span class="call-type-icon">${typeIcon}</span>
                        <span class="call-duration">${dur}</span>
                    </div>
                </div>
                <div class="call-time">${time}</div>
                <button class="call-back-btn" onclick="event.stopPropagation();callUser(${user.user_id || 0},'${c.call_type}')" title="${t('calls.callBack')}">
                    ${typeIcon}
                </button>
            </div>`;
        });

        container.innerHTML = html;
    } catch (e) {
        console.warn('Failed to load calls:', e);
    }
}

function filterCalls(filter) {
    _callsFilter = filter;
    document.querySelectorAll('.calls-filter-pill[id^="calls-filter-"]').forEach(b => {
        b.classList.toggle('active', b.id === 'calls-filter-' + filter);
    });
    loadRecentCalls();
}

async function clearCallHistory() {
    if (!confirm(t('calls.clearConfirm'))) return;
    try {
        await fetch('/api/calls/clear', { method: 'DELETE', credentials: 'include' });
        loadRecentCalls();
    } catch {}
}

function callUser(userId, type) {
    if (userId && window.startCall) window.startCall(userId, type === 'video');
}

function _fmtCallDur(s) {
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
    return Math.floor(s / 3600) + ':' + String(Math.floor((s % 3600) / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
}

function _fmtCallTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    const now = new Date();
    const diff = now - d;
    if (diff < 86400000) return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    if (diff < 604800000) return d.toLocaleDateString(undefined, { weekday: 'short' });
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function _fmtCallDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const callDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = today - callDay;
    if (diff === 0) return t('calls.today') || 'Today';
    if (diff === 86400000) return t('calls.yesterday') || 'Yesterday';
    if (diff < 604800000) return d.toLocaleDateString(undefined, { weekday: 'long' });
    return d.toLocaleDateString(undefined, { month: 'long', day: 'numeric' });
}

function _esc(s) { return String(s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }


export { Haptic, ThemeManager, togglePiP, transitionTo, initUXEnhancements, switchBottomTab, openRoomInfo, closeRoomInfo, loadRecentCalls, filterCalls, clearCallHistory, callUser };

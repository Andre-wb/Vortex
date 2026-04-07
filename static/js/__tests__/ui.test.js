/**
 * ui.test.js
 *
 * Comprehensive unit tests for ui.js.
 *
 * Coverage targets:
 *   - showWelcome()         — sets display styles, resets currentRoom
 *   - showChatScreen()      — sets display styles, activates chat tab
 *   - openRoom()            — null guard, sets currentRoom, updates header
 *   - updateSidebarStatus() — updates status dot and text
 *   - showProfileModal()    — null guard, populates DOM fields
 *   - avatarWithStatus()    — HTML generation
 *   - toggleMobileMenu()    — sidebar open/close
 */

// ── Dependency mocks ──────────────────────────────────────────────────────────

jest.mock('../utils.js', () => ({
    $:          jest.fn((id) => global.document?.getElementById(id)),
    api:        jest.fn().mockResolvedValue({}),
    esc:        jest.fn((s) => String(s ?? '')),
    openModal:  jest.fn(),
    closeModal: jest.fn(),
    showAlert:  jest.fn(),
}));

jest.mock('../rooms.js', () => ({
    renderRoomsList: jest.fn(),
}));

jest.mock('../chat/chat.js', () => ({
    connectWS: jest.fn(),
    saveDraft:  jest.fn(),
    loadDraft:  jest.fn(() => ''),
}));

jest.mock('../webrtc.js', () => ({
    connectSignal: jest.fn(),
}));

jest.mock('../notifications.js', () => ({
    clearUnread:        jest.fn(),
    getUnreadCount:     jest.fn(() => 0),
    hasMention:         jest.fn(() => false),
    stopMultiplexCover: jest.fn(),
}));

jest.mock('../auth.js', () => ({
    getAccounts: jest.fn(() => []),
}));

// ── Imports ───────────────────────────────────────────────────────────────────

import {
    showWelcome,
    showChatScreen,
    openRoom,
    showProfileModal,
    updateSidebarStatus,
    avatarWithStatus,
} from '../ui.js';

import { $ } from '../utils.js';
import { renderRoomsList } from '../rooms.js';
import { connectWS, saveDraft, loadDraft } from '../chat/chat.js';
import { connectSignal } from '../webrtc.js';
import { clearUnread } from '../notifications.js';
import { getAccounts } from '../auth.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeStorage() {
    const store = {};
    return {
        getItem:    (k)    => (k in store ? store[k] : null),
        setItem:    (k, v) => { store[k] = String(v); },
        removeItem: (k)    => { delete store[k]; },
        clear:      ()     => { Object.keys(store).forEach(k => delete store[k]); },
    };
}

/** Build the minimal DOM scaffold expected by ui.js functions. */
function buildFullDOM() {
    document.body.innerHTML = `
        <div id="welcome-screen"></div>
        <div id="chat-screen"></div>
        <div id="nav-welcome"></div>
        <div id="sidebar"></div>
        <button id="chat-back-btn"></button>
        <div id="main"></div>
        <div id="rooms-list"></div>
        <div id="messages-container"></div>
        <input id="msg-input" value="">
        <div id="input-area"></div>
        <div id="chat-room-name"></div>
        <div id="chat-room-meta"></div>
        <div id="not-contact-banner"></div>

        <!-- Profile modal -->
        <div id="profile-modal"></div>
        <div id="prof-phone"></div>
        <div id="prof-username"></div>
        <div id="prof-created"></div>
        <div id="prof-status-dot" class="status-dot online"></div>
        <div id="prof-status-text"></div>
        <div id="accounts-list"></div>
        <div id="prof-moderation" style="display:none"></div>
        <div id="prof-mod-title"></div>
        <div id="prof-mod-detail"></div>

        <!-- Sidebar status -->
        <div id="sb-status-dot" class="status-dot online"></div>
        <div id="sb-status-text" style="display:none"></div>
    `;
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

beforeEach(() => {
    jest.clearAllMocks();

    Object.defineProperty(window, 'localStorage',   { value: makeStorage(), writable: true });
    Object.defineProperty(window, 'sessionStorage', { value: makeStorage(), writable: true });

    window.AppState = {
        user:            { user_id: 1, username: 'alice', phone: '+79991234567', presence: 'online', status_emoji: null, custom_status: null },
        rooms:           [],
        currentRoom:     null,
        x25519PrivateKey: null,
        ws:              null,
    };

    window.t          = (key) => key;
    global.t          = (key) => key;
    window.openModal  = jest.fn();
    window.closeModal = jest.fn();
    window.api        = jest.fn().mockResolvedValue({ strike_count: 0, is_muted: false });

    $.mockImplementation((id) => document.getElementById(id));
    getAccounts.mockReturnValue([]);

    buildFullDOM();
});

// =============================================================================
// 1. showWelcome()
// =============================================================================

describe('showWelcome()', () => {
    test('adds "active" class to welcome-screen', () => {
        showWelcome();
        expect(document.getElementById('welcome-screen').classList.contains('active')).toBe(true);
    });

    test('sets welcome-screen display to flex', () => {
        showWelcome();
        expect(document.getElementById('welcome-screen').style.display).toBe('flex');
    });

    test('removes "active" class from chat-screen', () => {
        document.getElementById('chat-screen').classList.add('active');
        showWelcome();
        expect(document.getElementById('chat-screen').classList.contains('active')).toBe(false);
    });

    test('hides chat-screen (display: none)', () => {
        document.getElementById('chat-screen').style.display = 'flex';
        showWelcome();
        expect(document.getElementById('chat-screen').style.display).toBe('none');
    });

    test('adds "active" to nav-welcome', () => {
        showWelcome();
        expect(document.getElementById('nav-welcome').classList.contains('active')).toBe(true);
    });

    test('resets AppState.currentRoom to null', () => {
        window.AppState.currentRoom = { id: 5 };
        showWelcome();
        expect(window.AppState.currentRoom).toBeNull();
    });

    test('calls renderRoomsList', () => {
        showWelcome();
        expect(renderRoomsList).toHaveBeenCalled();
    });

    test('does not throw when optional DOM elements are absent', () => {
        document.body.innerHTML = ''; // remove all elements
        expect(() => showWelcome()).not.toThrow();
    });
});

// =============================================================================
// 2. showChatScreen()
// =============================================================================

describe('showChatScreen()', () => {
    test('sets chat-screen display to flex', () => {
        showChatScreen();
        expect(document.getElementById('chat-screen').style.display).toBe('flex');
    });

    test('adds "active" class to chat-screen', () => {
        showChatScreen();
        expect(document.getElementById('chat-screen').classList.contains('active')).toBe(true);
    });

    test('hides welcome-screen (display: none)', () => {
        document.getElementById('welcome-screen').style.display = 'flex';
        showChatScreen();
        expect(document.getElementById('welcome-screen').style.display).toBe('none');
    });

    test('removes "active" class from nav-welcome', () => {
        document.getElementById('nav-welcome').classList.add('active');
        showChatScreen();
        expect(document.getElementById('nav-welcome').classList.contains('active')).toBe(false);
    });

    test('calls window.switchBottomTab("chats") when available', () => {
        window.switchBottomTab = jest.fn();
        showChatScreen();
        expect(window.switchBottomTab).toHaveBeenCalledWith('chats');
        delete window.switchBottomTab;
    });
});

// =============================================================================
// 3. openRoom() — null guard and basic operation
// =============================================================================

describe('openRoom() — null guard', () => {
    test('returns early without throwing when room id is not in S.rooms', () => {
        window.AppState.rooms = [];
        expect(() => openRoom(999)).not.toThrow();
    });

    test('does not update currentRoom when room is not found', () => {
        window.AppState.rooms = [];
        window.AppState.currentRoom = null;
        openRoom(999);
        expect(window.AppState.currentRoom).toBeNull();
    });
});

describe('openRoom() — successful room open', () => {
    const ROOM = { id: 10, name: 'Lobby', is_dm: false, is_channel: false, is_voice: false, is_federated: false, member_count: 10, online_count: 2 };

    beforeEach(() => {
        window.AppState.rooms = [ROOM];
    });

    test('sets AppState.currentRoom to the found room', () => {
        openRoom(10);
        expect(window.AppState.currentRoom).toEqual(ROOM);
    });

    test('calls clearUnread with room id', () => {
        openRoom(10);
        expect(clearUnread).toHaveBeenCalledWith(10);
    });

    test('calls connectWS with room id', () => {
        openRoom(10);
        expect(connectWS).toHaveBeenCalledWith(10);
    });

    test('calls connectSignal with room id for non-federated room', () => {
        openRoom(10);
        expect(connectSignal).toHaveBeenCalledWith(10);
    });

    test('calls connectSignal with -1 for federated room', () => {
        const fedRoom = { ...ROOM, is_federated: true };
        window.AppState.rooms = [fedRoom];
        openRoom(10);
        expect(connectSignal).toHaveBeenCalledWith(-1);
    });

    test('clears messages-container HTML', () => {
        document.getElementById('messages-container').innerHTML = '<div>old msg</div>';
        openRoom(10);
        expect(document.getElementById('messages-container').innerHTML).toBe('');
    });

    test('saves draft for previous room before switching', () => {
        const prevRoom = { id: 9, name: 'OldRoom' };
        window.AppState.currentRoom = prevRoom;
        document.getElementById('msg-input').value = 'draft text';
        openRoom(10);
        expect(saveDraft).toHaveBeenCalledWith(9, 'draft text');
    });

    test('stores last opened room in localStorage', () => {
        openRoom(10);
        expect(window.localStorage.getItem('vortex_last_room')).toBe('10');
    });

    test('sets room name in chat header for regular room', () => {
        openRoom(10);
        expect(document.getElementById('chat-room-name').textContent).toBe('Lobby');
    });

    test('removes not-contact-banner if present', () => {
        openRoom(10);
        expect(document.getElementById('not-contact-banner')).toBeNull();
    });

    test('sets room name for a channel', () => {
        const chRoom = { ...ROOM, is_channel: true, name: 'News', subscriber_count: 50 };
        window.AppState.rooms = [chRoom];
        openRoom(10);
        expect(document.getElementById('chat-room-name').textContent).toBe('News');
    });

    test('sets room name for a DM from dm_user display_name', () => {
        const dmRoom = { ...ROOM, is_dm: true, dm_user: { display_name: 'Bob', username: 'bob', is_online: true, presence: 'online', last_seen: null } };
        window.AppState.rooms = [dmRoom];
        openRoom(10);
        expect(document.getElementById('chat-room-name').textContent).toBe('Bob');
    });
});

// =============================================================================
// 4. updateSidebarStatus()
// =============================================================================

describe('updateSidebarStatus()', () => {
    test('does not throw when AppState.user is null', () => {
        window.AppState.user = null;
        expect(() => updateSidebarStatus()).not.toThrow();
    });

    test('sets status dot class to the user presence value', () => {
        window.AppState.user = { presence: 'away', status_emoji: null, custom_status: null };
        updateSidebarStatus();
        expect(document.getElementById('sb-status-dot').className).toBe('status-dot away');
    });

    test('defaults to "online" presence when presence is not set', () => {
        window.AppState.user = { status_emoji: null, custom_status: null };
        updateSidebarStatus();
        expect(document.getElementById('sb-status-dot').className).toBe('status-dot online');
    });

    test('shows custom status text when status_emoji and custom_status are set', () => {
        window.AppState.user = { presence: 'online', status_emoji: '😎', custom_status: 'Coding' };
        updateSidebarStatus();
        const stEl = document.getElementById('sb-status-text');
        expect(stEl.textContent).toBe('😎 Coding');
        expect(stEl.style.display).toBe('');
    });

    test('hides sb-status-text when no emoji or custom status', () => {
        window.AppState.user = { presence: 'online', status_emoji: null, custom_status: null };
        updateSidebarStatus();
        expect(document.getElementById('sb-status-text').style.display).toBe('none');
    });

    test('shows emoji only (no custom_status) in status text', () => {
        window.AppState.user = { presence: 'online', status_emoji: '🔥', custom_status: '' };
        updateSidebarStatus();
        expect(document.getElementById('sb-status-text').textContent).toBe('🔥 ');
    });
});

// =============================================================================
// 5. showProfileModal()
// =============================================================================

describe('showProfileModal()', () => {
    test('returns early without throwing when AppState.user is null', () => {
        window.AppState.user = null;
        expect(() => showProfileModal()).not.toThrow();
    });

    test('does not call openModal when user is null', () => {
        window.AppState.user = null;
        showProfileModal();
        expect(window.openModal).not.toHaveBeenCalled();
    });

    test('populates prof-phone with user phone', () => {
        showProfileModal();
        expect(document.getElementById('prof-phone').textContent).toBe('+79991234567');
    });

    test('populates prof-username with @username', () => {
        showProfileModal();
        expect(document.getElementById('prof-username').textContent).toBe('@alice');
    });

    test('calls window.openModal("profile-modal")', () => {
        showProfileModal();
        expect(window.openModal).toHaveBeenCalledWith('profile-modal');
    });

    test('sets presence class on prof-status-dot', () => {
        window.AppState.user.presence = 'dnd';
        showProfileModal();
        expect(document.getElementById('prof-status-dot').className).toBe('status-dot dnd');
    });

    test('renders "add account" row when accounts list has fewer than 4 entries', () => {
        getAccounts.mockReturnValue([{ user_id: 1, username: 'alice', display_name: 'Alice', avatar_emoji: '😀', avatar_url: null }]);
        showProfileModal();
        expect(document.getElementById('accounts-list').innerHTML).toContain('ma-add-row');
    });

    test('shows rich status text in prof-status-text when emoji and text are present', () => {
        window.AppState.user.status_emoji  = '🏡';
        window.AppState.user.custom_status = 'Working from home';
        showProfileModal();
        const profStatusText = document.getElementById('prof-status-text');
        expect(profStatusText.textContent).toContain('🏡');
        expect(profStatusText.textContent).toContain('Working from home');
    });
});

// =============================================================================
// 6. avatarWithStatus()
// =============================================================================

describe('avatarWithStatus()', () => {
    test('generates HTML with avatar-status-wrap class', () => {
        const html = avatarWithStatus({ avatar_emoji: '😀', presence: 'online' });
        expect(html).toContain('avatar-status-wrap');
    });

    test('includes status-dot with the correct presence class', () => {
        const html = avatarWithStatus({ avatar_emoji: '😀', presence: 'dnd' });
        expect(html).toContain('status-dot dnd');
    });

    test('uses img tag when avatar_url is provided', () => {
        const html = avatarWithStatus({ avatar_url: '/img/alice.jpg', presence: 'online' });
        expect(html).toContain('<img');
    });

    test('uses emoji text when no avatar_url is provided', () => {
        const html = avatarWithStatus({ avatar_emoji: '🦊', presence: 'online' });
        expect(html).toContain('🦊');
    });

    test('defaults presence to "online" when not specified', () => {
        const html = avatarWithStatus({ avatar_emoji: '🐱' });
        expect(html).toContain('status-dot online');
    });

    test('accepts custom CSS class via second argument', () => {
        const html = avatarWithStatus({ avatar_emoji: '🐻' }, 'avatar-large');
        expect(html).toContain('avatar-large');
    });
});

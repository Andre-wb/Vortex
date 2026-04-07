// static/js/chat/mention.js — @mention autocomplete

/** Cached room members for autocomplete (refreshed on room switch via online list) */
let _roomMembers = [];

/** Store online users list for mention autocomplete */
export function _updateOnlineMembersCache(users) {
    if (Array.isArray(users)) {
        _roomMembers = users.map(u => ({
            username:     u.username,
            display_name: u.display_name || u.username,
            avatar_emoji: u.avatar_emoji || '\u{1F464}',
        }));
    }
}

export function _checkMentionAutocomplete(input) {
    const text = input.value;
    const cursorPos = input.selectionStart;
    // Look backwards from cursor for @
    const before = text.slice(0, cursorPos);
    const atMatch = before.match(/@(\w{0,30})$/);
    if (!atMatch) {
        _closeMentionDropdown();
        return;
    }
    const query = atMatch[1].toLowerCase();
    const S = window.AppState;

    // Filter members matching the query
    const filtered = _roomMembers
        .filter(m => m.username.toLowerCase() !== (S.user?.username || '').toLowerCase())
        .filter(m => !query || m.username.toLowerCase().startsWith(query) || m.display_name.toLowerCase().startsWith(query))
        .slice(0, 8);

    if (filtered.length === 0) {
        _closeMentionDropdown();
        return;
    }

    _showMentionDropdown(filtered, input);
}

function _showMentionDropdown(members, input) {
    let dropdown = document.getElementById('mention-dropdown');
    if (!dropdown) {
        dropdown = document.createElement('div');
        dropdown.id = 'mention-dropdown';
        dropdown.className = 'mention-autocomplete';
        input.parentElement.appendChild(dropdown);
    }
    dropdown.innerHTML = '';
    members.forEach((m, i) => {
        const item = document.createElement('div');
        item.className = 'mention-item' + (i === 0 ? ' active' : '');
        item.dataset.username = m.username;
        item.innerHTML = `<span class="mention-item-avatar">${m.avatar_emoji}</span><span class="mention-item-name">${m.display_name}</span><span class="mention-item-username">@${m.username}</span>`;
        item.addEventListener('mousedown', (e) => {
            e.preventDefault();
            _insertMention(m.username);
        });
        item.addEventListener('mouseenter', () => {
            dropdown.querySelectorAll('.mention-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
        });
        dropdown.appendChild(item);
    });
    dropdown.style.display = 'block';
}

export function _closeMentionDropdown() {
    const dropdown = document.getElementById('mention-dropdown');
    if (dropdown) dropdown.style.display = 'none';
}

export function _insertMention(username) {
    const input = document.getElementById('msg-input');
    if (!input) return;
    const text = input.value;
    const cursorPos = input.selectionStart;
    const before = text.slice(0, cursorPos);
    const after = text.slice(cursorPos);
    // Replace @partial with @username
    const newBefore = before.replace(/@\w{0,30}$/, '@' + username + ' ');
    input.value = newBefore + after;
    input.selectionStart = input.selectionEnd = newBefore.length;
    input.focus();
    _closeMentionDropdown();
}

// static/js/tasks.js
// =============================================================================
// Collaborative task list for group chats.
// Allows room members to create, toggle, update, and delete tasks.
// =============================================================================

import { api, openModal, closeModal } from './utils.js';

/** Cached member list for the assignee dropdown. */
let _cachedMembers = [];

/**
 * Opens the task list modal and loads tasks for the current room.
 */
export async function openTaskList() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    openModal('tasks-modal');
    await _loadMembers();
    await loadTasks();
}

/**
 * Fetches room members for the assignee dropdown.
 */
async function _loadMembers() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    try {
        const data = await api('GET', `/api/rooms/${S.currentRoom.id}/members`);
        _cachedMembers = data.members || [];
        _renderAssigneeDropdown();
    } catch {
        _cachedMembers = [];
    }
}

/**
 * Renders the assignee dropdown options.
 */
function _renderAssigneeDropdown() {
    const sel = document.getElementById('task-assignee-select');
    if (!sel) return;
    sel.innerHTML = `<option value="">-- ${t('tasks.noAssignee')} --</option>`;
    _cachedMembers.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.user_id;
        opt.textContent = m.display_name || m.username;
        sel.appendChild(opt);
    });
}

/**
 * Loads and renders the task list.
 */
export async function loadTasks() {
    const S = window.AppState;
    if (!S.currentRoom) return;

    const container = document.getElementById('tasks-list');
    if (!container) return;

    container.innerHTML = `<div style="text-align:center;padding:20px;color:var(--text3);">${t('app.loading')}</div>`;

    try {
        const data = await api('GET', `/api/rooms/${S.currentRoom.id}/tasks`);
        const items = data.tasks || [];

        if (items.length === 0) {
            container.innerHTML = `<div class="task-empty">${t('tasks.noTasks')}</div>`;
            return;
        }

        container.innerHTML = '';
        const pending = items.filter(t => !t.is_done);
        const done = items.filter(t => t.is_done);

        pending.forEach(t => container.appendChild(_buildTaskItem(t)));

        if (done.length > 0) {
            const separator = document.createElement('div');
            separator.className = 'task-done-separator';
            separator.innerHTML = `<span>${t('tasks.done')} (${done.length})</span>`;
            separator.addEventListener('click', () => {
                const wrap = document.getElementById('tasks-done-wrap');
                if (wrap) {
                    wrap.style.display = wrap.style.display === 'none' ? '' : 'none';
                    separator.classList.toggle('collapsed');
                }
            });
            container.appendChild(separator);

            const doneWrap = document.createElement('div');
            doneWrap.id = 'tasks-done-wrap';
            done.forEach(t => doneWrap.appendChild(_buildTaskItem(t)));
            container.appendChild(doneWrap);
        }
    } catch (err) {
        console.error('loadTasks error:', err);
        container.innerHTML = `<div class="task-empty">${t('tasks.loadError')}</div>`;
    }
}

/**
 * Creates a new task via API.
 */
export async function addTask() {
    const S = window.AppState;
    if (!S.currentRoom) return;

    const input = document.getElementById('task-text-input');
    const sel = document.getElementById('task-assignee-select');
    if (!input) return;

    const text = input.value.trim();
    if (!text) return;

    const assigneeId = sel && sel.value ? parseInt(sel.value) : null;

    try {
        const body = { text };
        if (assigneeId) body.assignee_id = assigneeId;
        await api('POST', `/api/rooms/${S.currentRoom.id}/tasks`, body);
        input.value = '';
        if (sel) sel.value = '';
        await loadTasks();
    } catch (err) {
        console.error('addTask error:', err);
    }
}

/**
 * Toggles a task's done status.
 * @param {number} taskId
 * @param {boolean} isDone - new done state
 */
export async function toggleTask(taskId, isDone) {
    const S = window.AppState;
    if (!S.currentRoom) return;

    try {
        await api('PUT', `/api/rooms/${S.currentRoom.id}/tasks/${taskId}`, { is_done: isDone });
        await loadTasks();
    } catch (err) {
        console.error('toggleTask error:', err);
    }
}

/**
 * Deletes a task.
 * @param {number} taskId
 * @param {HTMLElement} itemEl - DOM element to animate out
 */
export async function deleteTask(taskId, itemEl) {
    const S = window.AppState;
    if (!S.currentRoom) return;

    try {
        await api('DELETE', `/api/rooms/${S.currentRoom.id}/tasks/${taskId}`);
        if (itemEl) {
            itemEl.style.transition = 'opacity 0.2s, transform 0.2s';
            itemEl.style.opacity = '0';
            itemEl.style.transform = 'translateX(20px)';
            setTimeout(() => {
                itemEl.remove();
                _checkEmpty();
            }, 200);
        } else {
            await loadTasks();
        }
    } catch (err) {
        console.error('deleteTask error:', err);
    }
}

/**
 * Checks if the task list is empty and shows placeholder.
 */
function _checkEmpty() {
    const container = document.getElementById('tasks-list');
    if (!container) return;
    const items = container.querySelectorAll('.task-item');
    if (items.length === 0) {
        container.innerHTML = `<div class="task-empty">${t('tasks.noTasks')}</div>`;
    }
}

/**
 * Builds a single task DOM element.
 * @param {Object} task
 * @returns {HTMLElement}
 */
function _buildTaskItem(task) {
    const el = document.createElement('div');
    el.className = 'task-item' + (task.is_done ? ' done' : '');
    el.dataset.taskId = task.id;

    // Checkbox
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'task-checkbox';
    checkbox.checked = task.is_done;
    checkbox.addEventListener('change', () => {
        toggleTask(task.id, checkbox.checked);
    });
    el.appendChild(checkbox);

    // Text + meta wrapper
    const content = document.createElement('div');
    content.className = 'task-content';

    const textEl = document.createElement('div');
    textEl.className = 'task-text';
    textEl.textContent = task.text;
    content.appendChild(textEl);

    const meta = document.createElement('div');
    meta.className = 'task-meta';

    if (task.creator_name) {
        const creator = document.createElement('span');
        creator.textContent = task.creator_name;
        meta.appendChild(creator);
    }

    if (task.assignee_name) {
        const badge = document.createElement('span');
        badge.className = 'task-assignee';
        badge.textContent = task.assignee_name;
        meta.appendChild(badge);
    }

    content.appendChild(meta);
    el.appendChild(content);

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'task-delete';
    deleteBtn.title = t('tasks.deleteTask');
    deleteBtn.innerHTML = '&times;';
    deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        deleteTask(task.id, el);
    });
    el.appendChild(deleteBtn);

    return el;
}

/**
 * Create a task directly from a message context menu.
 * Extracts text from the message and creates a task via API.
 * @param {Object} msg — message object from context menu
 */
async function addTaskFromMessage(msg) {
    const S = window.AppState;
    if (!S.currentRoom) return;

    // Extract text: try DOM element first (decrypted), then msg fields
    let text = '';
    if (msg.msg_id) {
        const msgEl = document.querySelector(`[data-msg-id="${msg.msg_id}"] .msg-text`);
        if (msgEl) text = msgEl.textContent?.trim() || '';
    }
    if (!text) text = msg.decryptedText || msg.text || '';
    if (!text) text = `[${msg.msg_type || 'message'}]`;
    if (text.length > 200) text = text.slice(0, 200) + '…';

    try {
        await api('POST', `/api/rooms/${S.currentRoom.id}/tasks`, { text });
        if (typeof window.showToast === 'function') {
            window.showToast(t('tasks.taskCreated') || 'Task created', 'success');
        }
    } catch (err) {
        console.error('addTaskFromMessage error:', err);
        if (typeof window.showToast === 'function') {
            window.showToast(t('tasks.createError') || 'Failed to create task', 'error');
        }
    }
}

// Expose for context menu
window._addTaskFromMessage = addTaskFromMessage;

import { esc, fmtTime } from '../../utils.js';
import { t } from '../../i18n.js';
import { _attachSwipeReply } from './helpers.js';
import { _msgElements } from './shared.js';

// =============================================================================
// Polls — Telegram-style with all advanced features
// =============================================================================

const _pollElements = new Map();

// Timer intervals for auto-closing polls
const _pollTimers = new Map();

/**
 * Render a poll card in chat.
 */
export function appendPollMessage(msg) {
    const S = window.AppState;
    const container = document.getElementById('messages-container');
    const isOwn = msg.sender_id === S.user?.user_id;
    const myId = String(S.user?.user_id || '');

    const group = document.createElement('div');
    group.className = 'fade-in msg-group';
    group.dataset.msgId = msg.msg_id || '';
    group.dataset.senderId = msg.sender_id || '';

    // Author header
    if (!isOwn) {
        const author = document.createElement('div');
        author.className = 'msg-author';

        const avatarDiv = document.createElement('div');
        avatarDiv.className = 'msg-avatar';
        if (msg.avatar_url) {
            const avatarImg = document.createElement('img');
            avatarImg.src = msg.avatar_url;
            avatarImg.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:50%;';
            avatarDiv.appendChild(avatarImg);
        } else {
            avatarDiv.textContent = msg.avatar_emoji || '\u{1F464}';
        }
        author.appendChild(avatarDiv);

        const nameSpan = document.createElement('span');
        nameSpan.className = 'msg-name';
        nameSpan.textContent = msg.display_name || msg.sender || '?';
        author.appendChild(nameSpan);

        const timeSpan = document.createElement('span');
        timeSpan.className = 'msg-time';
        timeSpan.textContent = fmtTime(msg.created_at);
        author.appendChild(timeSpan);

        group.appendChild(author);
    }

    const card = document.createElement('div');
    card.className = `msg-bubble lg poll-card${isOwn ? ' lg-own own' : ''}`;
    card.dataset.pollId = msg.msg_id;

    const grain = document.createElement('div');
    grain.className = 'lg-grain';
    card.appendChild(grain);

    // Poll type badge
    const badge = document.createElement('div');
    badge.className = 'poll-type-badge';
    if (msg.quiz) {
        badge.textContent = '\u2705 ' + t('poll.quiz');
    } else if (msg.anonymous) {
        badge.textContent = '\uD83D\uDC64 ' + t('poll.anonymous');
    } else if (msg.multiple) {
        badge.textContent = '\u2611 ' + t('poll.multipleAnswers');
    } else {
        badge.textContent = '\uD83D\uDCCA ' + t('poll.title');
    }
    card.appendChild(badge);

    // Media attachment on question
    if (msg.media_url) {
        const mediaEl = document.createElement('div');
        mediaEl.className = 'poll-media';
        const img = document.createElement('img');
        img.src = msg.media_url;
        img.alt = '';
        img.loading = 'lazy';
        mediaEl.appendChild(img);
        card.appendChild(mediaEl);
    }

    // Question
    const qEl = document.createElement('div');
    qEl.className = 'poll-question';
    qEl.textContent = msg.question;
    card.appendChild(qEl);

    // Description
    if (msg.description) {
        const descEl = document.createElement('div');
        descEl.className = 'poll-description';
        descEl.textContent = msg.description;
        card.appendChild(descEl);
    }

    // Options
    const opts = msg.options || [];
    const totalVotes = Object.values(msg.votes || {}).reduce((a, b) => a + b, 0);
    const myVote = msg.voters?.[myId];
    const hasVoted = myVote !== undefined && myVote !== null;
    const isClosed = !!msg.closed;
    const showResults = hasVoted || isClosed;

    // Shuffle for display if enabled and user hasn't voted yet
    let displayOrder = opts.map((_, i) => i);
    if (msg.shuffle && !hasVoted && !isClosed) {
        displayOrder = _shuffleArray([...displayOrder], msg.msg_id);
    }

    const optsCont = document.createElement('div');
    optsCont.className = 'poll-options';

    displayOrder.forEach(idx => {
        const opt = opts[idx];
        const optText = typeof opt === 'object' ? opt.text : opt;
        const optDesc = typeof opt === 'object' ? opt.description : '';
        const optMedia = typeof opt === 'object' ? opt.media_url : null;
        const count = msg.votes?.[String(idx)] || 0;
        const pct = totalVotes > 0 ? Math.round((count / totalVotes) * 100) : 0;
        const isMyVote = msg.multiple
            ? (Array.isArray(myVote) ? myVote.includes(idx) : false)
            : myVote === idx;
        const isCorrect = msg.quiz && msg.correct_option === idx;

        const optEl = document.createElement('div');
        optEl.className = 'poll-option-btn'
            + (isMyVote ? ' voted' : '')
            + (showResults && isCorrect ? ' correct' : '')
            + (showResults && isMyVote && msg.quiz && !isCorrect ? ' incorrect' : '')
            + (isClosed ? ' closed' : '');

        if (!isClosed) {
            if (msg.multiple) {
                optEl.onclick = () => _toggleMultiVote(msg.msg_id, idx, optEl);
            } else {
                optEl.onclick = () => window.votePoll?.(msg.msg_id, idx);
            }
        }

        // Progress bar (visible when results shown)
        const bar = document.createElement('div');
        bar.className = 'poll-option-bar' + (isCorrect && showResults ? ' correct' : '');
        bar.style.width = showResults ? `${pct}%` : '0%';
        optEl.appendChild(bar);

        // Checkbox indicator for multiple choice
        if (msg.multiple && !showResults) {
            const check = document.createElement('div');
            check.className = 'poll-checkbox' + (isMyVote ? ' checked' : '');
            optEl.appendChild(check);
        }

        // Option content wrapper
        const contentWrap = document.createElement('div');
        contentWrap.className = 'poll-option-content';

        // Media on option
        if (optMedia) {
            const mi = document.createElement('img');
            mi.src = optMedia;
            mi.className = 'poll-option-media';
            mi.loading = 'lazy';
            contentWrap.appendChild(mi);
        }

        const textEl = document.createElement('span');
        textEl.className = 'poll-option-text';
        textEl.textContent = optText;
        contentWrap.appendChild(textEl);

        if (optDesc) {
            const dEl = document.createElement('span');
            dEl.className = 'poll-option-desc';
            dEl.textContent = optDesc;
            contentWrap.appendChild(dEl);
        }

        optEl.appendChild(contentWrap);

        // Vote count
        const countEl = document.createElement('span');
        countEl.className = 'poll-option-count';
        if (showResults && count > 0) {
            countEl.textContent = `${count} (${pct}%)`;
        }
        optEl.appendChild(countEl);

        // Correct answer icon for quiz
        if (showResults && isCorrect) {
            const checkIcon = document.createElement('span');
            checkIcon.className = 'poll-correct-icon';
            checkIcon.textContent = '\u2713';
            optEl.appendChild(checkIcon);
        }

        optsCont.appendChild(optEl);
    });

    card.appendChild(optsCont);

    // Suggest option button
    if (msg.allow_suggest && !isClosed) {
        const suggestBtn = document.createElement('button');
        suggestBtn.className = 'poll-suggest-btn';
        suggestBtn.textContent = t('poll.suggestOption');
        suggestBtn.onclick = () => _showSuggestInput(msg.msg_id, card);
        card.appendChild(suggestBtn);
    }

    // Multiple choice submit button
    if (msg.multiple && !isClosed && !hasVoted) {
        const submitBtn = document.createElement('button');
        submitBtn.className = 'poll-submit-btn';
        submitBtn.textContent = t('poll.submitVote');
        submitBtn.dataset.msgId = msg.msg_id;
        submitBtn.onclick = () => _submitMultiVote(msg.msg_id);
        card.appendChild(submitBtn);
    }

    // Footer: vote count + timer/closed status
    const footer = document.createElement('div');
    footer.className = 'poll-footer';

    const votesText = document.createElement('span');
    votesText.className = 'poll-votes-count';
    votesText.textContent = totalVotes + ' ' + _pluralVotes(totalVotes);
    footer.appendChild(votesText);

    if (isClosed) {
        const closedBadge = document.createElement('span');
        closedBadge.className = 'poll-closed-badge';
        closedBadge.textContent = t('poll.closed');
        footer.appendChild(closedBadge);
    } else if (msg.close_at) {
        const timerEl = document.createElement('span');
        timerEl.className = 'poll-timer';
        timerEl.id = `poll-timer-${msg.msg_id}`;
        footer.appendChild(timerEl);
        _startPollTimer(msg.msg_id, msg.close_at);
    }

    if (msg.anonymous && !isClosed) {
        const anonLabel = document.createElement('span');
        anonLabel.className = 'poll-anon-label';
        anonLabel.textContent = t('poll.votesHidden');
        footer.appendChild(anonLabel);
    }

    card.appendChild(footer);

    // Quiz explanation (shown after voting)
    if (msg.quiz && msg.explanation && hasVoted) {
        const expEl = document.createElement('div');
        expEl.className = 'poll-explanation';
        expEl.textContent = '\uD83D\uDCA1 ' + msg.explanation;
        card.appendChild(expEl);
    }

    // Close poll button for owner
    if (isOwn && !isClosed) {
        const closeBtn = document.createElement('button');
        closeBtn.className = 'poll-close-btn';
        closeBtn.textContent = t('poll.closePoll');
        closeBtn.onclick = () => {
            window._closePoll?.(msg.msg_id);
        };
        card.appendChild(closeBtn);
    }

    if (isOwn) {
        const timeEl = document.createElement('div');
        timeEl.style.cssText = 'font-size:10px;color:var(--text3);margin-top:3px;text-align:right;font-family:var(--mono);';
        timeEl.textContent = fmtTime(msg.created_at);
        group.appendChild(card);
        group.appendChild(timeEl);
    } else {
        group.appendChild(card);
    }

    container.appendChild(group);
    _pollElements.set(msg.msg_id, { group, card, msg });
    if (msg.msg_id) _msgElements.set(msg.msg_id, group);
    _attachSwipeReply(group, msg);
}

/**
 * Update poll after vote/close/suggest.
 */
export function updatePoll(data) {
    const S = window.AppState;
    const entry = _pollElements.get(data.msg_id);
    if (!entry) return;

    const { card, msg } = entry;

    // Update cached data
    msg.votes = data.votes;
    if (data.voters) msg.voters = data.voters;
    if (data.options) msg.options = data.options;
    if (data.closed !== undefined) msg.closed = data.closed;

    const myId = String(S.user?.user_id || '');
    const totalVotes = data.total_votes || Object.values(data.votes || {}).reduce((a, b) => a + b, 0);
    const myVote = (data.voters || msg.voters)?.[myId];
    const hasVoted = myVote !== undefined && myVote !== null;
    const isClosed = !!data.closed;
    const showResults = hasVoted || isClosed;

    // Update option buttons
    const optBtns = card.querySelectorAll('.poll-option-btn');
    optBtns.forEach((btn, idx) => {
        const count = data.votes?.[String(idx)] || 0;
        const pct = totalVotes > 0 ? Math.round((count / totalVotes) * 100) : 0;
        const isMyVote = msg.multiple
            ? (Array.isArray(myVote) ? myVote.includes(idx) : false)
            : myVote === idx;
        const isCorrect = msg.quiz && msg.correct_option === idx;

        btn.className = 'poll-option-btn'
            + (isMyVote ? ' voted' : '')
            + (showResults && isCorrect ? ' correct' : '')
            + (showResults && isMyVote && msg.quiz && !isCorrect ? ' incorrect' : '')
            + (isClosed ? ' closed' : '');

        const bar = btn.querySelector('.poll-option-bar');
        if (bar) {
            bar.style.width = showResults ? `${pct}%` : '0%';
            bar.className = 'poll-option-bar' + (isCorrect && showResults ? ' correct' : '');
        }

        const countEl = btn.querySelector('.poll-option-count');
        if (countEl) countEl.textContent = showResults && count > 0 ? `${count} (${pct}%)` : '';

        if (isClosed) {
            btn.onclick = null;
            btn.style.cursor = 'default';
        }
    });

    // Handle new suggested option
    if (data.new_option) {
        const optsCont = card.querySelector('.poll-options');
        if (optsCont) {
            const opt = data.new_option;
            const optEl = document.createElement('div');
            optEl.className = 'poll-option-btn';

            const bar = document.createElement('div');
            bar.className = 'poll-option-bar';
            bar.style.width = '0%';
            optEl.appendChild(bar);

            const contentWrap = document.createElement('div');
            contentWrap.className = 'poll-option-content';
            const textEl = document.createElement('span');
            textEl.className = 'poll-option-text';
            textEl.textContent = opt.text;
            contentWrap.appendChild(textEl);
            optEl.appendChild(contentWrap);

            const countEl = document.createElement('span');
            countEl.className = 'poll-option-count';
            optEl.appendChild(countEl);

            if (!isClosed) {
                optEl.onclick = () => window.votePoll?.(data.msg_id, opt.index);
            }
            optsCont.appendChild(optEl);
        }
    }

    // Update footer
    const votesCount = card.querySelector('.poll-votes-count');
    if (votesCount) votesCount.textContent = totalVotes + ' ' + _pluralVotes(totalVotes);

    // Update closed state
    if (isClosed) {
        let closedBadge = card.querySelector('.poll-closed-badge');
        if (!closedBadge) {
            const footer = card.querySelector('.poll-footer');
            if (footer) {
                closedBadge = document.createElement('span');
                closedBadge.className = 'poll-closed-badge';
                closedBadge.textContent = t('poll.closed');
                footer.appendChild(closedBadge);
            }
        }
        card.querySelectorAll('.poll-suggest-btn, .poll-submit-btn, .poll-close-btn').forEach(el => el.remove());
        const timerId = _pollTimers.get(data.msg_id);
        if (timerId) { clearInterval(timerId); _pollTimers.delete(data.msg_id); }
    }

    // Quiz feedback
    if (data.quiz_result && data.quiz_voter_id === S.user?.user_id) {
        _showQuizFeedback(card, data.quiz_result);
    }
}

// ── Multiple choice helper ──────────────────────────────────────────────────

const _multiSelections = new Map();

function _toggleMultiVote(msgId, idx, optEl) {
    if (!_multiSelections.has(msgId)) _multiSelections.set(msgId, new Set());
    const sel = _multiSelections.get(msgId);
    if (sel.has(idx)) {
        sel.delete(idx);
        optEl.classList.remove('selected');
        const cb = optEl.querySelector('.poll-checkbox');
        if (cb) cb.classList.remove('checked');
    } else {
        sel.add(idx);
        optEl.classList.add('selected');
        const cb = optEl.querySelector('.poll-checkbox');
        if (cb) cb.classList.add('checked');
    }
}

function _submitMultiVote(msgId) {
    const sel = _multiSelections.get(msgId);
    if (!sel || sel.size === 0) return;
    const S = window.AppState;
    if (!S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    S.ws.send(JSON.stringify({
        action: 'vote_poll',
        msg_id: msgId,
        option_index: [...sel],
    }));
    _multiSelections.delete(msgId);
}

// ── Suggest option ──────────────────────────────────────────────────────────

function _showSuggestInput(msgId, card) {
    if (card.querySelector('.poll-suggest-input-wrap')) return;
    const wrap = document.createElement('div');
    wrap.className = 'poll-suggest-input-wrap';
    const input = document.createElement('input');
    input.className = 'poll-suggest-input';
    input.placeholder = t('poll.suggestPlaceholder');
    input.maxLength = 200;
    const sendBtn = document.createElement('button');
    sendBtn.className = 'poll-suggest-send';
    sendBtn.textContent = '\u2713';
    sendBtn.onclick = () => {
        const text = input.value.trim();
        if (!text) return;
        window._suggestPollOption?.(msgId, text);
        wrap.remove();
    };
    input.addEventListener('keydown', e => {
        if (e.key === 'Enter') sendBtn.click();
    });
    wrap.append(input, sendBtn);
    const suggestBtn = card.querySelector('.poll-suggest-btn');
    if (suggestBtn) suggestBtn.after(wrap);
    else card.appendChild(wrap);
    input.focus();
}

// ── Quiz feedback ───────────────────────────────────────────────────────────

function _showQuizFeedback(card, result) {
    let existing = card.querySelector('.poll-quiz-feedback');
    if (existing) existing.remove();

    const fb = document.createElement('div');
    fb.className = 'poll-quiz-feedback ' + (result.correct ? 'correct' : 'incorrect');
    fb.textContent = result.correct ? t('poll.quizCorrect') : t('poll.quizIncorrect');
    if (!result.correct && result.explanation) {
        const exp = document.createElement('div');
        exp.className = 'poll-quiz-explanation';
        exp.textContent = result.explanation;
        fb.appendChild(exp);
    }
    card.appendChild(fb);
    setTimeout(() => fb.classList.add('show'), 10);
}

// ── Timer ───────────────────────────────────────────────────────────────────

function _startPollTimer(msgId, closeAt) {
    const el = document.getElementById(`poll-timer-${msgId}`);
    if (!el) return;
    const deadline = new Date(closeAt).getTime();
    const update = () => {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
            el.textContent = t('poll.closed');
            el.className = 'poll-closed-badge';
            clearInterval(interval);
            _pollTimers.delete(msgId);
            return;
        }
        const h = Math.floor(remaining / 3600000);
        const m = Math.floor((remaining % 3600000) / 60000);
        const s = Math.floor((remaining % 60000) / 1000);
        el.textContent = h > 0 ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
            : `${m}:${String(s).padStart(2, '0')}`;
    };
    update();
    const interval = setInterval(update, 1000);
    _pollTimers.set(msgId, interval);
}

// ── Shuffle (deterministic by poll id) ──────────────────────────────────────

function _shuffleArray(arr, seed) {
    let s = typeof seed === 'number' ? seed : 42;
    for (let i = arr.length - 1; i > 0; i--) {
        s = (s * 1103515245 + 12345) & 0x7fffffff;
        const j = s % (i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

// ── Plural ──────────────────────────────────────────────────────────────────

function _pluralVotes(n) {
    return n === 1 ? t('poll.vote') : t('poll.votes');
}

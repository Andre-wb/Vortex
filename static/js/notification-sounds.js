// static/js/notification-sounds.js
// ============================================================================
// Звуки уведомлений и режим «Не беспокоить» (Do Not Disturb).
// Генерирует звуки программно через Web Audio API — аудиофайлы не нужны.
// ============================================================================

const DND_KEY = 'vortex_dnd_enabled';

let _audioCtx = null;
let _callOsc1 = null;
let _callOsc2 = null;
let _callGain = null;
let _callInterval = null;
let _dndEnabled = localStorage.getItem(DND_KEY) === 'true';

/**
 * Lazy-init shared AudioContext (created on first use to comply with
 * browser autoplay policies — must happen after a user gesture).
 */
function _getAudioCtx() {
    if (!_audioCtx || _audioCtx.state === 'closed') {
        _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (_audioCtx.state === 'suspended') {
        _audioCtx.resume().catch(() => {});
    }
    return _audioCtx;
}

// ── Message sound ────────────────────────────────────────────────────────────
// Short 440 Hz sine beep, 150 ms, volume 0.3

let _lastMessageSound = 0;

/**
 * Play a subtle notification beep for a new message.
 * Debounced to 1 second so rapid messages don't overlap.
 */
export function playMessageSound() {
    if (_dndEnabled) return;
    const now = Date.now();
    if (now - _lastMessageSound < 1000) return;
    _lastMessageSound = now;

    try {
        const ctx = _getAudioCtx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.type = 'sine';
        osc.frequency.setValueAtTime(440, ctx.currentTime);

        gain.gain.setValueAtTime(0.3, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);

        osc.connect(gain).connect(ctx.destination);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.15);
    } catch (e) {
        console.warn('playMessageSound error:', e.message);
    }
}

// ── Call sound ───────────────────────────────────────────────────────────────
// Alternating 440 Hz / 520 Hz, 500 ms on / 500 ms off, looped

/**
 * Start playing a looped ringtone for an incoming call.
 * Alternates between 440 Hz and 520 Hz tones.
 */
export function playCallSound() {
    if (_dndEnabled) return;
    stopCallSound(); // Ensure no double-play

    try {
        const ctx = _getAudioCtx();
        _callGain = ctx.createGain();
        _callGain.gain.setValueAtTime(0.3, ctx.currentTime);
        _callGain.connect(ctx.destination);

        let toggle = false;

        function _ringTick() {
            try {
                const ctx2 = _getAudioCtx();
                const osc = ctx2.createOscillator();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(toggle ? 520 : 440, ctx2.currentTime);

                const env = ctx2.createGain();
                env.gain.setValueAtTime(0.3, ctx2.currentTime);
                env.gain.exponentialRampToValueAtTime(0.001, ctx2.currentTime + 0.5);

                osc.connect(env).connect(ctx2.destination);
                osc.start(ctx2.currentTime);
                osc.stop(ctx2.currentTime + 0.5);

                toggle = !toggle;
            } catch {}
        }

        // Play immediately, then every 1000 ms (500 ms tone + 500 ms silence)
        _ringTick();
        _callInterval = setInterval(_ringTick, 1000);
    } catch (e) {
        console.warn('playCallSound error:', e.message);
    }
}

/**
 * Stop the incoming-call ringtone.
 */
export function stopCallSound() {
    if (_callInterval) {
        clearInterval(_callInterval);
        _callInterval = null;
    }
    if (_callGain) {
        try { _callGain.disconnect(); } catch {}
        _callGain = null;
    }
    _callOsc1 = null;
    _callOsc2 = null;
}

// ── Do Not Disturb ──────────────────────────────────────────────────────────

/**
 * Enable or disable Do Not Disturb mode.
 * When enabled, all notification sounds are muted.
 * Persisted in localStorage.
 * @param {boolean} enabled
 */
export function setDND(enabled) {
    _dndEnabled = !!enabled;
    localStorage.setItem(DND_KEY, _dndEnabled ? 'true' : 'false');
    if (_dndEnabled) {
        stopCallSound();
    }
}

/**
 * Check whether Do Not Disturb mode is currently active.
 * @returns {boolean}
 */
export function isDND() {
    return _dndEnabled;
}

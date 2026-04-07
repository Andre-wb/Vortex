// static/js/webrtc.js
// ============================================================================
// Модуль WebRTC для аудио/видеозвонков в комнате.
// Обрабатывает сигнализацию через WebSocket, создание peer-соединения,
// управление медиапотоками, интерфейс входящего вызова.
//
// Мониторинг качества звонка (RTT, jitter, потери пакетов) через getStats().
// Метрики обновляются каждые 2 секунды и отображаются в overlay звонка.
//
// Адаптивный контроль качества (критерий 3 — контроль перегрузки):
//   • При ухудшении сети (RTT>300мс, loss>5%) понижается bitrate видео / аудио
//   • При восстановлении сети bitrate возвращается к норме
//   • Алгоритм на основе конечного автомата: high → medium → low → audio_only
// ============================================================================

import { $, api } from './utils.js';
import { t } from './i18n.js';
import { playCallSound, stopCallSound } from './notification-sounds.js';
import { getRoomKey } from './crypto.js';
import { isE2ESupported, needsEncodedInsertableStreams, deriveMediaKey, setupPeerE2E } from './e2e_media.js';

// ICE/TURN серверы загружаются динамически с сервера (требует аутентификации).
// Fallback — только STUN (без TURN), достаточно для LAN.
let _iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
let _iceLoaded  = false;

async function _loadIceServers() {
    if (_iceLoaded) return;
    try {
        const data = await api('GET', '/api/keys/ice-servers');
        if (data && data.ice_servers) {
            _iceServers = data.ice_servers;
        }
        _iceLoaded = true;
    } catch (e) {
        console.warn('ICE servers fetch failed, using STUN fallback:', e);
    }
}

let _isHangingUp      = false;
let _incomingCallFrom = null;
let _e2eMediaKey      = null;   // CryptoKey for E2E media frame encryption
let _statsInterval    = null;
let _prevStats        = null;
let _callTimerInterval = null;
let _callDurationSec   = 0;

// ─── Пороги качества ──────────────────────────────────────────────────────────
const QUALITY = {
    GOOD: { rtt: 150,  loss: 2,  jitter: 30  },
    FAIR: { rtt: 300,  loss: 8,  jitter: 80  },
    // хуже → poor
};

// ─── Адаптивное управление bitrate ────────────────────────────────────────────
// Уровни качества видео (kbps)
const VIDEO_BITRATES = {
    high:       2500_000,    // 2.5 Mbps — отличное качество
    medium:      800_000,    // 800 kbps — среднее
    low:         200_000,    // 200 kbps — плохая сеть
    audio_only:        0,    // видео отключено
};

// Уровни качества аудио (bps)
const AUDIO_BITRATES = {
    high:    64_000,   // 64 kbps opus
    medium:  32_000,   // 32 kbps
    low:     16_000,   // 16 kbps
    audio_only: 24_000,
};

let _currentQualityLevel = 'high';   // текущий уровень
let _qualityStableCount  = 0;        // счётчик стабильных итераций (для повышения)

// Минимальное число итераций подряд с хорошей сетью прежде чем повысить качество
const QUALITY_UPGRADE_THRESHOLD = 5;

// ----------------------------------------------------------------------------
// Подключение к сигнальному WebSocket
// ----------------------------------------------------------------------------
export async function connectSignal(roomId) {
    const S = window.AppState;

    // Подгружаем ICE/TURN серверы с бэкенда (lazy, один раз)
    _loadIceServers();

    if (S.signalWs?.readyState === WebSocket.OPEN && S._signalRoomId === roomId) return;

    if (S.signalWs) {
        S.signalWs.onclose = null;
        S.signalWs.close();
        S.signalWs = null;
    }

    S._signalRoomId = roomId;  // запоминаем правильный ID

    // Anti-probing: knock sequence в global mode
    if (window.AppState.user?.network_mode === 'global') {
        try {
            await fetch('/cover/pricing', {credentials: 'include'});
            await fetch('/cover/about', {credentials: 'include'});
        } catch {}
    }
    const knockCookie = document.cookie.split(';').find(c => c.trim().startsWith('_vk='))?.split('=')[1];
    const wsSignalPath = `/ws/signal/${roomId}`;
    const knockParam = knockCookie ? `?knock=${knockCookie}` : '';

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    S.signalWs  = new WebSocket(`${proto}://${location.host}${wsSignalPath}${knockParam}`);

    S.signalWs.onopen = () => console.log('Signal WS открыт, комната', roomId);

    S.signalWs.onmessage = async e => {
        try { await handleSignal(JSON.parse(e.data)); }
        catch (err) { console.error('Signal msg error:', err); }
    };

    S.signalWs.onclose = e => {
        console.log('Signal WS закрыт, code=', e.code);
        S.signalWs = null;
        if (e.code !== 1000) {
            setTimeout(() => {
                if (S._signalRoomId === roomId && !S.signalWs) {
                    connectSignal(roomId);
                }
            }, 3000);
        }
    };

    S.signalWs.onerror = err => console.error('Signal WS error:', err);
}

function waitForSignalOpen(timeout = 5000) {
    return new Promise((resolve, reject) => {
        const S = window.AppState;
        if (!S.signalWs) { reject(new Error('signalWs не создан')); return; }
        if (S.signalWs.readyState === WebSocket.OPEN) { resolve(); return; }
        const tid = setTimeout(() => reject(new Error('Signal WS timeout')), timeout);
        S.signalWs.addEventListener('open',  () => { clearTimeout(tid); resolve(); }, { once: true });
        S.signalWs.addEventListener('close', () => { clearTimeout(tid); reject(new Error(t('call.wsDisconnected'))); }, { once: true });
    });
}

function signal(msg) {
    const S = window.AppState;
    if (S.signalWs?.readyState === WebSocket.OPEN) {
        S.signalWs.send(JSON.stringify(msg));
    } else {
        console.warn('signal(): WS не готов, тип=', msg.type);
    }
}

function _sdpHasVideo(sdp) {
    return typeof sdp === 'string' && /^m=video /m.test(sdp);
}

// ----------------------------------------------------------------------------
// Инициирование звонков
// ----------------------------------------------------------------------------
export async function startVoiceCall() {
    const S = window.AppState;
    if (!S.currentRoom) return;

    // Group call notice — all room members get the invite via signal broadcast
    if (S.currentRoom.member_count > 2 && !S.currentRoom.is_dm) {
        const { appendSystemMessage } = await import('./chat/messages.js');
        appendSystemMessage('Group call — all room members will receive an invite. The first to accept will be connected.');
    }

    console.log('currentRoom:', JSON.stringify(S.currentRoom));
    console.log('signalRoomId:', S.currentRoom.signalRoomId);
    console.log('id:', S.currentRoom.id);
    console.log('_signalRoomId:', S._signalRoomId);
    if (!S.signalWs || S.signalWs.readyState === WebSocket.CLOSED) {
        const signalId = S.currentRoom.signalRoomId ?? S.currentRoom.id;
        connectSignal(signalId);
    }
    try { await waitForSignalOpen(); }
    catch (e) { alert(t('call.noSignalServer') + ': ' + e.message); return; }

    try {
        S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    } catch (e) { alert(t('call.noMicAccess') + ': ' + e.message); return; }

    const callName = (S.currentRoom.is_dm && S.currentRoom.dm_user)
        ? (S.currentRoom.dm_user.display_name || S.currentRoom.dm_user.username)
        : S.currentRoom.name;
    const callAvatar = (S.currentRoom.is_dm && S.currentRoom.dm_user)
        ? (S.currentRoom.dm_user.avatar_emoji || '\u{1F464}')
        : '\u{1F464}';
    _showCallOverlay({ name: callName, avatar: callAvatar, status: t('notifications.voiceCall') + '...', hasVideo: false });
    _isHangingUp = false;
    _currentQualityLevel = 'high';
    _qualityStableCount  = 0;

    S.pc = createPeerConnection();
    S.localStream.getTracks().forEach(t => S.pc.addTrack(t, S.localStream));

    // E2E media frame encryption
    _e2eMediaKey = null;
    const roomKey = getRoomKey(S.currentRoom?.id);
    if (roomKey && isE2ESupported()) {
        try {
            _e2eMediaKey = await deriveMediaKey(roomKey, `call-${S.currentRoom.id}-${Date.now()}`);
            setupPeerE2E(S.pc, _e2eMediaKey);
            console.log('[WebRTC] E2E media encryption active');
        } catch (e) { console.warn('[WebRTC] E2E setup failed:', e.message); }
    }

    const offer = await S.pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false });
    await S.pc.setLocalDescription(offer);

    signal({ type: 'invite', hasVideo: false });
    await new Promise(r => setTimeout(r, 50));
    signal({ type: 'offer', sdp: _maskSdp(offer.sdp) });
    _updatePrivacyBadge();
}

export async function startVideoCall() {
    const S = window.AppState;
    if (!S.currentRoom) return;

    // Group call notice — all room members get the invite via signal broadcast
    if (S.currentRoom.member_count > 2 && !S.currentRoom.is_dm) {
        const { appendSystemMessage } = await import('./chat/messages.js');
        appendSystemMessage('Group video call — all room members will receive an invite. The first to accept will be connected.');
    }

    if (!S.signalWs || S.signalWs.readyState === WebSocket.CLOSED) {
        const signalId = S.currentRoom.signalRoomId ?? S.currentRoom.id;
        connectSignal(signalId);
    }
    try { await waitForSignalOpen(); }
    catch (e) { alert(t('call.noSignalServer') + ': ' + e.message); return; }

    try {
        S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    } catch (e) { alert(t('call.noCameraAccess') + ': ' + e.message); return; }

    const vCallName = (S.currentRoom.is_dm && S.currentRoom.dm_user)
        ? (S.currentRoom.dm_user.display_name || S.currentRoom.dm_user.username)
        : S.currentRoom.name;
    const vCallAvatar = (S.currentRoom.is_dm && S.currentRoom.dm_user)
        ? (S.currentRoom.dm_user.avatar_emoji || '\u{1F464}')
        : '\u{1F464}';
    _showCallOverlay({ name: vCallName, avatar: vCallAvatar, status: t('notifications.videoCall') + '...', hasVideo: true });
    _isHangingUp = false;
    S.isCamOff   = false;
    _currentQualityLevel = 'high';
    _qualityStableCount  = 0;
    _updateCamBtn(false);

    S.pc = createPeerConnection();
    S.localStream.getTracks().forEach(t => S.pc.addTrack(t, S.localStream));

    // E2E media frame encryption
    _e2eMediaKey = null;
    const vRoomKey = getRoomKey(S.currentRoom?.id);
    if (vRoomKey && isE2ESupported()) {
        try {
            _e2eMediaKey = await deriveMediaKey(vRoomKey, `call-${S.currentRoom.id}-${Date.now()}`);
            setupPeerE2E(S.pc, _e2eMediaKey);
            console.log('[WebRTC] E2E media encryption active (video)');
        } catch (e) { console.warn('[WebRTC] E2E setup failed:', e.message); }
    }

    const offer = await S.pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true });
    await S.pc.setLocalDescription(offer);

    signal({ type: 'invite', hasVideo: true });
    await new Promise(r => setTimeout(r, 50));
    signal({ type: 'offer', sdp: _maskSdp(offer.sdp) });
    _updatePrivacyBadge();
}

// ----------------------------------------------------------------------------
// Call privacy settings (Force TCP / Relay / Traffic Masking)
// ----------------------------------------------------------------------------
function _getCallPrivacySettings() {
    return {
        forceRelay:  localStorage.getItem('vortex_call_force_relay') === 'true',
        forceTcp:    localStorage.getItem('vortex_call_force_tcp')   === 'true',
        trafficMask: localStorage.getItem('vortex_call_traffic_mask') === 'true',
    };
}

function _buildRtcConfig() {
    const priv = _getCallPrivacySettings();
    let servers = _iceServers;

    // Force TCP: filter ICE servers to only TCP-based TURN urls
    if (priv.forceTcp) {
        servers = _iceServers
            .map(s => {
                const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
                const tcpUrls = urls.filter(u =>
                    /\?transport=tcp/i.test(u) || /^turns:/i.test(u)
                );
                if (tcpUrls.length === 0) return null;
                return { ...s, urls: tcpUrls };
            })
            .filter(Boolean);

        // Fallback: if no TCP servers found, keep all TURN servers
        // (relay policy will still force TURN usage)
        if (servers.length === 0) servers = _iceServers;
    }

    const config = { iceServers: servers };

    // Force Relay or Force TCP both require relay-only transport
    if (priv.forceRelay || priv.forceTcp) {
        config.iceTransportPolicy = 'relay';
    }

    // Enable Insertable Streams for E2E media frame encryption (legacy Chrome 86–117 only)
    if (needsEncodedInsertableStreams()) {
        config.encodedInsertableStreams = true;
    }

    return config;
}

// Traffic masking: pad SDP with random a= attributes and randomize session params
function _maskSdp(sdp) {
    const priv = _getCallPrivacySettings();
    if (!priv.trafficMask) return sdp;

    // 1. Randomize session ID and version in o= line to prevent fingerprinting
    sdp = sdp.replace(
        /^(o=\S+\s+)\d+(\s+)\d+(\s+.*$)/m,
        (match, pre, sp1, post) => {
            const randId  = Math.floor(Math.random() * 9e18) + 1e18;
            const randVer = Math.floor(Math.random() * 9e8)  + 1e8;
            return `${pre}${randId}${sp1}${randVer}${post}`;
        }
    );

    // 2. Add random padding attributes to each media section
    //    These are ignored by SDP parsers (unknown a= lines are skipped per RFC 4566)
    const padCount = 2 + Math.floor(Math.random() * 4);  // 2-5 padding lines
    const padLines = [];
    for (let i = 0; i < padCount; i++) {
        const padLen = 16 + Math.floor(Math.random() * 48);
        const chars  = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let padVal   = '';
        for (let j = 0; j < padLen; j++) {
            padVal += chars[Math.floor(Math.random() * chars.length)];
        }
        padLines.push(`a=x-opad:${padVal}`);
    }
    const padding = padLines.join('\r\n') + '\r\n';

    // Insert padding before each m= line (except the first)
    const sections = sdp.split(/(?=^m=)/m);
    sdp = sections.map((section, idx) => {
        if (idx === 0) return section;
        return section.replace(/\r\n$/, '\r\n' + padding);
    }).join('');

    // Also add padding at end if not already there
    if (!sdp.endsWith('\r\n')) sdp += '\r\n';
    sdp += padding;

    return sdp;
}

// Show/hide privacy badge on call overlay
function _updatePrivacyBadge() {
    const priv  = _getCallPrivacySettings();
    const show  = priv.forceRelay || priv.forceTcp || priv.trafficMask;
    let badge   = document.getElementById('wrtc-privacy-badge');

    if (!show) {
        if (badge) badge.style.display = 'none';
        return;
    }

    const overlay = document.getElementById('call-overlay');
    if (!overlay) return;

    if (!badge) {
        badge = document.createElement('div');
        badge.id = 'wrtc-privacy-badge';
        badge.style.cssText = [
            'position:absolute', 'top:12px', 'left:14px',
            'display:inline-flex', 'align-items:center', 'gap:5px',
            'padding:4px 10px', 'border-radius:8px',
            'background:rgba(39,174,96,.15)',
            'border:1px solid rgba(39,174,96,.3)',
            'font-size:11px', 'font-weight:700', 'color:#27ae60',
            'z-index:10', 'backdrop-filter:blur(8px)',
            '-webkit-backdrop-filter:blur(8px)',
        ].join(';');
        overlay.appendChild(badge);
    }

    // Shield SVG icon
    const shieldSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 24 24">' +
        '<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>';

    let label = '';
    if (priv.forceTcp) label = 'TCP RELAY';
    else if (priv.forceRelay) label = 'RELAY';

    if (priv.trafficMask) label += (label ? ' + ' : '') + 'MASK';

    badge.innerHTML = shieldSvg + ' ' + label;
    badge.style.display = 'inline-flex';
}

// ----------------------------------------------------------------------------
// RTCPeerConnection
// ----------------------------------------------------------------------------
function createPeerConnection() {
    const config = _buildRtcConfig();
    const pc = new RTCPeerConnection(config);

    console.info('[WebRTC] PeerConnection config:', JSON.stringify({
        iceTransportPolicy: config.iceTransportPolicy ?? 'all',
        serverCount: config.iceServers?.length ?? 0,
    }));

    pc.onicecandidate = e => {
        if (!e.candidate) return;
        // Force TCP: drop non-TCP candidates
        const priv = _getCallPrivacySettings();
        if (priv.forceTcp) {
            const c = e.candidate;
            // Only allow TCP relay candidates
            if (c.protocol && c.protocol.toLowerCase() !== 'tcp') return;
            if (c.type && c.type !== 'relay') return;
        }
        signal({ type: 'ice', candidate: e.candidate.toJSON() });
    };

    pc.ontrack = e => {
        console.log('ontrack:', e.track.kind, e.streams[0]);
        $('remote-video').srcObject = e.streams[0];
        $('call-status').textContent = t('call.connected');
    };

    pc.onconnectionstatechange = () => {
        const state = pc.connectionState;
        console.log('RTCPeerConnection state:', state);

        if (state === 'connected') {
            $('call-status').textContent = t('call.inCall');
            _startStatsMonitor(pc);
        }
        if (state === 'disconnected') {
            _setQualityBadge('?', 'grey');
        }
        if (['failed', 'closed'].includes(state) && !_isHangingUp) {
            hangup();
        }
    };

    return pc;
}

// ============================================================================
// МОНИТОРИНГ И АДАПТИВНОЕ УПРАВЛЕНИЕ КАЧЕСТВОМ
// ============================================================================

function _startStatsMonitor(pc) {
    _stopStatsMonitor();
    _prevStats = null;
    _ensureQualityBadge();

    _statsInterval = setInterval(async () => {
        if (!pc || pc.connectionState !== 'connected') {
            _stopStatsMonitor();
            return;
        }
        try {
            const metrics = await _collectStats(pc);
            if (metrics) {
                _applyMetricsToUI(metrics);
                await _adaptQuality(pc, metrics);   // ← адаптивное управление
            }
        } catch (e) {
            console.debug('getStats error:', e);
        }
    }, 2000);
}

function _stopStatsMonitor() {
    if (_statsInterval) {
        clearInterval(_statsInterval);
        _statsInterval = null;
    }
    _prevStats = null;
}

async function _collectStats(pc) {
    const statsReport = await pc.getStats();
    const now         = Date.now();

    let rtt         = null;
    let jitter      = null;
    let packetsLost = null;
    let packetsRecv = null;
    let bytesRecv   = null;
    let transport   = null;

    statsReport.forEach(report => {
        if (report.type === 'candidate-pair' && report.state === 'succeeded') {
            if (report.currentRoundTripTime != null) {
                const candidate_rtt = report.currentRoundTripTime * 1000;
                if (rtt === null || candidate_rtt < rtt) rtt = candidate_rtt;
            }
        }
        if (report.type === 'inbound-rtp' && report.kind === 'audio') {
            if (report.jitter      != null) jitter      = report.jitter * 1000;
            if (report.packetsLost != null) packetsLost = report.packetsLost;
            if (report.packetsReceived != null) packetsRecv = report.packetsReceived;
            if (report.bytesReceived   != null) bytesRecv   = report.bytesReceived;
        }
        if (report.type === 'local-candidate' && report.candidateType) {
            const priority = { relay: 3, srflx: 2, host: 1 };
            const cur_p    = priority[report.candidateType] ?? 0;
            const prev_p   = priority[transport] ?? 0;
            if (cur_p > prev_p) transport = report.candidateType;
        }
    });

    let lossPercent = null;
    let bitrateKbps = null;

    if (_prevStats) {
        const dt = (now - _prevStats.ts) / 1000;
        if (packetsLost != null && _prevStats.packetsLost != null &&
            packetsRecv != null && _prevStats.packetsRecv != null) {
            const deltaLost  = Math.max(0, packetsLost - _prevStats.packetsLost);
            const deltaRecv  = Math.max(0, packetsRecv - _prevStats.packetsRecv);
            const deltaTotal = deltaLost + deltaRecv;
            lossPercent = deltaTotal > 0 ? (deltaLost / deltaTotal) * 100 : 0;
        }
        if (bytesRecv != null && _prevStats.bytesRecv != null && dt > 0) {
            const deltaBytes = Math.max(0, bytesRecv - _prevStats.bytesRecv);
            bitrateKbps = (deltaBytes * 8) / dt / 1000;
        }
    }

    _prevStats = { ts: now, packetsLost, packetsRecv, bytesRecv };

    if (rtt === null && jitter === null && lossPercent === null) return null;
    return { rtt, jitter, lossPercent, bitrateKbps, transport };
}

// ── Адаптивное управление качеством ──────────────────────────────────────────

/**
 * Конечный автомат адаптивного управления качеством.
 *
 * Логика:
 *   - Если сеть плохая (poor) → понижаем уровень на один шаг вниз
 *   - Если сеть справедливая (fair) → держим текущий уровень
 *   - Если сеть хорошая (good) N раз подряд → повышаем уровень на шаг
 *
 * Уровни (от высшего к низшему): high → medium → low → audio_only
 */
async function _adaptQuality(pc, metrics) {
    if (!pc) return;

    const { rtt, lossPercent, jitter } = metrics;

    // Определяем состояние сети
    let networkState = 'good';
    if (
        (rtt         != null && rtt         > QUALITY.FAIR.rtt)   ||
        (lossPercent != null && lossPercent > QUALITY.FAIR.loss)  ||
        (jitter      != null && jitter      > QUALITY.FAIR.jitter)
    ) networkState = 'poor';
    else if (
        (rtt         != null && rtt         > QUALITY.GOOD.rtt)   ||
        (lossPercent != null && lossPercent > QUALITY.GOOD.loss)  ||
        (jitter      != null && jitter      > QUALITY.GOOD.jitter)
    ) networkState = 'fair';

    const levels = ['audio_only', 'low', 'medium', 'high'];
    const curIdx = levels.indexOf(_currentQualityLevel);

    let newLevel = _currentQualityLevel;

    if (networkState === 'poor') {
        // Понижаем качество
        _qualityStableCount = 0;
        if (curIdx > 0) newLevel = levels[curIdx - 1];
    } else if (networkState === 'good') {
        // Считаем стабильные итерации
        _qualityStableCount++;
        if (_qualityStableCount >= QUALITY_UPGRADE_THRESHOLD && curIdx < levels.length - 1) {
            newLevel            = levels[curIdx + 1];
            _qualityStableCount = 0;
        }
    } else {
        // fair — ничего не меняем
        _qualityStableCount = 0;
    }

    if (newLevel !== _currentQualityLevel) {
        console.info(`[AdaptiveQuality] ${_currentQualityLevel} → ${newLevel} (net=${networkState})`);
        _currentQualityLevel = newLevel;
        await _applyQualityLevel(pc, newLevel);
    }
}

/**
 * Применяет уровень качества к RTCPeerConnection через setParameters().
 */
async function _applyQualityLevel(pc, level) {
    const senders = pc.getSenders();

    for (const sender of senders) {
        if (!sender.track) continue;
        try {
            const params = sender.getParameters();
            if (!params.encodings || params.encodings.length === 0) {
                params.encodings = [{}];
            }

            if (sender.track.kind === 'video') {
                if (level === 'audio_only') {
                    // Отключаем видео трек
                    sender.track.enabled = false;
                    params.encodings[0].maxBitrate = 0;
                } else {
                    sender.track.enabled = true;
                    params.encodings[0].maxBitrate = VIDEO_BITRATES[level];
                    // Для низкого качества ещё понижаем framerate
                    if (level === 'low')   params.encodings[0].maxFramerate = 15;
                    if (level === 'medium') params.encodings[0].maxFramerate = 24;
                    if (level === 'high')   delete params.encodings[0].maxFramerate;
                }
            } else if (sender.track.kind === 'audio') {
                const targetBitrate = AUDIO_BITRATES[level] ?? AUDIO_BITRATES.medium;
                params.encodings[0].maxBitrate = targetBitrate;
            }

            await sender.setParameters(params);
        } catch (e) {
            console.debug(`[AdaptiveQuality] setParameters failed for ${sender.track.kind}:`, e.message);
        }
    }

    // Обновляем UI
    const levelLabel = { high: '\u25CF HD', medium: '\u25CF SD', low: '\u25CF Low', audio_only: '\u25CF Audio' }[level];
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('sp-quality-level', levelLabel);

    // Показываем уведомление пользователю при деградации
    if (level !== 'high') {
        const statusEl = $('call-status');
        if (statusEl) {
            const prev = statusEl.textContent;
            statusEl.textContent = t('call.networkAdaptation').replace('{level}', levelLabel);
            setTimeout(() => { if (statusEl) statusEl.textContent = prev; }, 3000);
        }
    }
}

// ── Отображение метрик в UI ────────────────────────────────────────────────────

function _applyMetricsToUI(metrics) {
    const { rtt, jitter, lossPercent, bitrateKbps, transport } = metrics;

    let level = 'good';
    if (
        (rtt         != null && rtt         > QUALITY.FAIR.rtt)   ||
        (lossPercent != null && lossPercent > QUALITY.FAIR.loss)  ||
        (jitter      != null && jitter      > QUALITY.FAIR.jitter)
    ) level = 'poor';
    else if (
        (rtt         != null && rtt         > QUALITY.GOOD.rtt)   ||
        (lossPercent != null && lossPercent > QUALITY.GOOD.loss)  ||
        (jitter      != null && jitter      > QUALITY.GOOD.jitter)
    ) level = 'fair';

    const colors = { good: '#27ae60', fair: '#f39c12', poor: '#e74c3c' };
    const labels = { good: t('call.qualityGood'), fair: t('call.qualityFair'), poor: t('call.qualityPoor') };

    const rttVal = document.getElementById('wrtc-rtt-val');
    const dot    = document.getElementById('wrtc-dot');
    if (rttVal) rttVal.textContent = rtt != null ? `${rtt.toFixed(0)} ms` : '—';
    if (dot)    dot.style.background = colors[level];

    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('sp-rtt',    rtt         != null ? `${rtt.toFixed(0)} ms`           : '—');
    set('sp-jitter', jitter      != null ? `${jitter.toFixed(0)} ms`        : '—');
    set('sp-loss',   lossPercent != null ? `${lossPercent.toFixed(1)} %`    : '—');
    set('sp-brate',  bitrateKbps != null ? `${bitrateKbps.toFixed(0)} kbps` : '—');
    set('sp-type',   transport ? _transportLabel(transport) : '—');
    set('sp-qual',   labels[level]);

    const qualEl = document.getElementById('sp-qual');
    if (qualEl) qualEl.style.color = colors[level];

    const upd = document.getElementById('sp-updated');
    if (upd) upd.textContent = t('call.statsUpdated').replace('{time}', new Date().toLocaleTimeString());

    console.debug('[WebRTC Stats]',
        `RTT=${rtt?.toFixed(0)}мс jitter=${jitter?.toFixed(0)}мс ` +
        `loss=${lossPercent?.toFixed(1)}% brate=${bitrateKbps?.toFixed(0)}kbps [${transport}] ` +
        `quality=${_currentQualityLevel}`);
}

function _transportLabel(type) {
    return { host: 'Direct (LAN)', srflx: 'NAT (STUN)', relay: 'Relay (TURN)' }[type] ?? type;
}

// ── DOM: элементы overlay + статистика ────────────────────────────────────────

function _ensureQualityBadge() {
    if ($('wrtc-rtt-badge')) return;

    const overlay = $('call-overlay');
    if (!overlay) return;

    // RTT inline badge
    const rttBadge = document.createElement('div');
    rttBadge.id = 'wrtc-rtt-badge';
    rttBadge.style.cssText = [
        'display:inline-flex', 'align-items:center', 'gap:5px',
        'margin-top:6px', 'font-size:13px', 'font-weight:600',
        'color:#bbb', 'min-height:18px',
    ].join(';');
    rttBadge.innerHTML =
        '<span id="wrtc-dot" style="width:8px;height:8px;border-radius:50%;' +
        'background:#555;flex-shrink:0;transition:background .3s"></span>' +
        '<span style="color:#888;font-weight:400">Latency:</span>' +
        '<span id="wrtc-rtt-val" style="font-variant-numeric:tabular-nums">—</span>';

    const statusEl = $('call-status');
    if (statusEl?.parentNode) statusEl.parentNode.insertBefore(rttBadge, statusEl.nextSibling);
    else overlay.appendChild(rttBadge);

    // ⚙ кнопка
    const gearBtn = document.createElement('button');
    gearBtn.id    = 'wrtc-gear-btn';
    gearBtn.title = t('call.stats');
    gearBtn.innerHTML =
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">' +
        '<path d="M19.14,12.94c0.04-0.3,0.06-0.61,0.06-0.94c0-0.32-0.02-0.64-0.07-0.94l2.03-1.58' +
        'c0.18-0.14,0.23-0.41,0.12-0.61l-1.92-3.32c-0.12-0.22-0.37-0.29-0.59-0.22l-2.39,0.96' +
        'c-0.5-0.38-1.03-0.7-1.62-0.94L14.4,2.81c-0.04-0.24-0.24-0.41-0.48-0.41h-3.84' +
        'c-0.24,0-0.43,0.17-0.47,0.41L9.25,5.35C8.66,5.59,8.12,5.92,7.63,6.29L5.24,5.33' +
        'c-0.22-0.08-0.47,0-0.59,0.22L2.74,8.87C2.62,9.08,2.66,9.34,2.86,9.48l2.03,1.58' +
        'C4.84,11.36,4.8,11.69,4.8,12s0.02,0.64,0.07,0.94l-2.03,1.58c-0.18,0.14-0.23,0.41-0.12,0.61' +
        'l1.92,3.32c0.12,0.22,0.37,0.29,0.59,0.22l2.39-0.96c0.5,0.38,1.03,0.7,1.62,0.94l0.36,2.54' +
        'c0.05,0.24,0.24,0.41,0.48,0.41h3.84c0.24,0,0.44-0.17,0.47-0.41l0.36-2.54' +
        'c0.59-0.24,1.13-0.56,1.62-0.94l2.39,0.96c0.22,0.08,0.47,0,0.59-0.22l1.92-3.32' +
        'c0.12-0.22,0.07-0.47-0.12-0.61L19.14,12.94z' +
        'M12,15.6c-1.98,0-3.6-1.62-3.6-3.6s1.62-3.6,3.6-3.6s3.6,1.62,3.6,3.6S13.98,15.6,12,15.6z"/>' +
        '</svg>';
    gearBtn.style.cssText = [
        'position:absolute', 'top:12px', 'right:14px',
        'background:rgba(255,255,255,.08)', 'border:none',
        'border-radius:50%', 'width:32px', 'height:32px',
        'cursor:pointer', 'color:#aaa',
        'display:flex', 'align-items:center', 'justify-content:center',
        'transition:background .2s,color .2s', 'z-index:10',
    ].join(';');
    gearBtn.onmouseenter = () => { gearBtn.style.background='rgba(255,255,255,.18)'; gearBtn.style.color='#fff'; };
    gearBtn.onmouseleave = () => { gearBtn.style.background='rgba(255,255,255,.08)'; gearBtn.style.color='#aaa'; };
    gearBtn.onclick = _toggleStatsPanel;
    overlay.appendChild(gearBtn);

    // Панель статистики
    const panel = document.createElement('div');
    panel.id = 'wrtc-stats-panel';
    panel.style.cssText = [
        'position:absolute', 'top:50px', 'right:14px',
        'background:rgba(8,8,18,.93)',
        'backdrop-filter:blur(14px)', '-webkit-backdrop-filter:blur(14px)',
        'border:1px solid rgba(255,255,255,.1)',
        'border-radius:12px', 'padding:14px 18px 12px',
        'min-width:260px', 'font-size:12px', 'line-height:2.0',
        'color:#ddd', 'display:none', 'z-index:20',
        'box-shadow:0 8px 32px rgba(0,0,0,.6)',
    ].join(';');
    panel.innerHTML =
        '<div style="font-size:13px;font-weight:700;margin-bottom:10px;' +
        'color:#fff;display:flex;align-items:center;gap:7px">' +
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg> <span>' + t('call.stats') + '</span></div>' +
        '<table style="border-collapse:collapse;width:100%">' +
        '<tr><td style="color:#666;padding-right:14px;white-space:nowrap">Latency (RTT)</td>' +
        '<td id="sp-rtt"           style="font-weight:700;text-align:right;font-variant-numeric:tabular-nums">—</td></tr>' +
        '<tr><td style="color:#666">Jitter</td>' +
        '<td id="sp-jitter"        style="font-weight:700;text-align:right;font-variant-numeric:tabular-nums">—</td></tr>' +
        '<tr><td style="color:#666">Packet loss</td>' +
        '<td id="sp-loss"          style="font-weight:700;text-align:right;font-variant-numeric:tabular-nums">—</td></tr>' +
        '<tr><td style="color:#666">Inbound stream</td>' +
        '<td id="sp-brate"         style="font-weight:700;text-align:right;font-variant-numeric:tabular-nums">—</td></tr>' +
        '<tr><td style="color:#666">Connection type</td>' +
        '<td id="sp-type"          style="font-weight:700;text-align:right">—</td></tr>' +
        '<tr><td style="color:#666">Network quality</td>' +
        '<td id="sp-qual"          style="font-weight:700;text-align:right">—</td></tr>' +
        '<tr><td style="color:#666">Video level</td>' +
        '<td id="sp-quality-level" style="font-weight:700;text-align:right">—</td></tr>' +
        '</table>' +
        '<div id="sp-updated" style="margin-top:10px;padding-top:8px;' +
        'border-top:1px solid rgba(255,255,255,.07);' +
        'font-size:10px;color:#444;text-align:right">waiting for data...</div>';
    overlay.appendChild(panel);

    document.addEventListener('click', e => {
        const p = $('wrtc-stats-panel');
        const g = $('wrtc-gear-btn');
        if (p && g && !p.contains(e.target) && !g.contains(e.target))
            p.style.display = 'none';
    });

    if (!document.getElementById('wrtc-style')) {
        const s = document.createElement('style');
        s.id = 'wrtc-style';
        s.textContent =
            '#wrtc-stats-panel{animation:wrtc-fade .15s ease}' +
            '@keyframes wrtc-fade{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}' +
            '@keyframes ring{0%,100%{transform:rotate(-15deg)}50%{transform:rotate(15deg)}}' +
            '#call-ring-emoji{animation:ring .5s infinite;display:inline-block}';
        document.head.appendChild(s);
    }
}

function _toggleStatsPanel() {
    const p = $('wrtc-stats-panel');
    if (!p) return;
    p.style.display = p.style.display === 'none' ? 'block' : 'none';
}

function _setQualityBadge(icon, color) {
    const dot = document.getElementById('wrtc-dot');
    if (dot) dot.style.background = color;
}

// ----------------------------------------------------------------------------
// Обработка сигнальных сообщений
// ----------------------------------------------------------------------------
async function handleSignal(msg) {
    if (msg.type && msg.type.startsWith('group_')) {
        const gc = await import('./group_call.js');
        gc.handleGroupSignal(msg);
        return;
    }
    const S = window.AppState;
    const from = msg.from;

    if (msg.type === 'invite') {
        if ($('call-overlay').classList.contains('show')) return;
        _incomingCallFrom = from;
        S._offerHasVideo  = !!msg.hasVideo;
        showIncomingCallUI(msg.username || t('notifications.unknown'));
        return;
    }

    if (msg.type === 'offer') {
        if (!S.pc) S.pc = createPeerConnection();
        S._offerHasVideo = S._offerHasVideo ?? _sdpHasVideo(msg.sdp);
        await S.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        S._pendingOfferFrom = from;
    }

    if (msg.type === 'answer') {
        if (S.pc?.signalingState !== 'stable') {
            await S.pc?.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
        }
    }

    if (msg.type === 'ice') {
        try {
            if (S.pc?.remoteDescription) {
                await S.pc.addIceCandidate(msg.candidate);
            } else {
                if (!S._pendingCandidates) S._pendingCandidates = [];
                S._pendingCandidates.push(msg.candidate);
            }
        } catch (e) { console.warn('ICE error:', e.message); }
    }

    if (msg.type === 'bye') {
        hideIncomingCallUI();
        hangup();
    }
}

// ----------------------------------------------------------------------------
// UI
// ----------------------------------------------------------------------------
function _showCallOverlay({ name, avatar, status, hasVideo }) {
    const overlay = $('call-overlay');
    if (!overlay) { console.error('call-overlay не найден в DOM'); return; }

    _ensureQualityBadge();

    const peerName   = $('call-peer-name');
    const peerAvatar = $('call-peer-avatar');
    const callStatus = $('call-status');
    const localVideo = $('local-video');

    if (peerName)   peerName.textContent   = name;
    if (peerAvatar) peerAvatar.textContent = avatar;
    if (callStatus) callStatus.textContent = status;
    if (localVideo) localVideo.srcObject   = window.AppState.localStream ?? null;

    // Hide pip if it was visible
    const pip = document.getElementById('call-pip');
    if (pip) pip.classList.remove('show');

    overlay.classList.add('show');
    _setQualityBadge('\u2699', '#888');
    _updatePrivacyBadge();

    // Start call duration timer
    _callDurationSec = 0;
    clearInterval(_callTimerInterval);
    _callTimerInterval = setInterval(() => {
        _callDurationSec++;
        const m = Math.floor(_callDurationSec / 60);
        const s = String(_callDurationSec % 60).padStart(2, '0');
        const timerEl = document.getElementById('cp-timer');
        if (timerEl) timerEl.textContent = `${m}:${s}`;
    }, 1000);
}

function showIncomingCallUI(callerName) {
    let banner = $('incoming-call-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'incoming-call-banner';
        banner.style.cssText = [
            'position:fixed', 'top:20px', 'left:50%', 'transform:translateX(-50%)',
            'background:#1a1a2e', 'border:2px solid #4ecdc4', 'border-radius:16px',
            'padding:20px 28px', 'z-index:9999', 'display:flex', 'align-items:center',
            'gap:16px', 'box-shadow:0 8px 32px rgba(0,0,0,.6)',
            'font-family:sans-serif', 'color:#e0e0e0'
        ].join(';');

        banner.innerHTML = `
            <div style="font-size:32px;display:flex;align-items:center;" id="call-ring-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 24 24"><path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z"/></svg></div>
            <div>
                <div id="incoming-caller-name" style="font-weight:700;font-size:16px;margin-bottom:4px"></div>
                <div style="font-size:13px;color:#4ecdc4" id="incoming-call-type">${t('call.incoming')}</div>
            </div>
            <div style="display:flex;gap:10px;margin-left:12px">
                <button onclick="window.acceptCall()"
                    title="${t('notifications.answer')}"
                    style="background:#27ae60;color:#fff;border:none;border-radius:50%;
                           width:48px;height:48px;font-size:22px;cursor:pointer;display:flex;align-items:center;justify-content:center"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></button>
                <button onclick="window.declineCall()"
                    title="${t('notifications.decline')}"
                    style="background:#e74c3c;color:#fff;border:none;border-radius:50%;
                           width:48px;height:48px;font-size:22px;cursor:pointer;display:flex;align-items:center;justify-content:center"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></button>
            </div>`;

        if (!document.getElementById('webrtc-style')) {
            const style = document.createElement('style');
            style.id = 'webrtc-style';
            style.textContent =
                '@keyframes ring { 0%,100%{transform:rotate(-15deg)} 50%{transform:rotate(15deg)} }' +
                '#call-ring-emoji { animation: ring .5s infinite; display:inline-block; }';
            document.head.appendChild(style);
        }
        document.body.appendChild(banner);
    }

    const nameEl = document.getElementById('incoming-caller-name');
    const typeEl = document.getElementById('incoming-call-type');
    if (nameEl) nameEl.textContent = callerName + ' ' + t('call.isCalling');
    if (typeEl) typeEl.textContent = window.AppState._offerHasVideo
        ? t('call.incomingVideo')
        : t('call.incoming');
    banner.style.display = 'flex';

    // Воспроизводим рингтон входящего звонка
    playCallSound();
}

function hideIncomingCallUI() {
    const banner = $('incoming-call-banner');
    if (banner) banner.style.display = 'none';
    stopCallSound();
}

// ----------------------------------------------------------------------------
// Принять / отклонить / завершить
// ----------------------------------------------------------------------------
export async function acceptCall() {
    const S = window.AppState;
    hideIncomingCallUI();
    const needVideo = !!S._offerHasVideo;
    try {
        S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: needVideo });
        $('local-video').srcObject = S.localStream;
    } catch (e) {
        if (needVideo) {
            try {
                S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
                $('local-video').srcObject = S.localStream;
            } catch (e2) { console.warn('Нет микрофона:', e2.message); }
        } else { console.warn('Нет микрофона:', e.message); }
    }
    if (S.pc && S.localStream) {
        S.localStream.getTracks().forEach(t => {
            try { S.pc.addTrack(t, S.localStream); } catch {}
        });
        // E2E media frame encryption (answering side)
        _e2eMediaKey = null;
        const aRoomKey = getRoomKey(S.currentRoom?.id);
        if (aRoomKey && isE2ESupported()) {
            try {
                _e2eMediaKey = await deriveMediaKey(aRoomKey, `call-${S.currentRoom.id}-${Date.now()}`);
                setupPeerE2E(S.pc, _e2eMediaKey);
                console.log('[WebRTC] E2E media encryption active (answer)');
            } catch (e) { console.warn('[WebRTC] E2E setup failed:', e.message); }
        }
    }
    const to = S._pendingOfferFrom;
    if (S.pc?.signalingState === 'have-remote-offer') {
        const answer = await S.pc.createAnswer();
        await S.pc.setLocalDescription(answer);
        signal({ type: 'answer', sdp: _maskSdp(answer.sdp), to });
    }
    S._pendingOfferFrom = null;
    if (S._pendingCandidates?.length) {
        for (const c of S._pendingCandidates) {
            try { await S.pc.addIceCandidate(c); } catch {}
        }
        S._pendingCandidates = [];
    }

    S.isCamOff           = !needVideo;
    _currentQualityLevel = 'high';
    _qualityStableCount  = 0;
    _updateCamBtn(S.isCamOff);

    _showCallOverlay({
        name:     t('notifications.unknown'),
        avatar:   '\u{1F464}',
        status:   'Connecting...',
        hasVideo: needVideo,
    });
    _isHangingUp = false;
    _updatePrivacyBadge();
}

export function declineCall() {
    const S = window.AppState;
    hideIncomingCallUI();
    signal({ type: 'bye', to: _incomingCallFrom });
    S._pendingAnswer     = null;
    S._pendingCandidates = [];
    S._offerHasVideo     = null;
    S._pendingOfferFrom  = null;
    if (S.pc) {
        S.pc.onconnectionstatechange = null;
        S.pc.onicecandidate          = null;
        S.pc.ontrack                 = null;
        S.pc.close();
        S.pc = null;
    }
    _incomingCallFrom    = null;
    _currentQualityLevel = 'high';
    _stopStatsMonitor();
}

// ----------------------------------------------------------------------------
// Minimize / expand call
// ----------------------------------------------------------------------------
export function minimizeCall() {
    const overlay = $('call-overlay');
    const pip     = document.getElementById('call-pip');
    if (!overlay || !pip) return;

    // Copy name + avatar into pip
    const pipName   = document.getElementById('cp-name');
    const pipAvatar = document.getElementById('cp-avatar');
    const peerName  = document.getElementById('call-peer-name');
    const peerAv    = document.getElementById('call-peer-avatar');
    if (pipName   && peerName)  pipName.textContent   = peerName.textContent;
    if (pipAvatar && peerAv)    pipAvatar.textContent  = peerAv.textContent;

    // Sync mute button state
    _syncPipMuteBtn();

    overlay.classList.remove('show');
    pip.classList.add('show');
}

export function expandCall() {
    const overlay = $('call-overlay');
    const pip     = document.getElementById('call-pip');
    if (!overlay || !pip) return;
    pip.classList.remove('show');
    overlay.classList.add('show');
}

function _syncPipMuteBtn() {
    const btn = document.getElementById('cp-mute-btn');
    if (!btn) return;
    const muted = window.AppState?.isMuted;
    btn.classList.toggle('cp-muted', !!muted);
    btn.title = muted ? t('call.unmuteMic') : t('call.muteMic');
}

export function hangup() {
    if (_isHangingUp) return;
    _isHangingUp = true;

    const S = window.AppState;
    signal({ type: 'bye' });
    _stopStatsMonitor();

    if (S.pc) {
        S.pc.onconnectionstatechange = null;
        S.pc.onicecandidate          = null;
        S.pc.ontrack                 = null;
        S.pc.close();
        S.pc = null;
    }

    S.localStream?.getTracks().forEach(t => t.stop());
    S.localStream = null;
    _e2eMediaKey  = null;

    $('remote-video').srcObject = null;
    $('local-video').srcObject  = null;
    $('call-overlay').classList.remove('show');

    // Hide pip and stop timer
    const pip = document.getElementById('call-pip');
    if (pip) pip.classList.remove('show');
    clearInterval(_callTimerInterval);
    _callTimerInterval = null;
    _callDurationSec   = 0;

    hideIncomingCallUI();

    const detailEl = $('call-quality-detail');
    if (detailEl) detailEl.textContent = '';

    // Hide privacy badge
    const privBadge = document.getElementById('wrtc-privacy-badge');
    if (privBadge) privBadge.style.display = 'none';

    S._pendingAnswer     = null;
    S._pendingCandidates = [];
    S._offerHasVideo     = null;
    S._pendingOfferFrom  = null;
    _incomingCallFrom    = null;
    S.isMuted            = false;
    S.isCamOff           = false;
    _isScreenSharing     = false;
    _originalVideoTrack  = null;
    _currentQualityLevel = 'high';
    _qualityStableCount  = 0;
    _updateMuteBtn(false);
    _updateCamBtn(false);
    _updateScreenBtn(false);

    setTimeout(() => { _isHangingUp = false; }, 500);
}

// ----------------------------------------------------------------------------
// Управление медиа-треками
// ----------------------------------------------------------------------------
export function toggleMute() {
    const S = window.AppState;
    S.isMuted = !S.isMuted;
    S.localStream?.getAudioTracks().forEach(t => { t.enabled = !S.isMuted; });
    _updateMuteBtn(S.isMuted);
}

export async function toggleCam() {
    const S = window.AppState;
    const existingVideoTracks = S.localStream?.getVideoTracks() ?? [];

    if (existingVideoTracks.length > 0) {
        S.isCamOff = !S.isCamOff;
        existingVideoTracks.forEach(t => { t.enabled = !S.isCamOff; });
        _updateCamBtn(S.isCamOff);
        return;
    }
    if (!S.pc) { console.warn('toggleCam: нет RTCPeerConnection'); return; }

    try {
        const videoStream = await navigator.mediaDevices.getUserMedia({ video: true });
        const videoTrack  = videoStream.getVideoTracks()[0];

        if (S.localStream) S.localStream.addTrack(videoTrack);
        else S.localStream = videoStream;

        $('local-video').srcObject = S.localStream;
        S.pc.addTrack(videoTrack, S.localStream);
        S.isCamOff = false;
        _updateCamBtn(false);

        const offer = await S.pc.createOffer();
        await S.pc.setLocalDescription(offer);
        signal({ type: 'offer', sdp: _maskSdp(offer.sdp) });
    } catch (e) { alert(t('call.cameraError').replace('{error}', e.message)); }
}

// ----------------------------------------------------------------------------
// Демонстрация экрана
// ----------------------------------------------------------------------------

let _isScreenSharing = false;
let _originalVideoTrack = null;

export async function toggleScreenShare() {
    const S = window.AppState;
    if (!S.pc) { console.warn('toggleScreenShare: нет RTCPeerConnection'); return; }

    if (_isScreenSharing) {
        // Выключаем демонстрацию — возвращаем камеру или убираем видео
        _stopScreenShare();
        return;
    }

    try {
        const screenStream = await navigator.mediaDevices.getDisplayMedia({
            video: { cursor: 'always' },
            audio: false,
        });
        const screenTrack = screenStream.getVideoTracks()[0];

        // Сохраняем текущий видеотрек (камера) для восстановления
        const sender = S.pc.getSenders().find(s => s.track?.kind === 'video');

        if (sender) {
            _originalVideoTrack = sender.track;
            await sender.replaceTrack(screenTrack);
        } else {
            S.pc.addTrack(screenTrack, screenStream);
            // Нужен re-offer
            const offer = await S.pc.createOffer();
            await S.pc.setLocalDescription(offer);
            signal({ type: 'offer', sdp: _maskSdp(offer.sdp) });
        }

        // Показываем экран в local-video
        $('local-video').srcObject = screenStream;

        _isScreenSharing = true;
        _updateScreenBtn(true);

        // Когда пользователь нажмёт "Прекратить показ" в браузере
        screenTrack.onended = () => _stopScreenShare();

    } catch (e) {
        if (e.name !== 'NotAllowedError') {
            alert(t('call.screenShareError').replace('{error}', e.message));
        }
    }
}

async function _stopScreenShare() {
    const S = window.AppState;
    if (!S.pc) return;

    const sender = S.pc.getSenders().find(s => s.track?.kind === 'video');

    if (sender) {
        // Останавливаем screen track
        sender.track?.stop();

        if (_originalVideoTrack && !_originalVideoTrack.readyState === 'ended') {
            // Возвращаем камеру
            await sender.replaceTrack(_originalVideoTrack);
            if (S.localStream) {
                $('local-video').srcObject = S.localStream;
            }
        } else {
            // Камеры не было — просто убираем видео
            await sender.replaceTrack(null);
            $('local-video').srcObject = S.localStream || null;
        }
    }

    _isScreenSharing = false;
    _originalVideoTrack = null;
    _updateScreenBtn(false);
}

function _updateScreenBtn(active) {
    const btn = $('screen-btn');
    if (btn) {
        btn.style.background = active ? 'var(--accent)' : '';
        btn.style.color = active ? '#fff' : '';
        btn.title = active ? 'Stop screen sharing' : 'Screen sharing';
    }
}

// ----------------------------------------------------------------------------
// Кнопки
// ----------------------------------------------------------------------------
function _updateMuteBtn(muted) {
    _syncPipMuteBtn();
    $('mute-btn').innerHTML = muted
        ? '<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" viewBox="0 0 24 24"><path d="M8.03 12.27a3.98 3.98 0 0 0 3.7 3.7zM20 12h-2c0 1.29-.42 2.49-1.12 3.47l-1.44-1.44c.36-.59.56-1.28.56-2.02v-6c0-2.21-1.79-4-4-4s-4 1.79-4 4v.59L2.71 1.29 1.3 2.7l20 20 1.41-1.41-4.4-4.4A7.9 7.9 0 0 0 20 12M10 6c0-1.1.9-2 2-2s2 .9 2 2v6c0 .18-.03.35-.07.51L10 8.58V5.99Z"></path><path d="M12 18c-3.31 0-6-2.69-6-6H4c0 4.07 3.06 7.44 7 7.93V22h2v-2.07c.74-.09 1.45-.29 2.12-.57l-1.57-1.57c-.49.13-1.01.21-1.55.21"></path></svg>'
        : '<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" viewBox="0 0 24 24"><path d="M16 12V6c0-2.21-1.79-4-4-4S8 3.79 8 6v6c0 2.21 1.79 4 4 4s4-1.79 4-4m-6 0V6c0-1.1.9-2 2-2s2 .9 2 2v6c0 1.1-.9 2-2 2s-2-.9-2-2"></path><path d="M18 12c0 3.31-2.69 6-6 6s-6-2.69-6-6H4c0 4.07 3.06 7.44 7 7.93V22h2v-2.07c3.94-.49 7-3.86 7-7.93z"></path></svg>';
}

function _updateCamBtn(camOff) {
    $('cam-btn').innerHTML = camOff
        ? '<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" viewBox="0 0 24 24"><path d="M4 18V8.24L2.12 6.36c-.07.2-.12.42-.12.64v11c0 1.1.9 2 2 2h11.76l-2-2zm18 0V7c0-1.1-.9-2-2-2h-2.59L14.7 2.29a1 1 0 0 0-.71-.29h-4c-.27 0-.52.11-.71.29L6.57 5H6.4L2.71 1.29 1.3 2.7l20 20 1.41-1.41-1.62-1.62c.55-.36.91-.97.91-1.67M10.41 4h3.17l2.71 2.71c.19.19.44.29.71.29h3v11h-.59l-3.99-3.99c.36-.59.57-1.28.57-2.01 0-2.17-1.83-4-4-4-.73 0-1.42.21-2.01.57L7.91 6.5zm1.08 6.08c.16-.05.33-.08.51-.08 1.07 0 2 .93 2 2 0 .17-.03.34-.08.51z"></path><path d="M8.03 12.27c.14 1.95 1.75 3.56 3.7 3.7z"></path></svg>'
        : '<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" viewBox="0 0 24 24"><path d="M12 8c-2.17 0-4 1.83-4 4s1.83 4 4 4 4-1.83 4-4-1.83-4-4-4m0 6c-1.07 0-2-.93-2-2s.93-2 2-2 2 .93 2 2-.93 2-2 2"></path><path d="M20 5h-2.59L14.7 2.29a1 1 0 0 0-.71-.29h-4c-.27 0-.52.11-.71.29L6.57 5H3.98c-1.1 0-2 .9-2 2v11c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2Zm0 13H4V7h3c.27 0 .52-.11.71-.29L10.42 4h3.17l2.71 2.71c.19.19.44.29.71.29h3v11Z"></path></svg>';
}

// Экспортируем текущий уровень качества для внешнего использования
export function getCurrentQualityLevel() { return _currentQualityLevel; }
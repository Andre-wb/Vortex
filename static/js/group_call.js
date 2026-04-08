// static/js/group_call.js
// ============================================================================
// Модуль групповых звонков (ad-hoc group calls with invite lifecycle).
// Mesh-топология: каждый участник создаёт RTCPeerConnection с каждым другим.
// Smart mesh: адаптивный bitrate/resolution в зависимости от числа участников.
// Dominant speaker detection через AudioContext AnalyserNode.
// ============================================================================

import { $, api } from './utils.js';
import { t } from './i18n.js';
import { playCallSound, stopCallSound } from './notification-sounds.js';
import { getRoomKey } from './crypto.js';
import { isE2ESupported, needsEncodedInsertableStreams, deriveMediaKey, setupPeerE2E, setupNewSenderE2E } from './e2e_media.js';
import { SFUClient, checkSFUAvailable } from './sfu_client.js';

// ─── ICE servers (cached) ───────────────────────────────────────────────────

let _iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
let _iceLoaded = false;

async function _loadIceServers() {
    if (_iceLoaded) return;
    try {
        const data = await api('GET', '/api/keys/ice-servers');
        if (data?.ice_servers) _iceServers = data.ice_servers;
        _iceLoaded = true;
    } catch (e) {
        console.warn('[GroupCall] ICE servers fetch failed, using STUN fallback:', e);
    }
}

// ─── State ──────────────────────────────────────────────────────────────────

let _gcState       = 'idle';   // idle | ringing | connecting | connected | ended
let _gcCallId      = null;
let _gcRoomId      = null;
let _gcRoomName    = null;
let _gcWithVideo   = false;
let _gcLocalStream = null;
let _gcScreenStream = null;
let _gcSignalWs    = null;
let _gcMuted       = false;
let _gcCamOff      = false;
let _gcScreenSharing = false;
let _gcInitiatorId = null;
let _gcMediaKey    = null;   // CryptoKey for E2E media frame encryption
let _gcTopology    = 'mesh'; // mesh | sfu
/** @type {SFUClient|null} */
let _gcSfuClient   = null;

const _gcParticipants = {};   // userId → { user_id, username, display_name, avatar_emoji, avatar_url, state, is_muted, is_video }
const _gcPeers        = {};   // peerId → { pc, stream, audioEl, videoEl, analyser, speakingLevel }

let _gcDominantSpeaker  = null;
let _gcSpeakingInterval = null;
let _gcCallTimer        = null;
let _gcCallDuration     = 0;
const _gcReconnectAttempts = {};  // peerId → count

const MAX_RECONNECT = 5;
const RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 15000];

// ─── Bandwidth profiles ─────────────────────────────────────────────────────

const BW_PROFILES = {
    small:  { maxWidth: 1280, maxHeight: 720,  maxFrameRate: 30, maxBitrate: 2_500_000 },  // 2-3
    medium: { maxWidth: 854,  maxHeight: 480,  maxFrameRate: 20, maxBitrate: 800_000 },    // 4-6
    large:  { maxWidth: 640,  maxHeight: 360,  maxFrameRate: 15, maxBitrate: 300_000 },    // 7-10
};

function _getProfile() {
    const n = _connectedCount();
    if (n <= 3)  return BW_PROFILES.small;
    if (n <= 6)  return BW_PROFILES.medium;
    return BW_PROFILES.large;
}

function _connectedCount() {
    return Object.keys(_gcPeers).filter(id => {
        const p = _gcPeers[id];
        return p.pc && ['connecting', 'connected', 'new'].includes(p.pc.connectionState);
    }).length;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exported functions
// ═══════════════════════════════════════════════════════════════════════════════

export async function startGroupCall(roomId, withVideo = false) {
    if (_gcState !== 'idle') return;
    const S = window.AppState;

    await _loadIceServers();

    let topology = 'mesh';
    try {
        const resp = await api('POST', `/api/group-calls/${roomId}/start`, { call_type: withVideo ? 'group_video' : 'group_audio' });
        if (resp.already_active) {
            await joinGroupCall(resp.call_id, roomId, withVideo);
            return;
        }
        _gcCallId = resp.call_id;
        topology = resp.topology || 'mesh';
    } catch (e) {
        console.error('[GroupCall] start failed:', e);
        return;
    }

    _gcRoomId = roomId;
    _gcWithVideo = withVideo;
    _gcInitiatorId = S.user?.id;
    _gcTopology = topology;

    const room = S.rooms?.find(r => r.id === roomId);
    _gcRoomName = room?.name || 'Групповой звонок';

    try {
        _gcLocalStream = await navigator.mediaDevices.getUserMedia({
            audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, sampleRate: 48000, channelCount: 1 },
            video: withVideo ? { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } } : false,
        });
    } catch (e) {
        console.error('[GroupCall] getUserMedia failed:', e);
        return;
    }

    _gcState = 'connecting';
    _gcMuted = false;
    _gcCamOff = !withVideo;

    if (_gcTopology === 'sfu') {
        // SFU mode: single connection to server
        console.log('[GroupCall] SFU mode — connecting to server SFU');
        await _connectSfu();
    } else {
        // Mesh mode: E2E media key + direct peer connections
        _gcMediaKey = null;
        const roomKeyBytes = getRoomKey(roomId);
        if (roomKeyBytes && isE2ESupported()) {
            try {
                _gcMediaKey = await deriveMediaKey(roomKeyBytes, _gcCallId);
                console.log('[GroupCall] E2E media key derived');
            } catch (e) {
                console.warn('[GroupCall] E2E media key derivation failed:', e.message);
            }
        }
        _connectGcSignal(roomId);
    }

    _showGcOverlay();
    _updateGcStatus(_gcTopology === 'sfu' ? 'SFU — подключение...' : 'Ожидание участников...');
    _renderGcGrid();
}

export async function joinGroupCall(callId, roomId, withVideo = false) {
    if (_gcState !== 'idle' && _gcState !== 'ringing') return;

    await _loadIceServers();

    let joinResp;
    try {
        joinResp = await api('POST', `/api/group-calls/${callId}/join`);
    } catch (e) {
        console.error('[GroupCall] join failed:', e);
        return;
    }

    _gcCallId = callId;
    _gcRoomId = roomId;
    _gcWithVideo = withVideo;
    _gcTopology = joinResp?.call?.topology || 'mesh';

    const S = window.AppState;
    const room = S.rooms?.find(r => r.id === roomId);
    _gcRoomName = room?.name || 'Групповой звонок';

    try {
        _gcLocalStream = await navigator.mediaDevices.getUserMedia({
            audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, sampleRate: 48000, channelCount: 1 },
            video: withVideo ? { width: { ideal: 1280 }, height: { ideal: 720 } } : false,
        });
    } catch (e) {
        console.error('[GroupCall] getUserMedia failed:', e);
        return;
    }

    _gcState = 'connecting';
    _gcMuted = false;
    _gcCamOff = !withVideo;

    _hideGcIncomingBanner();
    stopCallSound();

    if (_gcTopology === 'sfu') {
        console.log('[GroupCall] SFU mode — connecting to server SFU');
        await _connectSfu();
    } else {
        _gcMediaKey = null;
        const roomKeyBytes = getRoomKey(roomId);
        if (roomKeyBytes && isE2ESupported()) {
            try {
                _gcMediaKey = await deriveMediaKey(roomKeyBytes, _gcCallId);
                console.log('[GroupCall] E2E media key derived');
            } catch (e) {
                console.warn('[GroupCall] E2E media key derivation failed:', e.message);
            }
        }
        _connectGcSignal(roomId);
    }

    _showGcOverlay();
    _updateGcStatus(_gcTopology === 'sfu' ? 'SFU — подключение...' : 'Подключение...');
    _renderGcGrid();
}

export async function declineGroupCall(callId) {
    _hideGcIncomingBanner();
    stopCallSound();
    try {
        await api('POST', `/api/group-calls/${callId}/decline`);
    } catch (e) {
        console.warn('[GroupCall] decline failed:', e);
    }
}

export async function leaveGroupCall() {
    if (_gcState === 'idle') return;
    const callId = _gcCallId;

    if (_gcSfuClient) {
        await _gcSfuClient.disconnect();
        _gcSfuClient = null;
    }

    _gcSignalSend({ type: 'group_leave' });
    _cleanup();

    try {
        await api('POST', `/api/group-calls/${callId}/leave`);
    } catch (e) {
        console.warn('[GroupCall] leave API failed:', e);
    }
}

export async function endGroupCall() {
    if (!_gcCallId) return;
    const callId = _gcCallId;

    _gcSignalSend({ type: 'group_end' });
    _cleanup();

    try {
        await api('POST', `/api/group-calls/${callId}/end`);
    } catch (e) {
        console.warn('[GroupCall] end API failed:', e);
    }
}

export async function addParticipantToCall(userId) {
    if (!_gcCallId) return;
    try {
        await api('POST', `/api/group-calls/${_gcCallId}/add/${userId}`);
    } catch (e) {
        console.error('[GroupCall] add participant failed:', e);
    }
}

export function toggleGroupMute() {
    _gcMuted = !_gcMuted;
    if (_gcLocalStream) {
        _gcLocalStream.getAudioTracks().forEach(t => { t.enabled = !_gcMuted; });
    }
    _gcSignalSend({ type: 'group_mute', muted: _gcMuted, video_off: _gcCamOff });
    _updateMuteBtn();
    _renderGcGrid();
}

export function toggleGroupVideo() {
    if (!_gcLocalStream) return;

    const videoTracks = _gcLocalStream.getVideoTracks();
    if (videoTracks.length > 0) {
        _gcCamOff = !_gcCamOff;
        videoTracks.forEach(t => { t.enabled = !_gcCamOff; });
    } else if (_gcCamOff) {
        navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 } } })
            .then(stream => {
                const videoTrack = stream.getVideoTracks()[0];
                _gcLocalStream.addTrack(videoTrack);

                for (const peer of Object.values(_gcPeers)) {
                    if (!peer.pc) continue;
                    const sender = peer.pc.getSenders().find(s => s.track?.kind === 'video' || !s.track);
                    if (sender) {
                        sender.replaceTrack(videoTrack).catch(() => {});
                    } else {
                        const newSender = peer.pc.addTrack(videoTrack, _gcLocalStream);
                        if (_gcMediaKey) setupNewSenderE2E(newSender, _gcMediaKey);
                    }
                }
                if (_gcSfuClient?.pc) {
                    const s = _gcSfuClient.pc.getSenders().find(s => s.track?.kind === 'video' || !s.track);
                    if (s) {
                        _gcSfuClient.replaceTrack(s.track, videoTrack).catch(() => {});
                    } else {
                        _gcSfuClient.addTrack(videoTrack, _gcLocalStream);
                    }
                }
                _gcCamOff = false;
                _gcWithVideo = true;
                _updateCamBtn();
                _renderGcGrid();
            })
            .catch(e => console.warn('[GroupCall] camera acquire failed:', e));
        return;
    }

    _gcSignalSend({ type: 'group_mute', muted: _gcMuted, video_off: _gcCamOff });
    _updateCamBtn();
    _renderGcGrid();
}

export async function toggleGroupScreenShare() {
    if (_gcScreenSharing) {
        if (_gcScreenStream) {
            _gcScreenStream.getTracks().forEach(t => t.stop());
            _gcScreenStream = null;
        }
        const camTrack = _gcLocalStream?.getVideoTracks()[0] || null;
        for (const peer of Object.values(_gcPeers)) {
            if (!peer.pc) continue;
            const sender = peer.pc.getSenders().find(s => s.track?.kind === 'video');
            if (sender) sender.replaceTrack(camTrack).catch(() => {});
        }
        if (_gcSfuClient?.pc) {
            const s = _gcSfuClient.pc.getSenders().find(s => s.track?.kind === 'video');
            if (s) _gcSfuClient.replaceTrack(s.track, camTrack).catch(() => {});
        }
        _gcScreenSharing = false;
        _gcSignalSend({ type: 'group_screen_share', sharing: false });
        _updateScreenBtn();
        _renderGcGrid();
        return;
    }

    try {
        _gcScreenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
    } catch (e) {
        console.warn('[GroupCall] screen share denied:', e);
        return;
    }

    const screenTrack = _gcScreenStream.getVideoTracks()[0];

    screenTrack.onended = () => {
        _gcScreenSharing = false;
        _gcScreenStream = null;
        const camTrack = _gcLocalStream?.getVideoTracks()[0] || null;
        for (const peer of Object.values(_gcPeers)) {
            if (!peer.pc) continue;
            const sender = peer.pc.getSenders().find(s => s.track?.kind === 'video');
            if (sender) sender.replaceTrack(camTrack).catch(() => {});
        }
        if (_gcSfuClient?.pc) {
            const s = _gcSfuClient.pc.getSenders().find(s => s.track?.kind === 'video');
            if (s) _gcSfuClient.replaceTrack(s.track, camTrack).catch(() => {});
        }
        _gcSignalSend({ type: 'group_screen_share', sharing: false });
        _updateScreenBtn();
        _renderGcGrid();
    };

    for (const peer of Object.values(_gcPeers)) {
        if (!peer.pc) continue;
        const sender = peer.pc.getSenders().find(s => s.track?.kind === 'video');
        if (sender) {
            sender.replaceTrack(screenTrack).catch(() => {});
        } else {
            const newSender = peer.pc.addTrack(screenTrack, _gcScreenStream);
            if (_gcMediaKey) setupNewSenderE2E(newSender, _gcMediaKey);
        }
    }
    if (_gcSfuClient?.pc) {
        const s = _gcSfuClient.pc.getSenders().find(s => s.track?.kind === 'video');
        if (s) {
            _gcSfuClient.replaceTrack(s.track, screenTrack).catch(() => {});
        } else {
            _gcSfuClient.addTrack(screenTrack, _gcScreenStream);
        }
    }

    _gcScreenSharing = true;
    _gcSignalSend({ type: 'group_screen_share', sharing: true });
    _updateScreenBtn();
    _renderGcGrid();
}

export function handleGroupSignal(msg) {
    _handleSignal(msg);
}

export function getGroupCallState() { return _gcState; }
export function isInGroupCall() { return _gcState !== 'idle'; }
export function getGroupCallTopology() { return _gcTopology; }

export function minimizeGroupCall() { _hideGcOverlay(); _showGcPip(); }
export function expandGroupCall()   { _hideGcPip(); _showGcOverlay(); }
export function showGcAddModal()    { _showAddModal(); }
export function hideGcAddModal()    { _hideAddModal(); }

// ═══════════════════════════════════════════════════════════════════════════════
// SFU mode — single PeerConnection to server
// ═══════════════════════════════════════════════════════════════════════════════

async function _connectSfu() {
    // Derive E2E media key (same as mesh — opaque SFU preserves encrypted frames)
    _gcMediaKey = null;
    const roomKeyBytes = getRoomKey(_gcRoomId);
    if (roomKeyBytes && isE2ESupported()) {
        try {
            _gcMediaKey = await deriveMediaKey(roomKeyBytes, _gcCallId);
            console.log('[GroupCall/SFU] E2E media key derived');
        } catch (e) {
            console.warn('[GroupCall/SFU] E2E key derivation failed:', e.message);
        }
    }

    _gcSfuClient = new SFUClient(_gcCallId, _gcRoomId, _gcLocalStream, _iceServers, _gcMediaKey);

    _gcSfuClient.onTrack = (track, stream) => {
        console.log('[GroupCall/SFU] remote track:', track.kind);
        // В SFU-режиме все удалённые треки приходят от сервера
        // Используем один виртуальный peer "sfu" для аудио, и рендерим grid
        if (track.kind === 'audio') {
            let audioEl = document.getElementById('gc-sfu-audio-' + track.id);
            if (!audioEl) {
                audioEl = document.createElement('audio');
                audioEl.autoplay = true;
                audioEl.id = 'gc-sfu-audio-' + track.id;
                const container = $('gc-audio-container');
                if (container) container.appendChild(audioEl);
            }
            audioEl.srcObject = stream;
        }
        _renderGcGrid();
    };

    _gcSfuClient.onParticipantJoined = (info) => {
        _gcParticipants[info.user_id] = {
            user_id: info.user_id,
            username: info.username,
            display_name: info.display_name,
            avatar_emoji: info.avatar_emoji,
            avatar_url: info.avatar_url,
            state: 'connected',
            is_muted: false,
            is_video: false,
        };
        _renderGcGrid();
    };

    _gcSfuClient.onParticipantLeft = (userId) => {
        delete _gcParticipants[userId];
        _renderGcGrid();
    };

    _gcSfuClient.onConnectionStateChange = (state) => {
        if (state === 'connected') {
            if (_gcState === 'connecting') {
                _gcState = 'connected';
                _startGcTimer();
                _updateGcStatus('SFU — звонок');
            }
        }
        if (state === 'failed') {
            _updateGcStatus('SFU — переподключение...');
        }
    };

    try {
        const participants = await _gcSfuClient.connect();
        // Populate initial participants
        for (const p of participants) {
            _gcParticipants[p.user_id] = {
                ...p,
                state: 'connected',
                is_muted: false,
                is_video: false,
            };
        }
        _renderGcGrid();
    } catch (e) {
        console.error('[GroupCall/SFU] connect failed:', e);
        _updateGcStatus('SFU — ошибка подключения');
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Signal WebSocket (mesh mode)
// ═══════════════════════════════════════════════════════════════════════════════

function _connectGcSignal(roomId) {
    if (_gcSignalWs) {
        _gcSignalWs.onclose = null;
        _gcSignalWs.close();
    }

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const knockCookie = document.cookie.split(';').find(c => c.trim().startsWith('_vk='))?.split('=')[1];
    const knockParam = knockCookie ? `&knock=${knockCookie}` : '';

    _gcSignalWs = new WebSocket(
        `${proto}://${location.host}/ws/signal/${roomId}?gc=1${knockParam}`
    );

    _gcSignalWs.onopen = () => {
        console.log('[GroupCall] Signal WS open, room', roomId);
        _gcSignalSend({
            type: 'group_join',
            call_id: _gcCallId,
            user_id: window.AppState.user?.id,
            username: window.AppState.user?.username,
            display_name: window.AppState.user?.display_name,
            avatar_emoji: window.AppState.user?.avatar_emoji,
            avatar_url: window.AppState.user?.avatar_url,
            with_video: _gcWithVideo,
        });
    };

    _gcSignalWs.onmessage = async (e) => {
        try {
            const msg = JSON.parse(e.data);
            await _handleSignal(msg);
        } catch (err) {
            console.error('[GroupCall] signal parse error:', err);
        }
    };

    _gcSignalWs.onclose = (ev) => {
        console.log('[GroupCall] Signal WS closed, code=', ev.code);
        if (_gcRoomId === roomId && _gcState !== 'idle' && ev.code !== 1000) {
            setTimeout(() => {
                if (_gcRoomId === roomId && _gcState !== 'idle') _connectGcSignal(roomId);
            }, 3000);
        }
    };

    _gcSignalWs.onerror = (err) => {
        console.error('[GroupCall] Signal WS error:', err);
    };
}

function _gcSignalSend(msg) {
    if (_gcSignalWs?.readyState === WebSocket.OPEN) {
        _gcSignalWs.send(JSON.stringify(msg));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Signal handling
// ═══════════════════════════════════════════════════════════════════════════════

async function _handleSignal(msg) {
    const S = window.AppState;
    const from = msg.from || msg.user_id;

    if (from === S.user?.id) return;

    switch (msg.type) {
        case 'group_call_invite':
        case 'group_invite': {
            if (_gcState !== 'idle') return;
            _gcState = 'ringing';
            const initiator = msg.initiator || {};
            _pendingInvite = {
                callId: msg.call_id,
                roomId: msg.room_id,
                callType: msg.call_type,
                initiator,
            };
            playCallSound('incoming');
            _showGcIncomingBanner(initiator);
            break;
        }

        case 'group_join': {
            if (msg.call_id !== _gcCallId) return;
            _gcParticipants[from] = {
                user_id: from,
                username: msg.username,
                display_name: msg.display_name,
                avatar_emoji: msg.avatar_emoji,
                avatar_url: msg.avatar_url,
                state: 'connecting',
                is_muted: false,
                is_video: !!msg.with_video,
            };
            _renderGcGrid();

            await _createPeerOffer(from);
            _adaptBitrate();

            if (_connectedCount() >= 1 && _gcState === 'connecting') {
                _gcState = 'connected';
                _startGcTimer();
                _updateGcStatus('Звонок');
                _startSpeakingDetection();
            }
            break;
        }

        case 'group_leave': {
            _closePeer(from);
            delete _gcParticipants[from];
            _renderGcGrid();
            _adaptBitrate();

            if (_connectedCount() === 0 && _gcState === 'connected') {
                _updateGcStatus('Все участники вышли');
                setTimeout(() => {
                    if (_connectedCount() === 0) leaveGroupCall();
                }, 5000);
            }
            break;
        }

        case 'group_offer': {
            await _handlePeerOffer(from, msg.sdp);
            break;
        }

        case 'group_answer': {
            await _handlePeerAnswer(from, msg.sdp);
            break;
        }

        case 'group_ice': {
            await _handlePeerIce(from, msg.candidate);
            break;
        }

        case 'group_mute': {
            const p = _gcParticipants[from];
            if (p) {
                p.is_muted = !!msg.muted;
                p.is_video = !msg.video_off;
            }
            _renderGcGrid();
            break;
        }

        case 'group_screen_share': {
            const p = _gcParticipants[from];
            if (p) p.is_screen_sharing = !!msg.sharing;
            _renderGcGrid();
            break;
        }

        case 'group_call_ended':
        case 'group_end': {
            if (msg.call_id && msg.call_id !== _gcCallId) return;
            _cleanup();
            break;
        }

        case 'group_call_participant_joined': {
            _gcParticipants[msg.user_id] = {
                user_id: msg.user_id,
                username: msg.username,
                display_name: msg.display_name,
                avatar_emoji: msg.avatar_emoji,
                avatar_url: msg.avatar_url,
                state: 'connecting',
                is_muted: false,
                is_video: false,
            };
            _renderGcGrid();
            break;
        }

        case 'group_call_participant_left': {
            _closePeer(msg.user_id);
            delete _gcParticipants[msg.user_id];
            _renderGcGrid();
            break;
        }
    }
}

let _pendingInvite = null;

// ═══════════════════════════════════════════════════════════════════════════════
// Peer Connection management (mesh)
// ═══════════════════════════════════════════════════════════════════════════════

function _createPeerConnection(peerId) {
    const config = { iceServers: _iceServers };
    if (_gcMediaKey && needsEncodedInsertableStreams()) {
        config.encodedInsertableStreams = true;
    }
    const pc = new RTCPeerConnection(config);

    if (_gcLocalStream) {
        _gcLocalStream.getTracks().forEach(track => pc.addTrack(track, _gcLocalStream));
    }

    // E2E media frame encryption — wraps senders and intercepts ontrack for receivers
    if (_gcMediaKey) {
        setupPeerE2E(pc, _gcMediaKey);
    }

    pc.onicecandidate = (e) => {
        if (!e.candidate) return;
        _gcSignalSend({
            type: 'group_ice',
            to: peerId,
            candidate: e.candidate.toJSON(),
        });
    };

    pc.ontrack = (e) => {
        console.log('[GroupCall] ontrack from peer', peerId, e.track.kind);
        const stream = e.streams[0] || new MediaStream([e.track]);
        if (!_gcPeers[peerId]) _gcPeers[peerId] = {};
        _gcPeers[peerId].stream = stream;

        if (e.track.kind === 'audio') {
            let audioEl = _gcPeers[peerId].audioEl;
            if (!audioEl) {
                audioEl = document.createElement('audio');
                audioEl.autoplay = true;
                audioEl.id = `gc-audio-${peerId}`;
                const container = $('gc-audio-container');
                if (container) container.appendChild(audioEl);
                _gcPeers[peerId].audioEl = audioEl;
            }
            audioEl.srcObject = stream;
        }

        _renderGcGrid();
        _setupPeerAnalyser(peerId, stream);
    };

    pc.onconnectionstatechange = () => {
        const state = pc.connectionState;
        console.log(`[GroupCall] peer ${peerId} state: ${state}`);

        if (state === 'connected') {
            _gcReconnectAttempts[peerId] = 0;
            if (_gcState === 'connecting') {
                _gcState = 'connected';
                _startGcTimer();
                _updateGcStatus('Звонок');
                _startSpeakingDetection();
            }
            _adaptBitrate();
        }

        if (state === 'failed') {
            _reconnectPeer(peerId);
        }
    };

    if (!_gcPeers[peerId]) _gcPeers[peerId] = {};
    _gcPeers[peerId].pc = pc;

    return pc;
}

async function _createPeerOffer(peerId) {
    const pc = _createPeerConnection(peerId);
    try {
        const offer = await pc.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true,
        });
        await pc.setLocalDescription(offer);
        _gcSignalSend({
            type: 'group_offer',
            to: peerId,
            sdp: offer.sdp,
        });
    } catch (e) {
        console.error('[GroupCall] createOffer failed for', peerId, e);
    }
}

async function _handlePeerOffer(peerId, sdp) {
    let peer = _gcPeers[peerId];
    if (!peer?.pc || peer.pc.signalingState === 'closed') {
        _createPeerConnection(peerId);
        peer = _gcPeers[peerId];
    }

    try {
        await peer.pc.setRemoteDescription({ type: 'offer', sdp });

        if (peer._pendingIce) {
            for (const c of peer._pendingIce) {
                try { await peer.pc.addIceCandidate(c); } catch {}
            }
            peer._pendingIce = [];
        }

        const answer = await peer.pc.createAnswer();
        await peer.pc.setLocalDescription(answer);
        _gcSignalSend({
            type: 'group_answer',
            to: peerId,
            sdp: answer.sdp,
        });
    } catch (e) {
        console.error('[GroupCall] handleOffer failed for', peerId, e);
    }
}

async function _handlePeerAnswer(peerId, sdp) {
    const peer = _gcPeers[peerId];
    if (!peer?.pc) return;
    try {
        if (peer.pc.signalingState !== 'stable') {
            await peer.pc.setRemoteDescription({ type: 'answer', sdp });
            if (peer._pendingIce) {
                for (const c of peer._pendingIce) {
                    try { await peer.pc.addIceCandidate(c); } catch {}
                }
                peer._pendingIce = [];
            }
        }
    } catch (e) {
        console.error('[GroupCall] handleAnswer failed for', peerId, e);
    }
}

async function _handlePeerIce(peerId, candidate) {
    const peer = _gcPeers[peerId];
    if (!peer) return;
    if (peer.pc?.remoteDescription) {
        try { await peer.pc.addIceCandidate(candidate); } catch (e) {
            console.warn('[GroupCall] ICE error for', peerId, e.message);
        }
    } else {
        if (!peer._pendingIce) peer._pendingIce = [];
        peer._pendingIce.push(candidate);
    }
}

function _closePeer(peerId) {
    const peer = _gcPeers[peerId];
    if (!peer) return;

    if (peer.pc) {
        peer.pc.ontrack = null;
        peer.pc.onicecandidate = null;
        peer.pc.onconnectionstatechange = null;
        peer.pc.close();
    }
    if (peer.audioEl) {
        peer.audioEl.srcObject = null;
        peer.audioEl.remove();
    }
    if (peer.analyserInterval) {
        clearInterval(peer.analyserInterval);
    }

    delete _gcPeers[peerId];
    delete _gcReconnectAttempts[peerId];
}

// ─── Reconnection ───────────────────────────────────────────────────────────

function _reconnectPeer(peerId) {
    const attempts = (_gcReconnectAttempts[peerId] || 0) + 1;
    _gcReconnectAttempts[peerId] = attempts;

    if (attempts > MAX_RECONNECT) {
        console.warn('[GroupCall] max reconnect attempts for peer', peerId);
        _closePeer(peerId);
        delete _gcParticipants[peerId];
        _renderGcGrid();
        return;
    }

    const delay = RECONNECT_DELAYS[Math.min(attempts - 1, RECONNECT_DELAYS.length - 1)];
    console.log(`[GroupCall] reconnecting peer ${peerId}, attempt ${attempts}, delay ${delay}ms`);

    setTimeout(async () => {
        if (_gcState === 'idle' || !_gcParticipants[peerId]) return;

        _closePeer(peerId);
        _gcPeers[peerId] = {};
        await _createPeerOffer(peerId);
    }, delay);
}

// ─── Bandwidth adaptation ───────────────────────────────────────────────────

function _adaptBitrate() {
    const profile = _getProfile();

    const videoTrack = _gcLocalStream?.getVideoTracks()[0];
    if (videoTrack) {
        videoTrack.applyConstraints({
            width: { ideal: profile.maxWidth },
            height: { ideal: profile.maxHeight },
            frameRate: { ideal: profile.maxFrameRate },
        }).catch(() => {});
    }

    for (const peer of Object.values(_gcPeers)) {
        if (!peer.pc) continue;
        const senders = peer.pc.getSenders();
        for (const sender of senders) {
            if (sender.track?.kind !== 'video') continue;
            const params = sender.getParameters();
            if (!params.encodings) params.encodings = [{}];

            let bitrate = profile.maxBitrate;
            const peerId = Object.keys(_gcPeers).find(k => _gcPeers[k] === peer);
            if (peerId && Number(peerId) === _gcDominantSpeaker) {
                bitrate = Math.floor(bitrate * 1.5);
            }

            params.encodings[0].maxBitrate = bitrate;
            sender.setParameters(params).catch(() => {});
        }
    }
}

// ─── Dominant speaker detection ─────────────────────────────────────────────

function _setupPeerAnalyser(peerId, stream) {
    const peer = _gcPeers[peerId];
    if (!peer || peer.analyserInterval) return;

    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const source = ctx.createMediaStreamSource(stream);
        const analyser = ctx.createAnalyser();
        analyser.fftSize = 256;
        source.connect(analyser);
        peer.analyser = analyser;
        peer._audioCtx = ctx;
    } catch (e) {
        console.warn('[GroupCall] analyser setup failed for', peerId, e);
    }
}

function _startSpeakingDetection() {
    if (_gcSpeakingInterval) return;

    _gcSpeakingInterval = setInterval(() => {
        let maxLevel = 0;
        let maxPeer = null;

        for (const [peerId, peer] of Object.entries(_gcPeers)) {
            if (!peer.analyser) continue;
            const data = new Uint8Array(peer.analyser.frequencyBinCount);
            peer.analyser.getByteFrequencyData(data);
            const avg = data.reduce((a, b) => a + b, 0) / data.length;
            peer.speakingLevel = avg;

            const tile = document.querySelector(`[data-peer-id="${CSS.escape(peerId)}"]`);
            if (tile) tile.classList.toggle('speaking', avg > 15);

            if (avg > maxLevel) {
                maxLevel = avg;
                maxPeer = Number(peerId);
            }
        }

        if (maxPeer !== _gcDominantSpeaker && maxLevel > 20) {
            document.querySelectorAll('.gc-tile.dominant').forEach(el => el.classList.remove('dominant'));

            _gcDominantSpeaker = maxPeer;
            const tile = document.querySelector(`[data-peer-id="${CSS.escape(String(maxPeer))}"]`);
            if (tile) tile.classList.add('dominant');

            _adaptBitrate();
        }
    }, 100);
}

function _stopSpeakingDetection() {
    if (_gcSpeakingInterval) {
        clearInterval(_gcSpeakingInterval);
        _gcSpeakingInterval = null;
    }
    for (const peer of Object.values(_gcPeers)) {
        if (peer._audioCtx) {
            peer._audioCtx.close().catch(() => {});
            peer._audioCtx = null;
        }
        if (peer.analyserInterval) {
            clearInterval(peer.analyserInterval);
        }
    }
    _gcDominantSpeaker = null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
// ═══════════════════════════════════════════════════════════════════════════════

function _cleanup() {
    _stopSpeakingDetection();
    _stopGcTimer();
    stopCallSound();

    for (const peerId of Object.keys(_gcPeers)) {
        _closePeer(peerId);
    }

    if (_gcLocalStream) {
        _gcLocalStream.getTracks().forEach(t => t.stop());
        _gcLocalStream = null;
    }
    if (_gcScreenStream) {
        _gcScreenStream.getTracks().forEach(t => t.stop());
        _gcScreenStream = null;
    }

    if (_gcSignalWs) {
        _gcSignalWs.onclose = null;
        _gcSignalWs.close();
        _gcSignalWs = null;
    }

    _gcState = 'idle';
    _gcCallId = null;
    _gcRoomId = null;
    _gcRoomName = null;
    _gcMuted = false;
    _gcCamOff = false;
    _gcScreenSharing = false;
    _gcInitiatorId = null;
    _gcMediaKey = null;
    _gcTopology = 'mesh';
    _gcSfuClient = null;
    _pendingInvite = null;

    for (const k of Object.keys(_gcParticipants)) delete _gcParticipants[k];
    for (const k of Object.keys(_gcReconnectAttempts)) delete _gcReconnectAttempts[k];

    _hideGcOverlay();
    _hideGcPip();
    _hideGcIncomingBanner();
}

// ═══════════════════════════════════════════════════════════════════════════════
// UI functions
// ═══════════════════════════════════════════════════════════════════════════════

function _showGcOverlay() {
    const overlay = $('gc-overlay');
    if (!overlay) return;
    const nameEl = $('gc-room-name');
    if (nameEl) nameEl.textContent = _gcRoomName || '';
    overlay.classList.add('show');
    _hideGcPip();
    _updateMuteBtn();
    _updateCamBtn();
    _updateScreenBtn();
}

function _hideGcOverlay() {
    const overlay = $('gc-overlay');
    if (overlay) overlay.classList.remove('show');
}

function _updateGcStatus(text) {
    const el = $('gc-status');
    if (el) el.textContent = text;
}

function _showGcPip() {
    const pip = $('gc-pip');
    if (!pip) return;

    const nameEl = $('gc-pip-name');
    if (nameEl) nameEl.textContent = _gcRoomName || '';

    const countEl = $('gc-pip-count');
    if (countEl) {
        const count = Object.keys(_gcParticipants).length;
        countEl.textContent = count + ' уч.';
    }

    pip.classList.add('show');
}

function _hideGcPip() {
    const pip = $('gc-pip');
    if (pip) pip.classList.remove('show');
}

function _showGcIncomingBanner(initiator) {
    const banner = $('gc-incoming');
    if (!banner) return;

    const avatarEl = $('gc-incoming-avatar');
    const nameEl = $('gc-incoming-name');

    if (avatarEl) avatarEl.textContent = initiator.avatar_emoji || '\u{1F464}';
    if (nameEl) nameEl.textContent = initiator.display_name || initiator.username || '?';

    const acceptBtn = $('gc-incoming-accept');
    const declineBtn = $('gc-incoming-decline');

    if (acceptBtn) {
        acceptBtn.onclick = () => {
            if (_pendingInvite) {
                joinGroupCall(_pendingInvite.callId, _pendingInvite.roomId, _pendingInvite.callType === 'group_video');
            }
        };
    }
    if (declineBtn) {
        declineBtn.onclick = () => {
            if (_pendingInvite) {
                declineGroupCall(_pendingInvite.callId);
                _pendingInvite = null;
                _gcState = 'idle';
            }
        };
    }

    banner.classList.add('show');
}

function _hideGcIncomingBanner() {
    const banner = $('gc-incoming');
    if (banner) banner.classList.remove('show');
}

// ─── Video Grid rendering ───────────────────────────────────────────────────

function _renderGcGrid() {
    const grid = $('gc-grid');
    if (!grid) return;

    const S = window.AppState;
    const myId = S.user?.id;

    const participants = [];

    // Self first
    participants.push({
        user_id: myId,
        username: S.user?.username,
        display_name: S.user?.display_name || S.user?.username,
        avatar_emoji: S.user?.avatar_emoji || '\u{1F464}',
        is_muted: _gcMuted,
        is_video: _gcWithVideo && !_gcCamOff,
        is_screen_sharing: _gcScreenSharing,
        is_self: true,
    });

    for (const p of Object.values(_gcParticipants)) {
        participants.push({ ...p, is_self: false });
    }

    const count = participants.length;
    grid.setAttribute('data-count', String(Math.min(count, 10)));

    const existingTiles = grid.querySelectorAll('.gc-tile');
    const existingMap = {};
    existingTiles.forEach(tile => { existingMap[tile.dataset.peerId] = tile; });

    const usedIds = new Set();

    participants.forEach(p => {
        const peerId = String(p.user_id);
        usedIds.add(peerId);

        let tile = existingMap[peerId];
        if (!tile) {
            tile = document.createElement('div');
            tile.className = 'gc-tile';
            tile.dataset.peerId = peerId;
            grid.appendChild(tile);
        }

        tile.classList.toggle('muted', !!p.is_muted);
        tile.classList.toggle('screen-sharing', !!p.is_screen_sharing);

        const hasVideo = p.is_self
            ? (p.is_video && _gcLocalStream?.getVideoTracks().some(t => t.enabled))
            : (p.is_video && _gcPeers[peerId]?.stream?.getVideoTracks().length > 0);

        if (hasVideo) {
            let videoEl = tile.querySelector('video');
            if (!videoEl) {
                videoEl = document.createElement('video');
                videoEl.autoplay = true;
                videoEl.playsInline = true;
                if (p.is_self) videoEl.muted = true;
                // Remove avatar if exists
                const avatar = tile.querySelector('.gc-tile-avatar');
                if (avatar) avatar.remove();
                tile.prepend(videoEl);
            }
            if (p.is_self) {
                videoEl.srcObject = _gcScreenSharing ? _gcScreenStream : _gcLocalStream;
            } else {
                const peerStream = _gcPeers[peerId]?.stream;
                if (peerStream && videoEl.srcObject !== peerStream) {
                    videoEl.srcObject = peerStream;
                }
            }
        } else {
            // Remove video if exists
            const videoEl = tile.querySelector('video');
            if (videoEl) videoEl.remove();

            // Ensure avatar
            let avatarDiv = tile.querySelector('.gc-tile-avatar');
            if (!avatarDiv) {
                avatarDiv = document.createElement('div');
                avatarDiv.className = 'gc-tile-avatar';
                tile.prepend(avatarDiv);
            }
            avatarDiv.textContent = p.avatar_emoji || '\u{1F464}';
        }

        // Ensure label
        let label = tile.querySelector('.gc-tile-label');
        if (!label) {
            label = document.createElement('div');
            label.className = 'gc-tile-label';
            tile.appendChild(label);
        }
        // Build label safely using DOM
        label.textContent = '';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'gc-tile-name';
        nameSpan.textContent = p.display_name || p.username || '';
        label.appendChild(nameSpan);
        if (p.is_self) {
            const youSpan = document.createElement('span');
            youSpan.className = 'gc-tile-you';
            youSpan.textContent = '(вы)';
            label.appendChild(youSpan);
        }

        // Mute badge
        let muteBadge = tile.querySelector('.gc-tile-mute');
        if (!muteBadge) {
            muteBadge = document.createElement('div');
            muteBadge.className = 'gc-tile-mute';
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', '12');
            svg.setAttribute('height', '12');
            svg.setAttribute('viewBox', '0 0 24 24');
            svg.setAttribute('fill', 'none');
            svg.setAttribute('stroke', 'currentColor');
            svg.setAttribute('stroke-width', '2');
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', '1'); line.setAttribute('y1', '1');
            line.setAttribute('x2', '23'); line.setAttribute('y2', '23');
            svg.appendChild(line);
            const path1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path1.setAttribute('d', 'M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V5a3 3 0 0 0-5.94-.6');
            svg.appendChild(path1);
            const path2 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path2.setAttribute('d', 'M17 16.95A7 7 0 0 1 5 12v-2m14 0v2c0 .76-.12 1.5-.34 2.18');
            svg.appendChild(path2);
            muteBadge.appendChild(svg);
            tile.appendChild(muteBadge);
        }
    });

    // Remove stale tiles
    existingTiles.forEach(tile => {
        if (!usedIds.has(tile.dataset.peerId)) {
            tile.remove();
        }
    });
}

// ─── Control button states ──────────────────────────────────────────────────

function _updateMuteBtn() {
    const btn = $('gc-mute-btn');
    if (btn) btn.classList.toggle('active', _gcMuted);
}

function _updateCamBtn() {
    const btn = $('gc-cam-btn');
    if (btn) btn.classList.toggle('active', _gcCamOff);
}

function _updateScreenBtn() {
    const btn = $('gc-screen-btn');
    if (btn) btn.classList.toggle('active', _gcScreenSharing);
}

// ─── Timer ──────────────────────────────────────────────────────────────────

function _startGcTimer() {
    if (_gcCallTimer) return;
    _gcCallDuration = 0;

    _gcCallTimer = setInterval(() => {
        _gcCallDuration++;
        const min = Math.floor(_gcCallDuration / 60);
        const sec = _gcCallDuration % 60;
        const text = min + ':' + String(sec).padStart(2, '0');

        const timerEl = $('gc-timer');
        if (timerEl) timerEl.textContent = text;

        const pipTimerEl = $('gc-pip-timer');
        if (pipTimerEl) pipTimerEl.textContent = text;
    }, 1000);
}

function _stopGcTimer() {
    if (_gcCallTimer) {
        clearInterval(_gcCallTimer);
        _gcCallTimer = null;
    }
    _gcCallDuration = 0;
}

// ─── Add participant modal ──────────────────────────────────────────────────

async function _showAddModal() {
    const modal = $('gc-add-modal');
    if (!modal) return;

    const list = $('gc-add-list');
    if (!list) return;

    // Show loading
    list.textContent = '';
    const loadingDiv = document.createElement('div');
    loadingDiv.style.cssText = 'padding:20px;text-align:center;color:var(--text2)';
    loadingDiv.textContent = 'Загрузка...';
    list.appendChild(loadingDiv);
    modal.classList.add('show');

    try {
        const data = await api('GET', `/api/rooms/${_gcRoomId}/members`);
        const members = data.members || data || [];
        const S = window.AppState;

        list.textContent = '';

        for (const m of members) {
            const userId = m.user_id || m.id;
            const inCall = !!_gcParticipants[userId] || userId === S.user?.id;

            const row = document.createElement('div');
            row.className = 'gc-add-row';

            const avatarDiv = document.createElement('div');
            avatarDiv.className = 'gc-add-avatar';
            avatarDiv.textContent = m.avatar_emoji || '\u{1F464}';
            row.appendChild(avatarDiv);

            const nameDiv = document.createElement('div');
            nameDiv.className = 'gc-add-name';
            nameDiv.textContent = m.display_name || m.username || '';
            row.appendChild(nameDiv);

            const inviteBtn = document.createElement('button');
            inviteBtn.className = 'gc-add-invite';
            inviteBtn.disabled = inCall;
            inviteBtn.textContent = inCall ? 'В звонке' : 'Пригласить';

            if (!inCall) {
                inviteBtn.addEventListener('click', async () => {
                    inviteBtn.disabled = true;
                    inviteBtn.textContent = 'Отправлено';
                    await addParticipantToCall(userId);
                });
            }

            row.appendChild(inviteBtn);
            list.appendChild(row);
        }

        if (members.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.style.cssText = 'padding:20px;text-align:center;color:var(--text2)';
            emptyDiv.textContent = 'Нет участников';
            list.appendChild(emptyDiv);
        }
    } catch (e) {
        list.textContent = '';
        const errDiv = document.createElement('div');
        errDiv.style.cssText = 'padding:20px;text-align:center;color:var(--red)';
        errDiv.textContent = 'Ошибка загрузки';
        list.appendChild(errDiv);
    }
}

function _hideAddModal() {
    const modal = $('gc-add-modal');
    if (modal) modal.classList.remove('show');
}

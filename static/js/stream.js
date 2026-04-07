// static/js/stream.js
// ============================================================================
// Модуль стримов (channel live streaming).
// Полноценная стриминговая система: host broadcast, управление правами,
// screen share, реакции, донаты, стрим-чат.
// ============================================================================

import { $, api, esc } from './utils.js';
import { t } from './i18n.js';

// ─── State ──────────────────────────────────────────────────────────────────

let _streamState = 'idle'; // idle | settings | connecting | live | ended
let _streamRoomId = null;
let _streamData = null; // StreamState from server
let _streamMyRole = null; // host | co_host | speaker | viewer
let _streamWs = null;
let _streamLocalStream = null;
let _streamScreenStream = null;
let _streamMuted = true;
let _streamVideoOn = false;
let _streamScreenSharing = false;
const _streamPeers = {}; // peerId -> { pc, stream, audioEl, videoEl }
let _streamTimer = null;
let _streamDuration = 0;
let _reactionTimeout = null;

// ICE servers
let _iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
let _iceLoaded = false;

async function _loadIceServers() {
    if (_iceLoaded) return;
    try {
        const data = await api('GET', '/api/keys/ice-servers');
        if (data && data.ice_servers) _iceServers = data.ice_servers;
        _iceLoaded = true;
    } catch (e) {
        console.warn('[Stream] ICE servers fetch failed:', e);
    }
}


/**
 * Открыть настройки стрима перед стартом (host flow).
 */
export function openStreamSettings(roomId) {
    const S = window.AppState;
    if (!S.currentRoom || !S.currentRoom.is_channel) return;
    _streamRoomId = roomId || S.currentRoom.id;
    _streamState = 'settings';

    // Populate settings modal
    const titleEl = $('stream-settings-title');
    if (titleEl) titleEl.value = S.currentRoom.name + ' — Live';
    const descEl = $('stream-settings-desc');
    if (descEl) descEl.value = '';

    // Reset toggles
    const reactionsEl = $('stream-settings-reactions');
    if (reactionsEl) reactionsEl.checked = true;
    const donationsEl = $('stream-settings-donations');
    if (donationsEl) donationsEl.checked = false;
    const autoAcceptEl = $('stream-settings-auto-accept');
    if (autoAcceptEl) autoAcceptEl.checked = false;
    const cardEl = $('stream-settings-card');
    if (cardEl) cardEl.value = '';
    const cardMsgEl = $('stream-settings-card-message');
    if (cardMsgEl) cardMsgEl.value = '';

    // Show donations section based on toggle
    _toggleDonationSection();

    // Show modal
    const modal = $('stream-settings-modal');
    if (modal) modal.classList.add('show');
}

/**
 * Запустить стрим с текущими настройками.
 */
export async function startStream() {
    if (_streamState !== 'settings' || !_streamRoomId) return;

    const title = $('stream-settings-title')?.value?.trim() || 'Live';
    const description = $('stream-settings-desc')?.value?.trim() || '';
    const allowReactions = $('stream-settings-reactions')?.checked !== false;
    const allowDonations = $('stream-settings-donations')?.checked || false;
    const donationCard = $('stream-settings-card')?.value?.trim() || '';
    const donationMessage = $('stream-settings-card-message')?.value?.trim() || '';
    const autoAcceptSpeakers = $('stream-settings-auto-accept')?.checked || false;

    _streamState = 'connecting';

    // Close settings modal
    const modal = $('stream-settings-modal');
    if (modal) modal.classList.remove('show');

    await _loadIceServers();

    // Get media (camera + mic)
    try {
        _streamLocalStream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } },
        });
        _streamMuted = false;
        _streamVideoOn = true;
    } catch (e) {
        // Try audio-only
        try {
            _streamLocalStream = await navigator.mediaDevices.getUserMedia({ audio: true });
            _streamMuted = false;
            _streamVideoOn = false;
        } catch (e2) {
            alert(t('stream.noMediaAccess') + ': ' + e2.message);
            _streamState = 'idle';
            return;
        }
    }

    // Start stream on server
    try {
        _streamData = await api('POST', `/api/stream/${_streamRoomId}/start`, {
            title, description, allow_reactions: allowReactions,
            allow_donations: allowDonations, donation_card: donationCard,
            donation_message: donationMessage, auto_accept_speakers: autoAcceptSpeakers,
        });
        _streamMyRole = 'host';
    } catch (e) {
        _cleanupMedia();
        _streamState = 'idle';
        alert(e.message || t('stream.startError'));
        return;
    }

    // Connect WebSocket
    _connectStreamWs(_streamRoomId);

    // Show overlay
    _streamState = 'live';
    _showStreamOverlay();
    _startStreamTimer();
    _updateStreamControls();

    console.log('[Stream] Started in room', _streamRoomId);
}

/**
 * Присоединиться к стриму как зритель.
 */
export async function joinStream(roomId) {
    if (_streamState !== 'idle') return;
    _streamRoomId = roomId;
    _streamState = 'connecting';

    await _loadIceServers();

    try {
        const resp = await api('POST', `/api/stream/${roomId}/join`);
        _streamData = resp.stream;

        // Determine role
        const me = _streamData.participants?.find(p => p.user_id === window.AppState.user?.id);
        _streamMyRole = me?.role || 'viewer';
    } catch (e) {
        _streamState = 'idle';
        alert(e.message || t('stream.joinError'));
        return;
    }

    // Connect WS
    _connectStreamWs(roomId);

    _streamState = 'live';
    _showStreamOverlay();
    _startStreamTimer();
    _updateStreamControls();

    console.log('[Stream] Joined room', roomId, 'as', _streamMyRole);
}

/**
 * Покинуть стрим.
 */
export async function leaveStream() {
    if (_streamState === 'idle') return;

    // Close all peers
    for (const peerId of Object.keys(_streamPeers)) {
        _closePeer(peerId);
    }

    _cleanupMedia();
    _stopStreamTimer();

    // Close WS
    if (_streamWs) {
        _streamWs.onclose = null;
        _streamWs.close();
        _streamWs = null;
    }

    // Notify server
    if (_streamRoomId) {
        try {
            await api('POST', `/api/stream/${_streamRoomId}/leave`);
        } catch (e) {
            console.warn('[Stream] leave error:', e);
        }
    }

    _streamState = 'idle';
    _streamRoomId = null;
    _streamData = null;
    _streamMyRole = null;

    _hideStreamOverlay();
    console.log('[Stream] Left');
}

/**
 * Завершить стрим (host/admin).
 */
export async function endStream() {
    if (!_streamRoomId) return;

    try {
        await api('POST', `/api/stream/${_streamRoomId}/stop`);
    } catch (e) {
        console.warn('[Stream] end error:', e);
    }

    // leaveStream handles cleanup
    await leaveStream();
}

/**
 * Поднять руку (запрос на выступление).
 */
export async function raiseHand() {
    if (!_streamRoomId || _streamMyRole === 'host' || _streamMyRole === 'co_host') return;
    try {
        const resp = await api('POST', `/api/stream/${_streamRoomId}/raise-hand`);
        if (resp.auto_accepted) {
            _streamMyRole = resp.role;
            _updateStreamControls();
            if (window.showToast) window.showToast(t('stream.speakGranted'), 'success');
        }
        _updateHandButton(true);
    } catch (e) {
        console.warn('[Stream] raise hand error:', e);
    }
}

/**
 * Опустить руку.
 */
export async function lowerHand() {
    if (!_streamRoomId) return;
    try {
        await api('POST', `/api/stream/${_streamRoomId}/lower-hand`);
        _updateHandButton(false);
    } catch (e) {
        console.warn('[Stream] lower hand error:', e);
    }
}

/**
 * Toggle микрофон.
 */
export function toggleStreamMute() {
    if (!_streamLocalStream) {
        // Viewer wants to speak — need to get media first
        if (_streamMyRole === 'speaker' || _streamMyRole === 'co_host') {
            _acquireMicAndUnmute();
        }
        return;
    }
    _streamMuted = !_streamMuted;
    _streamLocalStream.getAudioTracks().forEach(t => { t.enabled = !_streamMuted; });
    _sendStreamSignal({ type: 'stream_mute', is_muted: _streamMuted, is_video_on: _streamVideoOn });
    _updateStreamControls();
}

async function _acquireMicAndUnmute() {
    try {
        _streamLocalStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        _streamMuted = false;
        // Add audio track to all peer connections
        const audioTrack = _streamLocalStream.getAudioTracks()[0];
        for (const peerId of Object.keys(_streamPeers)) {
            const pc = _streamPeers[peerId]?.pc;
            if (pc) pc.addTrack(audioTrack, _streamLocalStream);
        }
        _sendStreamSignal({ type: 'stream_mute', is_muted: false, is_video_on: _streamVideoOn });
        _updateStreamControls();
    } catch (e) {
        console.warn('[Stream] mic acquire failed:', e);
    }
}

/**
 * Toggle камера.
 */
export async function toggleStreamVideo() {
    const canVideo = _streamMyRole === 'host' || _streamMyRole === 'co_host' || _streamMyRole === 'speaker';
    if (!canVideo) return;

    if (_streamVideoOn) {
        // Turn off
        if (_streamLocalStream) {
            _streamLocalStream.getVideoTracks().forEach(t => { t.stop(); });
        }
        _streamVideoOn = false;
    } else {
        // Turn on — acquire video
        try {
            const videoStream = await navigator.mediaDevices.getUserMedia({
                video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
            });
            const videoTrack = videoStream.getVideoTracks()[0];

            if (!_streamLocalStream) {
                _streamLocalStream = videoStream;
            } else {
                _streamLocalStream.addTrack(videoTrack);
            }

            // Replace track on all peer connections
            for (const peerId of Object.keys(_streamPeers)) {
                const pc = _streamPeers[peerId]?.pc;
                if (!pc) continue;
                const sender = pc.getSenders().find(s => s.track?.kind === 'video');
                if (sender) {
                    await sender.replaceTrack(videoTrack);
                } else {
                    pc.addTrack(videoTrack, _streamLocalStream);
                }
            }

            _streamVideoOn = true;
        } catch (e) {
            console.warn('[Stream] video acquire failed:', e);
            return;
        }
    }

    _sendStreamSignal({ type: 'stream_mute', is_muted: _streamMuted, is_video_on: _streamVideoOn });
    _updateStreamControls();
    _updateLocalPreview();
}

/**
 * Toggle screen share.
 */
export async function toggleStreamScreen() {
    const canScreen = _streamMyRole === 'host' || _streamMyRole === 'co_host';
    if (!canScreen) return;

    if (_streamScreenSharing) {
        // Stop
        if (_streamScreenStream) {
            _streamScreenStream.getTracks().forEach(t => t.stop());
            _streamScreenStream = null;
        }
        _streamScreenSharing = false;

        // Replace back to camera track
        const camTrack = _streamLocalStream?.getVideoTracks()[0];
        for (const peerId of Object.keys(_streamPeers)) {
            const pc = _streamPeers[peerId]?.pc;
            if (!pc) continue;
            const sender = pc.getSenders().find(s => s.track?.kind === 'video');
            if (sender && camTrack) await sender.replaceTrack(camTrack);
        }
    } else {
        // Start screen share
        try {
            _streamScreenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
            const screenTrack = _streamScreenStream.getVideoTracks()[0];
            _streamScreenSharing = true;

            // Replace video track on all peers
            for (const peerId of Object.keys(_streamPeers)) {
                const pc = _streamPeers[peerId]?.pc;
                if (!pc) continue;
                const sender = pc.getSenders().find(s => s.track?.kind === 'video');
                if (sender) {
                    await sender.replaceTrack(screenTrack);
                } else {
                    pc.addTrack(screenTrack, _streamScreenStream);
                }
            }

            // Handle user stopping share via browser UI
            screenTrack.onended = () => {
                _streamScreenSharing = false;
                _streamScreenStream = null;
                _sendStreamSignal({ type: 'stream_screen_share', sharing: false });
                _updateStreamControls();
                // Restore camera
                const camTrack = _streamLocalStream?.getVideoTracks()[0];
                if (camTrack) {
                    for (const peerId of Object.keys(_streamPeers)) {
                        const pc = _streamPeers[peerId]?.pc;
                        if (!pc) continue;
                        const sender = pc.getSenders().find(s => s.track?.kind === 'video');
                        if (sender) sender.replaceTrack(camTrack);
                    }
                }
            };
        } catch (e) {
            console.warn('[Stream] screen share failed:', e);
            return;
        }
    }

    _sendStreamSignal({ type: 'stream_screen_share', sharing: _streamScreenSharing });
    _updateStreamControls();
}

/**
 * Отправить реакцию.
 */
export function sendStreamReaction(emoji) {
    if (!_streamWs || _streamWs.readyState !== WebSocket.OPEN) return;
    _sendStreamSignal({ type: 'stream_reaction', emoji: emoji || '❤️' });
    _showLocalReaction(emoji || '❤️');
}

/**
 * Отправить сообщение в стрим-чат.
 */
export function sendStreamChat(text) {
    if (!text?.trim() || !_streamWs) return;
    _sendStreamSignal({ type: 'stream_chat', text: text.trim() });
    // Also show locally
    _appendStreamChat({
        username: window.AppState.user?.username,
        display_name: window.AppState.user?.display_name,
        text: text.trim(),
        is_self: true,
    });
}

/**
 * Управление правами участника (host only).
 */
export async function grantStreamPermission(userId, permissions) {
    if (!_streamRoomId) return;
    try {
        await api('POST', `/api/stream/${_streamRoomId}/permission`, {
            user_id: userId, ...permissions,
        });
    } catch (e) {
        console.warn('[Stream] permission error:', e);
    }
}

/**
 * Выгнать участника (host only).
 */
export async function kickStreamViewer(userId) {
    if (!_streamRoomId) return;
    try {
        await api('POST', `/api/stream/${_streamRoomId}/kick/${userId}`);
    } catch (e) {
        console.warn('[Stream] kick error:', e);
    }
}

/**
 * Отправить донат.
 */
export async function sendStreamDonation() {
    if (!_streamRoomId || !_streamData?.allow_donations) return;
    const amountEl = $('stream-donate-amount');
    const msgEl = $('stream-donate-message');
    const amount = amountEl?.value?.trim();
    if (!amount) return;

    try {
        await api('POST', `/api/stream/${_streamRoomId}/donate`, {
            amount, message: msgEl?.value?.trim() || '', currency: 'RUB',
        });
        if (amountEl) amountEl.value = '';
        if (msgEl) msgEl.value = '';
        _hideDonateModal();
        if (window.showToast) window.showToast(t('stream.donateSent'), 'success');
    } catch (e) {
        alert(e.message);
    }
}

/**
 * Проверить есть ли активный стрим в комнате.
 */
export async function checkStreamStatus(roomId) {
    try {
        const resp = await api('GET', `/api/stream/${roomId}/status`);
        return resp;
    } catch {
        return { is_live: false };
    }
}

export function isInStream() {
    return _streamState === 'live';
}

export function getStreamRoomId() {
    return _streamRoomId;
}


function _connectStreamWs(roomId) {
    if (_streamWs) {
        _streamWs.onclose = null;
        _streamWs.close();
    }

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const knockCookie = document.cookie.split(';').find(c => c.trim().startsWith('_vk='))?.split('=')[1];
    const knockParam = knockCookie ? `&knock=${knockCookie}` : '';

    _streamWs = new WebSocket(`${proto}://${location.host}/ws/stream/${roomId}?${knockParam}`);

    _streamWs.onopen = () => {
        console.log('[Stream] WS connected, room', roomId);
    };

    _streamWs.onmessage = async (e) => {
        try {
            const msg = JSON.parse(e.data);
            await _handleStreamMessage(msg);
        } catch (err) {
            console.error('[Stream] WS message error:', err);
        }
    };

    _streamWs.onclose = (e) => {
        console.log('[Stream] WS closed, code=', e.code);
        if (_streamState === 'live' && _streamRoomId === roomId && e.code !== 1000) {
            // Reconnect
            setTimeout(() => {
                if (_streamState === 'live' && _streamRoomId === roomId) {
                    _connectStreamWs(roomId);
                }
            }, 3000);
        }
    };
}

function _sendStreamSignal(msg) {
    if (_streamWs?.readyState === WebSocket.OPEN) {
        _streamWs.send(JSON.stringify(msg));
    }
}


async function _handleStreamMessage(msg) {
    const S = window.AppState;
    const from = msg.from || msg.user_id;

    switch (msg.type) {
        case 'stream_peers': {
            _streamMyRole = msg.my_role || _streamMyRole;
            if (msg.stream) _streamData = msg.stream;
            // Create peer connections for each participant with media
            const peers = msg.peers || [];
            for (const peer of peers) {
                if (peer.user_id === S.user?.id) continue;
                if (peer.role === 'host' || peer.role === 'co_host' || peer.role === 'speaker') {
                    // This peer has media — create connection
                    if (_streamMyRole === 'host' || _streamMyRole === 'co_host') {
                        await _createStreamOffer(peer.user_id);
                    }
                }
            }
            _updateStreamUI();
            break;
        }

        case 'stream_peer_joined': {
            const peerId = msg.user_id;
            if (peerId === S.user?.id) break;
            // Update participant list
            if (_streamData) {
                const existing = _streamData.participants?.find(p => p.user_id === peerId);
                if (!existing) {
                    if (!_streamData.participants) _streamData.participants = [];
                    _streamData.participants.push(msg);
                }
                _streamData.viewer_count = (_streamData.viewer_count || 0) + 1;
            }
            // If host, create offer for new peer
            if (_streamMyRole === 'host' || _streamMyRole === 'co_host') {
                await _createStreamOffer(peerId);
            }
            _updateViewerCount();
            break;
        }

        case 'stream_peer_left': {
            const leftId = msg.user_id;
            _closePeer(leftId);
            if (_streamData) {
                _streamData.participants = (_streamData.participants || []).filter(p => p.user_id !== leftId);
                _streamData.viewer_count = msg.viewer_count || _streamData.participants.length;
            }
            _updateViewerCount();
            break;
        }

        case 'stream_offer': {
            await _handleStreamOffer(from, msg.sdp);
            break;
        }

        case 'stream_answer': {
            await _handleStreamAnswer(from, msg.sdp);
            break;
        }

        case 'stream_ice': {
            await _handleStreamIce(from, msg.candidate);
            break;
        }

        case 'stream_mute': {
            if (_streamData) {
                const p = _streamData.participants?.find(p => p.user_id === msg.user_id);
                if (p) {
                    p.is_muted = msg.is_muted;
                    p.is_video_on = msg.is_video_on;
                }
            }
            _updateParticipantUI(msg.user_id);
            break;
        }

        case 'stream_screen_share': {
            if (_streamData) {
                const p = _streamData.participants?.find(p => p.user_id === msg.user_id);
                if (p) p.is_screen_sharing = msg.sharing;
            }
            _updateStreamUI();
            break;
        }

        case 'stream_permission_granted': {
            const participant = msg.participant;
            if (participant.user_id === S.user?.id) {
                _streamMyRole = participant.role;
                _updateStreamControls();
                if (participant.can_speak) {
                    if (window.showToast) window.showToast(t('stream.speakGranted'), 'success');
                }
            }
            // Update in data
            if (_streamData) {
                const idx = _streamData.participants?.findIndex(p => p.user_id === participant.user_id);
                if (idx >= 0) _streamData.participants[idx] = participant;
            }
            _updateStreamUI();
            break;
        }

        case 'stream_hand_raised': {
            _showHandRaised(msg);
            break;
        }

        case 'stream_hand_lowered': {
            _removeHandRaised(msg.user_id);
            break;
        }

        case 'stream_reaction': {
            _showReaction(msg.emoji, msg.username);
            break;
        }

        case 'stream_donation': {
            _showDonation(msg);
            break;
        }

        case 'stream_chat': {
            _appendStreamChat(msg);
            break;
        }

        case 'stream_settings_updated': {
            if (msg.stream) _streamData = msg.stream;
            _updateStreamUI();
            break;
        }

        case 'stream_ended': {
            _streamState = 'ended';
            _stopStreamTimer();
            _cleanupMedia();
            for (const peerId of Object.keys(_streamPeers)) _closePeer(peerId);
            _showStreamEnded();
            setTimeout(() => {
                _hideStreamOverlay();
                _streamState = 'idle';
                _streamRoomId = null;
                _streamData = null;
            }, 3000);
            break;
        }

        case 'stream_kicked': {
            _streamState = 'ended';
            _stopStreamTimer();
            _cleanupMedia();
            for (const peerId of Object.keys(_streamPeers)) _closePeer(peerId);
            if (window.showToast) window.showToast(t('stream.youWereKicked'), 'error');
            _hideStreamOverlay();
            _streamState = 'idle';
            _streamRoomId = null;
            _streamData = null;
            break;
        }

        case 'stream_error': {
            console.warn('[Stream] Server error:', msg.message);
            break;
        }
    }
}


function _createPeerConnection(peerId) {
    const pc = new RTCPeerConnection({ iceServers: _iceServers });

    // Add local tracks if we have them
    if (_streamLocalStream) {
        _streamLocalStream.getTracks().forEach(t => pc.addTrack(t, _streamLocalStream));
    }

    pc.onicecandidate = (e) => {
        if (!e.candidate) return;
        _sendStreamSignal({
            type: 'stream_ice',
            to: peerId,
            candidate: e.candidate.toJSON(),
        });
    };

    pc.ontrack = (e) => {
        console.log('[Stream] ontrack from peer', peerId, e.track.kind);
        const stream = e.streams[0] || new MediaStream([e.track]);
        if (!_streamPeers[peerId]) _streamPeers[peerId] = {};
        _streamPeers[peerId].stream = stream;

        if (e.track.kind === 'video') {
            _updateRemoteVideo(peerId, stream);
        } else if (e.track.kind === 'audio') {
            let audioEl = _streamPeers[peerId].audioEl;
            if (!audioEl) {
                audioEl = document.createElement('audio');
                audioEl.autoplay = true;
                audioEl.id = `stream-audio-${peerId}`;
                const container = $('stream-audio-container');
                if (container) container.appendChild(audioEl);
                _streamPeers[peerId].audioEl = audioEl;
            }
            audioEl.srcObject = stream;
        }
    };

    pc.onconnectionstatechange = () => {
        const state = pc.connectionState;
        console.log(`[Stream] peer ${peerId} state: ${state}`);
        if (state === 'failed') {
            _closePeer(peerId);
        }
    };

    if (!_streamPeers[peerId]) _streamPeers[peerId] = {};
    _streamPeers[peerId].pc = pc;
    return pc;
}

async function _createStreamOffer(peerId) {
    const pc = _createPeerConnection(peerId);
    try {
        const offer = await pc.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true,
        });
        await pc.setLocalDescription(offer);
        _sendStreamSignal({
            type: 'stream_offer',
            to: peerId,
            sdp: offer.sdp,
        });
    } catch (e) {
        console.error('[Stream] createOffer failed for', peerId, e);
    }
}

async function _handleStreamOffer(peerId, sdp) {
    let peer = _streamPeers[peerId];
    if (!peer?.pc || peer.pc.signalingState === 'closed') {
        _createPeerConnection(peerId);
        peer = _streamPeers[peerId];
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
        _sendStreamSignal({
            type: 'stream_answer',
            to: peerId,
            sdp: answer.sdp,
        });
    } catch (e) {
        console.error('[Stream] handleOffer failed for', peerId, e);
    }
}

async function _handleStreamAnswer(peerId, sdp) {
    const peer = _streamPeers[peerId];
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
        console.error('[Stream] handleAnswer failed for', peerId, e);
    }
}

async function _handleStreamIce(peerId, candidate) {
    const peer = _streamPeers[peerId];
    if (!peer) return;
    if (peer.pc?.remoteDescription) {
        try { await peer.pc.addIceCandidate(candidate); } catch {}
    } else {
        if (!peer._pendingIce) peer._pendingIce = [];
        peer._pendingIce.push(candidate);
    }
}

function _closePeer(peerId) {
    const peer = _streamPeers[peerId];
    if (!peer) return;
    if (peer.pc) {
        peer.pc.onicecandidate = null;
        peer.pc.ontrack = null;
        peer.pc.onconnectionstatechange = null;
        peer.pc.close();
    }
    if (peer.audioEl) {
        peer.audioEl.srcObject = null;
        peer.audioEl.remove();
    }
    delete _streamPeers[peerId];
}

function _cleanupMedia() {
    if (_streamLocalStream) {
        _streamLocalStream.getTracks().forEach(t => t.stop());
        _streamLocalStream = null;
    }
    if (_streamScreenStream) {
        _streamScreenStream.getTracks().forEach(t => t.stop());
        _streamScreenStream = null;
    }
    _streamMuted = true;
    _streamVideoOn = false;
    _streamScreenSharing = false;
}


function _showStreamOverlay() {
    const overlay = $('stream-overlay');
    if (overlay) {
        overlay.style.display = 'flex';
        overlay.classList.add('show');
    }

    // Set title
    const titleEl = $('stream-title');
    if (titleEl) titleEl.textContent = _streamData?.title || 'Live';

    // Set host info
    const hostEl = $('stream-host-name');
    if (hostEl) {
        const host = _streamData?.participants?.find(p => p.role === 'host');
        hostEl.textContent = host?.display_name || '';
    }

    _updateViewerCount();
    _updateStreamControls();
    _updateLocalPreview();
}

function _hideStreamOverlay() {
    const overlay = $('stream-overlay');
    if (overlay) {
        overlay.classList.remove('show');
        overlay.style.display = 'none';
    }
}

function _updateViewerCount() {
    const el = $('stream-viewer-count');
    if (el) {
        const count = _streamData?.viewer_count || _streamData?.participants?.length || 0;
        el.textContent = count;
    }
}

function _updateStreamControls() {
    const isHost = _streamMyRole === 'host' || _streamMyRole === 'co_host';
    const canSpeak = isHost || _streamMyRole === 'speaker';

    // Mute button
    const muteBtn = $('stream-mute-btn');
    if (muteBtn) {
        muteBtn.style.display = canSpeak ? '' : 'none';
        muteBtn.classList.toggle('active', !_streamMuted);
    }

    // Video button
    const camBtn = $('stream-cam-btn');
    if (camBtn) {
        camBtn.style.display = canSpeak ? '' : 'none';
        camBtn.classList.toggle('active', _streamVideoOn);
    }

    // Screen share button
    const screenBtn = $('stream-screen-btn');
    if (screenBtn) {
        screenBtn.style.display = isHost ? '' : 'none';
        screenBtn.classList.toggle('active', _streamScreenSharing);
    }

    // End/leave button text
    const endBtn = $('stream-end-btn');
    if (endBtn) {
        endBtn.textContent = isHost ? t('stream.endStream') : t('stream.leave');
        endBtn.onclick = isHost ? endStream : leaveStream;
    }

    // Hand button (viewers only)
    const handBtn = $('stream-hand-btn');
    if (handBtn) {
        handBtn.style.display = (!canSpeak && _streamMyRole !== 'co_host') ? '' : 'none';
    }

    // Host controls panel
    const hostPanel = $('stream-host-controls');
    if (hostPanel) {
        hostPanel.style.display = isHost ? '' : 'none';
    }

    // Donation button
    const donateBtn = $('stream-donate-btn');
    if (donateBtn) {
        donateBtn.style.display = (_streamData?.allow_donations && !isHost) ? '' : 'none';
    }

    // Reactions panel
    const reactPanel = $('stream-reactions-panel');
    if (reactPanel) {
        reactPanel.style.display = _streamData?.allow_reactions ? '' : 'none';
    }
}

function _updateLocalPreview() {
    const localVideo = $('stream-local-preview');
    if (localVideo && _streamLocalStream && _streamVideoOn) {
        localVideo.srcObject = _streamLocalStream;
        localVideo.style.display = '';
    } else if (localVideo) {
        localVideo.style.display = 'none';
    }
}

function _updateRemoteVideo(peerId, stream) {
    // Main video area — show host/active speaker
    const mainVideo = $('stream-main-video');
    if (mainVideo) {
        // Find if this peer is the host
        const peerInfo = _streamData?.participants?.find(p => p.user_id === peerId);
        if (peerInfo && (peerInfo.role === 'host' || peerInfo.is_screen_sharing)) {
            mainVideo.srcObject = stream;
            mainVideo.style.display = '';
            const placeholder = $('stream-video-placeholder');
            if (placeholder) placeholder.style.display = 'none';
        }
    }
}

function _updateParticipantUI(userId) {
    // Update any participant-specific UI elements
}

function _updateHandButton(raised) {
    const btn = $('stream-hand-btn');
    if (btn) btn.classList.toggle('active', raised);
}

function _startStreamTimer() {
    _streamDuration = 0;
    const timerEl = $('stream-timer');
    _streamTimer = setInterval(() => {
        _streamDuration++;
        if (timerEl) {
            const m = Math.floor(_streamDuration / 60);
            const s = _streamDuration % 60;
            timerEl.textContent = `${m}:${s.toString().padStart(2, '0')}`;
        }
    }, 1000);
}

function _stopStreamTimer() {
    if (_streamTimer) {
        clearInterval(_streamTimer);
        _streamTimer = null;
    }
}

function _showStreamEnded() {
    const mainVideo = $('stream-main-video');
    if (mainVideo) mainVideo.style.display = 'none';
    const placeholder = $('stream-video-placeholder');
    if (placeholder) {
        placeholder.style.display = 'flex';
        placeholder.textContent = t('stream.ended');
    }
}

// ─── Reactions ──────────────────────────────────────────────────────────────

function _showReaction(emoji, username) {
    const container = $('stream-reactions-float');
    if (!container) return;

    const el = document.createElement('div');
    el.className = 'stream-reaction-float';
    el.textContent = emoji;
    // Random horizontal position
    el.style.left = (20 + Math.random() * 60) + '%';
    container.appendChild(el);

    // Remove after animation
    setTimeout(() => el.remove(), 2000);
}

function _showLocalReaction(emoji) {
    _showReaction(emoji, window.AppState.user?.username);
}

// ─── Donations ──────────────────────────────────────────────────────────────

function _showDonation(data) {
    const container = $('stream-donation-alert');
    if (!container) return;

    const nameEl = container.querySelector('.stream-donation-name');
    const amountEl = container.querySelector('.stream-donation-amount');
    const msgEl = container.querySelector('.stream-donation-text');

    if (nameEl) nameEl.textContent = data.display_name || data.username;
    if (amountEl) amountEl.textContent = `${data.amount} ${data.currency || 'RUB'}`;
    if (msgEl) msgEl.textContent = data.message || '';

    container.classList.add('show');
    setTimeout(() => container.classList.remove('show'), 5000);
}

function _showDonateModal() {
    const modal = $('stream-donate-modal');
    if (modal) modal.classList.add('show');

    // Show card info
    const cardInfo = $('stream-donate-card-info');
    if (cardInfo && _streamData?.donation_card) {
        cardInfo.textContent = _streamData.donation_card;
        cardInfo.style.display = '';
    }
    const cardMsg = $('stream-donate-card-msg');
    if (cardMsg && _streamData?.donation_message) {
        cardMsg.textContent = _streamData.donation_message;
    }
}

function _hideDonateModal() {
    const modal = $('stream-donate-modal');
    if (modal) modal.classList.remove('show');
}

// ─── Hand raised notifications ──────────────────────────────────────────────

function _showHandRaised(data) {
    const list = $('stream-hands-list');
    if (!list) return;

    // Check if already shown
    if (list.querySelector(`[data-uid="${data.user_id}"]`)) return;

    const row = document.createElement('div');
    row.className = 'stream-hand-row';
    row.dataset.uid = data.user_id;

    const avatar = document.createElement('span');
    avatar.className = 'stream-hand-avatar';
    if (data.avatar_url) {
        const img = document.createElement('img');
        img.src = data.avatar_url;
        img.style.cssText = 'width:100%;height:100%;border-radius:50%;object-fit:cover;';
        avatar.appendChild(img);
    } else {
        avatar.textContent = data.avatar_emoji || '\u{1F464}';
    }
    row.appendChild(avatar);

    const name = document.createElement('span');
    name.className = 'stream-hand-name';
    name.textContent = data.display_name || data.username;
    row.appendChild(name);

    const handIcon = document.createElement('span');
    handIcon.className = 'stream-hand-icon';
    handIcon.textContent = '\u{270B}';
    row.appendChild(handIcon);

    // Accept button (host only)
    if (_streamMyRole === 'host' || _streamMyRole === 'co_host') {
        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'stream-hand-accept';
        acceptBtn.textContent = t('stream.allowSpeak');
        acceptBtn.onclick = () => {
            grantStreamPermission(data.user_id, { role: 'speaker', can_speak: true, can_video: true });
            row.remove();
        };
        row.appendChild(acceptBtn);

        const rejectBtn = document.createElement('button');
        rejectBtn.className = 'stream-hand-reject';
        rejectBtn.textContent = '\u{2715}';
        rejectBtn.onclick = () => {
            row.remove();
        };
        row.appendChild(rejectBtn);
    }

    list.appendChild(row);
}

function _removeHandRaised(userId) {
    const list = $('stream-hands-list');
    if (!list) return;
    const row = list.querySelector(`[data-uid="${userId}"]`);
    if (row) row.remove();
}

// ─── Stream chat ────────────────────────────────────────────────────────────

function _appendStreamChat(data) {
    const chatEl = $('stream-chat-messages');
    if (!chatEl) return;

    const msg = document.createElement('div');
    msg.className = 'stream-chat-msg' + (data.is_self ? ' self' : '');

    const name = document.createElement('span');
    name.className = 'stream-chat-name';
    name.textContent = data.display_name || data.username;
    msg.appendChild(name);

    const text = document.createElement('span');
    text.className = 'stream-chat-text';
    text.textContent = data.text;
    msg.appendChild(text);

    chatEl.appendChild(msg);
    chatEl.scrollTop = chatEl.scrollHeight;

    // Keep max 200 messages
    while (chatEl.children.length > 200) {
        chatEl.removeChild(chatEl.firstChild);
    }
}

function _updateStreamUI() {
    _updateViewerCount();
    _updateStreamControls();
}

function _toggleDonationSection() {
    const toggle = $('stream-settings-donations');
    const section = $('stream-donation-settings');
    if (toggle && section) {
        section.style.display = toggle.checked ? '' : 'none';
    }
}

// ─── Window bindings ────────────────────────────────────────────────────────

window._toggleStreamDonationSection = _toggleDonationSection;
window._showDonateModal = _showDonateModal;
window._hideDonateModal = _hideDonateModal;

// Export stream-chat send handler
window._sendStreamChatMsg = function() {
    const input = $('stream-chat-input');
    if (input && input.value.trim()) {
        sendStreamChat(input.value);
        input.value = '';
    }
};

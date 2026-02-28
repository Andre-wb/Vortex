import { $, getCookie } from './utils.js';

// ============================================================================
// WebRTC (Audio/Video calls)
// ============================================================================

const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

function connectSignal(roomId) {
    const S = window.AppState;
    if (S.signalWs) { S.signalWs.close(); S.signalWs = null; }
    const token = getCookie('access_token');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    S.signalWs = new WebSocket(`${proto}://${location.host}/ws/signal/${roomId}?token=${token}`);

    S.signalWs.onmessage = async e => {
        const msg = JSON.parse(e.data);
        await handleSignal(msg);
    };

    S.signalWs.onclose = () => { S.signalWs = null; };
}

export async function startVoiceCall() {
    const S = window.AppState;
    if (!S.currentRoom) return;

    connectSignal(S.currentRoom.id);
    await new Promise(r => setTimeout(r, 300));

    try {
        S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    } catch {
        try {
            S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        } catch (e) {
            alert('Не удалось получить доступ к микрофону: ' + e.message);
            return;
        }
    }

    $('call-peer-name').textContent = S.currentRoom.name;
    $('call-peer-avatar').textContent = '💬';
    $('call-status').textContent = 'Ожидание...';
    $('local-video').srcObject = S.localStream;
    $('call-overlay').classList.add('show');

    S.pc = createPeerConnection();
    S.localStream.getTracks().forEach(t => S.pc.addTrack(t, S.localStream));

    const offer = await S.pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true });
    await S.pc.setLocalDescription(offer);

    signal({ type: 'invite' });
    signal({ type: 'offer', sdp: offer.sdp });
}

export async function startVideoCall() {
    const S = window.AppState;
    if (!S.currentRoom) return;
    connectSignal(S.currentRoom.id);
    await new Promise(r => setTimeout(r, 300));

    try {
        S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    } catch (e) {
        alert('Нет доступа к камере: ' + e.message);
        return;
    }

    $('call-peer-name').textContent = S.currentRoom.name;
    $('call-peer-avatar').textContent = '💬';
    $('call-status').textContent = 'Исходящий видеозвонок...';
    $('local-video').srcObject = S.localStream;
    $('call-overlay').classList.add('show');

    S.pc = createPeerConnection();
    S.localStream.getTracks().forEach(t => S.pc.addTrack(t, S.localStream));

    const offer = await S.pc.createOffer();
    await S.pc.setLocalDescription(offer);
    signal({ type: 'offer', sdp: offer.sdp });
}

function createPeerConnection() {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    pc.onicecandidate = e => {
        if (e.candidate) signal({ type: 'ice', candidate: e.candidate.toJSON() });
    };

    pc.ontrack = e => {
        $('remote-video').srcObject = e.streams[0];
        $('call-status').textContent = 'Соединение установлено';
    };

    pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'connected') $('call-status').textContent = 'Разговор...';
        if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) hangup();
    };

    return pc;
}

async function handleSignal(msg) {
    const S = window.AppState;
    const from = msg.from;

    if (msg.type === 'invite') {
        $('call-peer-name').textContent = msg.username || 'Собеседник';
        $('call-peer-avatar').textContent = '📞';
        $('call-status').textContent = `${msg.username} звонит...`;
        if (!$('call-overlay').classList.contains('show')) {
            if (!confirm(`${msg.username} приглашает в звонок. Принять?`)) {
                signal({ type: 'bye', to: from });
                return;
            }
            try {
                S.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
                $('local-video').srcObject = S.localStream;
            } catch { }
            $('call-overlay').classList.add('show');
        }
    }

    if (msg.type === 'offer') {
        if (!S.pc) S.pc = createPeerConnection();
        if (S.localStream) S.localStream.getTracks().forEach(t => S.pc.addTrack(t, S.localStream));
        await S.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        const answer = await S.pc.createAnswer();
        await S.pc.setLocalDescription(answer);
        signal({ type: 'answer', sdp: answer.sdp, to: from });
    }

    if (msg.type === 'answer') {
        await S.pc?.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
    }

    if (msg.type === 'ice') {
        try {
            await S.pc?.addIceCandidate(msg.candidate);
        } catch { }
    }

    if (msg.type === 'bye') {
        hangup();
    }
}

function signal(msg) {
    const S = window.AppState;
    if (S.signalWs?.readyState === WebSocket.OPEN) {
        S.signalWs.send(JSON.stringify(msg));
    }
}

export function hangup() {
    const S = window.AppState;
    signal({ type: 'bye' });
    S.pc?.close(); S.pc = null;
    S.localStream?.getTracks().forEach(t => t.stop()); S.localStream = null;
    $('remote-video').srcObject = null;
    $('local-video').srcObject = null;
    $('call-overlay').classList.remove('show');
    S.signalWs?.close(); S.signalWs = null;
}

export function toggleMute() {
    const S = window.AppState;
    S.isMuted = !S.isMuted;
    S.localStream?.getAudioTracks().forEach(t => t.enabled = !S.isMuted);
    $('mute-btn').textContent = S.isMuted ? '🔇' : '🎤';
}

export function toggleCam() {
    const S = window.AppState;
    S.isCamOff = !S.isCamOff;
    S.localStream?.getVideoTracks().forEach(t => t.enabled = !S.isCamOff);
    $('cam-btn').textContent = S.isCamOff ? '🚫' : '📷';
}
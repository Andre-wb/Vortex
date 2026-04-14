// static/js/sfu_client.js
// ============================================================================
// SFU Client — подключение к Vortex SFU для групповых звонков > threshold.
//
// Один RTCPeerConnection к серверному SFU вместо N-1 mesh-соединений.
// SFU принимает медиа от всех участников и пересылает каждому остальных.
//
// Сигнализация:
//   - Начальное подключение: REST POST /api/sfu/{callId}/join (offer→answer)
//   - Renegotiation (новые участники): WS /ws/sfu/{callId}
//   - ICE candidates: через тот же WS
// ============================================================================

import { api } from './utils.js';
import { needsEncodedInsertableStreams, setupPeerE2E, setupNewSenderE2E } from './e2e_media.js';

/**
 * Проверяет доступность SFU на сервере.
 * @returns {Promise<{available: boolean, threshold: number, max_participants: number}>}
 */
export async function checkSFUAvailable() {
    try {
        return await api('GET', '/api/sfu/available');
    } catch (_) {
        return { available: false, threshold: 999, max_participants: 10 };
    }
}

/**
 * SFU Client — управляет единственным PeerConnection к серверу.
 */
export class SFUClient {
    /**
     * @param {string} callId
     * @param {number} roomId
     * @param {MediaStream} localStream — локальный audio (+video) поток
     * @param {Array} iceServers — ICE/TURN конфигурация
     * @param {{key: CryptoKey, raw: Uint8Array}|null} mediaKey — E2E media encryption key
     */
    constructor(callId, roomId, localStream, iceServers, mediaKey = null) {
        this.callId = callId;
        this.roomId = roomId;
        this.localStream = localStream;
        this.iceServers = iceServers || [{ urls: 'stun:stun.l.google.com:19302' }];
        this.mediaKey = mediaKey;

        /** @type {RTCPeerConnection|null} */
        this.pc = null;
        /** @type {WebSocket|null} */
        this.ws = null;
        this.connected = false;

        // Callbacks (set by group_call.js)
        /** @type {function(MediaStreamTrack, MediaStream)|null} */
        this.onTrack = null;
        /** @type {function(number, string)|null} */
        this.onParticipantLeft = null;
        /** @type {function(object)|null} */
        this.onParticipantJoined = null;
        /** @type {function(string)|null} */
        this.onConnectionStateChange = null;
        /** @type {function(number, number)|null} — dominant speaker changed */
        this.onDominantSpeaker = null;
        /** @type {Object<number, string>} — current viewport subscriptions */
        this._viewportSubs = {};
    }

    /**
     * Subscribe to specific quality per user (viewport selection).
     * Only the focused/large user gets "high", others "medium" or "low".
     * Users outside viewport get "none" (audio only, no video forwarded).
     *
     * @param {Object<number, string>} subs — { userId: "high"|"medium"|"low"|"none" }
     */
    setViewportSubscriptions(subs) {
        this._viewportSubs = subs;
        if (this.ws?.readyState === WebSocket.OPEN) {
            try {
                this.ws.send(JSON.stringify({
                    type: 'sfu_subscribe',
                    subscriptions: subs,
                }));
            } catch {}
        }
    }

    /**
     * Report simulcast SSRC mapping to SFU.
     * Called after simulcast negotiation.
     */
    _reportSimulcastInfo() {
        if (!this.pc || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;
        const senders = this.pc.getSenders();
        const layers = {};
        for (const sender of senders) {
            if (sender.track?.kind !== 'video') continue;
            const params = sender.getParameters();
            if (params.encodings) {
                for (const enc of params.encodings) {
                    if (enc.rid && enc.ssrc) {
                        layers[enc.rid] = enc.ssrc;
                    }
                }
            }
        }
        if (Object.keys(layers).length > 0) {
            try {
                this.ws.send(JSON.stringify({ type: 'sfu_simulcast_info', layers }));
            } catch {}
        }
    }

    /**
     * Подключиться к SFU: создать PC, отправить offer, получить answer.
     * @returns {Promise<Array>} — список существующих участников
     */
    async connect() {
        const config = { iceServers: this.iceServers };
        if (this.mediaKey && needsEncodedInsertableStreams()) {
            config.encodedInsertableStreams = true;
        }
        this.pc = new RTCPeerConnection(config);

        // Добавляем локальные треки с simulcast для видео
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                if (track.kind === 'video') {
                    // Simulcast: 3 layers (high/medium/low) — SFU выбирает какой пересылать
                    const sender = this.pc.addTrack(track, this.localStream);
                    const params = sender.getParameters();
                    params.encodings = [
                        { rid: 'low',    maxBitrate: 150_000,   maxFramerate: 10, scaleResolutionDownBy: 4 },
                        { rid: 'medium', maxBitrate: 600_000,   maxFramerate: 20, scaleResolutionDownBy: 2 },
                        { rid: 'high',   maxBitrate: 2_500_000, maxFramerate: 30, scaleResolutionDownBy: 1 },
                    ];
                    sender.setParameters(params).catch(e => {
                        console.warn('[SFU-Client] Simulcast params failed:', e.message);
                    });
                } else {
                    this.pc.addTrack(track, this.localStream);
                }
            });
        }

        // E2E media frame encryption — wraps senders + hooks ontrack for receivers
        if (this.mediaKey) {
            setupPeerE2E(this.pc, this.mediaKey);
        }

        // Удалённые треки от SFU (медиа других участников)
        this.pc.ontrack = (e) => {
            console.log('[SFU-Client] ontrack:', e.track.kind, 'streams:', e.streams.length);
            if (this.onTrack) {
                this.onTrack(e.track, e.streams[0] || new MediaStream([e.track]));
            }
        };

        // ICE → отправляем через WS (если открыт) или копим
        this._pendingIce = [];
        this.pc.onicecandidate = (e) => {
            if (!e.candidate) return;
            const msg = { type: 'sfu_ice', candidate: e.candidate.toJSON() };
            if (this.ws?.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify(msg));
            } else {
                this._pendingIce.push(msg);
            }
        };

        this.pc.onconnectionstatechange = () => {
            const state = this.pc?.connectionState;
            console.log('[SFU-Client] connection state:', state);
            if (state === 'connected') this.connected = true;
            if (state === 'failed') this.connected = false;
            if (this.onConnectionStateChange) this.onConnectionStateChange(state);
        };

        // Создаём offer и ждём ICE gathering
        const offer = await this.pc.createOffer();
        await this.pc.setLocalDescription(offer);
        await this._waitIceGathering();

        // POST offer → SFU → answer
        const resp = await api('POST', `/api/sfu/${this.callId}/join`, {
            sdp: this.pc.localDescription.sdp,
        });

        await this.pc.setRemoteDescription({ type: 'answer', sdp: resp.sdp });

        // Подключаем WS для renegotiation
        this._connectWs();

        return resp.participants || [];
    }

    /**
     * Подключить WS для renegotiation и ICE.
     */
    _connectWs() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${proto}//${location.host}/ws/sfu/${this.callId}`);

        this.ws.onopen = () => {
            console.log('[SFU-Client] WS open');
            // Отправляем накопленные ICE candidates
            for (const msg of this._pendingIce) {
                this.ws.send(JSON.stringify(msg));
            }
            this._pendingIce = [];
            // Report simulcast SSRC mapping
            this._reportSimulcastInfo();
            // Re-send viewport subscriptions if set
            if (Object.keys(this._viewportSubs).length > 0) {
                this.setViewportSubscriptions(this._viewportSubs);
            }
        };

        this.ws.onmessage = async (event) => {
            let data;
            try { data = JSON.parse(event.data); } catch { return; }

            if (data.type === 'sfu_offer') {
                // Renegotiation: SFU добавил новые треки
                try {
                    await this.pc.setRemoteDescription({ type: 'offer', sdp: data.sdp });
                    const answer = await this.pc.createAnswer();
                    await this.pc.setLocalDescription(answer);
                    this.ws.send(JSON.stringify({
                        type: 'sfu_answer',
                        sdp: this.pc.localDescription.sdp,
                    }));
                } catch (e) {
                    console.error('[SFU-Client] renegotiation error:', e);
                }
            }

            if (data.type === 'sfu_ice') {
                try {
                    await this.pc.addIceCandidate(data.candidate);
                } catch (e) {
                    console.debug('[SFU-Client] ICE error:', e.message);
                }
            }

            if (data.type === 'sfu_participant_joined' && this.onParticipantJoined) {
                this.onParticipantJoined(data);
            }

            if (data.type === 'sfu_participant_left' && this.onParticipantLeft) {
                this.onParticipantLeft(data.user_id, data.username);
            }

            if (data.type === 'sfu_dominant_speaker' && this.onDominantSpeaker) {
                this.onDominantSpeaker(data.user_id, data.level);
            }
        };

        this.ws.onclose = () => {
            console.log('[SFU-Client] WS closed');
        };
    }

    /**
     * Ждём завершения ICE gathering (max 5s timeout).
     */
    _waitIceGathering() {
        if (this.pc.iceGatheringState === 'complete') return Promise.resolve();
        return new Promise(resolve => {
            const check = () => {
                if (this.pc.iceGatheringState === 'complete') {
                    this.pc.removeEventListener('icegatheringstatechange', check);
                    resolve();
                }
            };
            this.pc.addEventListener('icegatheringstatechange', check);
            setTimeout(resolve, 5000);
        });
    }

    /**
     * Заменить трек (screen share, camera toggle).
     * @param {MediaStreamTrack} oldTrack
     * @param {MediaStreamTrack} newTrack
     */
    async replaceTrack(oldTrack, newTrack) {
        const sender = this.pc?.getSenders().find(
            s => s.track === oldTrack || (s.track?.kind === newTrack.kind)
        );
        if (sender) {
            await sender.replaceTrack(newTrack);
        }
    }

    /**
     * Добавить новый трек (e.g., video when starting with audio-only).
     * @param {MediaStreamTrack} track
     * @param {MediaStream} stream
     * @returns {RTCRtpSender|null}
     */
    addTrack(track, stream) {
        if (this.pc) {
            const sender = this.pc.addTrack(track, stream);
            if (this.mediaKey) setupNewSenderE2E(sender, this.mediaKey);
            return sender;
        }
        return null;
    }

    /**
     * Отключиться от SFU, закрыть всё.
     */
    async disconnect() {
        this.connected = false;

        if (this.ws) {
            this.ws.onclose = null;
            this.ws.close();
            this.ws = null;
        }

        if (this.pc) {
            this.pc.ontrack = null;
            this.pc.onicecandidate = null;
            this.pc.onconnectionstatechange = null;
            this.pc.close();
            this.pc = null;
        }

        try {
            await api('POST', `/api/sfu/${this.callId}/leave`);
        } catch (_) {}
    }
}

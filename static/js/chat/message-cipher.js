// static/js/chat/message-cipher.js
// Единая точка шифрования/расшифровки текста сообщений.
//
// Все чат-модули обязаны шифровать и расшифровывать сообщения ТОЛЬКО через
// эти функции — прямые вызовы ratchetEncrypt/ratchetDecrypt вне данного модуля
// запрещены (проверяется static/js/__tests__/cipher-guard.test.js). Это
// единственное место, куда подключён Double Ratchet (v2): добавление новой
// версии здесь не требует правок в десятке call-sites.
//
// Проверка версии конверта (isKnownEncVersion) и обработка «нет ключа»
// остаются на стороне call-sites — у них разные тексты-заглушки.

import { ratchetEncrypt, ratchetDecrypt } from '../crypto.js';
import { decryptText } from './room-crypto.js';
import { ENC_V_CURRENT } from './enc-version.js';
import { api } from '../utils.js';
import { createSessionStore, indexedDbBackend } from '../dr/session-store.js';
import { decryptV2 as _drDecryptV2, encryptV2 as _drEncryptV2, dmSessionId, importX25519PrivJwk } from '../dr/session.js';
import { edVerify, loadEd25519Identity } from '../dr/prekeys.js';
import { verifyDeviceCert, loadOrCreateDeviceIdentity } from '../dr/device-identity.js';
import { pinPeerAccountEd, pinnedPeerAccountEd } from '../dr/identity-pin.js';
import { encodeFanout } from '../dr/v2-fanout.js';
import { createHistoryStore, historyBackend, decryptWithCache } from '../dr/history-store.js';
import { getClientDeviceId } from '../utils.js';

const _fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

// Фичефлаг v2-отправки в DM. ПО УМОЛЧАНИЮ ВКЛ (M3.3, активировано после
// зелёного real-browser гейта: playwright-tests/tests/dr-fanout.spec.js на
// Chrome/Firefox/WebKit). Kill-switch: per-client `vortex_v2_dm_enabled='0'`
// выключает отправку → фолбэк в v1 (приём v2 всегда вкл — уже-отправленное
// остаётся читаемым). Недоступный localStorage → false (v2 всё равно требует его
// для device-identity/prekey-store).
function _v2SendEnabled() {
    try { return localStorage.getItem('vortex_v2_dm_enabled') !== '0'; } catch { return false; }
}

// Фичефлаг PQXDH-отправки (post-quantum X3DH). ПО УМОЛЧАНИЮ ВКЛ (активировано
// pre-launch: приложение ещё не в сети, нет прод-риска, нет оператора-флиппера).
// Отдельно от v2-send (`vortex_v2_dm_enabled`) и room-key-гибрида (`vortex_pq_hybrid_enabled`).
// Kill-switch: per-client `vortex_pqxdh_enabled='0'` → отправка классическим X3DH
// (0x01); приём PQ (0x03) всегда-вкл (P4) — уже-отправленное остаётся читаемым.
// Безопасность default-on: ML-KEM — pure-JS (детерминирован, engine-independent);
// сбой движка на отправке → mlkemEncaps throw → encryptV2ForDm возвращает null →
// v1 fallback (не broken 0x03). Приём self-gated: 0x03 шлётся лишь устройству,
// опубликовавшему валидный PQSPK (⟹ его движок уже прогнал ML-KEM keygen).
function _pqxdhEnabled() {
    try { return localStorage.getItem('vortex_pqxdh_enabled') !== '0'; } catch { return false; }
}

/**
 * Шифрует текст сообщения текущей продовой схемой (v1, sender-chain).
 *
 * @param {string|number} roomId
 * @param {string|number} senderId
 * @param {string} text
 * @param {Uint8Array} roomKey — 32-байтный ключ комнаты
 * @returns {Promise<{enc_v: number, ciphertext: string}>}
 * @throws пробрасывает ошибку шифрования (например, при неверном roomKey) —
 *         call-site отвечает за пред-проверку наличия ключа.
 */
export async function encryptMessage(roomId, senderId, text, roomKey) {
    const ciphertext = await ratchetEncrypt(text, roomId, senderId, roomKey);
    return { enc_v: ENC_V_CURRENT, ciphertext };
}

/**
 * Расшифровывает текст сообщения существующих форматов v0/v1.
 *
 * Порядок: v1 sender-chain (ratchetDecrypt, у которого внутри есть фолбэк
 * на голый legacy v0) → padded-legacy (decryptText, magic 0x5678). Полностью
 * повторяет цепочку, которую до абстракции дублировал каждый call-site.
 *
 * @param {string} ciphertextHex
 * @param {string|number} roomId
 * @param {string|number} senderId
 * @param {Uint8Array} roomKey
 * @returns {Promise<string>} расшифрованный текст
 * @throws если ни v1, ни legacy расшифровать не смогли — call-site выбирает
 *         текст-заглушку.
 */
export async function decryptMessage(ciphertextHex, roomId, senderId, roomKey) {
    try {
        return await ratchetDecrypt(ciphertextHex, roomId, senderId, roomKey);
    } catch {
        return await decryptText(ciphertextHex, roomKey);
    }
}

// v2 — Double Ratchet. ТОЛЬКО ПРИЁМ: клиент умеет
// расшифровывать v2, но отправка — за фичефлагом выше.

let _v2Store = null;
function _sessionStore() {
    // Ленивая инициализация — IndexedDB создаётся только при первом v2-сообщении.
    if (!_v2Store) _v2Store = createSessionStore(indexedDbBackend());
    return _v2Store;
}

let _histStore = null;
function _historyStore() {
    if (!_histStore) _histStore = createHistoryStore(historyBackend());
    return _histStore;
}

/**
 * Возвращает ПРИПИНЕННЫЙ аккаунтный Ed25519 отправителя (корень проверки его
 * device-cert'а). Если пина нет (первый контакт по приёму) — фетчит бандл
 * отправителя и пиннит его identity_key_ed (TOFU). Смена у известного пира → null
 * (блок; расшифровка упадёт в no_sender_pin → плейсхолдер).
 */
async function _resolveSenderPin(senderUserId) {
    // Своё другое устройство: корень доверия — свой аккаунтный Ed25519 ЛОКАЛЬНО
    // (не серверная копия), сообщения от него авторизует наш же аккаунтный ключ.
    if (senderUserId != null && senderUserId === window.AppState?.user?.user_id) {
        const mine = loadEd25519Identity()?.pubHex;
        if (mine) return mine;
    }
    const pinned = pinnedPeerAccountEd(senderUserId);
    if (pinned) return pinned;
    try {
        const b = await api('GET', `/api/keys/prekeys/${senderUserId}`);
        const r = pinPeerAccountEd(senderUserId, b?.identity_key_ed);
        return r.trusted || null;
    } catch { return null; }
}

/**
 * Расшифровывает v2-конверт (device-rooted DR-сессия). Сессия ключуется по
 * УСТРОЙСТВУ-отправителю (senderDeviceId), cert инициатора проверяется против
 * припиненного аккаунтного Ed25519 отправителя. Бросает SessionError при
 * невозможности — call-site деградирует в плейсхолдер.
 * @param {string} envelopeHex — внутренний v2-конверт (из под-конверта fan-out)
 * @param {string|number} roomId — id DM-комнаты
 * @param {string|number} senderUserId — id отправителя (для пина account Ed25519)
 * @param {string} senderDeviceId — client_device_id устройства-отправителя (ключ сессии)
 * @returns {Promise<string>} plaintext
 */
export async function decryptV2Message(envelopeHex, roomId, senderUserId, senderDeviceId) {
    const device = await loadOrCreateDeviceIdentity();
    const myDeviceX3dhPriv = await importX25519PrivJwk(device.x3dhPriv);
    const trustedSenderAccountEd = await _resolveSenderPin(senderUserId);
    return _drDecryptV2(
        _sessionStore(), dmSessionId(roomId, senderDeviceId),
        { myDeviceX3dhPriv, trustedSenderAccountEd }, envelopeHex,
    );
}

/**
 * Расшифровка v2 с локальным кэшем плейнтекста. Кэш ключуется по msgId: история
 * и дубли доставки читаются из кэша, БЕЗ повторного расхода ключей ратчета.
 * @param {string} envelopeHex — внутренний v2-конверт
 * @param {string|number} roomId — id DM-комнаты
 * @param {string|number} msgId — серверный id сообщения (ключ кэша)
 * @param {string|number} senderUserId — id отправителя
 * @param {string} senderDeviceId — client_device_id устройства-отправителя
 * @returns {Promise<string>} plaintext
 */
export async function decryptV2WithHistory(envelopeHex, roomId, msgId, senderUserId, senderDeviceId) {
    return decryptWithCache(_historyStore(), roomId, msgId,
        () => decryptV2Message(envelopeHex, roomId, senderUserId, senderDeviceId));
}

/**
 * Кэширует плейнтекст ОТПРАВЛЕННОГО v2-сообщения под серверным msgId. Свои
 * сообщения нельзя расшифровать по receiving-цепочке (DR асимметричен), поэтому
 * их плейнтекст берётся только из этого кэша — на перезагрузке истории и на
 * собственном эхе. Вызывать по ACK (когда известен server_id). Best-effort.
 */
export async function cacheV2Sent(roomId, msgId, plaintext) {
    try { await _historyStore().put(roomId, msgId, plaintext); }
    catch (e) { console.debug('[v2] cacheV2Sent failed:', e?.message); }
}

/** Читает кэшированный плейнтекст v2 (для своих сообщений — единственный источник). */
export async function getV2Cached(roomId, msgId) {
    try { return await _historyStore().get(roomId, msgId); }
    catch { return null; }
}

/**
 * Проверяет цепочку доверия бандла адресата против ПРИПИНЕННОГО аккаунтного
 * Ed25519 (не против отданного сервером в бандле — иначе сервер подменит корень):
 *   pinned account Ed25519 ──cert──▶ device signing key ──sign──▶ SPK,
 * плюс аккаунтный binding X25519 identity_key. Устройство без валидного cert
 * (в т.ч. вставленное сервером) отбраковывается.
 * @param {object} bundle
 * @param {string} trustedAccountEdPub — TOFU-пин аккаунтного Ed25519 пира
 */
async function _bundleWellSigned(bundle, trustedAccountEdPub) {
    if (!trustedAccountEdPub || !bundle.signed_prekey_sig || !bundle.identity_key_sig
        || !bundle.device_x3dh_pub || !bundle.device_sign_pub
        || !bundle.device_cert_sig || !bundle.client_device_id) return false;
    // припиненный account Ed25519 авторизует устройство (cert над тройкой)
    const certOk = await verifyDeviceCert(
        bundle.client_device_id, bundle.device_x3dh_pub, bundle.device_sign_pub,
        bundle.device_cert_sig, trustedAccountEdPub);
    // device signing-ключ подписал SPK
    const spkOk = await edVerify(bundle.device_sign_pub, _fromHex(bundle.signed_prekey), bundle.signed_prekey_sig);
    // припиненный account Ed25519 связывает X25519 identity_key (binding)
    const idOk  = await edVerify(trustedAccountEdPub, _fromHex(bundle.identity_key), bundle.identity_key_sig);
    return certOk && spkOk && idOk;
}

/**
 * Capability PQXDH: несёт ли бандл ВАЛИДНЫЙ подписанный per-device Kyber pre-key.
 * device_kyber_sig проверяется над СЫРЫМИ байтами device_kyber_pub против
 * device_sign_pub — тот же ключ и те же байты, что P2 подписывал (byte-lock seam).
 * device_sign_pub уже доверен (cert против припиненного account Ed в _bundleWellSigned),
 * поэтому валидная подпись = аутентичный PQSPK. Вызывать ТОЛЬКО для well-signed бандла.
 */
async function _pqspkVerified(bundle) {
    if (!bundle.device_kyber_pub || !bundle.device_kyber_sig || bundle.device_kyber_id == null) return false;
    return edVerify(bundle.device_sign_pub, _fromHex(bundle.device_kyber_pub), bundle.device_kyber_sig);
}

/** Копия бандла без PQSPK-полей → адресат таргетится классическим X3DH (0x01). */
function _stripPqspk(bundle) {
    return { ...bundle, device_kyber_pub: null, device_kyber_sig: null, device_kyber_id: null };
}

/**
 * Из ответа `/devices` собирает валидные целевые устройства для fan-out:
 * capability, account X25519 TOFU (для пира) и цепочка cert'а против
 * trustedAccountEd. Устройства без валидного cert (в т.ч. вставленные сервером)
 * и своё текущее (excludeDeviceId) отбрасываются — с логом.
 * @returns {Promise<Array<{clientDeviceId:string, bundle:object}>>}
 */
async function _collectValidDevices(list, trustedAccountEd, peerX25519, excludeDeviceId) {
    const out = [];
    for (const b of (list?.bundles || [])) {
        if (excludeDeviceId && b.client_device_id === excludeDeviceId) continue;   // своё текущее
        if (b.supports_v2 !== true) continue;
        if (peerX25519 && b.identity_key !== peerX25519) continue;                 // account X25519 TOFU
        if (await _bundleWellSigned(b, trustedAccountEd)) {
            // PQXDH capability: держим PQSPK-поля ТОЛЬКО при вкл-флаге И валидной
            // подписи; иначе снимаем → адресат таргетится классикой (плохой PQSPK
            // не ломает v2, лишь отключает PQ для этого устройства).
            const pqOk = _pqxdhEnabled() && await _pqspkVerified(b);
            out.push({ clientDeviceId: b.client_device_id, bundle: pqOk ? b : _stripPqspk(b) });
        } else {
            console.debug('[v2] fan-out: skipping device (invalid cert)', b.client_device_id);
        }
    }
    return out;
}

// TTL discovery-кэша набора устройств. Сессии durable (IndexedDB) — устройству с
// установленной сессией бандл/фетч не нужны; `/devices` дёргается ТОЛЬКО чтобы
// (пере)открыть набор устройств. `/devices` OPK НЕ расходует (M4a) — свежий OPK
// берётся на УСТАНОВЛЕНИИ сессии через /claim-opk. Стационарная переписка = 0
// фетчей, 0 OPK; на TTL-рефреше — тоже 0 OPK (только discovery).
const _V2_DISCOVERY_TTL_MS = 5 * 60 * 1000;

/**
 * Открывает набор валидных целевых устройств (адресат + свои другие): фетч
 * `/devices` (БЕЗ расхода OPK, M4a), пин аккаунтного Ed25519 адресата, проверка
 * cert-цепочки. Каждое устройство помечается userId (у кого claim'ить OPK на
 * установлении). Бросает с _fallback=true при окончательных причинах (не v2).
 */
async function _discoverTargets(peer, device) {
    const reject = (m) => { const e = new Error(m); e._fallback = true; throw e; };

    const peerList = await api('GET', `/api/keys/prekeys/${peer.user_id}/devices`);
    const peerEd = (peerList?.bundles || []).find(b => b.identity_key_ed)?.identity_key_ed;
    const pin = pinPeerAccountEd(peer.user_id, peerEd);
    if (pin.changed) { console.warn('[v2] peer account Ed25519 changed — blocking v2'); reject('acct_ed_changed'); }
    if (!pin.trusted) reject('no_acct_ed');
    const peerTargets = (await _collectValidDevices(peerList, pin.trusted, peer.x25519_public_key, null))
        .map(t => ({ ...t, userId: peer.user_id }));
    if (!peerTargets.length) reject('no_valid_peer_devices');

    let ownTargets = [];
    const myAccountEd = loadEd25519Identity()?.pubHex;
    const myUserId = window.AppState?.user?.user_id;
    if (myAccountEd && myUserId) {
        try {
            const ownList = await api('GET', `/api/keys/prekeys/${myUserId}/devices`);
            ownTargets = (await _collectValidDevices(ownList, myAccountEd, null, device.deviceId))
                .map(t => ({ ...t, userId: myUserId }));
        } catch (e) { console.debug('[v2] own-device fan-out skipped:', e?.message); }
    }
    return [...peerTargets, ...ownTargets];
}

/**
 * M4d: удаляет DR-сессии комнаты для устройств, которых больше нет в валидном
 * наборе (отозваны/удалены) — сессия к ним брошена и лишь занимает IndexedDB.
 * Вызывается после СВЕЖЕГО discovery (валидный набор устройств известен).
 * Отзыв ЧУЖОГО устройства доходит сюда через серверное удаление его бандла
 * (A1) — на TTL-рефреше discovery, не мгновенным push.
 */
async function _pruneAbandonedSessions(roomId, validDeviceIds) {
    try {
        const store = _sessionStore();
        if (typeof store.sessionIds !== 'function') return;
        const prefix = dmSessionId(roomId, '');   // "dm:<roomId>:"
        for (const sid of await store.sessionIds()) {
            if (!sid.startsWith(prefix)) continue;
            const deviceId = sid.slice(prefix.length);
            if (!validDeviceIds.has(deviceId)) {
                await store.delete(sid);
                console.debug('[v2] pruned abandoned session', sid);
            }
        }
    } catch (e) { console.debug('[v2] session prune skipped:', e?.message); }
}

/**
 * Устанавливающий getPeerBundle: claim'ит свежий OPK устройства (discovery его не
 * даёт — M4a). Вызывается _drEncryptV2 ТОЛЬКО при отсутствии сессии (установление);
 * для установленной сессии не зовётся → OPK не тратится. Нет OPK → 3-DH без OPK.
 */
async function _claimingBundle(target) {
    // PQOPK claim'им ТОЛЬКО когда сессия реально идёт в PQ (бандл несёт проверенный
    // PQSPK ⟺ флаг вкл + валидная подпись). Иначе не-PQ трафик выжигал бы пул PQOPK.
    const wantKyber = target.bundle.device_kyber_pub != null;
    let opk = null;
    try {
        opk = await api('POST', `/api/keys/prekeys/${target.userId}/claim-opk`,
            { device_id: target.bundle.device_id, want_kyber: wantKyber });
    } catch (e) { console.debug('[v2] claim-opk failed, X3DH without OPK:', e?.message); }
    return {
        ...target.bundle,
        one_time_prekey: opk?.one_time_prekey ?? null,
        one_time_prekey_id: opk?.one_time_prekey_id ?? null,
        one_time_kyber_prekey: opk?.one_time_kyber_prekey ?? null,
        one_time_kyber_prekey_id: opk?.one_time_kyber_prekey_id ?? null,
    };
}

/**
 * Пытается зашифровать сообщение в v2 для DM-комнаты через fan-out: по под-конверту
 * на каждое ВАЛИДНОЕ устройство адресата И на свои ДРУГИЕ устройства (own-device
 * fan-out). Возвращает {enc_v:2, ciphertext: fan-out-blob} при успехе, либо null —
 * тогда call-site шлёт v1. `room._v2`: 'no' — окончательно не v2. Набор устройств
 * кэшируется на room (`_v2Discovery`, TTL) — стационарная переписка не фетчит `/devices`.
 * @param {object} room — S.currentRoom (нужны is_dm, id, dm_user)
 * @param {string} plaintext
 * @returns {Promise<{enc_v:number, ciphertext:string}|null>}
 */
export async function encryptV2ForDm(room, plaintext) {
    if (!_v2SendEnabled()) return null;                 // фичефлаг (kill-switch)
    if (!room?.is_dm || room._v2 === 'no') return null;
    const peer = room.dm_user;
    if (!peer?.user_id || !peer?.x25519_public_key) return null;

    // Идентичность инициатора (наше устройство). Без cert'а авторизоваться нельзя.
    let device;
    try { device = await loadOrCreateDeviceIdentity(); } catch { return null; }
    if (!device?.certSig || !device?.x3dhPriv) return null;
    let myDeviceX3dhPriv;
    try { myDeviceX3dhPriv = await importX25519PrivJwk(device.x3dhPriv); } catch { return null; }
    const myCert = { clientDeviceId: device.deviceId, deviceSignPub: device.signPub, deviceCertSig: device.certSig };

    try {
        // Discovery-кэш: свежий набор → без фетча `/devices` (0 OPK); иначе открываем.
        let cached = room._v2Discovery && room._v2Discovery.expiresAt > Date.now();
        if (!cached) {
            const targets = await _discoverTargets(peer, device);
            room._v2Discovery = { targets, expiresAt: Date.now() + _V2_DISCOVERY_TTL_MS };
            // M4d: почистить сессии к устройствам, ушедшим из набора. Редко (только на
            // TTL-рефреше discovery) и быстро (локальный IndexedDB) — awaited, не блокер.
            await _pruneAbandonedSessions(room.id, new Set(targets.map(t => t.clientDeviceId)));
        }
        const targets = room._v2Discovery.targets;

        // Шифруем по под-конверту на каждое устройство (своя per-device сессия).
        // getPeerBundle claim'ит свежий OPK — ТОЛЬКО при установлении (нет сессии).
        const subs = {};
        try {
            for (const t of targets) {
                const ctx = { myDeviceX3dhPriv, myDeviceX3dhPubHex: device.x3dhPub, myCert, getPeerBundle: () => _claimingBundle(t) };
                subs[t.clientDeviceId] = await _drEncryptV2(_sessionStore(), dmSessionId(room.id, t.clientDeviceId), ctx, plaintext);
            }
        } catch (e) {
            // Establish/encrypt упал — сбрасываем discovery-кэш (набор мог устареть),
            // следующее сообщение перефетчит. Свежий OPK claim'ится заново.
            if (cached) delete room._v2Discovery;
            throw e;
        }
        room._v2 = 'yes';
        return { enc_v: 2, ciphertext: encodeFanout(device.deviceId, subs) };
    } catch (e) {
        if (e && e._fallback) room._v2 = 'no';   // окончательно — далее шлём v1 без перезапросов
        else console.debug('[v2] transient fan-out failure, will retry:', e?.message);
        return null;
    }
}

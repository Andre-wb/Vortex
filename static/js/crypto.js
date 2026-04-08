// static/js/crypto.js
// ============================================================================
// E2E криптография: ECIES (X25519 + HKDF + AES-256-GCM) для ключей комнат.
// Приватный ключ хранится как JWK JSON-строка (Web Crypto не позволяет
// экспортировать X25519 private key как 'raw').
// ============================================================================

const toHex   = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
const fromHex = h => {
    const m = h?.match(/.{2}/g);
    if (!m) throw new Error('Invalid hex string');
    return Uint8Array.from(m.map(b => parseInt(b, 16)));
};

/**
 * Шифрует roomKey для получателя через ECIES (X25519 + HKDF + AES-GCM).
 * @param {Uint8Array} roomKeyBytes - 32-байтный ключ комнаты
 * @param {string} recipientPubHex - X25519 публичный ключ получателя (hex)
 * @returns {Promise<{ephemeral_pub: string, ciphertext: string}>}
 */
export async function eciesEncrypt(roomKeyBytes, recipientPubHex) {
    // Эфемерная X25519 пара (новая для каждого шифрования — forward secrecy)
    const ephPair = await crypto.subtle.generateKey(
        { name: 'X25519' }, true, ['deriveBits']
    );
    const ephPubRaw = await crypto.subtle.exportKey('raw', ephPair.publicKey);

    // Импортируем публичный ключ получателя
    const recipientPub = await crypto.subtle.importKey(
        'raw', fromHex(recipientPubHex), { name: 'X25519' }, false, []
    );

    // X25519 DH → shared secret
    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: recipientPub },
        ephPair.privateKey, 256
    );

    // HKDF-SHA256(shared, salt=ephPub, info="ecies-room-key") → ключ AES
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const encKey  = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('vortex-session') },
        hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );

    // AES-256-GCM шифрование
    const nonce      = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, encKey, roomKeyBytes);

    return {
        ephemeral_pub: toHex(ephPubRaw),
        ciphertext:    toHex(nonce) + toHex(ciphertext),
    };
}

/**
 * Расшифровывает ключ комнаты через ECIES.
 * @param {string} ephemeralPubHex - эфемерный публичный ключ (hex)
 * @param {string} ciphertextHex   - зашифрованные данные (hex)
 * @param {string} ourPrivKeyJwk   - приватный ключ как JWK JSON-строка
 * @returns {Promise<Uint8Array>} - расшифрованный ключ комнаты (32 байта)
 */
export async function eciesDecrypt(ephemeralPubHex, ciphertextHex, ourPrivKeyJwk) {
    const ephPubRaw = fromHex(ephemeralPubHex);

    // Импортируем эфемерный публичный ключ
    const ephPub = await crypto.subtle.importKey(
        'raw', ephPubRaw, { name: 'X25519' }, false, []
    );

    // Импортируем наш приватный ключ из JWK (не raw — X25519 так не работает)
    const ourPriv = await crypto.subtle.importKey(
        'jwk', JSON.parse(ourPrivKeyJwk), { name: 'X25519' }, false, ['deriveBits']
    );

    // X25519 DH → shared secret
    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: ephPub }, ourPriv, 256
    );

    // HKDF → ключ AES
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const encKey  = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('vortex-session') },
        hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    // AES-256-GCM расшифровка
    const ctBytes = fromHex(ciphertextHex);
    const nonce   = ctBytes.slice(0, 12);
    const ct      = ctBytes.slice(12);
    const roomKey = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, encKey, ct);
    return new Uint8Array(roomKey);
}

// ============================================================================
// Хранилище ключей комнат в памяти (roomId → Uint8Array)
// Три уровня: JS heap → sessionStorage → localStorage
// + BroadcastChannel для синхронизации между вкладками
// ============================================================================

const _roomKeys = {};
const _rkHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const _rkFromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16)));

// BroadcastChannel — синхронизация ключей между вкладками в реальном времени
let _rkChannel = null;
try {
    _rkChannel = new BroadcastChannel('vortex_room_keys');
    _rkChannel.onmessage = (e) => {
        const { roomId, hex } = e.data || {};
        if (!roomId) return;
        if (hex) {
            _roomKeys[roomId] = _rkFromHex(hex);
        } else {
            delete _roomKeys[roomId];
        }
    };
} catch {}

export function getRoomKey(roomId) {
    if (_roomKeys[roomId]) return _roomKeys[roomId];
    // Fallback: sessionStorage → localStorage
    try {
        const hex = sessionStorage.getItem(`vortex_rk_${roomId}`)
                 || localStorage.getItem(`vortex_rk_${roomId}`);
        if (hex) {
            const bytes = _rkFromHex(hex);
            _roomKeys[roomId] = bytes;
            return bytes;
        }
    } catch {}
    return null;
}

export function setRoomKey(roomId, keyBytes) {
    _roomKeys[roomId] = keyBytes;
    try {
        if (keyBytes) {
            const hex = _rkHex(keyBytes);
            sessionStorage.setItem(`vortex_rk_${roomId}`, hex);
            localStorage.setItem(`vortex_rk_${roomId}`, hex);
            // Уведомляем другие вкладки
            _rkChannel?.postMessage({ roomId, hex });
        } else {
            sessionStorage.removeItem(`vortex_rk_${roomId}`);
            localStorage.removeItem(`vortex_rk_${roomId}`);
            _rkChannel?.postMessage({ roomId, hex: null });
        }
    } catch {}
}

// ============================================================================
// E2E File Encryption — шифрование файлов ключом комнаты
// ============================================================================

/**
 * Шифрует файл ключом комнаты (AES-256-GCM).
 * @param {ArrayBuffer} fileData — содержимое файла
 * @param {Uint8Array} roomKeyBytes — 32-байтный ключ комнаты
 * @returns {Promise<ArrayBuffer>} — nonce(12) + ciphertext
 */
export async function encryptFile(fileData, roomKeyBytes) {
    const key = await crypto.subtle.importKey(
        'raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, key, fileData
    );
    // nonce(12) + encrypted data
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(ct), 12);
    return result.buffer;
}

/**
 * Расшифровывает файл ключом комнаты.
 * @param {ArrayBuffer} encryptedData — nonce(12) + ciphertext
 * @param {Uint8Array} roomKeyBytes — 32-байтный ключ комнаты
 * @returns {Promise<ArrayBuffer>} — расшифрованное содержимое
 */
export async function decryptFile(encryptedData, roomKeyBytes) {
    const data = new Uint8Array(encryptedData);
    const nonce = data.slice(0, 12);
    const ct = data.slice(12);
    const key = await crypto.subtle.importKey(
        'raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
}

// ============================================================================
// Message Ratchet — KDF chain для forward secrecy
// ============================================================================

// Каждый отправитель в комнате имеет свой chain.
// При каждом сообщении:
//   message_key = HKDF(chain_key, info="msg-key")
//   next_chain  = HKDF(chain_key, info="chain-advance")
// Старый chain_key удаляется → forward secrecy.

const _ratchetChains = {};  // roomId:senderId → { chainKey: Uint8Array, counter: number }

export function initRatchet(roomId, senderId, roomKeyBytes) {
    const key = `${roomId}:${senderId}`;
    _ratchetChains[key] = {
        chainKey: new Uint8Array(roomKeyBytes),
        counter: 0,
    };
}

export async function ratchetEncrypt(text, roomId, senderId, roomKeyBytes) {
    const key = `${roomId}:${senderId}`;
    if (!_ratchetChains[key]) {
        initRatchet(roomId, senderId, roomKeyBytes);
    }

    const chain = _ratchetChains[key];

    // Derive message key from current chain key
    const msgKey = await _deriveKey(chain.chainKey, 'msg-key');

    // Advance chain (old chain key is overwritten → forward secrecy)
    chain.chainKey = await _deriveRaw(chain.chainKey, 'chain-advance');
    const counter = chain.counter++;

    // Encrypt with message key
    const aesKey = await crypto.subtle.importKey('raw', msgKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const nonce  = crypto.getRandomValues(new Uint8Array(12));
    const ct     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, new TextEncoder().encode(text));

    // Format: counter(4 bytes BE) + nonce(12) + ciphertext
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter);

    const result = new Uint8Array(4 + 12 + ct.byteLength);
    result.set(counterBytes, 0);
    result.set(nonce, 4);
    result.set(new Uint8Array(ct), 16);

    return Array.from(result, b => b.toString(16).padStart(2, '0')).join('');
}

export async function ratchetDecrypt(ciphertextHex, roomId, senderId, roomKeyBytes) {
    const raw = Uint8Array.from(ciphertextHex.match(/.{2}/g).map(b => parseInt(b, 16)));

    if (raw.length < 20) {
        return _legacyDecrypt(ciphertextHex, roomKeyBytes);
    }

    const counter = new DataView(raw.buffer, raw.byteOffset, 4).getUint32(0);

    // Если counter слишком большой — это скорее всего legacy формат (первые 4 байта = часть nonce)
    if (counter > 100000) {
        return _legacyDecrypt(ciphertextHex, roomKeyBytes);
    }

    const nonce = raw.slice(4, 16);
    const ct    = raw.slice(16);

    const key = `${roomId}:${senderId}`;
    if (!_ratchetChains[key]) {
        initRatchet(roomId, senderId, roomKeyBytes);
    }

    let chain = _ratchetChains[key];

    // Если counter меньше текущей позиции цепочки — отправитель перезагрузил страницу
    // и рачет сбросился. Переинициализируем цепочку с нуля.
    if (counter < chain.counter) {
        initRatchet(roomId, senderId, roomKeyBytes);
        chain = _ratchetChains[key];
    }

    // Сохраняем состояние на случай ошибки (чтобы не сломать chain)
    const savedChainKey = new Uint8Array(chain.chainKey);
    const savedCounter  = chain.counter;

    try {
        // Advance chain to the right counter
        while (chain.counter < counter) {
            chain.chainKey = await _deriveRaw(chain.chainKey, 'chain-advance');
            chain.counter++;
        }

        const msgKey = await _deriveKey(chain.chainKey, 'msg-key');
        chain.chainKey = await _deriveRaw(chain.chainKey, 'chain-advance');
        chain.counter++;

        const aesKey = await crypto.subtle.importKey('raw', msgKey, { name: 'AES-GCM' }, false, ['decrypt']);
        const plain  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct);
        return new TextDecoder().decode(plain);
    } catch {
        // Ratchet decrypt не удался — пробуем переинициализировать цепочку
        initRatchet(roomId, senderId, roomKeyBytes);
        chain = _ratchetChains[key];
        try {
            while (chain.counter < counter) {
                chain.chainKey = await _deriveRaw(chain.chainKey, 'chain-advance');
                chain.counter++;
            }
            const msgKey = await _deriveKey(chain.chainKey, 'msg-key');
            chain.chainKey = await _deriveRaw(chain.chainKey, 'chain-advance');
            chain.counter++;
            const aesKey = await crypto.subtle.importKey('raw', msgKey, { name: 'AES-GCM' }, false, ['decrypt']);
            const plain  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct);
            return new TextDecoder().decode(plain);
        } catch {
            // Всё ещё не получилось — пробуем legacy
            chain.chainKey = savedChainKey;
            chain.counter  = savedCounter;
            return _legacyDecrypt(ciphertextHex, roomKeyBytes);
        }
    }
}

async function _deriveRaw(keyBytes, info) {
    const hkdfKey = await crypto.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
        hkdfKey, 256
    );
    return new Uint8Array(bits);
}

async function _deriveKey(keyBytes, info) {
    return _deriveRaw(keyBytes, info);
}

async function _legacyDecrypt(ciphertextHex, roomKeyBytes) {
    const raw   = Uint8Array.from(ciphertextHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const nonce = raw.slice(0, 12);
    const ct    = raw.slice(12);
    const key   = await crypto.subtle.importKey('raw', roomKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
    return new TextDecoder().decode(plain);
}

export function clearRatchet(roomId) {
    const prefix = `${roomId}:`;
    for (const key of Object.keys(_ratchetChains)) {
        if (key.startsWith(prefix)) delete _ratchetChains[key];
    }
}
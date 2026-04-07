# Vortex API Reference

Base URL: `https://your-node:8443`

## Authentication

All API requests require JWT token via:
- Cookie: `access_token=<jwt>`
- Header: `Authorization: Bearer <jwt>`

### Register
```
POST /api/authentication/register
Body: { "username": "alice", "password": "strongpass123" }
Response: { "ok": true, "user_id": 1, "seed_phrase": "word1 word2 ... word24" }
```

### Login
```
POST /api/authentication/login
Body: { "username": "alice", "password": "strongpass123" }
Response: { "ok": true, "access_token": "<jwt>" }
```

### Login with Seed Phrase
```
POST /api/authentication/login-seed
Body: { "username": "alice", "seed_phrase": "word1 word2 ... word24" }
```

### 2FA (TOTP)
```
POST /api/authentication/2fa/setup    → { "secret": "...", "qr_uri": "..." }
POST /api/authentication/2fa/verify   → { "code": "123456" }
```

### WebAuthn / Passkey
```
POST /api/authentication/webauthn/register-begin
POST /api/authentication/webauthn/register-complete
POST /api/authentication/webauthn/login-begin
POST /api/authentication/webauthn/login-complete
```

## Rooms

### Create Room
```
POST /api/rooms/create
Body: { "name": "General", "description": "...", "is_private": true }
Response: { "ok": true, "room": { "id": 1, "name": "General", ... } }
```

### Join Room
```
POST /api/rooms/join/{room_id}
POST /api/rooms/join-invite/{invite_code}
```

### Room Members
```
GET  /api/rooms/{room_id}/members
POST /api/rooms/{room_id}/kick/{user_id}
POST /api/rooms/{room_id}/ban/{user_id}
POST /api/rooms/{room_id}/role   Body: { "user_id": 1, "role": "admin" }
```

## Messages (WebSocket)

Connect: `WSS /ws/{room_id}`

### Send Message
```json
{ "type": "message", "content_encrypted": "<base64(AES-GCM)>", "reply_to_id": null }
```

### Receive Message
```json
{
  "type": "message",
  "sender_pseudo": "b2a4...",
  "display_name": "Alice",
  "content_encrypted": "<base64>",
  "created_at": "2026-04-03T12:00:00Z",
  "msg_id": 42
}
```

### Message Actions
```
POST /api/messages/{msg_id}/react      Body: { "emoji": "👍" }
POST /api/messages/{msg_id}/edit       Body: { "content_encrypted": "<base64>" }
DELETE /api/messages/{msg_id}
POST /api/messages/{msg_id}/pin
```

## Files

### Upload
```
POST /api/files/upload/{room_id}
Content-Type: multipart/form-data
Field: file
Response: { "ok": true, "file_id": 1, "download_url": "/api/files/download/1" }
```

### Download
```
GET /api/files/download/{file_id}
```

## Calls

### 1-to-1
```
WebSocket signal: /ws/signal/{room_id}
Messages: { type: "offer/answer/ice", sdp/candidate: "..." }
```

### Group Calls
```
POST /api/group-calls/{room_id}/start    Body: { "with_video": true }
POST /api/group-calls/{call_id}/join
POST /api/group-calls/{call_id}/leave
POST /api/group-calls/{call_id}/end
GET  /api/group-calls/{call_id}/status
GET  /api/group-calls/{room_id}/active
POST /api/group-calls/{call_id}/add/{user_id}
```

## Key Management

### Key Backup
```
POST /api/keys/backup         Body: { "encrypted_keys": "<base64>", "salt": "<hex>" }
GET  /api/keys/backup
POST /api/keys/device-link/request
POST /api/keys/device-link/approve/{request_id}
```

### Fingerprint Verification
```
POST /api/contacts/{contact_id}/verify-fingerprint   Body: { "pubkey_hash": "<hex>" }
DELETE /api/contacts/{contact_id}/verify-fingerprint
```

## Federation

### Join Remote Room
```
POST /api/federation/join   Body: { "peer_ip": "node2.example.com", "peer_port": 8443, "remote_room_id": 5 }
```

### Multihop
```
POST /api/federation/multihop-join   Body: { "hops": ["node2:8443", "node3:8443"], "target_room_id": 5 }
```

## Push Notifications

### Web Push (VAPID)
```
POST /api/push/subscribe     Body: { "subscription": { "endpoint": "...", "keys": {...} } }
DELETE /api/push/unsubscribe
```

### UnifiedPush
```
POST /api/native/push/register   Body: { "token": "<endpoint>", "platform": "unified_push" }
```

## Webhooks

### Register Webhook
```
POST /api/webhooks/register   Body: { "room_id": 1, "url": "https://...", "events": ["message", "file_upload"] }
```

Webhook payload signed with `X-Vortex-Signature: sha256=<hmac>`.

## Privacy

```
GET  /api/privacy/tor/status
GET  /api/privacy/ip-policy
POST /api/privacy/panic       → Destroys account and all keys
```

## Native Bridge (Capacitor)

```
GET  /api/native/capabilities
POST /api/native/push/register
POST /api/native/biometric/challenge
```

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| Login | 5/min |
| Register | 3/min |
| Messages | 30/min |
| File upload | 10/min |
| API general | 100/min |

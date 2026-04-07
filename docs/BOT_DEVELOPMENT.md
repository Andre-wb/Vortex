# Vortex Bot Development Guide

## Overview

Vortex supports bots through three interfaces:
1. **HTTP Webhooks** — receive events via HTTPS POST
2. **WebSocket** — real-time bidirectional communication
3. **Gravitix DSL** — custom language for bot logic (Rust runtime)

## Quick Start: Webhook Bot

### 1. Register a Bot

```bash
curl -X POST https://your-node:8443/api/bots/create \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "MyBot", "description": "A helpful bot"}'
# Response: { "bot_id": 1, "token": "bot_abc123..." }
```

### 2. Set Webhook URL

```bash
curl -X POST https://your-node:8443/api/webhooks/register \
  -H "Authorization: Bearer bot_abc123..." \
  -d '{"room_id": 1, "url": "https://myserver.com/webhook", "events": ["message"]}'
```

### 3. Handle Events

```python
from flask import Flask, request
import hmac, hashlib

app = Flask(__name__)
WEBHOOK_SECRET = "your-webhook-secret"

@app.route("/webhook", methods=["POST"])
def handle():
    # Verify signature
    sig = request.headers.get("X-Vortex-Signature", "")
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), request.data, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return "Invalid signature", 403

    event = request.json
    if event["event"] == "message":
        print(f"New message in room {event['room_id']}: {event['data']}")
    return "OK"
```

## WebSocket Bot

```python
import asyncio, websockets, json

BOT_TOKEN = "bot_abc123..."
ROOM_ID = 1

async def bot():
    uri = f"wss://your-node:8443/ws/{ROOM_ID}"
    async with websockets.connect(uri, extra_headers={"Cookie": f"access_token={BOT_TOKEN}"}) as ws:
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("type") == "message":
                # Echo bot
                await ws.send(json.dumps({
                    "type": "message",
                    "content_encrypted": msg["content_encrypted"],  # Re-encrypt in production
                }))

asyncio.run(bot())
```

## Gravitix Bot (DSL)

Gravitix is Vortex's custom language for bots, compiled to Rust for performance.

### Example: Hello Bot

```gravitix
// examples/hello_bot.grav
on message {
    if content starts_with "/hello" {
        reply "Hello, " + sender.name + "! 👋"
    }
}

on member_join {
    send "Welcome to the room, " + member.name + "!"
}
```

### Moderation Bot

```gravitix
// Gravitix has built-in moderation functions
on message {
    if content matches "spam_pattern" {
        warn sender reason "Spam detected"
        delete message
    }

    if sender.strikes >= 3 {
        mute sender duration 3600
    }
}

on command "/ban" {
    if sender.role == "admin" {
        ban target reason args[0]
    }
}
```

### Available Gravitix Functions

| Function | Description |
|----------|-------------|
| `reply(text)` | Reply to the triggering message |
| `send(text)` | Send a message to the room |
| `delete(message)` | Delete a message |
| `vortex_mute(user, seconds)` | Mute a user |
| `vortex_ban(user, reason)` | Ban a user |
| `vortex_kick(user, reason)` | Kick a user |
| `vortex_warn(user, reason)` | Warn a user |
| `vortex_set_slow_mode(seconds)` | Set slow mode |
| `vortex_get_user(id)` | Get user info |
| `vortex_get_members()` | Get room members |
| `http_get(url)` | HTTP GET request |
| `http_post(url, body)` | HTTP POST request |
| `json_parse(text)` | Parse JSON string |
| `sleep(ms)` | Wait (async) |

### Deploy Gravitix Bot

```bash
# Via Bot IDE (in-browser)
# Navigate to /bots/ide → paste code → Deploy

# Via CLI
curl -X POST https://your-node:8443/api/bots/deploy \
  -H "Authorization: Bearer $TOKEN" \
  -F "code=@my_bot.grav" \
  -F "name=MyBot"
```

## Bot Permissions

| Scope | Description |
|-------|-------------|
| `messages.read` | Read messages in rooms |
| `messages.write` | Send messages |
| `messages.delete` | Delete messages |
| `members.read` | View member list |
| `members.manage` | Kick/ban/mute |
| `files.read` | Download files |
| `files.write` | Upload files |
| `rooms.manage` | Create/edit rooms |
| `webhooks.manage` | Register webhooks |

## Webhook Events

| Event | Payload |
|-------|---------|
| `message` | `{sender_pseudo, content_encrypted, msg_type, created_at}` |
| `member_join` | `{user_id, username, display_name}` |
| `member_leave` | `{user_id, username}` |
| `file_upload` | `{file_name, file_size, mime_type, download_url}` |
| `call_start` | `{call_id, initiator, with_video}` |
| `call_end` | `{call_id, duration}` |
| `reaction` | `{message_id, user_id, emoji}` |

## Best Practices

1. **Always verify webhook signatures** — never trust unverified payloads
2. **Encrypt bot messages** — use the room's E2E key for content
3. **Rate limit your bot** — respect the 30 msg/min limit
4. **Handle reconnections** — WebSocket bots should auto-reconnect
5. **Use Gravitix for moderation** — compiled Rust is faster than Python for pattern matching

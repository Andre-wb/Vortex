# `app/authentication/` — Auth, Session, Identity

Owns every way a user can identify themselves to the node: password, BIP39 seed, passkey (WebAuthn), 2FA, QR pairing, security questions, key-based challenge. Plus per-session token handling, profile updates, avatar upload.

All endpoints are mounted under `/api/authentication/*` by `_router.py` in the parent `main.py`.

## Files

| File                    | Covers                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------- |
| `password.py`           | `POST /register`, `POST /login`, `POST /logout`, password change. Argon2id-hashed; storage never sees plaintext. |
| `key_login.py`          | `GET /challenge` → signs with user's X25519 identity key → `POST /login-key`. Used by desktop and mobile for passwordless auth. |
| `qr_login.py`           | `POST /login-qr` — paired device scans the QR from an already-authenticated session; server hands a short-lived nonce that the scanner signs with its local key. |
| `passkey.py`            | WebAuthn flows — register a passkey, authenticate via a passkey, list + remove passkeys. |
| `two_factor.py`         | TOTP 2FA — enroll (show QR), verify during login, backup codes, disable.            |
| `security_questions.py` | Optional extra challenge for destructive actions (wipe, seed export).               |
| `session.py`            | `/refresh`, `/me`, session listing + revocation, device metadata.                   |
| `profile.py`            | `/profile`, `/avatar`, `/status`.                                                   |
| `_helpers.py`           | Argon2 wrappers, challenge-nonce bookkeeping, shared error shapes.                  |

## Key flows

### Register → login (password)

```
POST /api/authentication/register
  { username, password, display_name, public_key_x25519, public_key_ed25519,
    encrypted_identity_seed (AES-GCM blob under a key derived from password+salt) }
  → 201 { user_id, access_token, refresh_token }

POST /api/authentication/login
  { username, password }
  → 200 { access_token, refresh_token, encrypted_identity_seed, kdf_params }
```

The client re-derives its identity seed locally from password + `kdf_params` + the encrypted blob. The server never sees the seed or any private key.

### Key-based login (no password)

```
GET  /api/authentication/challenge?username=<u>
  → { nonce, issued_at, challenge_id }

# client signs nonce with its Ed25519 identity key

POST /api/authentication/login-key
  { challenge_id, signature }
  → { access_token, refresh_token }
```

### QR pairing

```
[logged-in device] GET /api/authentication/pair/new
  → { pair_id, nonce, expires_at }  # rendered as QR

[new device]  POST /api/authentication/login-qr
  { pair_id, signature_over_nonce }
  → { access_token, refresh_token }
```

## Token model

- **Access** — short-lived JWT (default 15 min).
- **Refresh** — rotating, revocable, server-side record.
- Every request goes through `TokenRefreshMiddleware` in `app/security/middleware.py` which transparently mints a new access token when the old one has ≤60s left.

## What's NOT here

- Actual cryptography primitives — those live in `app/security/crypto.py` (wrapping `vortex_chat` Rust).
- JWT signing / verification — in `app/security/auth_jwt.py`.
- Key material at rest — `app/keys/`.
- Device linking beyond QR — `app/session/handoff_token.py` for multi-device.

---

## License

Vortex is **dual-licensed** under the **GNU Affero General Public License
v3.0-or-later** (see `LICENSE`) or a **commercial license** (see
`LICENSE-COMMERCIAL.md`).

```
Copyright (C) 2026 Andrey Karavaev, Boris Maltsev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

## Authors

**Boris Maltsev**

[![GitHub](https://img.shields.io/badge/GitHub-BorisMalts-181717?style=flat-square&logo=github)](https://github.com/BorisMalts)

**Andrey Karavaev**

[![GitHub](https://img.shields.io/badge/GitHub-Andre--wb-181717?style=flat-square&logo=github)](https://github.com/Andre-wb)

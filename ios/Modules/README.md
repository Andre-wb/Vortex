# `ios/Modules/` — Swift Package (iOS Client)

The modular Swift Package that makes up the Vortex iOS client. 32 feature targets, 659 Swift files, SOLID `api/` protocol + `impl/` concrete-type split per feature. Composed by the `VortexApp` target (sibling folder `../VortexApp/`).

## Layout

```
ios/Modules/
├── Package.swift          ← SwiftPM manifest — 32 targets
├── Package.resolved       ← pinned deps (GRDB, Argon2Swift, WebRTC)
├── Sources/
│   ├── App/               ← composition root — AppEnvironment builds every module
│   ├── VortexCrypto/      ← X25519, Ed25519, AES-GCM, HKDF, Argon2id
│   ├── Bootstrap/         ← vortexx.sol probe + manual URL entry
│   ├── Net/               ← URLSession + JWT + retry + TLS handling
│   ├── Auth/              ← login, register, 2FA, passkey, QR pairing
│   ├── Identity/          ← BIP39 seed + key backup
│   ├── DB/                ← GRDB schema, migrations, models
│   ├── Rooms/             ← room CRUD, members, themes
│   ├── Keys/              ← ECIES + Variant-B key distribution
│   ├── WS/                ← URLSessionWebSocketTask wiring, reconnect, heartbeat
│   ├── Chat/              ← chat UI + message pipeline
│   ├── Reactions/         ← reactions, replies, thread creation
│   ├── Files/             ← chunked upload, download, viewer
│   ├── Stickers/          ← stickers, GIFs, voice notes (AVAudioRecorder)
│   ├── Calls/             ← WebRTC calls
│   ├── Push/              ← APNs registration + notification extension
│   ├── Federation/        ← multihop fallback
│   ├── Search/            ← global search
│   ├── Spaces/            ← spaces browser + categories
│   ├── Bots/              ← bot marketplace + control
│   ├── Threads/           ← thread view
│   ├── Feeds/             ← channel / RSS subscriber
│   ├── Contacts/          ← contact list + sync
│   ├── Drafts/            ← per-room drafts persisted locally
│   ├── Emoji/             ← emoji picker, custom emoji
│   ├── SavedGifs/         ← saved GIFs library
│   ├── Scheduled/         ← scheduled sends
│   ├── Folders/           ← client-side folder organisation
│   ├── Premium/           ← subscription state (Solana readback)
│   ├── Accounts/          ← multi-account support
│   ├── Settings/          ← all settings screens
│   └── I18N/              ← locale loader + 146 JSON files under Resources/locales/
└── Tests/
    └── …                   ← XCTest suites per module
```

## Conventions

- **One module per feature.** Cross-module imports go through the `api` protocol, never the `impl` concrete type.
- **No Objective-C.** Pure Swift, Swift Concurrency (`async / await`), no `completionHandler` style.
- **Minimum target**: iOS 17 (pinned for `onChange(of:initial:_:)`).
- **Deps are minimal**: GRDB (SQLite), Argon2Swift (Argon2id), WebRTC binary.
- **No UIKit**. SwiftUI-only. A handful of small `UIViewRepresentable` adapters where SwiftUI doesn't cover the native API yet (e.g. the call renderer).

## Building

Xcode resolves dependencies on first open. Generated from `../project.yml` via xcodegen:

```bash
brew install xcodegen
cd ios && xcodegen && open Vortex.xcodeproj
```

Then ⌘R.

## Wave plan

See [`../README.md`](../README.md) for the 20-wave plan and its mirror image on Android.

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

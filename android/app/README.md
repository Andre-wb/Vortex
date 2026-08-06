# `android/app/` — Android App Module

The Gradle `app` module — the single Android application target. Everything else is organised inside as Kotlin packages (no separate feature modules — the `api/impl/di` split is **within** `app/`).

## Layout

```
android/app/
├── build.gradle.kts          ← module build script (Compose, Hilt, Room, Ktor versions)
├── proguard-rules.pro        ← R8 rules for release builds
└── src/
    └── main/
        ├── AndroidManifest.xml
        ├── java/sol/vortexx/android/
        │   ├── VortexApp.kt                ← @HiltAndroidApp
        │   ├── MainActivity.kt
        │   ├── ui/                          ← Compose theme + screens + components
        │   └── <36 feature packages>/       ← api/ + impl/ + di/ per feature
        └── res/                             ← strings, icons, theme XML
```

## Feature packages

36 feature folders, all under `sol.vortexx.android.*`:

`accounts`, `auth`, `backup`, `bootstrap`, `bots`, `calls`, `chat`, `contacts`, `crypto`, `db`, `drafts`, `emoji`, `federation`, `feeds`, `files`, `folders`, `i18n`, `identity`, `keys`, `multidevice`, `net`, `premium`, `push`, `reactions`, `rooms`, `savedgifs`, `scheduled`, `search`, `settings`, `spaces`, `stickers`, `threads`, `ui`, `ws`.

Each feature has:

- `api/` — Kotlin interfaces with no Android dependencies (easier to test).
- `impl/` — concrete implementations that bind to Android / Hilt / Room / Ktor.
- `di/` — Hilt `@Module` wiring that binds the interface to the impl.

## Build

```bash
cd android
gradle wrapper --gradle-version 8.10        # first time only
./gradlew assembleDebug                     # → app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug                      # push to a connected device
```

## Dependencies (selected)

- Jetpack Compose (BOM pinned in `../gradle/libs.versions.toml`).
- Hilt (DI).
- Room (SQLite DB, schema v4, 12 tables).
- Ktor client (HTTP + WebSocket).
- WebRTC binary (via Maven).
- Libsodium / built-in `javax.crypto` + Rust JNI bridge for the primitives that need `vortex_chat` parity.
- Firebase Messaging (optional — gated behind a build flavor for Google-free forks).

## Flavors

- `goog` — includes FCM.
- `foss` — no FCM; uses UnifiedPush via `services/unified_push.py` path.

## Min / target

- Min SDK: 26 (Android 8.0).
- Target SDK: 34 (Android 14).
- Compile SDK: 34.

## Testing

```bash
./gradlew test                 # unit tests
./gradlew connectedAndroidTest # instrumented tests (needs emulator / device)
```

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

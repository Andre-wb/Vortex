# `android/gradle/` — Gradle Tooling

Gradle's version catalog + wrapper live here.

## Files

| Path                            | Role                                                                 |
| ------------------------------- | -------------------------------------------------------------------- |
| `libs.versions.toml`            | Single source of truth for every dependency version — Compose BOM, Kotlin, Hilt, Room, Ktor, Firebase, WebRTC, test libs. |
| `wrapper/gradle-wrapper.jar`    | Wrapper JAR (NOT committed; generated on first `gradle wrapper` run).|
| `wrapper/gradle-wrapper.properties` | Gradle distribution URL + checksum.                              |

## Why a version catalog

- Every module (currently just `app`, but growing) references the same versions by alias (`libs.compose.bom`, `libs.hilt.android`, …). Upgrading a library is one TOML edit, not N.
- TOML is human-diffable, IDE-friendly, and Gradle's preferred format in 8.x.

## Bootstrapping

```bash
cd android
gradle wrapper --gradle-version 8.10     # once; produces wrapper/gradle-wrapper.jar + .properties
./gradlew --version                      # confirm bootstrap worked
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

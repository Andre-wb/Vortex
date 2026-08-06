# `android/app/src/` — Android App Sources

Gradle's standard `src/` layout for the single `app` module.

## Layout

```
src/
├── main/
│   ├── AndroidManifest.xml
│   ├── java/sol/vortexx/android/       ← Kotlin sources (36 feature packages)
│   ├── res/                             ← strings, icons, themes
│   └── assets/                          ← locale JSON files + embedded brand assets
├── test/                                ← JVM unit tests (JUnit)
└── androidTest/                        ← instrumented tests (runs on device/emulator)
```

## Feature packages

Each feature under `java/sol/vortexx/android/<name>/` follows the same pattern:

```
<feature>/
├── api/             ← interfaces, no Android deps
├── impl/            ← concrete implementations (Room, Ktor, Compose)
└── di/              ← Hilt @Module bindings
```

This split keeps `api/` unit-testable on the JVM without dragging Android, and keeps Hilt wiring isolated so DI changes don't touch feature code.

## Tests

- `src/test/` — unit tests. Run via `./gradlew test`.
- `src/androidTest/` — instrumented tests that need a real Android runtime. Run via `./gradlew connectedAndroidTest` (requires a device or emulator).

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

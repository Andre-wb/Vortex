# `ios/Modules/Sources/` — Swift Package Sources

Source trees for every target declared in `../Package.swift`. One folder per target; each target is a feature module (`Auth`, `Chat`, `Rooms`, …) with its own `api` / `impl` / `di` split internally.

Every folder has a matching target in the Swift Package manifest. Adding a new feature:

1. Create `Sources/<NewFeature>/`.
2. Add `api/` (protocols), `impl/` (concrete types), optional `di/` (composition helpers).
3. Add a `.target(name: "<NewFeature>", …)` entry in `../Package.swift`.
4. Wire the feature into `AppEnvironment` inside `Sources/App/`.

See the parent [`Modules/README.md`](../README.md) for the full target list and conventions.

## Layout inside a target

```
Sources/Rooms/
├── api/
│   ├── RoomsService.swift        ← protocol
│   ├── RoomMember.swift
│   └── RoomKind.swift
├── impl/
│   ├── HttpRoomsService.swift    ← concrete, talks to node over REST + WS
│   └── RoomsCache.swift
└── di/
    └── RoomsAssembly.swift       ← registers bindings in the composition root
```

## I18N

The `I18N` target ships the locale JSON under `Resources/locales/` — **the same 146 files** used by the web and Android clients, kept in sync manually until automated sync lands.

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

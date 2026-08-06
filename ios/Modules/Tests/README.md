# `ios/Modules/Tests/` — XCTest Suites

Unit + integration tests for the Swift Package targets. One test target per feature module.

## Running

```bash
cd ios
xcodebuild test \
  -project Vortex.xcodeproj \
  -scheme VortexApp \
  -destination "platform=iOS Simulator,name=iPhone 15"
```

Or from inside Xcode: `⌘U`.

## Layout

```
Tests/
├── VortexCryptoTests/
├── AuthTests/
├── RoomsTests/
├── ChatTests/
├── I18NTests/
└── …                         ← one test target per Sources/<module>
```

Each test target depends only on the corresponding `api/` + `impl/` from `../Sources/` — **not** on other feature modules. Cross-feature integration is exercised in `AppTests`.

## Conventions

- `XCTestCase` subclasses. One class per production type.
- Prefer `async throws` test methods — mirrors the production async surface.
- No `import XCTest; import UIKit` together — keep UI concerns inside SwiftUI previews.
- Network-touching tests use `URLProtocol` stubs, not real HTTP.
- Crypto tests include known-answer tests — not just round-trips — so a regression in a primitive is caught immediately.

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

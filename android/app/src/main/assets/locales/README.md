# `android/app/src/main/assets/locales/` — Android Locale JSON

The 146 locale JSON files bundled into the APK. Mirrors `../../../../../../static/locales/` (web) and `../../../../../../ios/Modules/Sources/I18N/Resources/locales/` (iOS) byte-for-byte — single canonical English source of truth, same `hN / hN_a / hN_b / hN_c / hN_f` accordion convention.

## Loader

`sol.vortexx.android.i18n.impl.AssetLocaleSource` reads the active locale from `SharedPreferences`, falls back to the system locale, and falls back to `en.json` for missing keys. Zero network round-trip on language switch.

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

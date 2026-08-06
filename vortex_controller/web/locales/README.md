# `vortex_controller/web/locales/` — Controller Site Locales

Locale JSON files for the controller public site. Smaller than the main app's locale tree — this site is operator-focused, not chat-focused.

## Shape

```jsonc
{
  "meta":       { "locale": "en", "name": "English", "rtl": false },
  "nav":        { "home": "Home", "nodes": "Nodes", "entries": "Entries", "mirrors": "Mirrors", "security": "Security", "admin": "Admin" },
  "home":       { … landing copy … },
  "nodes":      { … table headers + empty state … },
  "entries":    { … },
  "mirrors":    { … },
  "security":   { … integrity copy … },
  "admin":      { … token prompt + revenue dashboard labels … }
}
```

## Scope

- No user-facing chat strings — those live in `../../../static/locales/`.
- No `apiSurface` / `glossary` / `deepReference` — those are read only on the main site's `/docs.html`.

## Fallback

English is the source of truth. Non-English files fall back to English for missing keys at runtime (same convention as the main app).

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

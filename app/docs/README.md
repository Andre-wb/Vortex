# `app/docs/` — OpenAPI Configuration

Small helper package that configures FastAPI's auto-generated OpenAPI schema — tags, descriptions, grouping, security scheme declarations.

## Files

| File                  | Role                                                                             |
| --------------------- | -------------------------------------------------------------------------------- |
| `openapi_config.py`   | Exports `tags_metadata` (one entry per feature tag) and a `customize_openapi(app)` function called from `app/main.py` after the app is fully assembled. |

## What it does

1. Declares every tag a router uses (`authentication`, `rooms`, `channels`, `files`, `bots`, `keys`, `federation`, `transport`, `peer`, `security`, `push`, `session`, `spaces`, `stream`, `voice`, `calls`, `dm`, `contacts`, `ai`, `privacy`, `gdpr`, `admin`, …).
2. Gives each tag a one-sentence description and an external-docs link into the locale-driven docs portal (`/docs.html#<slug>`).
3. Declares the `bearerAuth` HTTP Bearer scheme + CSRF header scheme, so the Swagger UI gets real auth buttons.
4. Reorders tags into a logical grouping (auth → identity → rooms → messages → media → network → security → admin).

## Why it's its own package

FastAPI auto-generates OpenAPI from your routes, but the **ordering, grouping, and narrative** have to be configured once and kept in sync with new routes. Keeping that in one module next to `main.py` avoids sprinkling `tags=["…"]` descriptions across every feature file.

## Consumers

- Swagger UI at `/docs` (FastAPI default).
- ReDoc at `/redoc`.
- `apiSurface` locale generator — `scripts/build_api_glossary.py` reads this file to get per-tag descriptions for the card headers.

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

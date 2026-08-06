# `scripts/` — Build, Docs, and Integrity

All operator-side tooling that doesn't run inside the node. Most are Python; a couple are shell / PowerShell for platform-specific packaging.

## Build

| Script                      | Produces                                                                               |
| --------------------------- | -------------------------------------------------------------------------------------- |
| `build-linux.sh`            | Linux tarball + .deb via `Dockerfile.build-linux`. Bundles the wizard + node into one. |
| `build-windows.ps1`         | Windows portable zip + installer stub. Invokes PyInstaller on `vortex-wizard.spec`.    |
| `Dockerfile.build-linux`    | Reproducible Linux build image (Debian slim + Python 3.10 + Rust + Node).              |

See `BUILD.md` for the full operator walkthrough — prerequisites, signing flow, CI matrix.

## Docs generators

Every script here writes into the locale JSON files under `static/locales/` (and into the iOS `ios/Modules/Sources/I18N/Resources/locales/`). They are **pure data generators** — no network calls, deterministic output.

| Script                         | Produces                                                                                      |
| ------------------------------ | --------------------------------------------------------------------------------------------- |
| `build_vortex_docs.py`         | First-generation top-level Vortex docs tree.                                                  |
| `build_vortex_docs_v2.py`      | Mid-round extension: adds sub-chapters under deep reference.                                  |
| `build_vortex_docs_v3.py`      | Current generator for the Vortex root of the docs site. Produces every non-deep-reference chapter with full Description / How it works / History / Formula sections. |
| `build_docs_expand.py`         | Expands accordion sub-sections (`_a/_b/_c/_f`) across the whole tree. Owns the BMP history entry that credits the Vortex team. |
| `build_architex_docs.py`       | Architex root tree — overview, language, components, runtime, examples.                       |
| `build_architex_arxd.py`       | Architex deep reference (`arxd`) leaf keys — one per language construct.                      |
| `convert_gx_docs_i18n.py`      | Migrates legacy `gxd` Gravitix docs into the canonical `hN/hN_a/hN_b/hN_c/hN_f` scheme.       |
| `build_api_glossary.py`        | Rebuilds `apiSurface` (540+ REST endpoints × 6 panels each) and `glossary` (37 terms A–Z). Run after adding or renaming any endpoint. |

All generators are idempotent — re-running does not duplicate keys, and locale overrides in non-English files survive regeneration unless the English key is deleted.

## Integrity

- `integrity_repo.py` — signs and verifies the **repo-wide** integrity manifest (`INTEGRITY.repo.json` at the repo root). Usage:

  ```bash
  python scripts/integrity_repo.py sign   --key keys/integrity.key
  python scripts/integrity_repo.py verify
  ```

  The controller's `IntegrityGateMiddleware` loads this same file at boot; the wizard exposes `/wizard/integrity` which calls this script via `importlib` so "Sign repo" / "Verify" work inside the PyInstaller bundle.

## Running a generator

From the repo root:

```bash
python scripts/build_api_glossary.py
python scripts/build_vortex_docs_v3.py
python scripts/build_docs_expand.py
```

The generators read/write `static/locales/en.json` as the canonical source; translation scripts (`translate_cloud.py`, `translate_locales.py` at the repo root) propagate new English keys into the other 145 locales via external providers.

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

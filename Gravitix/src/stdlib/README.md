# `Gravitix/src/stdlib/` — Safe Standard Library

Pure built-in functions available to every Gravitix program. **Everything here is side-effect-free** — no I/O, no network, no process access. HTTP / DB / file access is mediated through `../bot/` instead.

## Modules

| Module          | Functions                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------- |
| `math`          | `abs`, `floor`, `ceil`, `round`, `min`, `max`, `sqrt`, `pow`, `sin`, `cos`, `tan`, `log`, `exp`, `pi`, `e`, `clamp`. |
| `math_complex`  | Complex-number arithmetic — `c(a,b)`, `conj`, `re`, `im`, `arg`, `abs_c`.                |
| `math_calculus` | Numerical derivative, integral, simple solver.                                            |
| `math_stats`    | `mean`, `median`, `mode`, `stddev`, `variance`, `quantile`.                              |
| `math_transforms` | `fft`, `ifft`, `dct` (single-precision).                                                |
| `strings`       | `upper`, `lower`, `trim`, `len`, `split`, `join`, `replace`, `contains`, `starts_with`, `ends_with`, `regex_match`, `regex_capture`. |
| `lists`         | `map`, `filter`, `reduce`, `foldl`, `foldr`, `len`, `sort`, `sort_by`, `reverse`, `slice`, `unique`, `zip`, `flatten`. |
| `maps`          | `keys`, `values`, `entries`, `has`, `get`, `put`, `remove`, `merge`.                    |
| `time`          | `now()`, `date_format`, `date_parse`, `duration_between`, `timestamp`.                  |
| `json`          | `to_json`, `from_json`.                                                                  |
| `base64`        | `encode`, `decode`.                                                                       |
| `uuid`          | `uuid4()`.                                                                                |
| `bitwise`       | `and`, `or`, `xor`, `not`, `shl`, `shr`.                                                 |

## Registration

Every function is registered at runtime-init time via a single `register_stdlib(env: &mut Environment)` call. Adding a function is a one-line registration plus the implementation.

## Conventions

- **No panics.** Every function returns a `Result` and converts panics into runtime errors with the function name + call site.
- **UTF-8 correct.** String functions operate on codepoints, not bytes. `len("🌊")` returns 1.
- **Deterministic.** Same inputs always yield the same output — important for bot audit logs.

## Not in stdlib

- HTTP, file I/O, shell — use `../bot/`'s gated helpers.
- Anything that reads the wall clock unpredictably — `time.now()` is allowed, but only as an opaque instant. Use `time.duration_between` for relative logic.

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

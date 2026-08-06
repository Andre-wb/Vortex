# `vortex_waf/` — Web Application Firewall

The WAF engine behind Vortex. Written in Rust, exposed to the FastAPI application through PyO3 bindings and mounted as ASGI middleware by `app/security/waf/`.

Not a replacement for a reverse-proxy WAF (ModSecurity, Cloudflare, …) — it's a last-line, application-layer filter tuned to Vortex's specific threat model, sitting close enough to the app to see decoded bodies and parsed parameters.

## Layout

The crate is split by responsibility: the domain knows nothing about storage, the engine depends only on traits in `ports/`, and concrete implementations are wired together in `engine/builder.rs`.

| Directory     | Role                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------- |
| `domain/`     | Value types — findings, severities, requests, timestamps. No I/O, no dependencies.            |
| `ports/`      | One trait per file. Everything the engine depends on: `Clock`, `Rule`, `Inspector`, `BodyParser`, `RateLimiter`, `BlockStore`, `BlockPolicy`, `StatsCollector`, `ClientIpResolver`, `ChallengeIssuer`/`Verifier`, `Signer`, `Prunable`. |
| `rules/`      | Signature catalog and rule sources. `patterns/` holds one file per attack class.               |
| `inspectors/` | One check per file — method, URL length, headers, params, body, path. Composed via `composite.rs`. |
| `body/`       | Content-type-aware parsing. `parsers/multipart/` splits into boundary walking, traversal and web-shell detection. |
| `scanning/`   | The single place where rules meet data. Safe-parameter skip list lives here.                   |
| `blocking/`   | Allow list, deny list, temporary block store, and the reputation gate that combines them.      |
| `ratelimit/`  | Sliding-window limiter and its configuration.                                                  |
| `policy/`     | Verdict policies — severity threshold, monitor-only, rule deny list.                           |
| `captcha/`    | Stateless HMAC-signed arithmetic challenges.                                                   |
| `engine/`     | The engine itself, its builder, runtime handle, reporting and maintenance.                     |
| `http/`       | Transport glue — client-IP resolution, excluded paths, 403/413/429 responses.                  |
| `manager/`    | Administrative operations behind `/waf/*`.                                                     |
| `interop/`    | Primitive-typed facade for callers outside Rust.                                               |
| `python/`     | PyO3 bindings (feature `python`). Argument marshalling only, no logic.                          |

## What the WAF catches

- **Known attack shapes** — 74 signatures across SQL injection, XSS, path traversal, command injection, file inclusion, SSRF, XXE, API abuse and scanner fingerprints. Tuned to avoid false positives on legitimate E2E ciphertext, which looks like high-entropy noise but has deterministic envelope structure.
- **Protocol abuse** — non-standard methods, oversized URLs and paths, oversized bodies, malformed JSON, suspicious `User-Agent` and `javascript:` in `Referer`.
- **Dangerous uploads** — web-shell extensions in `filename=` tokens *and* in the `file_name` text field used by resumable uploads. Binary file parts are skipped so attachment bytes never trip a signature.
- **Volumetric abuse** — per-IP sliding-window rate limiting, with temporary blocks and an escalation threshold.

## What it explicitly does NOT do

- It does not inspect E2E ciphertext payloads. They are opaque to the WAF by design.
- It does not terminate TLS (that's nginx or the load balancer).
- It does not block based on country or ASN. Censorship-resistance users connect from exactly those places.
- It does not trust `X-Forwarded-For` unless the peer is an explicitly configured proxy.

## Request flow

```
request → engine.analyze()
            │
            ├── reputation gate      (allow list → deny list → temp blocks)
            ├── rate limiter         (sliding window, per IP)
            ├── inspectors           (method, url, headers, params, body, path)
            │     └── field scanner  ──► signature catalog
            └── policy decision:
                   ALLOW  → continue
                   BLOCK  → 403 + audit log entry
```

Findings are collected first and judged afterwards: the policy decides what blocks, the inspectors only report. Swapping `SeverityThresholdPolicy` for `MonitorOnlyPolicy` turns the whole WAF into a log-only sensor without touching a single check.

## Usage from Rust

```rust
use vortex_waf::prelude::*;

let waf = WafBuilder::new().build()?;

let request = RequestBuilder::new()
    .client_ip("203.0.113.7")
    .path("/api/search")
    .query("q=%27+OR+1%3D1+--+")
    .build();

assert!(waf.analyze(&request).block);
```

Transport-level use goes through `WafGuard`, which adds excluded paths, the body-size cap and captcha verification:

```rust
let guard = GuardBuilder::new(Arc::new(waf)).build();
match guard.evaluate(&raw_request) {
    GuardOutcome::Pass => { /* hand off to the application */ }
    GuardOutcome::Reject(response) => { /* return it verbatim */ }
}
```

## Usage from Python

The extension module is imported by `app/security/waf/backend.py`; the application never talks to it directly.

```python
import vortex_waf

engine = vortex_waf.WafEngine({"rate_limit_requests": 120, "rate_limit_window": 60})

verdict = engine.analyze_request({
    "client_ip": "203.0.113.7",
    "method": "GET",
    "path": "/api/search",
    "url": "/api/search?q=...",
    "headers": {"user-agent": "Mozilla/5.0"},
    "params": {"q": ["' OR 1=1 --"]},
    "content_type": "",
    "body": "",
})
verdict["block"]          # True
verdict["matched_rules"]  # ['SQLI-002', 'SQLI-006']
```

| Method                                   | Purpose                                            |
| ---------------------------------------- | -------------------------------------------------- |
| `analyze_request(dict) -> dict`           | Full verdict: `block`, `reason`, `findings`, `matched_rules`, `client_ip`. |
| `is_ip_blocked(ip)`                       | Reputation check without side effects.              |
| `block_ip(ip, reason, duration)`          | Temporary block; refuses allow-listed addresses.    |
| `unblock_ip(ip)` / `blocked_ips()`        | Manage and list active blocks.                      |
| `add_whitelist_ip` / `remove_whitelist_ip` / `whitelist` | Allow-list operations.               |
| `add_blacklist_ip` / `remove_blacklist_ip` / `blacklist` | Deny-list operations.                 |
| `get_stats()` / `rules()`                 | Counters and the live rule catalog with trigger counts. |
| `generate_captcha(ip)` / `verify_captcha(id, answer)` | Issue and check challenges.            |
| `run_maintenance()`                       | Drop expired blocks and idle rate-limit history.    |

Module level: `vortex_waf.VERSION`, `vortex_waf.RULE_COUNT`, and `resolve_client_ip(peer, headers, trusted_proxies)`.

## Building

The application imports `vortex_waf` at startup, so the extension must be built before the app runs.

```bash
make waf-build          # maturin develop --release
make waf-check          # cargo test + clippy + fmt --check
```

CI builds it in the `waf` job and again inside the `test` job for each interpreter; the Docker builder stage compiles it into the image.

## Configuration

Engine settings are passed as a dict to `WafEngine(...)`; `app/main.py` fills them from `Config`.

| Key                    | Default   | Purpose                                            |
| ---------------------- | --------- | -------------------------------------------------- |
| `rate_limit_requests`  | `100`     | Allowed requests per window, per IP.                |
| `rate_limit_window`    | `60`      | Window length in seconds.                           |
| `block_duration`       | `3600`    | Default duration of a temporary block.              |
| `max_content_length`   | `10 MiB`  | Body size above which a request is blocked outright.|
| `safe_params`          | CSRF names| Parameters excluded from signature matching.        |
| `whitelist_ips`        | loopback  | Addresses that skip both blocking and rate limiting.|
| `captcha_secret`       | per-process | Shared secret so any instance can verify any challenge. |

Environment variables read by the Python layer:

| Env var                | Purpose                                                          |
| ---------------------- | ---------------------------------------------------------------- |
| `WAF_RATE_LIMIT_REQUESTS` | Per-IP request cap (`999999` under `TESTING=true`).           |
| `WAF_RATE_LIMIT_WINDOW`   | Window length in seconds.                                     |
| `WAF_BLOCK_DURATION`      | Default block duration.                                       |
| `WAF_MAX_BODY_BYTES`      | ASGI-level body cap; larger requests get 413 before buffering (default 25 MiB). |
| `TRUSTED_PROXY_IPS`       | Comma-separated proxy IPs/CIDRs whose forwarding headers are honoured. Empty by default. |
| `CSRF_SECRET` / `JWT_SECRET` | Source of the captcha signing key.                         |

## Operator endpoints

Mounted under `/waf/*` by `app/security/waf/routes.py`.

| Endpoint                    | Method   | Returns                                    |
| --------------------------- | -------- | ------------------------------------------ |
| `/waf/stats`                | `GET`    | Request counters, block rate, active rules. |
| `/waf/rules`                | `GET`    | Rule catalog with trigger counts.           |
| `/waf/blocked-ips`          | `GET`    | Active temporary blocks.                    |
| `/waf/block-ip`             | `POST`   | Block an address.                           |
| `/waf/unblock-ip`           | `POST`   | Release a block.                            |
| `/waf/whitelist`            | `GET`    | Current allow list.                         |
| `/waf/whitelist/add`        | `POST`   | Add an address to the allow list.           |
| `/waf/whitelist/remove`     | `DELETE` | Remove an address from the allow list.      |
| `/waf/captcha/generate`     | `POST`   | Issue a challenge.                          |
| `/waf/test`                 | `GET`    | Liveness probe echoing the resolved client IP. |

## Design notes

**Rules are pure predicates.** Trigger counters live in the stats collector, not inside the rule object, so a rule is immutable and shared across threads without locking.

**Input is truncated to 4096 characters before matching.** Rust's regex engine does not backtrack, so this is not a ReDoS guard — it keeps match semantics identical to the signature set's original tuning.

**Pattern compilation is fallible.** A broken pattern surfaces as `WafError::RuleCompile` instead of silently becoming a never-matching rule. `catalog_source::every_shipped_pattern_compiles` asserts the whole catalog builds.

**Dangerous-extension lists differ by context on purpose.** A request to `/shell.py` is an attempt to execute a script; sending `.py` as a chat attachment is legitimate. Path checks block `.php .asp .aspx .jsp .py .pl .sh`; upload checks block only `.php .asp .aspx .jsp .exe .bat .cmd`.

**Rate-limit escalation is opt-in.** The "block at twice the limit" branch cannot fire under the default configuration, because history only accumulates allowed requests and therefore never exceeds the limit. The threshold is exposed as `RateLimitConfig::escalation_threshold` for deployments that want it.

**Maintenance is driven by the caller.** The crate has no async runtime. `WafRuntime::run_maintenance()` drops expired blocks and idle rate-limit history; the ASGI middleware calls it every 300 seconds.

**Clock and randomness are injected.** Block expiry, rate-limit windows and captcha TTLs are tested without sleeping, and challenge IDs are reproducible under test.

## Tests

```bash
cd vortex_waf
cargo test    # 209 unit + integration tests
```

Unit tests sit next to the code they cover. Integration tests live in `tests/`:

| File                       | Covers                                                              |
| -------------------------- | ------------------------------------------------------------------- |
| `engine_blocking.rs`       | End-to-end verdicts, safe params, severity thresholds.               |
| `body_multipart.rs`        | Uploads, the `file_name` field, traversal, attachment false positives. |
| `body_json_and_forms.rs`   | JSON, forms, broken JSON, unknown content types, size cap.           |
| `path_inspection.rs`       | Traversal, extensions, length, path signatures.                      |
| `rate_limit_and_blocks.rs` | Windows, blocks, expiry, maintenance.                                |
| `stats_reporting.rs`       | Counters and the management API.                                     |
| `http_guard.rs`            | 403/413/429, excluded paths, `X-Forwarded-For` spoofing, captcha.    |
| `extensibility.rs`         | Plugging in custom inspectors, rules and policies.                   |

## Dependencies

`regex`, `serde`, `serde_json`, `hmac`, `sha2`, `hex`, `rand`, and `pyo3` behind the optional `python` feature. No async runtime, no HTTP framework. `#![forbid(unsafe_code)]`.

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

# `app/security/waf/` — WAF integration layer

Thin Python layer that mounts the WAF into FastAPI. The engine itself — signatures, body parsing, rate limiting, blocking, captcha — lives in the Rust crate [`vortex_waf/`](../../../vortex_waf/README.md) and is loaded as a compiled extension module.

Not a replacement for a reverse-proxy WAF (ModSecurity, Cloudflare, …) — it's a last-line, application-layer filter tuned to Vortex's specific threat model.

## Files

| File            | Role                                                                                          |
| --------------- | ----------------------------------------------------------------------------------------------- |
| `backend.py`    | Loads the `vortex_waf` extension. Re-exports `WAFEngine`, `resolve_client_ip`, `VERSION`, `RULE_COUNT`. Raises with build instructions if the module is missing. |
| `middleware.py` | ASGI middleware. Buffers the body under a hard size cap, builds the request dict, calls the engine, short-circuits on a verdict, forwards otherwise. Runs engine maintenance every 300 s. |
| `routes.py`     | Operator endpoints at `/waf/*` and the process-wide engine singleton (`init_waf_engine`, `get_waf_engine`, `setup_waf`). |

There is no Python rule engine any more: `engine.py`, `signatures.py` and `captcha.py` were replaced by the Rust implementation.

## Where the boundary sits

```
ASGI scope ─► middleware.py
                 │  buffer body (413 above WAF_MAX_BODY_BYTES)
                 │  skip excluded paths
                 │  resolve client IP  ──► vortex_waf.resolve_client_ip
                 │
                 └─ engine.analyze_request(dict) ──► Rust
                          │
                          ├─ block → 403 with the top-3 violations
                          ├─ captcha headers present → verify, 429 on failure
                          └─ pass  → replay the buffered body downstream
```

Everything above the arrow is Python because ASGI requires it; everything below is Rust.

## Build requirement

The extension must exist before the app starts:

```bash
make waf-build      # cd vortex_waf && maturin develop --release
```

`make install` depends on it, CI builds it for every interpreter in the test matrix, and the Docker builder stage compiles it into the image. If it is missing, importing `app.security.waf` fails with the build command in the error message rather than silently degrading.

## Excluded paths

Streaming-upload endpoints are skipped entirely — their bodies must not be buffered into RAM, and they carry their own rate limits:

`/static/`, `/health`, `/favicon.ico`, `/robots.txt`, `/waf/stats`, `/waf/captcha`, `/waf/test`, `/api/files/upload-*`, `/api/authentication/qr-`, `/api/bmp/`, `/api/push-proxy/`, `/api/authentication/passkey/`.

`/api/link-preview` is deliberately **not** excluded: it performs an outbound fetch and is an SSRF surface worth inspecting.

## Configuration

See the [crate README](../../../vortex_waf/README.md#configuration) for the full table. The Python layer reads two variables of its own:

| Env var              | Purpose                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| `WAF_MAX_BODY_BYTES` | ASGI-level body cap; larger requests get 413 before buffering (default 25 MiB). |
| `TRUSTED_PROXY_IPS`  | Comma-separated proxy IPs/CIDRs whose `X-Forwarded-For` is honoured. Empty by default, so forwarding headers cannot be used to spoof a source IP. |

---

## License

Vortex is released under the **Apache License 2.0**.

```
Copyright 2026 Andrey Karavaev, Boris Maltsev

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## Authors

**Boris Maltsev**

[![GitHub](https://img.shields.io/badge/GitHub-BorisMalts-181717?style=flat-square&logo=github)](https://github.com/BorisMalts)

**Andrey Karavaev**

[![GitHub](https://img.shields.io/badge/GitHub-Andre--wb-181717?style=flat-square&logo=github)](https://github.com/Andre-wb)

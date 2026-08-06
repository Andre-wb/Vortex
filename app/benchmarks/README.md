# `app/benchmarks/` — Synthetic Benchmarks

Synthetic load + crypto micro-benchmarks for the node backend. Standalone scripts — not part of pytest.

## Files

| File                | Role                                                                          |
| ------------------- | ----------------------------------------------------------------------------- |
| `run_benchmarks.py` | Entry point. Parses CLI flags, wires the selected benchmarks into `pyperf`-compatible runs, writes a `results.json` alongside.  |

## Running

```bash
cd /Users/borismaltsev/RustroverProjects/Vortex
python -m app.benchmarks.run_benchmarks --all
python -m app.benchmarks.run_benchmarks --only crypto
python -m app.benchmarks.run_benchmarks --only message-roundtrip --iterations 1000
```

## What's measured

- **Crypto primitives**: AES-256-GCM seal/unseal throughput, X25519 keygen/ECDH rate, BLAKE3 MB/s, Argon2id hashes/sec at the configured parameters.
- **Message round-trip**: client send → node receive → node ack, isolated from network — runs in-process against a test client.
- **BMP hot path**: mailbox ID derivation throughput, cover-traffic polling latency.
- **Federation**: envelope pack + sign + verify cycle, single-peer fan-out.
- **Upload**: chunk hashing throughput, finalise latency for 1GB synthetic file.

## What it's NOT

- **Not a load test.** For long-running realistic load use `../../deploy/loadtest/k6_load_test.js` or `locustfile.py`.
- **Not a correctness test.** The benchmarks assume the code is already correct (pytest handles that).
- **Not production tracing.** Use Prometheus + Grafana (`../../deploy/grafana/dashboards/`) for live data.

## Results layout

`results.json` is a flat list of records:

```json
[
  {"name": "aes_gcm_seal_1kb", "mean_ns": 3400, "stdev_ns": 120, "iterations": 10000},
  {"name": "x25519_ecdh",      "mean_ns": 19000, "stdev_ns": 900,  "iterations": 5000},
  ...
]
```

Comparing across commits is left to the reader — diff `results.json` files, no CI harness bundled.

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

# `deploy/prometheus/` — Prometheus Alert Rules

Alert rules evaluated against metrics scraped from the Vortex node. The top-level scrape config lives at `../prometheus.yml`; only **rules** live here.

## Files

| File             | Role                                                                           |
| ---------------- | ------------------------------------------------------------------------------ |
| `alerts.yml`     | All alert groups — latency, errors, resources, federation, integrity.          |
| `prometheus.yml` | Rule files reference (points at `alerts.yml`). Loaded by Prometheus via `--config.file`. |

## Alerts (summary)

### Latency / errors

| Alert                      | Condition                                                  | Severity |
| -------------------------- | ---------------------------------------------------------- | -------- |
| `HighRequestLatency`       | p99 `/api/chat/messages` > 500 ms for 5 min                | warning  |
| `HighErrorRate`            | 5xx rate > 1 % for 5 min                                   | critical |
| `WebSocketDisconnectSpike` | disconnect rate > 3× baseline for 10 min                   | warning  |

### Resources

| Alert                      | Condition                                                  | Severity |
| -------------------------- | ---------------------------------------------------------- | -------- |
| `PodCPUSaturation`         | CPU > 90 % for 10 min (per pod)                            | warning  |
| `DiskPressure`             | Free disk < 10 GB on the uploads volume                    | critical |
| `PostgresConnectionsHigh`  | >85 % of `max_connections` used for 5 min                   | warning  |

### Federation

| Alert                      | Condition                                                  | Severity |
| -------------------------- | ---------------------------------------------------------- | -------- |
| `FederationBacklogGrowing` | outbox depth per link > 10 000 and growing over 15 min     | warning  |
| `PeerTrustDecayStorm`      | > 10 % of known peers have `last_checkin_age > 24h`        | critical |

### Integrity

| Alert                      | Condition                                                  | Severity |
| -------------------------- | ---------------------------------------------------------- | -------- |
| `IntegrityMismatch`        | any peer's reported `code_hash` diverges from on-chain value| critical |
| `WAFBlockFlood`            | block rate > 500 / min for 5 min                           | warning  |

## Routing

Alerts are emitted with `team: vortex-oncall` and `service: vortex` labels. Alertmanager routing is NOT bundled (shape of `alertmanager.yml` is deployment-specific — paging policy, Slack channels, escalation).

A sample alertmanager route would be:

```yaml
route:
  receiver: slack-vortex
  routes:
    - matchers: [severity="critical"]
      receiver: pagerduty-vortex
```

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

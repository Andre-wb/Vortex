# `deploy/grafana/` — Grafana Provisioning & Dashboards

Self-contained Grafana setup. Drop the provisioning directory into a Grafana container and it will auto-load datasources and dashboards on startup.

## Layout

```
deploy/grafana/
├── provisioning/
│   ├── datasources/prometheus.yaml     ← Points at the Prometheus defined in ../prometheus.yml
│   └── dashboards/dashboards.yaml      ← Imports everything in ../dashboards/
└── dashboards/
    ├── node-overview.json              ← Per-node health, latency, throughput, peer count
    └── federation-health.json          ← Cross-node replication, trust decay, outbox depth
```

## Running

```bash
docker run -d --name graf -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=<your-password> \
  -v $PWD/deploy/grafana/provisioning:/etc/grafana/provisioning \
  -v $PWD/deploy/grafana/dashboards:/var/lib/grafana/dashboards \
  grafana/grafana
```

On first boot, Grafana reads `provisioning/`, creates the Prometheus datasource, and imports the dashboards — no clicking required.

## Dashboards

### `node-overview.json`

Panels:

- Request rate (req/s), split by route family.
- p50 / p95 / p99 latency per route family.
- Error rate (%) per route.
- WebSocket connection count (gauge + 1h rate).
- Peer discovery success rate per channel (UDP, controller, Solana, Redis).
- Uploads MB/s in / out.
- CPU + memory per pod (if scraping cadvisor).
- WAF verdicts per second — allow / challenge / block / tarpit.

### `federation-health.json`

Panels:

- Outbox depth per link (how many envelopes are waiting to ship).
- Replication lag per peer (seconds).
- Trust decay — live histogram of `last_checkin` ages across known peers.
- Cross-node integrity divergence — red if any peer's `code_hash` differs from its on-chain record.
- BMP mailbox polls per second (cover-traffic vs real).

## Editing

Dashboards are exported JSON — edit visually in Grafana, then "Share → Export → Save to file" back into this directory. Do not hand-edit the JSON (Grafana re-writes field order).

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

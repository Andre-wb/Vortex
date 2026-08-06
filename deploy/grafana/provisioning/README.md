# `deploy/grafana/provisioning/` — Auto-provisioning

Grafana provisioning tree. When the provisioning directory is mounted at `/etc/grafana/provisioning` inside a Grafana container, it auto-creates datasources and dashboard folders on startup — no click-through config.

## Layout

```
provisioning/
├── datasources/
│   └── prometheus.yaml    ← registers the Prometheus datasource pointing at the URL from env
└── dashboards/
    └── dashboards.yaml    ← tells Grafana to import every JSON file under ../dashboards/
```

## Environment

The datasource YAML references `$PROMETHEUS_URL` so the same files work across local Docker and Kubernetes:

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: ${PROMETHEUS_URL:-http://prometheus:9090}
    isDefault: true
```

## Running

See [`../README.md`](../README.md) for the full Grafana bring-up.

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

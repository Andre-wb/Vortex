# `deploy/chaos/` — Chaos Mesh Experiments

[Chaos Mesh](https://chaos-mesh.org/) manifests for stress-testing a Kubernetes-deployed Vortex cluster. Every experiment is scoped to the `vortex` namespace.

## Files

| File                     | Scenario                                                        |
| ------------------------ | --------------------------------------------------------------- |
| `pod-kill.yaml`          | Random pod kill every 5 minutes. Verifies stateless recovery, session re-auth, WebSocket reconnect. |
| `network-delay.yaml`     | 200 ms ± 50 ms delay between pods. Surfaces latency-sensitive flows — voice handshake, WebRTC negotiation. |
| `network-partition.yaml` | Split the cluster in two halves for 3 minutes. Validates eventual consistency of federation + peer registry. |
| `cpu-stress.yaml`        | Pin 80% of one core for 10 minutes. Exercises the HPA and WAF rate limits under real CPU pressure. |

## Prerequisites

```bash
helm repo add chaos-mesh https://charts.chaos-mesh.org
helm install chaos-mesh chaos-mesh/chaos-mesh -n chaos-mesh --create-namespace
```

## Running

```bash
# Single-shot
kubectl apply -f pod-kill.yaml

# All at once
kubectl apply -f .

# Watch
kubectl get podchaos,networkchaos,stresschaos -n vortex
```

Delete with `kubectl delete -f .` to stop the experiments.

## What to watch for

- **Pod kill**: all WebSockets re-establish within 10s. No message loss for messages acknowledged before the kill.
- **Network delay**: call-setup still succeeds, media quality degrades gracefully.
- **Partition**: each half keeps accepting traffic from peers in its half. When heal happens, federation catches up within `FEDERATION_RETRY_INTERVAL`.
- **CPU stress**: HPA scales up; WAF's token-bucket slows down offenders; SLO (p99 < 500ms for `GET /api/rooms`) holds.

## Safety

- Manifests select by label `app=vortex` **and** namespace `vortex`. They cannot escape to an unrelated workload if you accidentally apply them in a shared cluster — but please don't.
- The `cpu-stress` and `network-partition` experiments run for bounded windows (declared in the manifest), so forgetting to delete them won't wedge the cluster forever.

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

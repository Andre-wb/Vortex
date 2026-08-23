# `rust_utils/src/udp_broadcast/` — PyO3-мост UDP-обнаружения

Тонкий мост между Python и крейтом `vortex-net`. Вся доменная логика (формат
конверта, stealth-конверт, адресные правила, реестр живучести) живёт в
`vortex-net` и вектор-тестируется; здесь — только ввод-вывод и выставление
функций в `vortex_chat`.

## Что здесь

- `service.rs` — фоновый tokio-цикл: `run_sender` шлёт конверт на subnet- и
  глобальный broadcast с интервалом из конфига, `run_receiver` принимает,
  фильтрует свой IP/`127.*`, при stealth снимает XOR-конверт и заносит пира в
  `vortex_net::registry::PeerStore`. Определение локального IP — `detect_local_ip`.
- `mod.rs` — глобальное состояние сервиса, `start_discovery`, `get_peers`,
  `discovery_own_ip`.
- `api.rs` — чистые функции для паритет-тестов и шимов `app/transport/stealth.py`
  (`udp_encode`, `udp_decode`, `udp_stealth_seal`/`_random`/`open`,
  `udp_stealth_port`, `udp_subnet_broadcast`).

Граница переноса — «сокет-цикл в Rust»: listener и sender целиком здесь, Python
лишь опрашивает `get_peers` и тянет комнаты пиров по httpx.

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

# `rust_utils/src/bmp/` — мост BMP в Python

Тонкая PyO3-обёртка над крейтом `vortex-bmp`. Сам протокол (хранилище ящиков,
деривация идентификаторов, пределы, частота запросов, секреты комнат, уборка)
живёт в крейте; здесь только преобразование типов и процессные синглтоны.
Дизайн протокола — `RESEARCH-BMP.md` в корне репозитория.

## Что здесь

- `shared.rs` — один `BmpService` на процесс (`BmpServiceBuilder` с настройками по умолчанию).
- `api.rs` — функции, выставленные в `vortex_chat`.
- `rejection.rs`, `batch.rs` — классы `BmpRejection` и `BmpBatch`, возвращаемые в Python.
- `limits.rs` — словарь `vortex_chat.BMP_LIMITS`: пределы берутся из Rust, Python их только применяет.
- `maintenance.rs` — фоновый поток уборки, запускается один раз за процесс.

## Выставлено в Python

```python
import vortex_chat

rejection = vortex_chat.bmp_deposit(mailbox_id, ciphertext, client_ip)
if rejection is not None:
    raise HTTPException(rejection.status, rejection.detail)

batch = vortex_chat.bmp_fetch_batch(ids, since, client_ip, False)
batch.rejection, batch.mailboxes, batch.padding

vortex_chat.bmp_set_room_secret(room_id, secret_hex)
vortex_chat.bmp_deposit_envelope(room_id, envelope_hex)
vortex_chat.bmp_compute_mailbox_id(secret_hex, timestamp)
vortex_chat.bmp_compute_mailbox_ids(secret_hex, timestamp)
vortex_chat.bmp_pair_jitter(secret_hex)
vortex_chat.bmp_bucket_timestamp(timestamp)
vortex_chat.bmp_wake_category(mailbox_id)
vortex_chat.bmp_stats()
vortex_chat.bmp_gc()
vortex_chat.bmp_start_gc()
vortex_chat.BMP_LIMITS
```

Python-сторона — `app/transport/bmp_backend.py` (загрузка, без fallback) и
`app/transport/blind_mailbox.py` (маршруты FastAPI).

## Тесты

- Домен: `cargo test -p vortex-bmp` — деривация, пределы, вытеснение, уборка, отказы.
- Паритет Python↔Rust: `app/tests/test_rust_parity.py` (`bmp_pair_jitter`,
  `bmp_compute_mailbox_id`, `bmp_compute_mailbox_ids`, `bmp_wake_category`,
  `bmp_bucket_timestamp`), векторы — `app/tests/vectors/rust_parity.json`.
- HTTP: `app/tests/test_bmp.py`.

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

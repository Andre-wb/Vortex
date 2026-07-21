# ADR-007: Post-quantum ratchet (continuous KEM ratchet) для v2 Double Ratchet

- **Статус:** **Proposed / Deferred — дизайн-документ, НЕ реализовывать под текущей моделью угроз.** Реализация требует, чтобы проект СНАЧАЛА принял endpoint-compromise в модель угроз — это решение о security-posture, не задача кодирования. Ниже — reference-дизайн + обоснование отсрочки.
- **Связано:** [ADR-006](006-pqxdh-double-ratchet.md) (PQXDH — handshake уже PQ; этот ADR продолжает его на ratchet), [ADR-002](002-multi-device-v2-sesame.md) (Double Ratchet, который здесь модифицируется).
- **Тип:** reference-дизайн. НЕ план к исполнению. Батчи — эскиз, контингентен принятию модели угроз.

## 1. Находка + модель угроз (крукс — читать первым)

Продолжающиеся DH-шаги Double Ratchet (`ratchet.js:_dhRatchetStep`, `kdfRk`) — **X25519-only**. KEM в ratchet не подмешивается.

**Но это НЕ пробел внутри защищаемой модели (A1).** По индукции корня сессия уже полностью PQ-стойкая после PQXDH-handshake (ADR-006):
```
rk₀ = SK            — требует KEM-SS (квант не достаёт) ⟹ PQ-стойкий
rk_{n+1} = HKDF(rk_n, dh_out)   — требует rk_n (PQ-стойкий по индукции),
                                  хотя dh_out (X25519) квантом ломается
```
⟹ под A1 (honest-but-curious сервер, HNDL) harvest-now-атакующему X25519-ратчет-публики **ничего не дают** — вся сессия PQ-конфиденциальна из handshake. **ADR-007 добавляет под A1 РОВНО НОЛЬ.**

**Единственная выгода PQ-ратчета — post-quantum post-compromise security (PQ-PCS):** заживление сессии ПОСЛЕ компрометации устройства против КВАНТОВОГО противника. Классический DR заживает после компрометации на первом же DH-шаге (свежий DH-приватный, которого у атакующего нет); но квантовый атакующий, укравший состояние, вычисляет DH из захваченных публиков → классический PCS против кванта сломан. PQ-ратчет подмешивает свежий KEM-секрет, который квант не выведет → PCS заживает и против кванта.

**Требуемый противник: квант ∧ endpoint-compromise ∧ хочет-снова-быть-выключенным (PCS).** Это **Б2 + компрометация устройства — явно ВНЕ скоупа проекта** (A1-defended, Б2-out-of-scope — как везде).

## 2. Надо ли вообще? (обоснование отсрочки — сердце ADR)

**Ценность:** узкая — только против «квант + уже скомпрометировал устройство + мы хотим восстановить PCS». Под заявленной моделью (A1) — нулевая (§1).

**Цена — высокая, и это самый рискованный код проекта:**
- **Модифицирует ЯДРО Double Ratchet** (`kdfRk`, `_dhRatchetStep`) — самый load-bearing путь: через него идут ВСЕ v2-сообщения (не только prekey-прелюда, как ADR-006). Баг здесь ломает всю личку.
- **Bandwidth = robustness (§3)** — наивная форма либо прожорлива (2272 байта/сообщение), либо хрупка к потере пакетов (клинит сессию). Устойчивая форма (SPQR) — research-grade.
- **Byte-parity re-work затмевает ADR-006:** трогает `kdfRk` + **transcript-векторы** `dr_vectors.json` (самая сложная часть) + Python-ratchet + генератор. Это не «один вектор `x3dh_pq`», а пере-деривация всего транскрипта с PQ-подмешиванием.
- **Formal-verification gap:** Signal PQ3/SPQR прошёл рецензирование на Eurocrypt/USENIX; наша композиция была бы informed-by, но не смоделирована.

**РЕКОМЕНДАЦИЯ: Deferred.** Не реализовывать, пока проект не примет endpoint-compromise в модель угроз. Это product/security-posture решение, не техническое. Под текущим A1 ADR-006 достаточно.

## 3. Bandwidth = robustness (крукс механизма)

Классический DR переживает потерю пакетов, потому что `dh_public` едет в **КАЖДОМ** заголовке — любое сообщение цепочки ре-триггерит ratchet. Наивная оптимизация «KEM-материал только на первом сообщении новой цепочки» это **ломает**: потеряли то сообщение, приняли позднее без KEM-байт → root keys сторон расходятся → **сессия клинит**. Единственный наивный фикс — повторять `(kem_pub‖kem_ct)` в КАЖДОМ сообщении = 1184+1088 = **2272 байта/сообщение** (vs текущие 40). Итог: «sparse ради bandwidth» и «loss-tolerant» тянут в разные стороны — и ровно это разрешает **erasure-кодирование SPQR** (мелкие чанки на сообщение + пересборка под потерю).

Три формы:
- **Reference (наивная per-ratchet):** простая, in-order-корректная, byte-parity-able. **Хрупкая к потере** (или прожорливая). ⟹ **документировать как эталон, НЕ шипить.** Её хрупкость сама по себе — аргумент, что прод нужен SPQR.
- **Sparse-periodic (KEM-ратчет раз в K DH-ратчетов):** заживление за K шагов vs 1 — против квант-endpoint-противника разница маргинальна. Bandwidth амортизирован, но **та же loss-хрупкость** без retransmit-until-confirmed.
- **SPQR (production-correct):** Signal «Triple Ratchet» = DH-ратчет + symmetric + SPQR («ML-KEM Braid» + erasure-code chunking). Research-grade; открытая реализация `signalapp/SparsePostQuantumRatchet`.

**SPQR не изобретать из этого ADR.** Точные параметры чанкинга, coding-параметры и state-машину sparse-ратчета брать ТОЛЬКО из первоисточников (см. Источники). R-фаза-1 = **прочитать их**, а не имплементить по этому эскизу.

## 4. Reference-механизм (дизайн-fidelity, не имплементация)

Расширение DH-шага подмешиванием KEM-секрета в root key:
```
kdfRkPq(rk, dh_out, kem_ss) = HKDF-SHA256(ikm = dh_out ‖ kem_ss, salt = rk,
                                          info = "vortex-pq-ratchet", 64) → (rk', ck)
```
- **Направление (зеркало DH-ратчета):** сторона несёт в заголовке свой текущий KEM-pub + ciphertext, инкапсулированный к KEM-pub собеседника. На ratchet-шаге: decaps входящего ct своим KEM-priv → `kem_ss` (recv-цепочка); генерит СВЕЖУЮ KEM-пару, encaps к KEM-pub пира → новый ct (send-цепочка); шлёт новый KEM-pub + ct.
- **Wire:** новый тип нормального сообщения `0x04` (PQ-normal) с KEM-полями; `0x02` не трогается. (Для reference — наивно; для SPQR — чанки.)
- **State:** `RatchetState` += `kemSendingPriv`, `kemSendingPubHex`, `kemReceivingPubHex`; `serializeState` растёт.
- **Byte-parity:** KEM только JS (liboqs≠FIPS ML-KEM, §2 ADR-006); Python-референс берёт `kem_ss` фиксированным входом; **PQ-вариант transcript-вектора** — большая работа (§2).

## 5. Четыре обязательных-к-правильности (не деталь — фундамент)

1. **Эфемерные KEM-ключи НА КАЖДЫЙ ratchet — несущее.** PCS происходит ЦЕЛИКОМ из свежей случайности, которой у атакующего нет. Статический/долговременный KEM-ключ даёт **ноль PCS** — это театр. KEM-пара регенерится каждый ratchet, как DH-пара. Это и есть свойство, ради которого трек существует.
2. **Byte-parity re-work.** См. §2 — transcript-векторы + Python-ratchet + генератор, не «один вектор».
3. **Путь апгрейда сессии.** Существующие классические сессии не могут ретроактивно PQ-ратчетиться. ADR-007 применяется ТОЛЬКО к сессиям, установленным после активации, ИЛИ нужен renegotiation/upgrade-handshake? Реальная развилка, не деталь.
4. **Взаимодействие с reorder/skipped-keys.** Подмешивание `kem_ss` в `rk` на конкретном сообщении обязано сходиться под out-of-order доставкой — чего текущая `_skipMessageKeys`/skipped-map логика НЕ учитывает. Тот же корень, что §3 loss-хрупкость.

## 6. Батч-эскиз (пропорционально; контингентен принятию модели угроз)

НЕ детализирован (детальные R1–R6 с критериями приёмки сигналили бы intent-to-build для того, что рекомендуется НЕ строить). Если проект примет endpoint-compromise:
- **R1 — прочитать первоисточники** (Signal SPQR spec + `signalapp/SparsePostQuantumRatchet` + Eurocrypt-статья). НЕ имплементить по этому ADR. Решить: sparse-periodic vs SPQR.
- **R2** — `kdfRkPq`-примитив + Python-референс + PQ-вектор ratchet-шага (byte-parity, KEM-ss фиксирован).
- **R3** — эфемерный KEM-lifecycle в state + serialize (§5.1).
- **R4** — wire `0x04` (или SPQR-чанки) + reorder-конвергенция (§5.4).
- **R5** — приём всегда-вкл → отправка за флагом (дисциплина ADR-006 P4/P5).
- **R6** — активация (гейт), И только с путём апгрейда (§5.3).

## 7. Не-цели / вне скоупа / открытые вопросы

- **Полный SPQR из этого ADR** — нет; R1 = первоисточники.
- **Формальная верификация нашей композиции** — gold standard, вне impl-трека.
- **Открытый вопрос (product, не тех):** принимает ли проект endpoint-compromise в модель угроз? Без «да» — весь трек нулевой по ценности (§1).
- **Открытый вопрос:** sparse-periodic (проще, loss-хрупок) vs SPQR (сложнее, устойчив) — решается на R1 по первоисточникам.
- **Открытый вопрос:** новые-сессии-only vs upgrade-handshake (§5.3).

## Источники

- [Signal — Signal Protocol and Post-Quantum Ratchets (SPQR / Triple Ratchet)](https://signal.org/blog/spqr/)
- [signalapp/SparsePostQuantumRatchet (открытая реализация)](https://github.com/signalapp/SparsePostQuantumRatchet)
- [Post-Quantum Ratcheting for Signal (NIST 6th PQC Standardization Conference, 2025)](https://csrc.nist.gov/csrc/media/events/2025/sixth-pqc-standardization-conference/post-quantum%20ratcheting%20for%20signal.pdf)
- [Quarkslab — Triple Threat: Signal's Ratchet Goes Post-Quantum](https://blog.quarkslab.com/triple-threat-signals-ratchet-goes-post-quantum.html)
- [PQShield — Diving into Signal's new PQ protocol](https://pqshield.com/diving-into-signals-new-pq-protocol/)

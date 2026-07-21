# ADR-006: PQXDH — post-quantum X3DH для v2 Double Ratchet (личка)

- **Статус:** Accepted, код-полон P1–P7 и **АКТИВИРОВАН**. `vortex_pqxdh_enabled` — **default-on** (opt-out kill-switch `='0'`), включён pre-launch (приложение ещё не в сети: нет прод-риска, нет оператора-флиппера). P6 (PQOPK) и P7 (активация default-on) — по явному решению оператора. Playwright-гейт `pqxdh.spec.js` — ЗЕЛЁНЫЙ на всех трёх движках: Firefox(Gecko)+Safari(WebKit)+Chrome(Blink). Каждый батч реверсивный, с advisor-чеком.
- **Связано:** [ADR-002](002-multi-device-v2-sesame.md) (v2 Sesame X3DH — device-rooted, тот путь мы и делаем PQ), [ADR-003](003-device-account-binding.md) (аккаунтный Ed25519 → device-cert → SPK; ту же цепочку зеркалим для PQSPK), [ADR-004](004-post-quantum-hybrid.md) (ML-KEM-768 либа + Kyber-lifecycle — фундамент K1–K2 переиспользуется; §5 предвидел этот трек как «Kyber-pre-keys, не аккаунтный Kyber»).
- **Тип:** дизайн + план. Модель угроз и дисциплина — как трек ADR-004.

## 1. Находка (проверено по коду, не по утверждению)

v2 Double Ratchet (`static/js/dr/`) — единственный путь E2E-шифрования лички 1:1, и он **X25519-only, без PQ**:

- `x3dhInitiate/x3dhRespond` (`static/js/dr/x3dh.js`) считают `km = 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]`, `shared = HKDF-SHA256(km, salt=0*32, info="vortex-x3dh", 32)` (`primitives.js:kdfX3dh`). Все четыре DH — X25519. Kyber отсутствует.
- Начальное prekey-сообщение (`v2-envelope.js`, type `0x01`) несёт `IK_A ‖ EK_A ‖ spk_id ‖ [opk_id] ‖ device-cert`. Поля под KEM-ciphertext нет.
- Prekey-бандл (`app/models/prekeys.py::PreKeyBundle`) — per-device: `device_x3dh_pub` (IK устройства), `signed_prekey`+`signed_prekey_sig`, OPK-пул (`onetime_prekeys`). **Kyber-колонок на prekey-таблицах нет.** Единственный опубликованный Kyber — аккаунтный (`users.kyber_public_key`+`_sig`, ADR-004 K2).

**Модель угроз: HNDL (harvest-now-decrypt-later) под A1** (honest-but-curious сервер / пассивный наблюдатель) — как ADR-004. Захваченные сегодня prekey-сообщение + опубликованный бандл дают будущему кванту сломать X25519-DH → восстановить X3DH shared secret → root key → всю сессию. KEM-инкапсуляция к Kyber-ключу, который квант не ломает, закрывает это. Активный сервер (Б2), подменяющий PQSPK на фетче, — вне скоупа (граница safety-number/подписи, как везде).

## 2. Несущие инварианты (проверено)

1. **X3DH — client-side JS; Python `double_ratchet.py` = тест-оракул.** Прод-ссылок на `x3dh_initiate/x3dh_respond` в Python нет (единственный прод-импорт — `verify_spk_signature` в `app/keys/prekeys.py`). Реальный обмен — в браузере (`session.js`). Векторы `app/tests/vectors/dr_vectors.json` пинят JS↔Python byte-parity KDF.
   - **Следствие (крукс §2 ADR-004):** Python-Kyber — это liboqs `Kyber768` (round-3), **несовместимый** с JS ML-KEM-768 (FIPS 203). ⟹ KEM (encaps/decaps) — **только JS**. Python-референс берёт `kyber_shared`/`CT`/`PQPK` как **фиксированные входы** вектора → byte-parity KDF-структуры сохраняется без затягивания liboqs.
2. **Сессии device-rooted (Sesame).** X3DH идёт против `device_x3dh_pub` пира (per-device IK), не против аккаунтного ключа. ⟹ Kyber-pre-key **ДОЛЖЕН быть per-device.** Reuse аккаунтного Kyber (ADR-004) воспроизвёл бы K5-лок-аут: аккаунтный Kyber-priv есть не на всех устройствах → устройство без него не декапсулирует. Per-device pre-key генерится на устройстве и **не портируется** → лок-аут невозможен. Это буквальное расширение уже существующей per-device SPK/OPK-машинерии.
3. **`v2-envelope.js` — жёсткий бинарный формат с байтом `type`** (`0x01` prekey / `0x02` normal). ⟹ расширение через **новый `type 0x03`** (PQ-prekey), `0x01`/`0x02` не трогаются (regression-safe, backward-compat). Дисциплина enc_v-реестра ADR-001.
4. **E2E-инвариант ADR-004 §2 держится:** сервер релеит opaque KEM-ciphertext, не декапсулирует. Не добавлять серверный путь, декапсулирующий user-directed KEM.

## 3. Решения

1. **Per-device signed Kyber pre-key (PQSPK), НЕ аккаунтный Kyber.** Новые nullable-колонки на `PreKeyBundle`: `device_kyber_pub` (ML-KEM-768 pub, 1184 б), `device_kyber_sig` (подпись), `device_kyber_id` (rotation-id). Приватный — в `prekey-store.js` рядом с SPK/OPK-приватными (per-device, не покидает устройство). Обоснование — инвариант §2.2.

2. **KDF-привязка KEM-транскрипта (первоисточник, не наивная форма).** Спека Signal PQXDH (Rev 3) даёт `SK = KDF(DH1‖DH2‖DH3[‖DH4]‖SS)` и требует привязку PQPK (в AD, если KEM не встраивает pub в ciphertext). Формальный анализ (Bhargavan/Jacomme/Kiefer/Schmidt, USENIX'24; Fiedler/Günther, PKC'25) показал re-encapsulation/binding-gap, **не эксплуатируемый в Signal лишь потому, что ML-KEM связывает SS с pub**, и рекомендовал класть привязку **внутрь KDF** (проще доказательство, не зависит от AEAD). Берём строго-сильную форму — не полагаемся на внутреннее binding-свойство ML-KEM:
   ```
   km_pq = 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ PQPK_B ‖ CT ‖ SS
   SK    = HKDF-SHA256(ikm=km_pq, salt=0x00*32, info="vortex-pqxdh", 32)
   ```
   `PQPK_B` — Kyber-pre-key pub адресата (1184 б, из бандла у инициатора / свой у ответчика); `CT` — KEM-ciphertext (1088 б, из прелюды); `SS` — KEM shared secret (32 б, encaps/decaps). Длины фиксированы → канонизация не нужна. `info="vortex-pqxdh"` домен-сепарирует от классического `"vortex-x3dh"` (тот байт-в-байт не трогаем).

3. **Новый wire-`type 0x03` (PQ-prekey).** Раскладка = поля `0x01` + `pqspk_id` (BE u32) + `has_pqopk`(1)[+`pqopk_id` BE u32] + `kyber_ciphertext` (1088 б). Декодер роутит по type-байту; `0x01` нетронут. `CT` в AAD не кладём: тампер CT → ML-KEM implicit rejection даёт другой `SS` → другой `SK` → ratchet InvalidTag (тот же аргумент, что нота `v2-envelope.js` про prelude-не-в-AAD; KDF-binding §3.2 усиливает).

4. **Подпись PQSPK — зеркало SPK-цепочки, без второй конвенции.** PQSPK подписывается **device-подписывающим ключом** (`device_sign_pub`), как SPK; device-cert связывает `device_sign_pub` с аккаунтным Ed25519; проверка на приёме — `verify_spk_signature`-паттерн против **припиненного** аккаунтного Ed отправителя (`_bundleWellSigned`/`resolvePeerKyberPub`-дисциплина). Никакого нового корня доверия.

5. **Отдельный флаг `vortex_pqxdh_enabled` (дефолт ВЫКЛ), приём-везде-первым.** Приём `0x03` (P4) раскатывается ВЕЗДЕ дормантно ДО того, как любой инициатор флипнет отправку (P5) — как K4b→K4c. Не куплен к `vortex_pq_hybrid_enabled`: у PQXDH предусловие флипа **проще** (нет multi-device-гейта §2.2), треки флипаются независимо.

6. **Fallback + именованный downgrade-edge.** Инициатор шлёт `0x03` ТОЛЬКО если бандл пира несёт валидный подписанный PQSPK И флаг ВКЛ; иначе — классический `0x01` (backward-compat). **Явно:** сессия не несёт PQ-гарантии, пока не выполнены оба условия; пир без PQSPK → классика → HNDL-экспонирован (осознанно, безопасно-но-без-PQ); активный strip PQSPK — Б2/вне скоупа.

7. **PQOPK (one-time Kyber pre-keys) — СДЕЛАНО в P6 (по явному решению оператора).** Под A1 FS-дельта нулевая: Kyber-priv не утекает (E2E, сервер не видит; A1 не компрометит устройство). One-time PQ-pre-keys покупают KEM-forward-secrecy против будущей кражи PQSPK-priv (device-compromise ≈ Б2). Отсрочка — по **размеру батча, не ценности угрозы** (как sealed/stories в ADR-004). Окно экспозиции ограничивает **cadence ротации PQSPK** (§3.1 rotation-id); PQOPK — именованное FS-усиление, не блокер.

## 4. Батчи (P1–P7)

Каждый дормантный/реверсивный; активация — отдельным гейтом P7.

- **P1 — KDF-примитив PQXDH + Python-референс + вектор (byte-parity lock).** `primitives.js`: `kdfX3dhPq` / расширение `kdfX3dh` доп-входом (`info="vortex-pqxdh"`, конкатенация `km ‖ PQPK ‖ CT ‖ SS`). Зеркало в `app/security/double_ratchet.py` (`x3dh_*_pq`, `kyber_shared`/`CT`/`PQPK` — параметры). Новый вектор `x3dh_pq` в `dr_vectors.json` с **фиксированными** `pqpk_pub`/`kyber_ct`/`kyber_shared` + ожидаемый `shared_secret` (liboqs НЕ вызывается — §2.1). Классические `x3dh`-векторы не трогаются. Тесты JS+Python сходятся на векторе. Чистый аддитив, дормантно.

- **P2 — per-device Kyber pre-key lifecycle.** Клиент (`prekeys.js`): генерация PQSPK (ML-KEM keygen из `mlkem.js`), приватный → `prekey-store.js` (per-device, как SPK); подпись `device_sign_pub`; поля `device_kyber_pub`/`device_kyber_sig`/`device_kyber_id` в `buildPrekeyBundle`. Сервер: nullable-колонки на `PreKeyBundle` + идемпотентный ALTER (`database.py`, SQLite-ветка — caveat Postgres/Alembic как ADR-004); `PublishPreKeysRequest`/`PreKeyBundleResponse`/`DeviceBundle` расширены (аддитивно, backward-compat); `verify_spk_signature`-проверка PQSPK-подписи под `Config.PREKEY_SIG_ENFORCE` (как SPK). Fetch отдаёт PQSPK-поля (`claim-opk` не трогаем — PQSPK не one-time до P6). **Data-plane-дормантно** (никто не шлёт/принимает `0x03` до P5), но **control-plane-active на деплое:** backfill-арм `!hasPqspkPrivate()` в `ensurePrekeysPublished` заставляет каждое существующее устройство сделать ОДИН републиш (новый SPK + OPK-пачка + PQSPK) на следующем boot — прецедент арма `supports_v2`. Оператору ждать fleet-wide обновления бандлов при мёрже, не только при флипе.

- **P3 — X3DH-PQ математика + wire `0x03`.** `x3dh.js`: `x3dhInitiatePq` (encaps к `PQPK_B` → `CT`,`SS`; `km_pq` §3.2) / `x3dhRespondPq` (decaps `CT` своим PQSPK-priv → `SS`; тот же `km_pq`). `v2-envelope.js`: encode/decode `type 0x03` (§3.3). Не провязано в `session.js`. JS-тесты: initiate↔respond сходятся, чужой PQSPK-priv → implicit-rejection → InvalidTag, tamper CT → InvalidTag.
  - **Критерий приёмки (load-bearing):** реальные `x3dhInitiatePq`/`x3dhRespondPq` обязаны сойтись с вектором `x3dh_pq` (инъекция фиксированных `ct`/`ss`), НЕ только self-consistent live round-trip. Иначе arg-order slip (перестановка `pqpk`/`ct`/`ss`) обе JS-стороны разделят, interop'нут между собой, пройдут live round-trip и молча зашлют не-спек-деривацию — Python остаётся оракулом, рантайм-interop с ним не идёт. (P1 добавил length-tripwire в `kdfX3dhPq` как первую линию.)

- **P4 — ПРИЁМ всегда-вкл (load-bearing).** `session.js:decryptV2` понимает `0x03`: находит локальный PQSPK-priv по `pqspk_id` → `mlkemDecaps(ct, sk)` → `mlkemGetPublic(sk)` → `x3dhRespondPq(..., pqpkOwnPub, ct, ss)`. Раскатывается везде дормантно. Тест: приём `0x03` при наличии priv (round-trip), при отсутствии → `SessionError`, не краш.
  - **Триггер деградации — null-lookup, НЕ пойманное исключение (advisor).** `mlkemDecaps` НЕ бросает (ML-KEM implicit rejection: чужой/битый ct → детерминированный ДРУГОЙ ss, не ошибка). Поэтому единственный fail-closed сигнал — отсутствие PQSPK-priv для `pqspk_id`: null → `SessionError`→плейсхолдер ДО decaps (как `no_prekey_privates`). После decaps сигнала нет — расхождение ss всплывёт как ratchet InvalidTag→плейсхолдер.
  - **Bob-связанный PQPK = `mlkemGetPublic(sk)` — load-bearing, сверить byte-identity (advisor).** P2 хранит только `{id, sk}`; P4 выводит pub из sk для `pqpkOwnPubHex`. Если выведенный pub ≠ опубликованному (к которому Alice инкапсулировала), decaps даёт правильный ss (нет сигнала), но KDF-binding расходится → SK-mismatch → InvalidTag → **невидимый fallback**. Почти наверняка ок (FIPS 203 sk встраивает ek → getPublic = слайс). Покрытие разбито: **JS-нога закрыта P4** (`mlkemGetPublic(sk)` == keygen-pub + полный 0x03-round-trip использует derived pub на приёме); **DB-round-trip нога — P2** (`test_kyber_prekey_verifiable_from_fetch`: подпись над fetched-байтами не сошлась бы при hex→BLOB→hex-порче); **полный server-fetch E2E остаётся на гейт P7.**

- **P5 — ОТПРАВКА за флагом.** `session.js:_establishInitiator`/`message-cipher.js:_claimingBundle`: если бандл пира несёт валидный подписанный PQSPK (capability: `resolvePeerKyberPub`-дисциплина против припиненного Ed пира) И `vortex_pqxdh_enabled` → `x3dhInitiatePq` + `encodeV2(0x03)`; иначе классика. Читает PQSPK из discovery-бандла `/devices` (`DeviceBundle`), не из claim-opk. Тесты: capability-verify, fallback без PQSPK/при выкл-флаге, чужая подпись → классика.
  - **Критерий приёмки (sign/verify byte-lock):** P2 подписывает `edSign(deviceSignPriv, СЫРЫЕ 1184 байта kyber pub)` (как SPK подписывает сырые 32 байта); `_bundleWellSigned` в P5 обязан Ed25519-верифицировать над ТЕМИ ЖЕ сырыми байтами против `device_sign_pub`. hex-vs-raw или length-slip → тихий провал в классику (невидимо, fallback корректен). Проверить реальным publish→verify на браузер-гейте P7.

- **P6 — PQOPK (one-time Kyber pre-keys) — СДЕЛАНО (по явному решению §3.7).** Таблица `onetime_kyber_prekeys` (per-device, зеркало `OneTimePreKey`) — новая таблица через `create_all` (Postgres-safe, без ALTER-caveat). Инициатор предпочитает PQOPK, иначе last-resort PQSPK; `deletePqopkPrivate` на приёме после успеха (KEM-FS). Batch=6 (малый: ML-KEM тяжелее X25519, out-of-scope-ценность). Ключевые решения (advisor):
  - **Fork-a (дефект в наивном дизайне, исправлен):** `claim-opk` расходует PQOPK ТОЛЬКО при `want_kyber=true`, а клиент шлёт его лишь когда сессия реально идёт в PQ (`device_kyber_pub != null` после capability-гейта). Иначе flag-off трафик (дефолт) выжигал бы пул → фича не срабатывала бы. Депленция PQOPK ≤ OPK → OPK-low-триггер реплениширует оба (пиггибек, без отдельного счётчика).
  - **PQOPK-pub НЕ подписываем** (в отличие от PQSPK): подмена сервером ловится связыванием `PQPK_B` в `km_pq` (§3.2) — responder биндит `mlkemGetPublic(своего sk)`, mismatch → InvalidTag (fail-closed DoS, не тихий downgrade), даже под Б2. Аутентичность устройства — из cert-цепочки.
  - **Receive-ветка строго аддитивна:** `pqopkId==null` → байт-идентично P4 (PQSPK-путь); деградация `no_pqopk_privates` при отсутствии priv (тот же generic-catch→плейсхолдер). Тесты: `test_kyber_onetime_prekey.py` (4: claim consume/exhaust, **want_kyber=false не трогает пул**, длина), `pqxdh-pqopk.test.js` (3: **E2E PQOPK+FS-delete**, flag-off want_kyber=false пул цел, **исчерпание→pqopk_id=null→PQSPK fallback**).

- **P7 — активация default-on (pre-launch) — СДЕЛАНО.** Вместо оператор-флипа (оператора нет) `vortex_pqxdh_enabled` переключён на **default-on** (opt-out, зеркало `_v2SendEnabled`; kill-switch `='0'`). Безопасно pre-launch: приложение не в сети → нет прод-риска; и default-on само по себе низкориск — ML-KEM pure-JS (детерминирован, engine-independent), DH/HKDF/AEAD — те же Web Crypto, что классический v2 уже гоняет.
  - **Защитная сеть подтверждена (advisor):** сбой ML-KEM-движка на ОТПРАВКЕ → `mlkemEncaps` throw → `x3dhInitiatePq` reject → `encryptV2ForDm` outer-catch → `return null` → **v1 fallback** (не broken 0x03; транзиентно, не `_fallback`). Приём self-gated: 0x03 шлётся лишь устройству с опубликованным валидным PQSPK ⟹ его движок уже прогнал ML-KEM keygen ⟹ decaps работает (тот же pure-JS).
  - **Playwright-гейт `pqxdh.spec.js` — ЗЕЛЁНЫЙ на всех трёх движках (Gecko+WebKit+Blink):** реальный ML-KEM keygen/encaps/decaps + **byte-identity `mlkemGetPublic(sk)==pub`** (закрывает P4-остаток §3.1 на движке); полный X3DH-PQ round-trip (initiate encaps ↔ respond decaps); wire 0x03; **published PQSPK-sig над СЫРЫМИ байтами** (P2↔P5 seam); PQOPK-путь; негативы (чужой PQSPK-priv → расходится, чужой Ed → sig fail). Само-consistency каждого движка + P1 кросс-язычный вектор (Python-паритет) + детерминизм pure-JS ⟹ кросс-движковый interop.
  - **Тесты default-on:** флип инвертировал 2 теста, полагавшихся на default-off — переведены на явный kill-switch `='0'` (`pqxdh-send` kill-switch, `pqxdh-pqopk` fork-a). Остальной v2-send не затронут (те бандлы без PQSPK → классика независимо от флага).
  - **Rollout order N/A:** pre-launch, все клиенты атомарно на одном коде (P2-backfill публикует PQSPK на boot) → нет skew получатель/отправитель.
  - **Предусловие перед выходом в сеть — закрыто:** гейт прогнан на всех трёх движках (Gecko+WebKit+Blink). Остаётся лишь держать его в CI как регрессию (`npm run test:e2e`), не прод-флип.
  - **Receive-first само-гейтится (advisor, усиление):** P2–P5 едут одним атомарным JS-бандлом ⟹ «устройство рекламирует валидный PQSPK» ⟹ «устройство исполняет P4» ⟹ «умеет принять 0x03». Alice может ОТПРАВИТЬ 0x03 только устройству, которое умеет ПРИНЯТЬ — инвариант держит сам механизм рекламы, не только последовательность оператора.
  - **Rollback-residual (записать, не строить):** откат клиента НИЖЕ P4 при живых flag-on отправителях + сервер всё ещё отдаёт старый PQSPK → 0x03 → плейсхолдер. Так же для P6: устройство опубликовало PQOPK, откатилось ниже P6, пир claim'ит его stale PQOPK и шлёт `pqopk_id` → pre-P6 приёмник игнорит `pqopk_id`, decaps'ит PQSPK-priv → неверный ss → плейсхолдер. Митигация: откат СНАЧАЛА снимает send-флаг (или обнуляет рекламируемые PQSPK/PQOPK), потом код.

## 5. Не-цели / вне скоупа

- **Активный сервер (Б2):** подмена/strip PQSPK на фетче — граница safety-number/подписи, как везде. Подпись PQSPK (§3.4) даёт Б2-аутентичность, но strip-до-классики под Б2 остаётся вне скоупа проекта.
- **Group/room/stories/voice:** покрыты ADR-004 (room-key hybrid). Этот ADR — только 1:1 DR-сессии.
- **Серверный hybrid node↔node** (`key_exchange.py`, федерация) — не трогаем (кросс-язычность к liboqs — своя граница).
- **PQOPK** — отложен в P6 (§3.7); базовая PQ-защита — уже в PQSPK (P1–P5).
- **PQ — только handshake, не продолжающийся ратчет.** PQXDH делает PQ-стойким начальный `SK`; последующие DH-шаги Double Ratchet остаются X25519. Под HNDL этого **достаточно**: каждый root key цепочится из PQ-стойкого начального `SK`, поэтому захват X25519-ратчет-публиков не помогает будущему кванту без root key. Это **не** даёт post-quantum post-compromise security (PQ-ратчет — SPQR-территория, отдельный трек); endpoint-compromise/active — уже Б2/вне скоупа. §1 «делаем личку PQ» читать в этой границе: PQ-стойкость сессии происходит из handshake, не из каждого сообщения-ратчета.

## 6. Открытые под-вопросы (до P1)

1. **Минимальная vs строго-сильная форма binding.** Берём максимум (`PQPK ‖ CT ‖ SS` в KDF, §3.2) — не зависит от внутреннего binding-свойства ML-KEM. Signal-минимум — `SS` в KDF + `PQPK` в AD. Наша форма строго сильнее и следует рекомендации формального анализа (привязка в KDF). Зафиксировать в P1-векторе как канон; НЕ откатывать к наивному `km ‖ SS`.
2. **Cadence ротации PQSPK** (`device_kyber_id`). Сейчас SPK не ротируется (`SPK_ID=1` фиксирован, `prekeys.js`). PQSPK наследует то же ограничение до отдельного rotation-батча; окно HNDL это не расширяет (KEM держит против кванта независимо от cadence), но ограничивает FS-окно до PQOPK (§3.7).
3. **CT в AAD** — НЕ добавляем (KDF-binding §3.2 + implicit rejection покрывают tamper; отдельный MAC не нужен, как в классическом `v2-envelope.js`). Проверить на гейте P7, что tamper CT → плейсхолдер, а не тихий mis-decrypt.

## Источники

- [Signal — The PQXDH Key Agreement Protocol (Rev 3)](https://signal.org/docs/specifications/pqxdh/)
- [Bhargavan, Jacomme, Kiefer, Schmidt — Formal verification of PQXDH (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf)
- [Fiedler, Günther — Security Analysis of Signal's PQXDH Handshake (PKC 2025 / eprint 2024/702)](https://eprint.iacr.org/2024/702.pdf)
- [Inria-Prosecco/pqxdh-analysis](https://github.com/Inria-Prosecco/pqxdh-analysis)

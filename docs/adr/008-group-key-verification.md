# ADR-008: Верификация ключей участников групповых комнат

- **Статус:** Accepted, код-полон G1–G6 и АКТИВИРОВАН. Wrap-гейт `vortex_member_verify_enabled` — дефолт ВКЛ (kill-switch '0'). Каждый батч дормантный/реверсивный, с advisor-чеком. Фаза 1 (MVP) + Фаза 2 сделаны.
- **Связано:** [ADR-003](003-device-account-binding.md) (account Ed25519 + `identity_key_sig`, `device-cert`), [ADR-004](004-post-quantum-hybrid.md)/[ADR-006](006-pqxdh-double-ratchet.md) (`kyber_public_key_sig`; «safety-number» назван там ортогональным B2-слоем). Переиспользует `fingerprint.js`, `identity-pin.js`, `resolvePeerKyberPub`, `_bundleWellSigned`.
- **Тип:** дизайн + план.

## 1. Находка (проверено по коду)

- Группы: раздача room-key идёт по member-pubkey, которые отдаёт сервер; **верификации нет**. `ui.js:206` прячет fingerprint-shield для не-DM. Точка обёртки — `key_request`-хендлеры (`websocket.js:305-307`, `notifications.js:323-325`): recipient X25519/kyber приходит из **серверного broadcast** (`msg.for_pubkey`/`for_kyber_pubkey`/`for_kyber_sig`).
- 1:1 закрыто отпечатками, но: per-`Contact`, над **X25519-парой**, как chat-shield (`fingerprint.js`). Член группы не-в-контактах не имеет записи вообще.
- `GET /api/rooms/{id}/members` отдаёт **только `x25519_pubkey`** — нет kyber/sig/`identity_key_ed`.
- **Крукс (проверено):** account Ed25519 — корень доверия. `users.x25519_public_key` == `PreKeyBundle.identity_key` (`prekeys.js:296,237`), подписан account Ed через **`identity_key_sig`** (`prekeys.js:8` «cross-signature сам X25519 identity_key»); `users.kyber_public_key` подписан **`kyber_public_key_sig`**. ⟹ верификация account Ed **транзитивно покрывает и X25519, и Kyber** (обе подписи существуют; `_bundleWellSigned` уже проверяет `edVerify(ed, identity_key, identity_key_sig)`). Корень пинится TOFU через `pinPeerAccountEd` (identity-pin.js); единственный потребитель сегодня — `pq-capability.js`.

## 2. Модель угроз (+ коэрентность с PQ-ADR)

Защищает **B2-подвектор: подмену identity-ключа недоверенным/скомпрометированным сервером** (MITM на раздаче group room-key — сервер отдаёт свой pubkey как ключ жертвы, отправители заворачивают room-key на него → сервер читает группу). Это **тот самый «safety-number» слой, который ADR-004/006/007 называли ортогональным** поверх A1. **Активный-протокольный B2** (downgrade/stripping/подмена на живом протоколе) — по-прежнему вне скоупа. (Явно — против видимого противоречия с «B2 out of scope» тех ADR.)

**Честный скоуп Фазы 1 (не переоценивать критерий 3):** делает подмену **ДЕТЕКТИРУЕМОЙ и ОТКАЗУЕМОЙ**, но **сама по себе НЕ предотвращает from-start MITM.** TOFU пинит first-sight; если first-sight УЖЕ подменён — событие «changed» не сработает, а MVP-гейт (warn-on-unverified) всё равно завернёт. From-start закрывается ТОЛЬКО OOB-верификацией (пользователь сверил отпечаток вне канала) ИЛИ hard-mode (refuse-unverified) — ровно модель Signal.

## 3. Несущий инвариант (ГЛАВНОЕ — иначе фича = театр)

**Заворачивать room-key ТОЛЬКО на ВЕРИФИЦИРОВАННЫЙ ключ, НИКОГДА на серверный `for_pubkey` напрямую.** Wrap-target выводится из **аутентифицированной** member-keys цепочки; `for_pubkey` из broadcast — **недоверенный вход, обязан РАВНЯТЬСЯ** wrap-target. `edVerify(pinned_ed, WRAP_TARGET_x25519, identity_key_sig)` проходит над ТЕМ ЖЕ ключом, на который шифруем — им является **`bundle.identity_key`** (который подписывает `identity_key_sig`), НЕ `users.x25519_public_key`, если недоверенный сервер их разведёт. Иначе (проверить Ed-пин, но завернуть на `for_pubkey`) — подмена `for_pubkey` переживает, и весь механизм декоративен.

## 4. Решения (несущие)

1. **Защита = пин (identity-pin) + проверка sig-цепочки + wrap-гейт.** Бейдж — не защита, а OOB-апгрейд TOFU→verified.
2. **Security-состояние ЛОКАЛЬНО-авторитетно** (локальный пин account-Ed + локальная запись «сверил ed_hash»). **Серверное хранилище верификации (ТЗ B2) — ОТЛОЖЕНО** (сервер недоверен → foot-gun: он может соврать «verified»; безопасно лишь если потребитель ре-чекает mirrored ed_hash против СВОЕГО локального пина). MVP — local-only; server-mirror — отдельный opt-in батч, когда мультидевайс станет частым.
3. **Единый gate-модуль** `verifyMemberForWrap(userId, x25519, kyber, kyberSig) → {status, verifiedX25519}` (не инлайнить в WS-хендлер). Зовёт `key_request` (сайты A/B); дормантные `provision`/`approve-join` наследуют при активации. Fix-the-class.
4. **Поведение (fork-a):** **block на `changed`** (пин-mismatch ИЛИ sig-fail против пина = сигнал активной атаки; **fail-closed** — легит account-reset пир не получит ключ до ре-верификации; осознанная posture, UX-цена названа); **warn+wrap на `unverified`** (TOFU, sig-valid, не OOB); **hard-mode (opt-in setting)** — refuse unverified.
5. **B1 member-keys** отдаёт per-member `{identity_key_ed, x25519(=bundle.identity_key), identity_key_sig, kyber, kyber_public_key_sig}` — ключи, которые sig'и РЕАЛЬНО покрывают. `identity_key_ed` — account-константа (одна на аккаунт, на всех device-бандлах — это и делает «новое устройство не сбрасывает верификацию», §7). Если device-бандлы расходятся по Ed → это сам по себе red flag, surface, не молча выбирать.
6. **DM-fp миграция на Ed (ТЗ B4) — ОТЛОЖЕНА** из Фазы 1. Меняет working DM-fp value (X25519→Ed) → молча сбросит КАЖДУЮ существующую DM-верификацию и встревожит («fingerprint changed»). Model-tidiness, не требуется для групп (группа юзает Ed напрямую). Свой батч с migration story (re-verify prompt / dual-display). Не рисковать групповой фичей ради несвязанной регрессии.
7. **Cross-impl (критерий 6):** fp+room_sn пиннятся Python↔JS вектором. **Сериализация зафиксирована точно** (класс багов, что кусал на ECIES-salt и key-login raw-vs-HKDF): `fingerprint.js` сортирует **LOWERCASE hex-СТРОКИ**, join `':'`; `room_sn = SHA-256("vortex-room-sn:v1" ‖ room_id ‖ concat(sorted account-Ed hex))`. **hex-string-sort vs raw-byte-sort указать явно** (они различаются) + разделители + регистр — в ADR и в векторе.

## 5. Дизайн

**Отпечаток участника (Фаза 1):**
```
fp_input   = account Ed25519 pub (не X25519!)
combined   = computeFingerprint(sort(my_ed_hex, their_ed_hex))   # reuse, key-agnostic
статус     = verified | unverified | changed
             из pinPeerAccountEd({trusted}/{changed}) + локальная verified-запись
```
**Room safety number (Фаза 2):**
```
members_ed = отсортированные account-Ed hex всех участников
room_sn    = SHA-256("vortex-room-sn:v1" ‖ room_id ‖ concat(members_ed)) → hex-блоки + emoji
```
Одинаковый состав → одинаковый room_sn у всех; расхождение = подмена ключа или разъехавшийся состав. Пересчёт при изменении состава.

## 6. Батчи

**Фаза 1 (MVP):**
- **G1 — B1 member-keys endpoint** `GET /api/rooms/{id}/member-keys` (полная цепочка §4.5, `_require_member`-гейт, только участникам). Дормантно-аддитивно.
- **G2 — client verify-модуль** `verifyMemberForWrap` + per-member статус: пин Ed (identity-pin), `edVerify(pinned_ed, x25519, identity_key_sig)` + `resolvePeerKyberPub`-стиль для kyber, локальная verified-запись. Reuse, не изобретать.
- **G3 — wrap-гейт в `key_request`** (сайты A/B) через G2: block-changed / warn-unverified. **Инвариант §3: шифровать на `verifiedX25519`, `for_pubkey` == target или abort.** ✅ Активирован (дефолт ВКЛ). Безопасно, т.к. в честном потоке `for_pubkey` (сервер шлёт `user.x25519_public_key`) == `verifiedX25519` (= `bundle.identity_key`): клиент публикует бандл с `identity_key = user.x25519_public_key` (`prekeys.js`), подписанным account-Ed → `pubkey_mismatch` бьёт только по реальной подмене/смене, не по легитимной раздаче. v1-участники без бандла → member-keys отдаёт тот же `user.x25519` → allow. Три условия блока: смена пиннутого Ed, невалидная `identity_key_sig`, невалидная `kyber_public_key_sig` — все → `changed`. NB: на невалидной kyber-sig ON блокирует всю обёртку, тогда как OFF деградировал бы до X25519-only (PQ null через `resolvePeerKyberPub`) и всё же доставил ключ; на свежих данных не срабатывает (kyber подписан тем же Ed).
- **G4 — UX:** F1 бейджи (`showMembersModal`, слот `.member-item-name`), F2 fp-модалка над Ed-парой, F3 групповой индикатор (снять `ui.js:206`-условие → «N из M верифицированы»), F4 change-баннер в комнате.

**Фаза 2:**
- **G5 — room safety number** (client calc §5 + F5 room-info блок `info.js`) + cross-impl Python↔JS вектор. ✅ Сделано: `computeRoomSafetyNumber` (fingerprint.js), F5-секция `rss-safety-section` (room_settings.html + info.js, только группы, информативно/дормантно — ничего не блокирует), вектор `room_sn(42,[ff·32,aa·32,0f·32])=14820ad9…475a` пиннят JS-тест + `test_room_safety_number.py`.
- **G6 — F6 QR** (reuse `VORTEX-FP:` из fingerprint.js). ✅ Сделано: QR-панель и скан модалки отпечатка переиспользуются в identity-режиме (отпечаток над account-Ed парой симметричен → QR одного участника == локальный отпечаток другого → скан-матч зовёт `verifyCurrentFingerprint` → `markIdentityVerified`). Формат вынесен в чистые `fingerprintQRPayload`/`parseFingerprintQR`. Cross-impl вектор fp/emoji/QR `fp(aa·32, bb·32)=6173CF9D…47AB` пиннят JS-тест + `test_member_fingerprint.py` (крит. приёмки #6 по fp закрыт).

**Отложено (свои батчи, вне Фазы 1):**
- **server verification mirror** (cross-device, §4.2). ✅ Сделано: атестация «сверил пира P = account-Ed E» подписана DEVICE-ключом (account-Ed приватного на линкованном устройстве нет — blast-radius), с приложенным device-cert; сервер — НЕподделываемое хранилище, owner-scoped, rollback-guard по `signed_at`. Потребитель (`syncAttestations`) верифицирует device-cert→свой account-Ed + attest-sig и применяет latest-per-peer. Заворачивание G3 всё равно НЕЗАВИСИМО ре-чекает живой ed → подделка/откат мирора не даёт завернуть на подменённый ключ. Дормантно за `vortex_verify_mirror_enabled` (дефолт ВЫКЛ). Cross-impl вектор `attest(1,2,cd·32,verified,1700000000)` пиннят JS + `test_verify_mirror.py`. Метадата-цена: сервер узнаёт who-verified-whom (инкрементально к уже известным контактам) — потому opt-in.
  - **Blast-radius флипа ВКЛ ≈ ноль для текущего гейта:** мирор ed-привязан → может лишь двигать пира между `unverified↔verified` для ТОГО ЖЕ ed (на подменённый live-ключ не наложится — `isIdentityVerified` вернёт mismatch). Активный гейт заворачивает и в `unverified`, и в `verified`, блокирует лишь `changed`/`pubkey_mismatch` → мирор не меняет НИ ОДНОГО решения об обёртке сегодня. Его радиус — только будущий hard-mode.
  - **Границы (названы, не чинятся):** (1) ротация account-Ed (logout→login без vault-restore регенерирует его) → `verifyDeviceCert` против нового ключа отвергнет все прежние атестации — fail-closed, но молчаливая потеря верификаций. (2) Нет device-revocation: `verifyDeviceCert` доверяет любому КОГДА-ЛИБО сертифицированному устройству — украденное-но-отвязанное подпишет валидно. Это endpoint-compromise (вне скоупа), унаследовано от того же `_bundleWellSigned` на приёме сообщений — не новая дыра.
- **DM-fp→Ed миграция** (§4.6). ✅ Сделано: DM-верификация унифицирована на account-Ed (как в группах) — shield (`updateShieldForRoom`/`onShieldClick`) И профиль (`user-profile.js`) читают статус из `isIdentityVerified(peer, pinnedEd)` и открывают модалку в identity-режиме через единый хелпер `openDmFingerprint`/`dmVerifiedState` (fix-the-class: оба входа мигрированы вместе). **Авто-миграция НЕ делается** (несостоятельна: сервер может подсунуть свой E', который тоже подписывает публичный X25519 → OOB-сверка X25519 не аутентифицирует Ed-корень) — старую X25519-верификацию сохраняем, не повышаем молча, `needsReverify` просит пере-сверить над Ed. Дормантно за `vortex_dm_ed_verify_enabled` (дефолт ВЫКЛ). Тест доказывает единство через ТОТ ЖЕ источник ed (`pinnedPeerAccountEd`, общий с групповым путём). Cross-impl Ed-отпечатка унаследован (`member-fingerprint`).
  - **Флип ВКЛ — это UX-событие, НЕ silent no-op** (в отличие от gate/mirror): пересчёт статуса из пустой Ed-записи покажет ВСЕ ранее X25519-сверенные DM как «пере-сверить» разом. Не флипать походя.
  - **Sync-регрессия:** старый `fingerprint_verified` был серверный (синк между устройствами даром); Ed-верификация локальна → кросс-девайс только если ВКЛючён и `vortex_verify_mirror_enabled`. Флаги компонуются, включать вместе.
- **hard-mode setting** (opt-in, §4.4). ✅ Сделано: флаг `vortex_verify_hard_mode` (дефолт ВЫКЛ) + тоггл в настройках приватности («Строгая проверка участников»). ВКЛ: единый гейт `verifyMemberForWrap` allow ТОЛЬКО `verified`/`self` — room-key уходит лишь OOB-верифицированным; changed/pubkey_mismatch блокируются как прежде. Каллеры (websocket/notifications) enforce через существующий `!gate.allow` (fix-the-class, без правок). API `isHardModeEnabled`/`setHardMode`.
  - **Fail-CLOSED на неверифицируемых путях (advisor — иначе фича декоративна):** сервер сам отдаёт `/member-keys`, значит может индуцировать 500/пустой ответ → в обычном гейте passthrough завернул бы на серверный `for_pubkey`, обойдя И changed-, И unverified-блок. Поэтому hard-mode блокирует и `no_chain`, и `not_member` (`*_hardblock`). Availability-цена (в hard-mode нельзя слать при реальном отказе member-keys) — ровно то, на что подписался пользователь. **Известное ограничение для §6/Фазы 1:** тот же fetch-fail bypass есть в БАЗОВОМ (не-hard) гейте — для общей популяции fail-open оправдан, но это прямой вход для equivocation-работы KT.
  - **Пререквизит-фикс:** identity-модалка теперь открывается и на линкованном устройстве — `myPubkey` fallback `loadEd25519Identity()?.pubHex || loadAccountLinkMaterial(uid)?.accountEdPub` (отпечаток над публичными ключами, приватный account-Ed не нужен). Иначе в hard-mode юзер на вторичном устройстве заблокирован без возможности открыть модалку → тупик. Тот же фикс закрывает G4-ограничение `openMemberIdentityFp`.
  - **Честная гарантия (не overclaim):** в модели общего room-key hard-mode гарантирует лишь, что **ВЫ** не завернёте ключ неверифицированному; другой участник без hard-mode ответит на тот же key_request и отдаст ключ → непроверенный всё равно прочитает. Текст тоггла сужен под это. Включать ВМЕСТЕ с mirror+dm-ed флагами (иначе сверка не переживает устройство/не унифицирована).
  - **Блокеры КОГЕРЕНТНОЙ активации (не дормантного коммита; дефолт ВЫКЛ → сегодня поведение не меняется):** (1) `verifyMemberForWrap` зовётся из key_request для ЛЮБОЙ комнаты, DM — тоже room → hard-mode молча применится к DM, где «другие участники» вакуумны и отказ ломает саму личку до сверки пира (возможно желаемая строгость, но не оттестировано/не оформлено — трассировать DM-key_request; при активации либо ограничить hard-mode не-DM, либо сделать текст условным). (2) При блоке отправитель молча молчит, а запрашивающий висит на `waiting_for_key` без сигнала — UX-пробел, закрыть до активации.

## 7. Краевые случаи (ТЗ §9 — обязательны)

- **Новый участник** → `unverified` по умолчанию; `room_sn` меняется — **норма, не тревога** (в отличие от смены ключа существующего).
- **Мультидевайс (v2 Sesame):** account Ed один на аккаунт → новое устройство **не сбрасывает** верификацию (верифицируем account Ed, а device-cert подписан тем же Ed — проверять цепочку, не device-ключ).
- **Ротация Kyber/X25519** при неизменном account Ed: не влияет (статус ведём по account Ed; sig проверяем против него).
- **Легит смена account Ed** (сброс аккаунта): статус честно → `changed`, пользователь переверифицирует. Правильно.
- **Большие группы:** пер-участник руками не масштабируется → `room_sn` (Фаза 2) как быстрый общий чек.

## 8. Критерии приёмки (ТЗ §10, уточнены §2-3)

1. В группе у каждого участника виден `verified/unverified/changed`.
2. Сверка отпечатка (Ed-пара, hex+emoji) + отметка «верифицирован» работают; статус (локальный) переживает перезагрузку.
3. Подмена `identity_key_ed`/`x25519` участника на сервере → у пинившего его статус `changed` + баннер, И **room-key НЕ заворачивается на подменённый ключ** (block-changed, §3-4.4). Тест: мок member-keys с чужим ключом → UI `⚠️` + wrap abort. *(NB: from-start-подмена, §2 — детектируема/отказуема, предотвращается лишь после OOB-verify/hard-mode.)*
4. Смена device/Kyber при неизменном account Ed **не** сбрасывает верификацию.
5. (Фаза 2) У всех с одинаковым составом совпадает `room_sn`; подмена ключа одного → его `room_sn` расходится.
6. Юнит-тесты: fp (детерминизм, симметрия sort), room_sn, детект смены. **Cross-impl Python↔JS расчёта fp/room_sn** (как ECIES/DR — зафиксированная сериализация §4.7).

## 9. Не-цели / вне скоупа

- Полный переход группы на MLS / Sender Keys.
- Серверная инфраструктура доверия (сервер остаётся недоверенным — вся суть в OOB-сверке клиентом).
- Активный-протокольный B2 (downgrade/stripping) — §2, вне скоупа проекта.
- server verification mirror, DM-fp миграция, hard-mode — отложены в отдельные батчи (§6), не Фаза 1.

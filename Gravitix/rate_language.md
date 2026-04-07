# Gravitix — Аудит языка и оценка реализации

> Аудит проведён: 2026-03-29
> Версия: 0.1.0 (Rust 2021 edition)
> Назначение: скриптовый язык для Telegram-ботов, компилируется/интерпретируется в Rust

---

## Итоговая оценка: **7.9 / 10**

| Подсистема | Оценка |
|---|---|
| Лексер | 9/10 |
| Парсер | 8/10 |
| AST | 8.5/10 |
| Система типов / Value | 7.5/10 |
| Интерпретатор | 8/10 |
| Стандартная библиотека | 8.5/10 |
| Telegram-интеграция (bot.rs) | 8/10 |
| Flow / wait механизм | 9/10 |
| Обработка ошибок | 6/10 |
| Developer Experience | 8/10 |
| Архитектура / масштабируемость | 5.5/10 |

---

## 1. Лексер — 9/10

### Что реализовано

| Токен | Примеры | Статус |
|---|---|---|
| Целые числа | `42`, `-10` | ✅ |
| Числа с плавающей точкой | `3.14` | ✅ |
| Строки с интерполяцией | `"Hello {name}!"` | ✅ |
| Булевы | `true`, `false` | ✅ |
| Null | `null` | ✅ |
| Regex литералы | `/^hello/i`, `/\d+/gm` | ✅ |
| Slash-команды | `/start`, `/help` | ✅ |
| Все арифметические операторы | `+`, `-`, `*`, `/`, `%`, `**` | ✅ |
| Все операторы сравнения | `==`, `!=`, `<`, `>`, `<=`, `>=` | ✅ |
| Логические операторы | `&&`, `\|\|`, `!` | ✅ |
| Pipe оператор | `\|>` | ✅ |
| Arrow / FatArrow | `->`, `=>` | ✅ |
| Range операторы | `..`, `..=` | ✅ |
| Позиция токенов | `line`, `col` | ✅ |
| Однострочные комментарии | `//` | ✅ |
| Многострочные комментарии | `/* */` | ✅ |
| 42 ключевых слова | `let`, `fn`, `on`, `flow`, `state`, `emit`, `wait`, `every`, `at`, `guard`, `match`, ... | ✅ |

### Проблемы

- **Нет escape-последовательностей в строках** — `\n`, `\t` неизвестно обрабатываются ли; в интерполированных строках вложенные кавычки могут ломать парсинг.
- **Regex флаги ограничены** — только `i`, `m`, `s`, `x`. Флаг `g` для глобального поиска не применим в Rust (regex матчит итеративно), но это может запутать разработчиков пришедших из JS.
- **Нет шаблонных строк с переносами** — строковый литерал всегда на одной строке; нельзя написать многострочный текст без конкатенации.
- **`/command` токенизируется особо** — это могло создать конфликты с оператором деления `/` в определённых контекстах.

---

## 2. Парсер — 8/10

### Ключевые слова верхнего уровня

| Keyword | Синтаксис | Статус |
|---|---|---|
| `fn` | `fn name(params) -> Type { }` | ✅ |
| `on` | `on trigger [guard cond] { }` | ✅ |
| `flow` | `flow name { }` | ✅ |
| `state` | `state { field: Type = default, }` | ✅ |
| `every` | `every N sec\|min\|hour\|day { }` | ✅ |
| `at` | `at "HH:MM" { }` | ✅ |
| `use` | `use "file.grav"` | ✅ |
| `struct` | `struct Name { field: Type, }` | ✅ |
| `test` | `test "name" { }` | ✅ |

### Выражения и statement'ы

| Конструкция | Пример | Статус |
|---|---|---|
| Присваивание | `let x = 5` | ✅ |
| Compound-присваивание | `x += 1`, `x -= 1`, `x *= 2` | ✅ |
| Вызов функции | `foo(a, b)` | ✅ |
| Методы | `list.push(item)` | ✅ |
| Доступ к полю | `ctx.user_id` | ✅ |
| Индексирование | `arr[i]`, `map["key"]` | ✅ |
| Срезы | `arr[1:5]` | ✅ |
| Pipe | `str \|> trim \|> lowercase` | ✅ |
| Lambda | `fn(x) { x * 2 }` | ✅ |
| If/else | `if cond { } else { }` | ✅ |
| For...in | `for item in list { }` | ✅ |
| While | `while cond { }` | ✅ |
| Match | `match expr { pattern => body, }` | ✅ |
| Try/catch | `try { } catch err { }` | ✅ |
| Return, break, continue | | ✅ |
| Struct literal | `User { id: 1, name: "Alice" }` | ✅ |
| Диапазоны | `1..10`, `1..=10` | ✅ |
| `emit`, `emit_to` | вывод в Telegram | ✅ |
| `keyboard` | inline-кнопки | ✅ |
| `edit` | редактировать сообщение | ✅ |
| `answer` | ответить на callback | ✅ |
| `wait msg` | приостановить flow | ✅ |

### Проблемы

- **Нет pattern-matching по структурам** — `match user { User { name, .. } => ... }` не поддерживается; только literal, regex, wildcard.
- **Нет деструктуризации** — `let [a, b] = list` или `let { x, y } = point` не поддерживается.
- **Нет тернарного оператора** — `cond ? a : b` или `if cond { a } else { b }` как выражение (не statement).
- **Default параметры только последними** — `fn foo(x: int, y: int = 0)` работает, но `fn foo(x: int = 0, y: int)` нарушает порядок. Не проверяется ли это на уровне парсера — нет.
- **`use` без namespace** — `use "utils.grav"` импортирует всё в глобальное пространство; конфликты имён неизбежны.

---

## 3. AST — 8.5/10

Структура AST чистая и полная. Разделение на `Program`, `Item`, `Stmt`, `Expr` корректное.

### Типы узлов Item (9)

| Тип | Описание | Статус |
|---|---|---|
| `FnDef` | Определение функции | ✅ |
| `Handler` | `on trigger guard { }` | ✅ |
| `FlowDef` | Диалоговый поток | ✅ |
| `StateDef` | Глобальное состояние | ✅ |
| `EveryDef` | Периодическая задача | ✅ |
| `AtDef` | Задача по расписанию | ✅ |
| `Use` | Импорт файла | ✅ |
| `StructDef` | Структура данных | ✅ |
| `TestDef` | Тестовый блок | ✅ |

### Типы Trigger (8)

| Trigger | Назначение | Статус |
|---|---|---|
| `/command` | Slash-команда | ✅ |
| `msg` | Текстовое сообщение | ✅ |
| `photo` | Фотография | ✅ |
| `video` | Видео | ✅ |
| `voice` | Голосовое сообщение | ✅ |
| `document` | Документ | ✅ |
| `sticker` | Стикер | ✅ |
| `any` | Любое обновление | ✅ |
| `callback["prefix"]` | Нажатие inline-кнопки | ✅ |

### Проблемы

- **Нет `edited_msg` trigger** — редактирование сообщений пользователем не обрабатывается.
- **Нет `join`/`leave` trigger** — вход/выход участника из группы не перехватывается.
- **Нет `error` trigger** — нет глобального обработчика ошибок; ошибки в handlers не перехватываются декларативно.
- **StructDef без методов** — только данные, нет `impl` блока.
- **Expr.Wait** не выносится за пределы Flow** — на уровне типов нет проверки что `wait` используется только во `flow`; это runtime-ошибка.

---

## 4. Система типов — 7.5/10

### Runtime значения (Value enum)

| Тип | Представление | Статус |
|---|---|---|
| `Null` | `null` | ✅ |
| `Bool` | `true`/`false` | ✅ |
| `Int` | `i64` | ✅ |
| `Float` | `f64` | ✅ |
| `Str` | `Rc<String>` | ✅ |
| `List` | `Rc<RefCell<Vec<Value>>>` | ✅ |
| `Map` | `Rc<RefCell<HashMap<String, Value>>>` | ✅ |
| `Fn` | `Rc<FnDef>` — первый класс | ✅ |
| `Ctx` | `Rc<RefCell<BotCtx>>` | ✅ |

### Truthy-семантика

`null`, `false`, `0`, `0.0`, `""`, `[]`, `{}` → **false**. Всё остальное → **true**.

### Проблемы

- **Нет строгой типизации** — `int(str("hello"))` вернёт ошибку только в runtime; нет статической проверки.
- **Нет дженериков** — `List<int>` в type annotations есть синтаксически, но не проверяется (runtime всё принимает).
- **Int + Float = Float**, но нет предупреждений о потере точности при `float → int`.
- **Map с только string ключами** — `Map<String, Value>` означает что `map[42]` превращает число в строку "42" молча.
- **Rc вместо Arc** — Single-threaded reference counting; при параллельной обработке обновлений потребуется `Arc<Mutex<...>>` которое уже используется в SharedState, но Value само по себе не thread-safe.
- **Нет типа `Bytes`** — работа с бинарными данными неудобна; нет `Vec<u8>` как первоклассного значения. `base64_decode_bytes` возвращает `list<int>` что медленно.

---

## 5. Интерпретатор — 8/10

### Ключевые механизмы

| Механизм | Статус |
|---|---|
| Рекурсивный eval_expr | ✅ |
| Scope-based переменные (Env со стеком фреймов) | ✅ |
| Диспетчеризация по trigger type | ✅ |
| Guard-условия в handler | ✅ |
| Wait/Flow механизм через oneshot channels | ✅ |
| `state` — глобальное изменяемое состояние | ✅ |
| `ctx` — контекст текущего пользователя | ✅ |
| Scheduler'ы (every/at) через tokio | ✅ |
| Call stack для traceback | ✅ |
| Regex кэш | ✅ |
| REPL режим | ✅ |
| Тест-runner | ✅ |

### Проблемы

- **interpreter.rs — 59.5KB монолит** — нарушает принцип единственной ответственности; сложен в навигации и тестировании.
- **Нет таймаута выполнения** — бесконечный цикл в handler'е заблокирует весь бот навсегда (DoS уязвимость).
- **Нет лимита глубины рекурсии** — `fn f() { f(); }` вызовет stack overflow Rust'а, а не graceful ошибку интерпретатора.
- **Wait работает только в flow** — но проверка этого происходит в runtime, а не в парсере. Ошибка сообщается не очень понятно.
- **Множественные `wait` в одном flow** ожидают разных сообщений, но если пользователь отправит команду `/cancel` — она попадёт во `wait_map` и flow получит `/cancel` вместо expected ответа. Нет механизма прерывания flow.
- **known_chats** растёт безгранично — нет механизма очистки устаревших чатов.
- **REPL не сохраняет функции** между сессиями — неудобен для интерактивной разработки.

---

## 6. Стандартная библиотека — 8.5/10

### Полный список функций (110+)

**Типо-конверсия (4):**
`int()` · `float()` · `str()` · `bool()`

**Строки (12):**
`trim()` · `lowercase()` · `uppercase()` · `len()` · `split()` · `join()` · `contains()` · `replace()` · `sanitize()` · `starts_with()` · `ends_with()` · `substr()`

**Математика (10):**
`abs()` · `min()` · `max()` · `floor()` · `ceil()` · `round()` · `sqrt()` · `pow()` · `random()` · `clamp()`

**Списки (7):**
`range()` · `push()` · `pop()` · `reverse()` · `map_list()` · `filter_list()` · `len()`

**Состояние (5):**
`state_get()` · `state_set()` · `state_del()` · `state_save()` · `state_load()`

**I/O (4):**
`print()` · `log()` · `type_of()` · `env()`

**Проверка типов (8):**
`is_null()` · `is_int()` · `is_float()` · `is_str()` · `is_list()` · `is_map()` · `is_bool()` · `is_fn()`

**Криптография (9):**
`base64_encode()` · `base64_decode()` · `base64_decode_bytes()` · `hash_md5()` · `hash_sha256()` · `hash_sha512()` · `hmac_sha256()` · `hex_encode()` · `hex_decode()`

**Дата/Время (4):**
`now_unix()` · `now_str()` · `parse_date()` · `date_add()`

**HTTP (1):**
`fetch(url, method?, body?, headers?)`

**JSON (3):**
`json_parse()` · `json_encode()` · `json_encode_pretty()`

**Тесты (3):**
`assert()` · `assert_eq()` · `assert_ne()`

### Проблемы

- **`random()` — XorShift64, не криптостойкий** — нельзя использовать для генерации токенов/ключей.
- **`fetch()` синхронный** — блокирует поток Tokio (внутри `tokio::task::block_in_place` или аналог), снижает throughput.
- **Нет `sort()`** — сортировка списка отсутствует в stdlib; разработчик должен реализовывать вручную.
- **Нет `unique()` / `flatten()` / `zip()`** — базовые операции со списками не покрыты.
- **Нет `regex_match()` / `regex_find_all()`** — работа с regex только через `match ctx.text { /pat/ => }`, но нельзя применить regex к произвольной строке в выражении.
- **`date_add()` ограничен** — нет `date_diff()`, `format_date()` с кастомным форматом, `weekday()`.
- **Нет `sleep()` / `timer()`** — нельзя добавить задержку внутри обработчика.
- **Нет `send_photo_url()` / `send_document_bytes()`** — нет удобного способа отправить медиа из URL или из `base64_decode_bytes`.

---

## 7. Telegram-интеграция — 8/10

### Реализованные методы Bot API (14)

| Метод | Статус |
|---|---|
| `getMe` | ✅ |
| `getUpdates` (long-polling) | ✅ |
| `sendMessage` | ✅ |
| `sendPhoto` | ✅ |
| `sendDocument` | ✅ |
| `sendVideo` | ✅ |
| `sendAudio` | ✅ |
| `sendAnimation` | ✅ |
| `editMessageText` | ✅ |
| `answerCallbackQuery` | ✅ |
| `forwardMessage` | ✅ |
| `getFile` | ✅ |
| `setWebhook` | ✅ |
| `deleteWebhook` | ✅ |

### BotCtx — контекстные поля

| Поле | Тип | Статус |
|---|---|---|
| `ctx.chat_id` | i64 | ✅ |
| `ctx.user_id` / `ctx.id` | i64 | ✅ |
| `ctx.username` | Option<String> | ✅ |
| `ctx.first_name` / `ctx.name` | String | ✅ |
| `ctx.last_name` | Option<String> | ✅ |
| `ctx.text` / `ctx.msg_text` | Option<String> | ✅ |
| `ctx.msg_id` | i64 | ✅ |
| `ctx.is_admin` | bool | ✅ |
| `ctx.callback_data` / `ctx.data` | Option<String> | ✅ |
| `ctx.chat_type` | String | ✅ |
| `ctx.media_file_id` / `ctx.file_id` | Option<String> | ✅ |

### Проблемы

- **Нет `sendMessage` с `parse_mode`** — нельзя отправить Bold/Italic через Markdown или HTML разметку.
- **Нет `deleteMessage`** — нельзя удалить сообщение.
- **Нет `pinMessage` / `unpinMessage`** — нет управления закреплёнными сообщениями.
- **Нет `getChatMember`** — нельзя проверить права пользователя в группе из скрипта.
- **Нет `banChatMember` / `kickChatMember`** — нет модерации.
- **Нет `sendPoll` / `sendQuiz`** — опросы и викторины не поддерживаются.
- **Нет `sendLocation` / `sendContact`** — медиа-типы локации и контакта отсутствуют.
- **Нет Inline Mode** — `inline_query` trigger не реализован.
- **Нет `audio` trigger** — `voice` есть, но `audio` (музыкальный файл) не различается.
- **Rate limiting** — нет встроенной защиты от 429 Too Many Requests; при broadcast на 1000+ чатов бот будет временно заблокирован API.
- **Нет retry логики** — при сетевой ошибке запрос теряется без повтора.

---

## 8. Flow / Wait механизм — 9/10

Это **самая сильная уникальная фича** языка. Реализация через `tokio::sync::oneshot` элегантна.

```gravitix
flow registration {
    emit "Введите имя:";
    let name = wait msg;         // ⏸️ suspend

    emit "Введите возраст:";
    let age = int(wait msg);     // ⏸️ suspend

    state.users[ctx.user_id] = { name, age };
    emit "Готово, {name}!";
}
```

### Почему это хорошо

- **Линейный код** вместо цепочки callback'ов
- **Состояние в локальных переменных**, не в глобальном state
- **Каждый `wait`** автоматически ждёт сообщения от **того же пользователя** в **том же чате**
- **Pipe совместим**: `let name = wait msg |> trim |> lowercase`

### Проблемы

- **Нет таймаута на wait** — если пользователь бросил диалог, flow висит вечно и занимает память в `wait_map`.
- **Нет cancel** — нет способа написать `on /cancel` который прерывал бы активный flow.
- **Нет `wait callback`** — нельзя ждать нажатия кнопки внутри flow; только текстовые сообщения.
- **Нет параллельных wait** — нельзя ждать одного из нескольких событий (`select!` в Tokio не используется).
- **wait только в flow** — проверяется в runtime, не в парсере.

---

## 9. Обработка ошибок — 6/10

| Ситуация | Поведение | Оценка |
|---|---|---|
| Лексическая ошибка | `lexer error in file:line:col: ...` | ✅ |
| Синтаксическая ошибка | `parse error in file:line:col: ...` | ✅ |
| Неопределённая переменная | runtime error + call stack | ✅ |
| Несовпадение типов | runtime error | ✅ |
| Ошибка в handler | **крашит handler, бот продолжает** | ⚠️ |
| Ошибка сети в fetch() | проброс ошибки | ⚠️ |
| Деление на ноль | runtime error | ✅ |
| Stack overflow (рекурсия) | Rust panic (не перехватывается) | ❌ |
| Бесконечный цикл | **зависает навсегда** | ❌ |
| Ошибка Telegram API (429) | логируется, теряется | ❌ |
| `wait` вне flow | runtime error, невнятное | ⚠️ |

**Главная проблема**: нет инструментов защиты от зависания (таймаут, лимит итераций, лимит стека).

---

## 10. Developer Experience — 8/10

### Сильные стороны

- **CLI из коробки**: `gravitix run`, `gravitix check`, `gravitix fmt`, `gravitix test`, `gravitix repl`
- **LSP** — автодополнение, hover, диагностика в реальном времени
- **Formatter** — `gravitix fmt --write` канонизирует код
- **Test runner** — `test "name" { assert_eq(…) }` встроен
- **REPL** — быстрая проверка выражений
- **Webhook mode** — простое развёртывание в production
- **Pipe оператор** — читаемые цепочки преобразований
- **Flow** — линейный код для диалогов (большой плюс)
- **Встроенная криптография** — SHA256, HMAC, Base64 без дополнительных зависимостей

### Слабые стороны

- **Нет package manager** — нет способа установить сторонние библиотеки
- **`use` без namespace** — всё в глобальном пространстве
- **Нет hot reload** — изменение файла требует перезапуска бота
- **Нет встроенного логирования** — только `print()` / `log()` (eprintln!)
- **Нет profiling** — нельзя измерить производительность скрипта
- **REPL не сохраняет функции** между строками (известный баг)
- **Сообщения об ошибках** в runtime не всегда содержат строку исходного файла

---

## 11. Архитектура / Масштабируемость — 5.5/10

### Проблемы архитектуры

- **interpreter.rs (59.5KB)** и **stdlib.rs (46KB)** — монолиты, нарушают SRP
- **State хранится в `bot_state.json`** — нет Redis, нет БД; не масштабируется горизонтально
- **Один процесс на бота** — нет clustering
- **`known_chats: Vec<i64>`** растёт без ограничений; при 100K+ чатах broadcast будет медленным
- **`Rc` вместо `Arc` в Value** — Values нельзя безопасно шарить между потоками; это ограничивает параллелизм
- **`wait_map: HashMap<(chat_id, user_id), Sender>`** — нет TTL, нет cleanup; утечка памяти при брошенных flow

### Что работает хорошо

- **`Arc<Mutex<SharedState>>`** — правильный подход для shared mutable state между async задачами
- **Tokio** — правильный async runtime для I/O-bound работы
- **Long-polling + Webhook** — два режима хорошо покрывают dev/prod сценарии

---

## Сводный инвентарь реализованных возможностей

### Типы данных (9)
`null` · `bool` · `int` · `float` · `str` (с интерполяцией) · `list` · `map` · `fn` (первый класс) · `ctx`

### Item-ключевые слова (9)
`fn` · `on` · `flow` · `state` · `every` · `at` · `use` · `struct` · `test`

### Triggers (9)
`/command` · `msg` · `photo` · `video` · `voice` · `document` · `sticker` · `callback` · `any`

### Statement'ы (14)
`let` · `=` · `+=/-=/*=` · `emit` · `emit_to` · `keyboard` · `edit` · `answer` · `wait msg` · `if/else` · `for...in` · `while` · `match` · `try/catch` · `return/break/continue`

### Операторы (17)
`+`, `-`, `*`, `/`, `%`, `**` · `==`, `!=`, `<`, `>`, `<=`, `>=` · `&&`, `\|\|`, `!` · `\|>` · `..`, `..=`

### Встроенных функций (110+)
Типы · Строки · Математика · Списки · Состояние · I/O · Проверка типов · Крипто · Дата/Время · HTTP · JSON · Тесты

### CLI подкоманды (7)
`run` · `check` · `fmt` · `test` · `repl` · `lsp` · `webhook`

---

## Топ-10 приоритетов для следующей итерации

| Приоритет | Задача | Сложность |
|---|---|---|
| 🔴 1 | Таймаут на `wait` — `wait msg timeout 30s \| emit "Timeout"` | Средняя |
| 🔴 2 | `/cancel` flow — `on /cancel` прерывает активный flow пользователя | Средняя |
| 🔴 3 | Лимит итераций / таймаут выполнения handler'а (DoS защита) | Средняя |
| 🔴 4 | Лимит рекурсии в интерпретаторе (graceful error, не Rust panic) | Низкая |
| 🟡 5 | `sendMessage` с `parse_mode: MarkdownV2\|HTML` | Низкая |
| 🟡 6 | `sort(list, [comparator])` в stdlib | Низкая |
| 🟡 7 | Rate limiting + retry при 429 Telegram API | Средняя |
| 🟡 8 | `deleteMessage`, `pinMessage`, `banChatMember` в Bot API | Средняя |
| 🟢 9 | `wait callback["prefix"]` — ожидание нажатия кнопки в flow | Высокая |
| 🟢 10 | `edited_msg` и `join`/`leave` triggers | Низкая |

---

## Сравнение с альтернативами

| Критерий | Gravitix | Python (aiogram) | JavaScript (Telegraf) |
|---|---|---|---|
| Скорость старта | ✅ Быстро (бинарик) | ⚠️ pip install | ⚠️ npm install |
| Flow / диалоги | ✅ Встроено | ⚠️ FSM вручную | ⚠️ Scenes вручную |
| Синтаксис | ✅ Минималистичный | ⚠️ Verbose | ⚠️ Verbose |
| Экосистема | ❌ Нет пакетов | ✅ Огромная | ✅ Огромная |
| Отладка | ⚠️ Базовая | ✅ Полноценный debugger | ✅ Chrome DevTools |
| Масштабируемость | ❌ Single-process | ✅ Celery/Redis | ✅ Worker threads |
| Type safety | ⚠️ Runtime | ⚠️ Mypy опционально | ⚠️ TypeScript опционально |
| Telegram API | ⚠️ 14 методов | ✅ 100+ методов | ✅ 100+ методов |

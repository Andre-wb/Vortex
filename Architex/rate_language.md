# Architex DSL — Аудит языка и оценка реализации

> Аудит проведён: 2026-03-29
> Версия кодовой базы: после P0/P1/P2/P3 + Б1–Б10

---

## Итоговая оценка: **7.4 / 10**

| Подсистема | Оценка |
|---|---|
| Лексер | 8/10 |
| Парсер | 7/10 |
| AST | 9/10 |
| Реактивность | 8.5/10 |
| Рендерер — компоненты | 7/10 |
| Рендерер — модификаторы | 8/10 |
| Рендерер — события | 7/10 |
| Runtime | 8/10 |
| Обработка ошибок | 5/10 |
| Developer Experience | 6/10 |

---

## 1. Лексер — 8/10

### Что реализовано

| Токен | Синтаксис | Статус |
|---|---|---|
| `AtKw` | `@screen`, `@if`, `@watch`, ... | ✅ |
| `Reactive` | `~var`, `~obj.field.sub` | ✅ |
| `Compute` | `:=` | ✅ |
| `DColon` | `::` (модификаторы) | ✅ |
| `Arrow` | `=>` (обработчики) | ✅ |
| `PlusEq`, `MinusEq` | `+=`, `-=` | ✅ |
| `String` | `"text"`, `'text'` | ✅ |
| `Number` | `42`, `3.14` | ✅ |
| `Color` | `#fff`, `#ffffff`, `#rrggbbaa` | ✅ |
| `Ident` | идентификаторы, `bot.data` | ✅ |
| `LBrace`, `RBrace` | `{` `}` (объекты) | ✅ |
| `LBrack`, `RBrack` | `[` `]` (массивы, индекс) | ✅ |
| `LParen`, `RParen` | `(` `)` (аргументы) | ✅ |
| Комментарии `//` | отбрасываются при сканировании | ✅ |
| Пустые строки | отбрасываются | ✅ |

### Проблемы

- **Нет многострочных строк** — строковый литерал всегда на одной строке; нельзя написать длинный текст со `\n` без интерполяции.
- **Нет escape-последовательностей** в строках (`\t`, `\n`, `\\`) — неизвестно, обрабатываются ли они или выдаются буквально.
- **Нет отрицательных числовых литералов** — `-10` не токенизируется как одно число; это может приводить к неожиданному поведению в аргументах модификаторов типа `pad(-4)`.
- **Нет операторов сравнения** (`==`, `!=`, `>`, `<`) — условия в `@if` могут принимать только `~reactiveVar` как truthy/falsy. Нельзя написать `@if ~count > 5`.

---

## 2. Парсер — 7/10

### @-ключевые слова

| Ключевое слово | Назначение | Статус |
|---|---|---|
| `@screen Name(params)` | Определить экран с параметрами | ✅ |
| `@if ~cond` | Условное ветвление | ✅ |
| `@elseif ~cond` | Альтернативная ветвь | ✅ |
| `@else` | Ветвь по умолчанию | ✅ |
| `@watch ~var` | Реакция на изменение переменной | ✅ |
| `@onMount` | Хук монтирования экрана | ✅ |
| `@onUnmount` | Хук размонтирования экрана | ✅ |

### Структура языка

```
@screen HomeScreen
  ~count = 0
  ~items = ["a", "b", "c"]
  ~total := ~count * 2

  @if ~isLoaded
    text "Loaded: {~total}"
  @else
    text "Loading..."

  list item from ~items
    text ~item

  button "Add" => ~count += 1

  @watch ~count
    => ~total = ~count * 2

  @onMount
    => fetch("/api/data") ~items

  @onUnmount
    => ~count = 0
```

### Проблемы

- **Нет операторов сравнения в условиях** — `@if ~count > 0` не парсится; только truthy/falsy проверка.
- **Нет вложенных @if** внутри блока `list` (зависит от реализации reconcile — нужно проверять).
- **Нет `@for` / `@each` как альтернативы `list`** — синтаксис `list item from ~arr` нестандартен; разработчики ожидают что-то ближе к `@for item in ~arr`.
- **Нет `@component` / `@def`** — нельзя определить переиспользуемый компонент в рамках одного файла; всё определяется в `@screen`.
- **Нет импортов** — язык не поддерживает разделение на файлы.
- **Б5 закрыт** — неизвестные `@keyword` теперь не поглощают дочерний блок, но всё равно молча игнорируются без сообщения пользователю в консоли.
- **Ошибки не всплывают на уровень UI** — `ParseError[]` логируются только через `console.error`; приложение продолжает работу с пустым/неполным AST.

---

## 3. AST — 9/10

Структура AST чистая, типобезопасная и полная. Все узлы имеют `span` с номером строки для диагностики.

### Типы узлов

| Тип | Описание | Статус |
|---|---|---|
| `ScreenNode` | Экран с параметрами и телом | ✅ |
| `VarDeclNode` | `~var = value` | ✅ |
| `ComputedNode` | `~var := expr` | ✅ |
| `ComponentNode` | UI-компонент | ✅ |
| `ListNode` | Итерация по массиву | ✅ |
| `HandlerNode` | Обработчик события | ✅ |
| `IfNode` + `IfBranch` | Условные ветви | ✅ |
| `WatchNode` | Подписка на переменную | ✅ |
| `LifecycleNode` | `@onMount` / `@onUnmount` | ✅ |

### Типы значений (ValueNode)

| Kind | Пример | Статус |
|---|---|---|
| `string` | `"hello"` | ✅ |
| `number` | `42`, `3.14` | ✅ |
| `color` | `#ff5733` | ✅ |
| `reactive` | `~count`, `~user.name` | ✅ |
| `ident` | `true`, `left`, `bot.data` | ✅ |
| `array` | `["a", "b", ~c]` | ✅ |
| `object` | `{ key: val, "x": ~v }` | ✅ |
| `index` | `~arr[~i]`, `~map["key"]` | ✅ |
| `interpolated` | `"Hello {~name}!"` | ✅ |

### Типы действий (Action)

| Kind | Синтаксис | Статус |
|---|---|---|
| `assign =` | `~var = val` | ✅ |
| `assign +=` | `~var += val` | ✅ |
| `assign -=` | `~var -= val` | ✅ |
| `call` | `fn(args...)` | ✅ |
| `call` с `into` | `fetch(url) ~var` | ✅ |

### Проблемы

- **Нет boolean-операторов** в ValueNode — нет `not`, `and`, `or`. Нельзя написать `~a && ~b`.
- **Нет унарного минуса** — не как токен, не как ValueNode.
- **`ident` слишком широкий** — `true`, `false`, `null` разрешаются как строки `"true"`, `"false"`, `"null"` через `ctx[node.v]`. Нет отдельного `BooleanNode` или `NullNode`.

---

## 4. Реактивность — 8.5/10

### StateAPI — полный интерфейс

| Метод | Описание | Статус |
|---|---|---|
| `get(key)` | Получить значение | ✅ |
| `set(key, val)` | Установить значение | ✅ |
| `update(key, fn)` | Обновить через функцию | ✅ |
| `subscribe(key, fn)` | Подписаться → возвращает unsub | ✅ |
| `watch(key, fn)` | Alias для subscribe | ✅ |
| `computed(key, expr, deps?)` | Вычисляемое значение | ✅ |
| `batch(fn)` | Пакетные обновления | ✅ |
| `snapshot()` | Снимок всего состояния | ✅ |
| `reset(data)` | Перезагрузить состояние | ✅ |

### Ключевые механизмы

| Механизм | Статус |
|---|---|
| Auto-tracking зависимостей в `computed` | ✅ |
| Каскадное обновление dependent computed | ✅ |
| Обнаружение циклических зависимостей | ✅ (с `console.warn`) |
| Batching нотификаций | ✅ |
| `subscribe` возвращает функцию отписки | ✅ |
| Глубокие пути `~obj.field` | ✅ (в renderer) |

### Проблемы

- **`computed` не реагирует на изменения вложенных полей** — если `~user.name` изменилось через `state.set('user', {...})`, computed подписаны на `user`, но если `set('user.name', ...)` вызвать, ключ `user.name` не нотифицирует подписчиков на `user`. Подписки работают только на root keys.
- **Нет глубокой реактивности** — `state.set('obj.field', val)` не поддерживается; нужно всегда заменять весь объект.
- **`@watch` поддерживает только `assign` действия** — вызов `navigate`, `fetch`, `send` внутри `@watch` не работает (они игнорируются в `execActions`). Это скрытое ограничение, которое сложно обнаружить.
- **Auto-tracking работает только при инициализации** — если зависимости computed динамически меняются (условные ветки), они не будут добавлены в deps.

---

## 5. Рендерер — компоненты — 7/10

### Полный список компонентов (29)

| Компонент | HTML | Особенности | Статус |
|---|---|---|---|
| `text` | `<p>` | live binding, interpolation | ✅ |
| `label` | `<span>` | | ✅ |
| `header` | `<h2>` | | ✅ |
| `h1` | `<h1>` | | ✅ |
| `h2` | `<h2>` | | ✅ |
| `h3` | `<h3>` | | ✅ |
| `button` / `btn` | `<button>` | | ✅ |
| `input` | `<input>` | placeholder из args | ✅ |
| `textarea` | `<textarea>` | двусторонняя привязка | ✅ |
| `select` | `<select>` | двусторонняя привязка | ✅ |
| `option` | `<option>` | label + value args | ✅ |
| `checkbox` | `<input type="checkbox">` | boolean binding | ✅ |
| `toggle` | `<input type="checkbox">` | alias checkbox | ✅ |
| `image` / `img` | `<img>` | src из args | ✅ |
| `box` / `div` | `<div>` | | ✅ |
| `row` | `<div>` | `display: flex` | ✅ |
| `col` | `<div>` | `flex-direction: column` | ✅ |
| `card` | `<div>` | padding, shadow, radius | ✅ |
| `scroll` | `<div>` | `overflow-y: auto` | ✅ |
| `divider` | `<hr>` | | ✅ |
| `spacer` | `<div>` | `flex: 1` | ✅ |
| `badge` | `<span>` | | ✅ |
| `icon` | `<span>` | textContent из args | ✅ |
| `link` / `a` | `<a>` | href + label из args | ✅ |
| `modal` | overlay + dialog | click-outside, z-index | ✅ |
| `tabs` | header + panels | реактивная активная вкладка | ✅ |
| `tab` | panel внутри tabs | label + key args | ✅ |

### Проблемы

- **Нет `form`** — нет компонента для группировки input с submit.
- **Нет `table` / `tr` / `td`** — табличные данные не поддерживаются.
- **Нет `video` / `audio`** — медиа компоненты отсутствуют.
- **Нет `progress` / `slider`** — нет компонентов для числового ввода диапазона.
- **`modal` не поддерживает `visible`/`hidden` binding** — видимость модала управляется только включением/исключением из DOM через `@if ~isOpen`, а не реактивным атрибутом самого компонента.
- **`tabs` не поддерживает динамические вкладки** — список `tab`-дочерних элементов определяется статически в момент рендера; нельзя добавить вкладку из `list`.
- **`option` не реагирует на реактивные аргументы** — `resolveValue` вызывается один раз; если label/value реактивны, они не обновятся.
- **`select` не строит options при отсутствии `stateKey`** — если первый аргумент не реактивный, children не рендерятся (ранний `return` в ветке `if (stateKey)` не включает fallback рендер дочерних).

---

## 6. Рендерер — модификаторы — 8/10

### Полный список (44 модификатора)

**Типографика (6):**
`bold`, `italic`, `underline`, `strike`, `weight(n)`, `size(px|%|rem)`

**Выравнивание текста (3):**
`center`, `left`, `right`

**Flex-layout (3):**
`grow`, `shrink`, `wrap`

**Оформление (5):**
`color(hex)`, `bg(hex)`, `border(color)`, `radius(px)`, `opacity(0..1)`

**Размеры (8):**
`w(px)`, `h(px)`, `pad(px)`, `gap(px)`, `minw(px)`, `maxw(px)`, `minh(px)`, `maxh(px)`

**HTML-атрибуты (6):**
`placeholder(text)`, `href(url)`, `src(url)`, `alt(text)`, `title(text)`, `tabindex(n)`

**ARIA/Accessibility (3):**
`role(role)`, `label(text)`, `aria(attr, val)`

**Анимация/Переходы (4):**
`shadow`, `transition(ms, prop?)`, `animate(name)`, `keyframes(name)`

**Реактивное управление (3):**
`visible(~bool)`, `hidden(~bool)`, `disabled(~bool)`

**CSS-классы (1):**
`class(name)`

### Проблемы

- **Нет `margin`** — можно управлять только `pad` (padding). Внешние отступы между элементами не настраиваются без CSS классов.
- **Нет `overflow`** — только `scroll` компонент; нельзя задать `overflow: hidden` на произвольный элемент.
- **Нет `position` / `top` / `left`** — абсолютное позиционирование недоступно через модификаторы.
- **Нет `z-index`** — управление наслоением только через прямые CSS классы.
- **Нет `cursor`** — курсор мыши нельзя задать без `class(css)`.
- **`visible` / `hidden` / `disabled` не принимают статические значения** — работают только с `reactive` ValueNode; `visible(true)` будет молча проигнорирован.
- **`color` и `bg` принимают любую строку**, но нет валидации — опечатки в именах цветов (`red2`) будут просто применены как невалидное CSS значение без предупреждения.
- **`border` захардкожен на `1px solid`** — нельзя задать `border: 2px dashed #ccc`.
- **Адаптивные единицы** — `toCSSLen` корректно добавляет `px` к числам без единиц, но не поддерживает `vw`, `vh`, `em`, `ch`.

---

## 7. Рендерер — события — 7/10

### Встроенные функции в обработчиках

| Функция | Описание | Статус |
|---|---|---|
| `navigate(screen, {params})` | Переход на экран | ✅ |
| `back()` | Назад по истории | ✅ |
| `send(key: val, ...)` | Отправка данных наружу | ✅ |
| `fetch(url) ~var` | Загрузка данных | ✅ |
| Custom `fn(args)` | Делегирование в `rt[fn]` | ✅ |

### Двусторонняя привязка

| Компонент | Тип привязки | Статус |
|---|---|---|
| `input` (text, email, password, number, ...) | value ↔ `~var` | ✅ |
| `textarea` | value ↔ `~var` | ✅ |
| `select` | value ↔ `~var` | ✅ |
| `checkbox` / `toggle` | checked ↔ `~bool` | ✅ |
| `input type="radio"` | нет | ❌ |
| `input type="range"` | нет | ❌ |

### Проблемы

- **Нет нескольких действий на одно событие** — обработчик `=>` поддерживает ровно одно действие. Нельзя написать `onClick(~a = 1, ~b = 2)` или цепочку.
- **Нет `onBlur` / `onFocus` / `onHover`** — поддерживается только `click` для обычных элементов и `input` для текстовых полей. Нельзя реагировать на потерю фокуса.
- **Нет `onSubmit` для форм** — нет формы, нет сабмита.
- **`fetch` не показывает состояние загрузки** — нет встроенного `~loading` или `~error` после `fetch(...)`. Разработчик должен управлять этим вручную через `@watch`.
- **Custom функции (`rt[fn]`) возвращаемое значение игнорируется** — нет способа сохранить результат кастомного вызова.
- **`back()` не проверяет `canGoBack`** — если история пуста, функция молча возвращается без UI-фидбэка.

---

## 8. Runtime — 8/10

### Публичный API

```typescript
class ArchiRuntime {
  constructor(src: string, opts: ArchiOptions)
  start(screenName?: string): this

  navigate(screenName: string, params?: Record<string, unknown>): void
  back(): void
  canGoBack: boolean

  get(key: string): unknown
  set(key: string, val: unknown): void
  subscribe(key: string, fn: (v) => void): Unsubscribe

  screens: string[]
  currentScreen: string | null
}
```

### ArchiOptions

```typescript
interface ArchiOptions {
  container: HTMLElement;
  send?:  (payload: Record<string, unknown>) => void;
  fetch?: (url: string, state: StateAPI) => Promise<unknown>;
  [key: string]: unknown;  // custom runtime hooks
}
```

### Lifecycle

| Хук | Когда | Поддерживаемые действия | Статус |
|---|---|---|---|
| `@onMount` | После рендера экрана | assign, call, fetch, navigate, send | ✅ |
| `@onUnmount` | Перед очисткой экрана | assign, call, fetch, navigate, send | ✅ |

### Проблемы

- **Нет `destroy()`** — нет метода для полной остановки runtime (отписки, очистки таймеров).
- **Нет горячей перезагрузки** — нельзя перезапустить с новым источником без пересоздания объекта.
- **Params пишутся в state** — при `navigate(screen, {id: 5})` ключ `id` попадает в глобальное состояние; может конфликтовать с переменными других экранов.
- **`_runActions` дублирует логику `handlers.ts`** — два места обрабатывают CallAction/AssignAction с небольшими расхождениями (например, обработка `send` в handlers использует KeyVal, а в `_runActions` тоже, но код скопирован).
- **Нет multi-screen state isolation** — все экраны делят одно состояние; нет scope per screen.
- **`buildTree` ошибки только логируются**, приложение продолжает работу с пустым/неполным AST без уведомления хост-приложения.

---

## 9. Обработка ошибок — 5/10

| Ситуация | Поведение | Оценка |
|---|---|---|
| Синтаксическая ошибка парсера | `console.error` + работа дальше | ⚠️ |
| Неизвестный `@keyword` | молча игнорируется | ❌ |
| Циклическая зависимость computed | `console.warn` + пропуск | ⚠️ |
| `navigate` на несуществующий экран | `console.warn` + ничего | ⚠️ |
| `fetch` ошибка сети | `console.error` + ничего | ⚠️ |
| Невалидный модификатор | молча игнорируется | ❌ |
| Реактивная переменная не объявлена | `undefined` без предупреждения | ❌ |
| `@if` без условия | ParseError + пропуск | ✅ |
| `back()` при пустой истории | молча возвращается | ⚠️ |

**Главная проблема**: ошибки не передаются в хост-приложение. `ArchiOptions` не содержит `onError` callback. Разработчик узнаёт об ошибках только из console, а не из программного API.

---

## 10. Developer Experience — 6/10

### Сильные стороны

- **Лаконичный синтаксис** — UI описывается компактно, без шаблонного кода
- **Декларативная реактивность** — `~var := expr` с auto-tracking работает интуитивно
- **String interpolation** — `"Hello {~name}!"` привычно для большинства разработчиков
- **Единая система модификаторов** — `::` вместо смеси props и style
- **Встроенная навигация** — `navigate()` и `back()` из коробки

### Слабые стороны

- **Нет Type-checking DSL** — ошибки в именах компонентов или модификаторов обнаруживаются только в runtime
- **Нет IDE поддержки** — нет LSP, нет подсветки синтаксиса, нет autocomplete
- **Нет примеров ошибок** — когда что-то идёт не так, сообщения вида `[Architex] Parse error at line N: ...` недостаточно диагностичны
- **Нет `@import`** — всё в одном файле, невозможно масштабировать
- **Нет переиспользуемых компонентов** — `@component` / `@def` отсутствуют; повторение кода неизбежно
- **Нет условий с выражениями** — `@if ~count > 0` не работает, только truthy check

---

## Сводный инвентарь реализованных возможностей

### @keywords (7)
`@screen` · `@if` · `@elseif` · `@else` · `@watch` · `@onMount` · `@onUnmount`

### Операторы (5)
`= ` · `:=` · `+=` · `-=` · `::`

### Value Types (9)
`string` · `number` · `color` · `reactive` · `ident` · `array` · `object` · `index` · `interpolated`

### Компоненты (29)
`text` · `label` · `header` · `h1` · `h2` · `h3` · `button` · `btn` · `input` · `textarea` · `select` · `option` · `checkbox` · `toggle` · `image` · `img` · `box` · `div` · `row` · `col` · `card` · `scroll` · `divider` · `spacer` · `badge` · `icon` · `link` · `modal` · `tabs` · `tab`

### Модификаторы (44)
`bold` · `italic` · `underline` · `strike` · `weight` · `size` · `center` · `left` · `right` · `grow` · `shrink` · `wrap` · `color` · `bg` · `border` · `radius` · `opacity` · `w` · `h` · `pad` · `gap` · `minw` · `maxw` · `minh` · `maxh` · `placeholder` · `href` · `src` · `alt` · `title` · `tabindex` · `role` · `label` · `aria` · `shadow` · `transition` · `animate` · `keyframes` · `class` · `visible` · `hidden` · `disabled`

### Встроенные функции (4)
`navigate(screen, params?)` · `back()` · `send(key: val, ...)` · `fetch(url) ~var`

### Reactive API (9)
`get` · `set` · `update` · `subscribe` · `watch` · `computed` · `batch` · `snapshot` · `reset`

---

## Топ-10 приоритетов для следующей итерации

| Приоритет | Задача | Сложность |
|---|---|---|
| 🔴 1 | Операторы сравнения в `@if` (`>`, `<`, `==`, `!=`, `&&`, `||`) | Средняя |
| 🔴 2 | Несколько действий в одном обработчике | Средняя |
| 🔴 3 | `@component Name(args)` — переиспользуемые компоненты | Высокая |
| 🟡 4 | `onError` callback в `ArchiOptions` | Низкая |
| 🟡 5 | `margin` модификатор | Низкая |
| 🟡 6 | `onBlur` / `onFocus` события | Низкая |
| 🟡 7 | `fetch` loading/error state из коробки | Средняя |
| 🟢 8 | `@import "file.arx"` | Высокая |
| 🟢 9 | IDE LSP / syntax highlighting | Высокая |
| 🟢 10 | `input type="range"` / `type="radio"` двусторонняя привязка | Низкая |

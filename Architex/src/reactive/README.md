# `Architex/src/reactive/` — Fine-grained Reactivity

Signal + computed + effect primitives. The foundation every `.arx` program's state lives in.

## API

```ts
function signal<T>(initial: T): [() => T, (next: T) => void];
function computed<T>(fn: () => T): () => T;
function effect(fn: () => void): () => void;   // returns dispose
function batch<T>(fn: () => T): T;              // group updates into one notify round
function untrack<T>(fn: () => T): T;            // read without subscribing
```

## Model

- Every read of a signal inside an `effect` / `computed` **subscribes** that reactive context to the signal.
- Every write to a signal **schedules** every subscribed context to run.
- Dependencies are re-computed each run — stale subscriptions are pruned automatically.
- `batch` collapses multiple writes into a single notify pass — no subscriber runs more than once per batch.
- `untrack` is for side-channel reads that must not create a dependency (e.g. logging).

## Runtime integration

The Architex interpreter wraps every `~name = expr` declaration in a `signal`, every template expression in a `computed`, and every `@effect` block in an `effect`. DOM / native updates happen inside an `effect` that reads the reactive element tree, so only the exact node that reads a signal re-renders when that signal changes — no VDOM diffing.

## Performance

- O(1) subscribe + unsubscribe.
- No object allocation per read after the first run.
- Scales to tens of thousands of signals without noticeable overhead (tested on an iPad Mini 5).

## Testing

`__tests__/reactive.test.ts` — chain of signals → computed → effects, testing correctness + prune behaviour under rapid updates.

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

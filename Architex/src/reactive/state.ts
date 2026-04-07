/** createState — observer store with computed values, auto-tracking, and batching. */

import type { StateAPI, Subscriber } from './types.js';

interface ComputedDef {
  expr: (state: StateAPI) => unknown;
  deps: Set<string>;
}

export function createState(initial: Record<string, unknown> = {}): StateAPI {
  const _data:  Record<string, unknown>                   = { ...initial };
  const _subs:  Record<string, Set<Subscriber>>           = {};
  const _comps: Record<string, ComputedDef>               = {};
  let   _batch = false;
  const _dirty = new Set<string>();

  // P2 #16 — auto-tracking: points to the deps set being built during expr evaluation
  let _tracking: Set<string> | null = null;

  // P0 #5 — cycle detection: keys currently being recomputed
  const _computing = new Set<string>();

  const _notify = (key: string): void => {
    const val = _data[key];
    if (_subs[key]) for (const fn of _subs[key]!) fn(val, key);
  };

  const _recompute = (key: string): void => {
    if (_computing.has(key)) {
      console.warn(`[Architex] Cyclic dependency on "~${key}" — skipping`);
      return;
    }
    const comp = _comps[key];
    if (!comp) return;
    _computing.add(key);
    try {
      const next = comp.expr(api);
      if (_data[key] !== next) {
        _data[key] = next;
        _notify(key);
        _cascade(key); // P0 #6 — transitive cascade
      }
    } finally {
      _computing.delete(key);
    }
  };

  const _cascade = (changedKey: string): void => {
    for (const [cKey, comp] of Object.entries(_comps)) {
      if (comp.deps.has(changedKey)) _recompute(cKey);
    }
  };

  const api: StateAPI = {
    get(key) {
      // P2 #16 — record access while tracking is active
      if (_tracking) _tracking.add(key);
      return _data[key];
    },

    set(key, val) {
      if (_data[key] === val) return;
      _data[key] = val;
      if (_batch) _dirty.add(key);
      else        { _notify(key); _cascade(key); }
    },

    update(key, fn) { api.set(key, fn(_data[key])); },

    subscribe(key, fn) {
      (_subs[key] ??= new Set()).add(fn);
      return () => _subs[key]?.delete(fn);
    },

    watch(key, fn) {
      return api.subscribe(key, fn);
    },

    computed(key, expr, deps = []) {
      // P2 #16 — auto-track: run expression once with tracking active to discover deps
      const trackedDeps = new Set<string>(deps);
      _tracking = trackedDeps;
      let initVal: unknown;
      try { initVal = expr(api); } finally { _tracking = null; }
      _comps[key] = { expr, deps: trackedDeps };
      _data[key]  = initVal;
    },

    batch(fn) {
      _batch = true;
      try { fn(); } finally {
        _batch = false;
        for (const k of _dirty) { _notify(k); _cascade(k); }
        _dirty.clear();
      }
    },

    snapshot() { return { ..._data }; },

    reset(data) {
      api.batch(() => { for (const [k, v] of Object.entries(data)) api.set(k, v); });
    },
  };

  return api;
}

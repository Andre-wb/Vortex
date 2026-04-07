/** Resolve AST value nodes to concrete JS values; live text / interpolated binding. */

import type { ValueNode } from '../ast/values.js';
import type { StateAPI }  from '../reactive/types.js';
import type { RenderCtx } from './types.js';

export function resolveValue(node: ValueNode, state: StateAPI, ctx: RenderCtx): unknown {
  switch (node.kind) {
    case 'string':   return node.v;
    case 'number':   return node.v;
    case 'color':    return node.v;
    case 'reactive': {
      const parts = node.v.split('.');
      let val: unknown = state.get(parts[0]!) ?? ctx[parts[0]!];
      for (let i = 1; i < parts.length; i++) {
        if (val == null) return null;
        val = (val as Record<string, unknown>)[parts[i]!];
      }
      return val;
    }
    case 'ident':  return ctx[node.v] !== undefined ? ctx[node.v] : node.v;
    case 'array':  return node.v.map(n => resolveValue(n, state, ctx));

    // P0 #2 — object literals
    case 'object': {
      const result: Record<string, unknown> = {};
      for (const { key, val } of node.entries) result[key] = resolveValue(val, state, ctx);
      return result;
    }

    // P0 #3 — array / map indexing  ~arr[~i]
    case 'index': {
      const arr = resolveValue(node.arr, state, ctx);
      const idx = resolveValue(node.idx, state, ctx);
      if (Array.isArray(arr) && typeof idx === 'number') return arr[Math.floor(idx)] ?? null;
      if (arr != null && typeof arr === 'object') {
        return (arr as Record<string, unknown>)[String(idx)] ?? null;
      }
      return null;
    }

    // P2 #20 — string interpolation  "Hello {~name}!"
    case 'interpolated':
      return node.parts
        .map(p => typeof p === 'string' ? p : String(resolveValue(p, state, ctx) ?? ''))
        .join('');

    case 'binary': {
      const l = resolveValue(node.left,  state, ctx);
      const r = resolveValue(node.right, state, ctx);
      switch (node.op) {
        case '||': return l || r;
        case '&&': return l && r;
        case '==': return l === r;
        case '!=': return l !== r;
        case '>':  return (l as number) >  (r as number);
        case '<':  return (l as number) <  (r as number);
        case '>=': return (l as number) >= (r as number);
        case '<=': return (l as number) <= (r as number);
        case '+':
          return (typeof l === 'string' || typeof r === 'string')
            ? String(l ?? '') + String(r ?? '')
            : (l as number) + (r as number);
        case '-': return (l as number) -  (r as number);
        case '*': return (l as number) *  (r as number);
        case '/': return (r as number) !== 0 ? (l as number) / (r as number) : null;
        case '%': return (r as number) !== 0 ? (l as number) % (r as number) : null;
        default:  return null;
      }
    }
    case 'unary': {
      const v = resolveValue(node.operand, state, ctx);
      if (node.op === '!') return !v;
      if (node.op === '-') return -(v as number);
      return v;
    }
    case 'ternary': {
      const cond = resolveValue(node.condition, state, ctx);
      return cond ? resolveValue(node.then, state, ctx) : resolveValue(node.else_, state, ctx);
    }
    case 'funcall':
      return _evalFuncall(node.fn, node.args.map(a => resolveValue(a, state, ctx)), state);
  }
}

/** Evaluate built-in functions used in expressions. */
function _evalFuncall(fn: string, args: unknown[], state?: StateAPI): unknown {
  switch (fn) {
    // String methods
    case 'trim':       return typeof args[0] === 'string' ? args[0].trim() : args[0];
    case 'upper': case 'uppercase': return typeof args[0] === 'string' ? args[0].toUpperCase() : args[0];
    case 'lower': case 'lowercase': return typeof args[0] === 'string' ? args[0].toLowerCase() : args[0];
    case 'split':      return typeof args[0] === 'string' ? args[0].split(String(args[1] ?? ',')) : [];
    case 'replace':    return typeof args[0] === 'string' ? args[0].replace(String(args[1] ?? ''), String(args[2] ?? '')) : args[0];
    case 'startsWith': return typeof args[0] === 'string' ? args[0].startsWith(String(args[1] ?? '')) : false;
    case 'endsWith':   return typeof args[0] === 'string' ? args[0].endsWith(String(args[1] ?? '')) : false;
    case 'contains':   return typeof args[0] === 'string' ? args[0].includes(String(args[1] ?? '')) : Array.isArray(args[0]) ? args[0].includes(args[1]) : false;
    case 'substr': case 'substring': return typeof args[0] === 'string' ? args[0].substring(Number(args[1] ?? 0), args[2] != null ? Number(args[2]) : undefined) : '';
    case 'charAt':     return typeof args[0] === 'string' ? args[0].charAt(Number(args[1] ?? 0)) : '';

    // Array methods (non-mutating)
    case 'len': case 'length': return Array.isArray(args[0]) ? args[0].length : typeof args[0] === 'string' ? args[0].length : 0;
    case 'join':       return Array.isArray(args[0]) ? args[0].join(String(args[1] ?? ', ')) : '';
    case 'includes':   return Array.isArray(args[0]) ? args[0].includes(args[1]) : false;
    case 'indexOf':    return Array.isArray(args[0]) ? args[0].indexOf(args[1]) : typeof args[0] === 'string' ? args[0].indexOf(String(args[1] ?? '')) : -1;
    case 'slice':      return Array.isArray(args[0]) ? args[0].slice(Number(args[1] ?? 0), args[2] != null ? Number(args[2]) : undefined) : typeof args[0] === 'string' ? args[0].slice(Number(args[1] ?? 0), args[2] != null ? Number(args[2]) : undefined) : null;
    case 'concat':     return Array.isArray(args[0]) && Array.isArray(args[1]) ? [...args[0], ...args[1]] : null;
    case 'flat':       return Array.isArray(args[0]) ? args[0].flat() : args[0];
    case 'unique':     return Array.isArray(args[0]) ? [...new Set(args[0])] : args[0];
    case 'first':      return Array.isArray(args[0]) ? args[0][0] ?? null : null;
    case 'last':       return Array.isArray(args[0]) ? args[0][args[0].length - 1] ?? null : null;
    case 'count':      return Array.isArray(args[0]) ? args[0].length : 0;

    // Math functions
    case 'Math.round': case 'round': return Math.round(Number(args[0] ?? 0));
    case 'Math.floor': case 'floor': return Math.floor(Number(args[0] ?? 0));
    case 'Math.ceil':  case 'ceil':  return Math.ceil(Number(args[0] ?? 0));
    case 'Math.abs':   case 'abs':   return Math.abs(Number(args[0] ?? 0));
    case 'Math.min':   case 'min':   return Math.min(...args.map(Number));
    case 'Math.max':   case 'max':   return Math.max(...args.map(Number));
    case 'Math.random': case 'random': return Math.random();
    case 'Math.sqrt':  case 'sqrt':  return Math.sqrt(Number(args[0] ?? 0));
    case 'Math.pow':   case 'pow':   return Math.pow(Number(args[0] ?? 0), Number(args[1] ?? 1));
    case 'Math.PI':    return Math.PI;

    // Type conversion
    case 'int': case 'parseInt':   return parseInt(String(args[0] ?? '0'), 10);
    case 'float': case 'parseFloat': return parseFloat(String(args[0] ?? '0'));
    case 'str': case 'String':     return String(args[0] ?? '');
    case 'bool':                   return !!args[0];
    case 'json':                   try { return JSON.parse(String(args[0] ?? '{}')); } catch { return null; }
    case 'stringify':              return JSON.stringify(args[0]);

    // Date
    case 'now':   return Date.now();
    case 'today': return new Date().toISOString().slice(0, 10);

    // persist() is handled at init time
    case 'persist': return args[0] ?? null;

    // i18n translation function
    case 't': case 'translate': {
      const key = String(args[0] ?? '');
      // Check if state has i18n data loaded
      const i18nData = state?.get('_i18n') as Record<string, string> | undefined;
      if (i18nData && key in i18nData) return i18nData[key];
      return key; // fallback: return key itself
    }

    default: return fn; // Unknown — return fn name as fallback
  }
}

/** Collect all root reactive keys referenced in a ValueNode. */
export function reactiveKeysOf(node: ValueNode): Set<string> {
  const keys = new Set<string>();
  function walk(n: ValueNode): void {
    if (n.kind === 'reactive')     { keys.add(n.v.split('.')[0]!); }
    if (n.kind === 'interpolated') { n.parts.forEach(p => typeof p !== 'string' && walk(p)); }
    if (n.kind === 'array')        { n.v.forEach(walk); }
    if (n.kind === 'object')       { n.entries.forEach(e => walk(e.val)); }
    if (n.kind === 'index')        { walk(n.arr); walk(n.idx); }
    if (n.kind === 'binary')  { walk(n.left); walk(n.right); }
    if (n.kind === 'unary')   { walk(n.operand); }
    if (n.kind === 'ternary') { walk(n.condition); walk(n.then); walk(n.else_); }
    if (n.kind === 'funcall') { n.args.forEach(walk); }
  }
  walk(node);
  return keys;
}

// Б8 fix: arrays rendered as "[a, b, c]" instead of "a,b,c" via String()
export function toDisplayString(v: unknown): string {
  if (v == null) return '';
  if (Array.isArray(v)) return '[' + v.map(toDisplayString).join(', ') + ']';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

/** Set element text and keep it live for both reactive and interpolated values. */
export function bindValue(el: HTMLElement, node: ValueNode, state: StateAPI, ctx: RenderCtx): void {
  const resolve = (): string => toDisplayString(resolveValue(node, state, ctx));
  el.textContent = resolve();
  for (const key of reactiveKeysOf(node)) {
    state.subscribe(key, () => { el.textContent = resolve(); });
  }
}

/** Legacy single-key text binding (kept for backward compat). */
export function bindText(el: HTMLElement, key: string, state: StateAPI, ctx: RenderCtx): void {
  const rootKey = key.split('.')[0]!;
  const resolve = (): string => {
    const parts = key.split('.');
    let val: unknown = state.get(parts[0]!) ?? ctx[parts[0]!];
    for (let i = 1; i < parts.length; i++) {
      if (val == null) return '';
      val = (val as Record<string, unknown>)[parts[i]!];
    }
    return toDisplayString(val);
  };
  el.textContent = resolve();
  state.subscribe(rootKey, () => { el.textContent = resolve(); });
}

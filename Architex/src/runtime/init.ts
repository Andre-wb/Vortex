/** State initialisation helpers — walk AST, collect vars, computeds, watches. */

import type { Node, VarDeclNode, ComputedNode, WatchNode } from '../ast/nodes.js';
import type { ValueNode }  from '../ast/values.js';
import type { Action }     from '../ast/actions.js';
import type { StateAPI }   from '../reactive/types.js';
import { createState }     from '../reactive/state.js';

/** Persist binding: var name → localStorage key */
interface PersistBinding {
  varName: string;
  storageKey: string;
  defaultValue: unknown;
}

export function initState(ast: Node[]): StateAPI {
  const initial:   Record<string, unknown> = {};
  const computeds: ComputedNode[]          = [];
  const watches:   WatchNode[]             = [];
  const persists:  PersistBinding[]        = [];

  collect(ast, initial, computeds, watches, persists);

  // Apply persisted values from localStorage
  for (const p of persists) {
    const stored = _readStorage(p.storageKey);
    initial[p.varName] = stored !== undefined ? stored : p.defaultValue;
  }

  const state = createState(initial);

  for (const comp of computeds) {
    const deps = collectDeps(comp.expr);
    state.computed(comp.name, s => evalExpr(comp.expr, s), deps);
  }

  // Set up auto-save subscribers for persist() bindings
  for (const p of persists) {
    state.subscribe(p.varName, (val) => {
      _writeStorage(p.storageKey, val);
    });
  }

  return state;
}

function _readStorage(key: string): unknown | undefined {
  try {
    const raw = localStorage.getItem('arx:' + key);
    return raw !== null ? JSON.parse(raw) as unknown : undefined;
  } catch { return undefined; }
}

function _writeStorage(key: string, val: unknown): void {
  try {
    localStorage.setItem('arx:' + key, JSON.stringify(val));
  } catch { /* storage full or unavailable */ }
}

function collect(
  nodes:     Node[],
  initial:   Record<string, unknown>,
  computeds: ComputedNode[],
  watches:   WatchNode[],
  persists:  PersistBinding[],
): void {
  for (const node of nodes) {
    if (node.kind === 'varDecl') {
      // Check for persist("key", default) pattern
      if (node.expr.kind === 'funcall' && node.expr.fn === 'persist') {
        const keyArg = node.expr.args[0];
        const defArg = node.expr.args[1];
        const storageKey = keyArg ? String(literalValue(keyArg) ?? node.name) : node.name;
        const defaultValue = defArg ? literalValue(defArg) : null;
        persists.push({ varName: node.name, storageKey, defaultValue });
        initial[node.name] = defaultValue;
      } else {
        initial[node.name] = literalValue(node.expr);
      }
    }
    if (node.kind === 'computed')  computeds.push(node);
    if (node.kind === 'watch')     watches.push(node);
    if (node.kind === 'screen')    collect(node.body, initial, computeds, watches, persists);
    if (node.kind === 'component') collect(node.children, initial, computeds, watches, persists); // Б10 fix
    if (node.kind === 'list')      collect(node.body, initial, computeds, watches, persists);
    if (node.kind === 'if') {
      for (const branch of node.branches) collect(branch.body, initial, computeds, watches, persists);
      collect(node.else_, initial, computeds, watches, persists);
    }
    if (node.kind === 'compDef')   collect(node.body, initial, computeds, watches, persists);
    if (node.kind === 'for')       collect(node.body, initial, computeds, watches, persists);
    // @theme — inject design token vars into initial state
    if (node.kind === 'theme') {
      for (const v of node.vars) initial[v.name] = literalValue(v.expr);
    }
    // lifecycle / handler / style / slot / hotkey / timer nodes contain no state declarations — nothing to collect
  }
}

function literalValue(node: ValueNode): unknown {
  switch (node.kind) {
    case 'string':       return node.v;
    case 'number':       return node.v;
    case 'color':        return node.v;
    case 'ident':        return node.v;
    case 'array':        return node.v.map(literalValue);
    case 'reactive':     return null;
    case 'interpolated': return null;
    case 'index':        return null;
    case 'funcall':      return null;  // persist() etc. handled separately
    case 'object': {
      const result: Record<string, unknown> = {};
      for (const { key, val } of node.entries) result[key] = literalValue(val);
      return result;
    }
  }
}

/** Evaluate a ValueNode against state at runtime. Exported for use in ArchiRuntime. */
export function evalExpr(node: ValueNode, state: StateAPI): unknown {
  if (node.kind === 'reactive') return state.get(node.v);
  if (node.kind === 'interpolated') {
    return node.parts
      .map(p => typeof p === 'string' ? p : String(evalExpr(p, state) ?? ''))
      .join('');
  }
  if (node.kind === 'object') {
    const result: Record<string, unknown> = {};
    for (const { key, val } of node.entries) result[key] = evalExpr(val, state);
    return result;
  }
  if (node.kind === 'index') {
    const arr = evalExpr(node.arr, state);
    const idx = evalExpr(node.idx, state);
    if (Array.isArray(arr) && typeof idx === 'number') return arr[Math.floor(idx)] ?? null;
    if (arr != null && typeof arr === 'object') {
      return (arr as Record<string, unknown>)[String(idx)] ?? null;
    }
    return null;
  }
  if (node.kind === 'binary') {
    const l = evalExpr(node.left,  state);
    const r = evalExpr(node.right, state);
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
  if (node.kind === 'unary') {
    const v = evalExpr(node.operand, state);
    if (node.op === '!') return !v;
    if (node.op === '-') return -(v as number);
    return v;
  }
  if (node.kind === 'ternary') {
    const cond = evalExpr(node.condition, state);
    return cond ? evalExpr(node.then, state) : evalExpr(node.else_, state);
  }
  if (node.kind === 'funcall') {
    const args = node.args.map(a => evalExpr(a, state));
    return _evalBuiltin(node.fn, args);
  }
  return literalValue(node);
}

function collectDeps(node: ValueNode): string[] {
  if (node.kind === 'reactive')     return [node.v.split('.')[0]!];
  if (node.kind === 'array')        return node.v.flatMap(collectDeps);
  if (node.kind === 'object')       return node.entries.flatMap(e => collectDeps(e.val));
  if (node.kind === 'index')        return [...collectDeps(node.arr), ...collectDeps(node.idx)];
  if (node.kind === 'binary')  return [...collectDeps(node.left), ...collectDeps(node.right)];
  if (node.kind === 'unary')   return collectDeps(node.operand);
  if (node.kind === 'ternary') return [...collectDeps(node.condition), ...collectDeps(node.then), ...collectDeps(node.else_)];
  if (node.kind === 'interpolated') {
    return node.parts.flatMap(p => typeof p === 'string' ? [] : collectDeps(p));
  }
  if (node.kind === 'funcall') {
    return node.args.flatMap(collectDeps);
  }
  return [];
}

/** Evaluate built-in functions in expressions. */
function _evalBuiltin(fn: string, args: unknown[]): unknown {
  switch (fn) {
    case 'trim':       return typeof args[0] === 'string' ? args[0].trim() : args[0];
    case 'upper': case 'uppercase': return typeof args[0] === 'string' ? args[0].toUpperCase() : args[0];
    case 'lower': case 'lowercase': return typeof args[0] === 'string' ? args[0].toLowerCase() : args[0];
    case 'split':      return typeof args[0] === 'string' ? args[0].split(String(args[1] ?? ',')) : [];
    case 'replace':    return typeof args[0] === 'string' ? args[0].replace(String(args[1] ?? ''), String(args[2] ?? '')) : args[0];
    case 'contains':   return typeof args[0] === 'string' ? args[0].includes(String(args[1] ?? '')) : Array.isArray(args[0]) ? args[0].includes(args[1]) : false;
    case 'len': case 'length': return Array.isArray(args[0]) ? args[0].length : typeof args[0] === 'string' ? args[0].length : 0;
    case 'join':       return Array.isArray(args[0]) ? args[0].join(String(args[1] ?? ', ')) : '';
    case 'slice':      return Array.isArray(args[0]) ? args[0].slice(Number(args[1] ?? 0), args[2] != null ? Number(args[2]) : undefined) : null;
    case 'first':      return Array.isArray(args[0]) ? args[0][0] ?? null : null;
    case 'last':       return Array.isArray(args[0]) ? args[0][args[0].length - 1] ?? null : null;
    case 'unique':     return Array.isArray(args[0]) ? [...new Set(args[0])] : args[0];
    case 'Math.round': case 'round': return Math.round(Number(args[0] ?? 0));
    case 'Math.floor': case 'floor': return Math.floor(Number(args[0] ?? 0));
    case 'Math.ceil':  case 'ceil':  return Math.ceil(Number(args[0] ?? 0));
    case 'Math.abs':   case 'abs':   return Math.abs(Number(args[0] ?? 0));
    case 'Math.min':   case 'min':   return Math.min(...args.map(Number));
    case 'Math.max':   case 'max':   return Math.max(...args.map(Number));
    case 'Math.random': case 'random': return Math.random();
    case 'Math.sqrt':  case 'sqrt':  return Math.sqrt(Number(args[0] ?? 0));
    case 'Math.pow':   case 'pow':   return Math.pow(Number(args[0] ?? 0), Number(args[1] ?? 1));
    case 'int': case 'parseInt': return parseInt(String(args[0] ?? '0'), 10);
    case 'float': case 'parseFloat': return parseFloat(String(args[0] ?? '0'));
    case 'str': case 'String': return String(args[0] ?? '');
    case 'now':   return Date.now();
    case 'today': return new Date().toISOString().slice(0, 10);
    case 'persist': return args[0] ?? null;
    case 't': case 'translate': return String(args[0] ?? ''); // placeholder — full i18n in runtime
    default: return fn;
  }
}

/** Execute state-only assign actions (used by @watch). */
export function execActions(actions: Action[], state: StateAPI): void {
  for (const action of actions) {
    if (action.kind === 'assign') {
      const cur = (state.get(action.var) as number) ?? 0;
      const val = evalExpr(action.val, state);
      if      (action.op === '+=') state.set(action.var, cur + (val as number));
      else if (action.op === '-=') state.set(action.var, cur - (val as number));
      else                         state.set(action.var, val);
    }
  }
}

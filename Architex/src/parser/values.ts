/** Parse a single value expression with full operator precedence. */

import { T, Token } from '../lexer/tokens.js';
import type { ValueNode } from '../ast/values.js';
import { TokStream }      from './stream.js';

/**
 * Entry point. Parses a full expression with operator precedence:
 * Level 0 (lowest): ternary  ? :
 * Level 1: ||
 * Level 2: &&
 * Level 3: ==, !=
 * Level 4: >, <, >=, <=
 * Level 5: +, - (additive)
 * Level 6: *, /, % (multiplicative)
 * Level 7: unary !, -
 * Level 8 (highest): primary (base value with optional postfix index)
 */
export function parseValue(ts: TokStream): ValueNode | null {
  return parseTernary(ts);
}

function parseTernary(ts: TokStream): ValueNode | null {
  const cond = parseOr(ts);
  if (!cond) return null;
  if (ts.peek()?.t === T.Question) {
    ts.eat(); // ?
    const then_ = parseTernary(ts);
    if (!then_) return cond;
    // expect ':'
    if (ts.peek()?.t === T.Colon) ts.eat();
    const else_ = parseTernary(ts);
    if (!else_) return cond;
    return { kind: 'ternary', condition: cond, then: then_, else_: else_ };
  }
  return cond;
}

function parseOr(ts: TokStream): ValueNode | null {
  let left = parseAnd(ts);
  if (!left) return null;
  while (ts.peek()?.t === T.Or) {
    ts.eat();
    const right = parseAnd(ts);
    if (!right) break;
    left = { kind: 'binary', op: '||', left, right };
  }
  return left;
}

function parseAnd(ts: TokStream): ValueNode | null {
  let left = parseEquality(ts);
  if (!left) return null;
  while (ts.peek()?.t === T.And) {
    ts.eat();
    const right = parseEquality(ts);
    if (!right) break;
    left = { kind: 'binary', op: '&&', left, right };
  }
  return left;
}

function parseEquality(ts: TokStream): ValueNode | null {
  let left = parseRelational(ts);
  if (!left) return null;
  while (ts.peek()?.t === T.Eq || ts.peek()?.t === T.Neq) {
    const tok = ts.eat()!;
    const op = tok.t === T.Eq ? '==' : '!=';
    const right = parseRelational(ts);
    if (!right) break;
    left = { kind: 'binary', op, left, right };
  }
  return left;
}

function parseRelational(ts: TokStream): ValueNode | null {
  let left = parseAdditive(ts);
  if (!left) return null;
  while (
    ts.peek()?.t === T.Gt || ts.peek()?.t === T.Lt ||
    ts.peek()?.t === T.Gte || ts.peek()?.t === T.Lte
  ) {
    const tok = ts.eat()!;
    const op = tok.t === T.Gt ? '>' : tok.t === T.Lt ? '<' : tok.t === T.Gte ? '>=' : '<=';
    const right = parseAdditive(ts);
    if (!right) break;
    left = { kind: 'binary', op, left, right };
  }
  return left;
}

function parseAdditive(ts: TokStream): ValueNode | null {
  let left = parseMultiplicative(ts);
  if (!left) return null;
  while (ts.peek()?.t === T.Plus || ts.peek()?.t === T.Minus) {
    const tok = ts.eat()!;
    const op = tok.t === T.Plus ? '+' : '-';
    const right = parseMultiplicative(ts);
    if (!right) break;
    left = { kind: 'binary', op, left, right };
  }
  return left;
}

function parseMultiplicative(ts: TokStream): ValueNode | null {
  let left = parseUnary(ts);
  if (!left) return null;
  while (
    ts.peek()?.t === T.Star || ts.peek()?.t === T.Slash || ts.peek()?.t === T.Mod
  ) {
    const tok = ts.eat()!;
    const op = tok.t === T.Star ? '*' : tok.t === T.Slash ? '/' : '%';
    const right = parseUnary(ts);
    if (!right) break;
    left = { kind: 'binary', op, left, right };
  }
  return left;
}

function parseUnary(ts: TokStream): ValueNode | null {
  if (ts.peek()?.t === T.Bang) {
    ts.eat();
    const operand = parseUnary(ts);
    return operand ? { kind: 'unary', op: '!', operand } : null;
  }
  if (ts.peek()?.t === T.Minus) {
    // Check if followed by a number (negative literal optimisation)
    ts.eat();
    const inner = parsePrimary(ts);
    if (!inner) return null;
    // Fold negative number literal
    if (inner.kind === 'number') return { kind: 'number', v: -inner.v };
    return { kind: 'unary', op: '-', operand: inner };
  }
  return parsePrimary(ts);
}

function parsePrimary(ts: TokStream): ValueNode | null {
  const base = parseBaseValue(ts);
  if (!base) return null;

  // Postfix index — only for reactive values: ~arr[~i] or ~arr[0]
  if (base.kind === 'reactive' && ts.peek()?.t === T.LBrack) {
    ts.eat(); // [
    const idx = parseValue(ts);
    if (ts.peek()?.t === T.RBrack) ts.eat(); // ]
    if (idx) return { kind: 'index', arr: base, idx };
  }

  return base;
}

function parseBaseValue(ts: TokStream): ValueNode | null {
  const tok = ts.peek();
  if (!tok) return null;

  // String literal — detect interpolation  "Hello {~name}!"  (P2 #20)
  if (tok.t === T.String) {
    ts.eat();
    return tok.v.includes('{~') ? parseInterpolated(tok.v) : { kind: 'string', v: tok.v };
  }

  if (tok.t === T.Number)   { ts.eat(); return { kind: 'number',   v: tok.v }; }
  if (tok.t === T.Color)    { ts.eat(); return { kind: 'color',    v: tok.v }; }
  if (tok.t === T.Reactive) { ts.eat(); return { kind: 'reactive', v: tok.v }; }

  // Array literal  [v, v, ...]
  if (tok.t === T.LBrack) {
    ts.eat();
    const items: ValueNode[] = [];
    while (!ts.atEnd() && ts.peek()?.t !== T.RBrack) {
      const v = parseValue(ts);
      if (v) items.push(v);
      if (ts.peek()?.t === T.Comma) ts.eat();
    }
    ts.eat(); // ]
    return { kind: 'array', v: items };
  }

  // Object literal  { key: value, … }  (P0 #2)
  if (tok.t === T.LBrace) {
    ts.eat();
    const entries: { key: string; val: ValueNode }[] = [];
    while (!ts.atEnd() && ts.peek()?.t !== T.RBrace) {
      const keyTok = ts.peek();
      let key: string | null = null;
      if (keyTok?.t === T.String) { ts.eat(); key = keyTok.v; }
      else if (keyTok?.t === T.Ident) { ts.eat(); key = keyTok.v; }
      else { ts.eat(); break; }
      if (ts.peek()?.t === T.Colon) ts.eat();
      const val = parseValue(ts);
      if (key !== null && val) entries.push({ key, val });
      if (ts.peek()?.t === T.Comma) ts.eat();
    }
    ts.eat(); // }
    return { kind: 'object', entries };
  }

  // Identifier — possibly a function call or dot-chained: Math.round(x)
  if (tok.t === T.Ident) {
    ts.eat();
    let name = tok.v;

    // Dot-chain first: Math.round, str.split, etc.
    while (ts.peek()?.t === T.Dot) {
      ts.eat();
      const next = ts.eat() as Extract<Token, { v: string }> | undefined;
      name += '.' + (next?.v ?? '');
    }

    // Function call: ident(args…) or ident.chain(args…)
    if (ts.peek()?.t === T.LParen) {
      ts.eat(); // (
      const args: ValueNode[] = [];
      while (!ts.atEnd() && ts.peek()?.t !== T.RParen) {
        const v = parseValue(ts);
        if (v) args.push(v);
        if (ts.peek()?.t === T.Comma) ts.eat();
      }
      ts.eat(); // )
      return { kind: 'funcall', fn: name, args };
    }

    return { kind: 'ident', v: name };
  }

  return null;
}

/** Split "Hello {~name}, you have {~count} items!" into parts. */
function parseInterpolated(s: string): ValueNode {
  const parts: Array<string | ValueNode> = [];
  const re = /\{~([\w.]+)\}/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    if (m.index > last) parts.push(s.slice(last, m.index));
    parts.push({ kind: 'reactive', v: m[1]! });
    last = m.index + m[0].length;
  }
  if (last < s.length) parts.push(s.slice(last));
  return { kind: 'interpolated', parts };
}

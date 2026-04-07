/** Parse the right-hand side of  =>  */

import { T, Token } from '../lexer/tokens.js';
import type { Action, KeyVal } from '../ast/actions.js';
import type { ValueNode }      from '../ast/values.js';
import { TokStream }           from './stream.js';
import { parseValue }          from './values.js';

export function parseAction(ts: TokStream): Action | null {
  // ~var op value
  if (ts.peek()?.t === T.Reactive) {
    const varTok = ts.eat() as Extract<Token, { t: T.Reactive }>;
    const op = ts.peek();
    if (op?.t === T.Assign)  { ts.eat(); const val = parseValue(ts); if (val) return { kind: 'assign', var: varTok.v, op: '=',  val }; }
    if (op?.t === T.PlusEq)  { ts.eat(); const val = parseValue(ts); if (val) return { kind: 'assign', var: varTok.v, op: '+=', val }; }
    if (op?.t === T.MinusEq) { ts.eat(); const val = parseValue(ts); if (val) return { kind: 'assign', var: varTok.v, op: '-=', val }; }
  }

  // fn(args)  [P2 #18: fetch(url) ~resultVar]
  if (ts.peek()?.t === T.Ident) {
    const fnTok = ts.eat() as Extract<Token, { t: T.Ident }>;
    const args: Array<ValueNode | KeyVal> = [];

    if (ts.peek()?.t === T.LParen) {
      ts.eat();
      while (!ts.atEnd() && ts.peek()?.t !== T.RParen) {
        // key: value  pair
        if (ts.peek()?.t === T.Ident && ts.peek(1)?.t === T.Colon) {
          const key = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
          ts.eat(); // :
          const val = parseValue(ts);
          if (val) args.push({ key, val });
        } else {
          const v = parseValue(ts);
          if (v) args.push(v);
        }
        if (ts.peek()?.t === T.Comma) ts.eat();
      }
      ts.eat(); // )
    }

    // P2 #18: fetch(url) ~resultVar  — store async result into state key
    let into: string | undefined;
    if (fnTok.v === 'fetch' && ts.peek()?.t === T.Reactive) {
      into = (ts.eat() as Extract<Token, { t: T.Reactive }>).v;
    }

    return { kind: 'call', fn: fnTok.v, args, ...(into ? { into } : {}) };
  }

  return null;
}

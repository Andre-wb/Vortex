/** Parse modifier lists after  ::  */

import { T } from '../lexer/tokens.js';
import type { Modifier } from '../ast/modifiers.js';
import { TokStream }     from './stream.js';
import { parseValue }    from './values.js';

export function parseMod(ts: TokStream): Modifier | null {
  const tok = ts.peek();
  if (!tok || tok.t !== T.Ident) return null;
  ts.eat();

  const mod: Modifier = { name: tok.v, args: [] };

  if (ts.peek()?.t === T.LParen) {
    ts.eat();
    while (!ts.atEnd() && ts.peek()?.t !== T.RParen) {
      const v = parseValue(ts);
      if (v) mod.args.push(v);
      if (ts.peek()?.t === T.Comma) ts.eat();
    }
    ts.eat(); // )
  }

  return mod;
}

export function parseModifiers(ts: TokStream): Modifier[] {
  const mods: Modifier[] = [];
  if (ts.peek()?.t !== T.DColon) return mods;
  ts.eat(); // ::
  while (!ts.atEnd() && ts.peek()?.t !== T.DColon && ts.peek()?.t !== T.Arrow) {
    const m = parseMod(ts);
    if (!m) break;
    mods.push(m);
  }
  return mods;
}

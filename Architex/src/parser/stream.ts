/** Token stream with peek / eat helpers. */

import type { Token } from '../lexer/tokens.js';

export class TokStream {
  private readonly _t: Token[];
  private _i = 0;

  constructor(tokens: Token[]) { this._t = tokens; }

  peek(off = 0): Token | undefined { return this._t[this._i + off]; }
  eat(): Token | undefined         { return this._t[this._i++]; }
  atEnd(): boolean                 { return this._i >= this._t.length; }
}

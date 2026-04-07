/** Phase 2: tokenise a single line of Architex source. */

import { T, Token } from './tokens.js';

export function tokeniseLine(text: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < text.length) {
    if (/\s/.test(text[i]!)) { i++; continue; }
    if (text[i] === '/' && text[i + 1] === '/') break;

    // @keyword
    if (text[i] === '@') {
      const m = text.slice(i).match(/^@([A-Za-z_]\w*)/);
      if (m) { tokens.push({ t: T.AtKw, v: m[1]! }); i += m[0].length; continue; }
    }

    // ~reactive
    if (text[i] === '~') {
      const m = text.slice(i).match(/^~([\w]+(?:\.[\w]+)*)/);
      if (m) { tokens.push({ t: T.Reactive, v: m[1]! }); i += m[0].length; continue; }
    }

    // String literal
    if (text[i] === '"' || text[i] === "'") {
      const q = text[i] as string;
      let s = '';
      i++;
      while (i < text.length && text[i] !== q) {
        if (text[i] === '\\') { i++; s += text[i] ?? ''; }
        else s += text[i];
        i++;
      }
      i++;
      tokens.push({ t: T.String, v: s });
      continue;
    }

    // Color  #hex
    if (text[i] === '#') {
      const m = text.slice(i).match(/^#([0-9A-Fa-f]{3,8})\b/);
      if (m) { tokens.push({ t: T.Color, v: '#' + m[1]! }); i += m[0].length; continue; }
    }

    // Number
    {
      const m = text.slice(i).match(/^\d+(\.\d+)?/);
      if (m) { tokens.push({ t: T.Number, v: parseFloat(m[0]) }); i += m[0].length; continue; }
    }

    // Two-char operators (order matters)
    const two = text.slice(i, i + 2);
    if (two === '==') { tokens.push({ t: T.Eq  }); i += 2; continue; }
    if (two === '!=') { tokens.push({ t: T.Neq }); i += 2; continue; }
    if (two === '>=') { tokens.push({ t: T.Gte }); i += 2; continue; }
    if (two === '<=') { tokens.push({ t: T.Lte }); i += 2; continue; }
    if (two === '&&') { tokens.push({ t: T.And }); i += 2; continue; }
    if (two === '||') { tokens.push({ t: T.Or  }); i += 2; continue; }
    if (two === ':=') { tokens.push({ t: T.Compute  }); i += 2; continue; }
    if (two === '::') { tokens.push({ t: T.DColon   }); i += 2; continue; }
    if (two === '=>') { tokens.push({ t: T.Arrow    }); i += 2; continue; }
    if (two === '+=') { tokens.push({ t: T.PlusEq   }); i += 2; continue; }
    if (two === '-=') { tokens.push({ t: T.MinusEq  }); i += 2; continue; }

    // Single-char operators
    const ch = text[i]!;
    if (ch === '>') { tokens.push({ t: T.Gt    }); i++; continue; }
    if (ch === '<') { tokens.push({ t: T.Lt    }); i++; continue; }
    if (ch === '!') { tokens.push({ t: T.Bang  }); i++; continue; }
    if (ch === '-') { tokens.push({ t: T.Minus }); i++; continue; }
    if (ch === '+') { tokens.push({ t: T.Plus  }); i++; continue; }
    if (ch === '*') { tokens.push({ t: T.Star  }); i++; continue; }
    if (ch === '%') { tokens.push({ t: T.Mod   }); i++; continue; }
    if (ch === '/' && text[i + 1] !== '/') { tokens.push({ t: T.Slash }); i++; continue; }
    if (ch === '=') { tokens.push({ t: T.Assign }); i++; continue; }
    if (ch === '(') { tokens.push({ t: T.LParen }); i++; continue; }
    if (ch === ')') { tokens.push({ t: T.RParen }); i++; continue; }
    if (ch === '[') { tokens.push({ t: T.LBrack }); i++; continue; }
    if (ch === ']') { tokens.push({ t: T.RBrack }); i++; continue; }
    if (ch === '{') { tokens.push({ t: T.LBrace }); i++; continue; }
    if (ch === '}') { tokens.push({ t: T.RBrace }); i++; continue; }
    if (ch === ',') { tokens.push({ t: T.Comma  }); i++; continue; }
    if (ch === ':') { tokens.push({ t: T.Colon  }); i++; continue; }
    if (ch === '.') { tokens.push({ t: T.Dot    }); i++; continue; }
    if (ch === '?') { tokens.push({ t: T.Question }); i++; continue; }

    // Identifier
    const mId = text.slice(i).match(/^[A-Za-z_]\w*/);
    if (mId) { tokens.push({ t: T.Ident, v: mId[0] }); i += mId[0].length; continue; }

    i++;
  }

  return tokens;
}

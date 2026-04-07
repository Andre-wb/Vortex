/** Token type enum and Token union. */

export const enum T {
  AtKw     = 'AT_KW',
  Reactive = 'REACTIVE',
  Compute  = 'COMPUTE',    // :=
  DColon   = 'DCOLON',     // ::
  Arrow    = 'ARROW',      // =>
  PlusEq   = 'PLUS_EQ',    // +=
  MinusEq  = 'MINUS_EQ',   // -=
  Eq     = 'EQ',      // ==
  Neq    = 'NEQ',     // !=
  Gte    = 'GTE',     // >=
  Lte    = 'LTE',     // <=
  Gt     = 'GT',      // >
  Lt     = 'LT',      // <
  And    = 'AND',     // &&
  Or     = 'OR',      // ||
  Bang   = 'BANG',    // !
  Minus  = 'MINUS',   // - (unary / arithmetic)
  Plus   = 'PLUS',    // + (arithmetic)
  Star   = 'STAR',    // * (multiplication)
  Slash  = 'SLASH',   // / (division)
  Mod    = 'MOD',     // % (modulo)
  Assign   = 'ASSIGN',     // =
  LParen   = 'LPAREN',
  RParen   = 'RPAREN',
  LBrack   = 'LBRACK',
  RBrack   = 'RBRACK',
  LBrace   = 'LBRACE',     // {  (object literals)
  RBrace   = 'RBRACE',     // }
  Comma    = 'COMMA',
  Colon    = 'COLON',
  Dot      = 'DOT',
  Question = 'QUESTION',  // ? (ternary operator)
  String   = 'STRING',
  Number   = 'NUMBER',
  Color    = 'COLOR',
  Ident    = 'IDENT',
}

export type Token =
  | { t: T.AtKw;     v: string }
  | { t: T.Reactive; v: string }
  | { t: T.String;   v: string }
  | { t: T.Number;   v: number }
  | { t: T.Color;    v: string }
  | { t: T.Ident;    v: string }
  | { t: T.Compute  }
  | { t: T.DColon   }
  | { t: T.Arrow    }
  | { t: T.PlusEq   }
  | { t: T.MinusEq  }
  | { t: T.Eq    }
  | { t: T.Neq   }
  | { t: T.Gte   }
  | { t: T.Lte   }
  | { t: T.Gt    }
  | { t: T.Lt    }
  | { t: T.And   }
  | { t: T.Or    }
  | { t: T.Bang  }
  | { t: T.Minus }
  | { t: T.Plus  }
  | { t: T.Star  }
  | { t: T.Slash }
  | { t: T.Mod   }
  | { t: T.Assign   }
  | { t: T.LParen   }
  | { t: T.RParen   }
  | { t: T.LBrack   }
  | { t: T.RBrack   }
  | { t: T.LBrace   }
  | { t: T.RBrace   }
  | { t: T.Comma    }
  | { t: T.Colon    }
  | { t: T.Dot      }
  | { t: T.Question };

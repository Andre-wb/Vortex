/** Value node — any expression that resolves to a concrete value. */

export type ValueNode =
  | { kind: 'string';       v: string }
  | { kind: 'number';       v: number }
  | { kind: 'color';        v: string }
  | { kind: 'reactive';     v: string }                              // ~ident or ~ident.field
  | { kind: 'ident';        v: string }
  | { kind: 'array';        v: ValueNode[] }
  | { kind: 'object';       entries: { key: string; val: ValueNode }[] }   // { key: val, … }
  | { kind: 'index';        arr: ValueNode; idx: ValueNode }                // ~arr[~i]
  | { kind: 'interpolated'; parts: Array<string | ValueNode> }             // "Hello {~name}!"
  | { kind: 'binary'; op: string; left: ValueNode; right: ValueNode }
  | { kind: 'unary';  op: string; operand: ValueNode }
  | { kind: 'ternary'; condition: ValueNode; then: ValueNode; else_: ValueNode }  // ~a > 0 ? "yes" : "no"
  | { kind: 'funcall'; fn: string; args: ValueNode[] };                    // persist("key", default)

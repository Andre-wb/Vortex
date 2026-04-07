/** Action types used in event handlers  =>  */

import type { ValueNode } from './values.js';

export type AssignOp = '=' | '+=' | '-=';

export interface AssignAction {
  kind: 'assign';
  var:  string;
  op:   AssignOp;
  val:  ValueNode;
}

export interface KeyVal {
  key: string;
  val: ValueNode;
}

export interface CallAction {
  kind:  'call';
  fn:    string;
  args:  Array<ValueNode | KeyVal>;
  /** P2 #18 — store async fetch result into this state key */
  into?: string;
}

export type Action = AssignAction | CallAction;

export function isKeyVal(x: unknown): x is KeyVal {
  return typeof x === 'object' && x !== null && 'key' in x && 'val' in x;
}

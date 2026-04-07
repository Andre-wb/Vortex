/** Modifier applied via  ::  syntax. */

import type { ValueNode } from './values.js';

export interface Modifier {
  name: string;
  args: ValueNode[];
}

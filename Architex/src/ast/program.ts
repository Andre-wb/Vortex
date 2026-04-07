/** Top-level program container. */

import type { ScreenNode, GlobalNode } from './nodes.js';

export interface Program {
  screens: ScreenNode[];
  globals: GlobalNode[];
}

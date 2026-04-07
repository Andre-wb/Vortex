import { scanLines }   from '../lexer/scanner.js';
import { buildTree }   from './tree.js';
import type { Program }         from '../ast/program.js';
import type { ScreenNode, VarDeclNode, ComputedNode } from '../ast/nodes.js';

export function parse(src: string): Program {
  const { nodes: all } = buildTree(scanLines(src));
  return {
    screens: all.filter((n): n is ScreenNode  => n.kind === 'screen'),
    globals: all.filter(
      (n): n is VarDeclNode | ComputedNode => n.kind === 'varDecl' || n.kind === 'computed',
    ),
  };
}

export { buildTree } from './tree.js';
export { TokStream } from './stream.js';

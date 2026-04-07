/**
 * Architex — public API root
 */

export { ArchiRuntime }             from './runtime/index.js';
export type { ArchiOptions }        from './runtime/index.js';

export { parse, buildTree }         from './parser/index.js';

export { createState }              from './reactive/index.js';
export type { StateAPI, Subscriber } from './reactive/index.js';

export { renderNode, resolveValue } from './renderer/index.js';
export type { RuntimeHooks, RenderCtx } from './renderer/index.js';

export { scanLines, tokeniseLine }  from './lexer/index.js';
export type { Token, Line }         from './lexer/index.js';

export type { Program, Node, ScreenNode, ComponentNode, ListNode,
              ForNode, VarDeclNode, ComputedNode, HandlerNode,
              ThemeNode, ImportNode, SlotNode, StyleNode,
              ValueNode, Modifier, Action, AssignOp } from './ast/index.js';

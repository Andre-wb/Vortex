/** renderNode — main dispatch, renders any AST node to DOM. */

import type { Node, ScreenNode, IfNode, ForNode } from '../ast/nodes.js';
import type { StateAPI }                  from '../reactive/types.js';
import type { RuntimeHooks, RenderCtx }   from './types.js';
import { renderComponent }                from './component.js';
import { renderList }                     from './list.js';
import { resolveValue, reactiveKeysOf }   from './values.js';

export { resolveValue } from './values.js';

export function renderNode(
  node:  Node,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement | null {
  switch (node.kind) {
    case 'screen': {
      const el = document.createElement('div');
      el.className = 'arx-screen';
      el.dataset['screen'] = node.name;

      // Apply screen transition if specified via :: transition(type)
      const screenNode = node as ScreenNode;
      el.style.animation = 'arx-fade-in 0.25s ease';

      for (const child of screenNode.body) {
        const c = renderNode(child, state, ctx, rt);
        if (c) el.appendChild(c);
      }
      return el;
    }

    case 'component': return renderComponent(node, state, ctx, rt);
    case 'list':      return renderList(node, state, ctx, rt);

    // @for item, index in ~source — loop with index
    case 'for': return renderFor(node as ForNode, state, ctx, rt);

    // Fix #1 — @if / @elseif / @else conditional rendering
    case 'if': {
      const ifNode = node as IfNode;
      const container = document.createElement('div');
      container.className = 'arx-if';

      const render = (): void => {
        container.innerHTML = '';
        let matched = false;
        for (const branch of ifNode.branches) {
          if (resolveValue(branch.condition, state, ctx)) {
            for (const child of branch.body) {
              const c = renderNode(child, state, ctx, rt);
              if (c) container.appendChild(c);
            }
            matched = true;
            break;
          }
        }
        if (!matched) {
          for (const child of ifNode.else_) {
            const c = renderNode(child, state, ctx, rt);
            if (c) container.appendChild(c);
          }
        }
      };

      render();

      // Subscribe to all reactive conditions for live updates
      const subscribed = new Set<string>();
      for (const branch of ifNode.branches) {
        for (const key of reactiveKeysOf(branch.condition)) {
          if (!subscribed.has(key)) {
            subscribed.add(key);
            state.subscribe(key, render);
          }
        }
      }

      return container;
    }

    default: return null;
  }
}

// ── @for rendering with index support ───────────────────────────────────────

function renderFor(
  node:  ForNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-for';

  const buildSlot = (item: unknown, idx: number): HTMLElement[] => {
    const childCtx: RenderCtx = {
      ...ctx,
      [node.itemName]: item,
    };
    if (node.indexName) childCtx[node.indexName] = idx;
    // Also provide itemIndex for backwards compat
    childCtx[`${node.itemName}Index`] = idx;

    const els: HTMLElement[] = [];
    for (const child of node.body) {
      const c = renderNode(child, state, childCtx, rt);
      if (c) els.push(c);
    }
    return els;
  };

  let rendered: { key: unknown; els: HTMLElement[] }[] = [];

  const reconcile = (): void => {
    const src = resolveValue(node.source, state, ctx);
    const arr: unknown[] = Array.isArray(src) ? src : [];

    while (rendered.length > arr.length) {
      const removed = rendered.pop()!;
      for (const el of removed.els) container.removeChild(el);
    }

    for (let idx = 0; idx < arr.length; idx++) {
      const item = arr[idx];
      if (idx < rendered.length) {
        if (rendered[idx]!.key !== item) {
          const newEls = buildSlot(item, idx);
          const oldEls = rendered[idx]!.els;
          const anchor = oldEls[0]!;
          for (const el of newEls) container.insertBefore(el, anchor);
          for (const el of oldEls) container.removeChild(el);
          rendered[idx] = { key: item, els: newEls };
        }
      } else {
        const newEls = buildSlot(item, idx);
        for (const el of newEls) container.appendChild(el);
        rendered.push({ key: item, els: newEls });
      }
    }
  };

  reconcile();

  if (node.source.kind === 'reactive') {
    let unsub: (() => void) | undefined;
    unsub = state.subscribe(node.source.v, () => {
      if (!container.isConnected) { unsub?.(); return; }
      reconcile();
    });
  }

  return container;
}

export type { RuntimeHooks, RenderCtx } from './types.js';

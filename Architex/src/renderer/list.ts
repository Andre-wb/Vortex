/** Render a ListNode — reactive repeated items with keyed reconciliation. */

import type { ListNode }  from '../ast/nodes.js';
import type { StateAPI }  from '../reactive/types.js';
import type { RuntimeHooks, RenderCtx } from './types.js';
import { resolveValue }   from './values.js';
import { renderNode }     from './index.js';

interface Slot { key: unknown; els: HTMLElement[] }

export function renderList(
  node:  ListNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-list';

  const buildSlot = (item: unknown, idx: number): HTMLElement[] => {
    const childCtx: RenderCtx = {
      ...ctx,
      [node.itemName]:           item,
      [`${node.itemName}Index`]: idx,
    };
    const els: HTMLElement[] = [];
    for (const child of node.body) {
      const c = renderNode(child, state, childCtx, rt);
      if (c) els.push(c);
    }
    return els;
  };

  let rendered: Slot[] = [];

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

  // Б1 fix: self-healing subscription — auto-unsubscribes when container leaves the DOM
  if (node.source.kind === 'reactive') {
    let unsub: (() => void) | undefined;
    unsub = state.subscribe(node.source.v, () => {
      if (!container.isConnected) {
        unsub?.();
        return;
      }
      reconcile();
    });
  }

  return container;
}

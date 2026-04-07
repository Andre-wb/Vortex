/** Drag & Drop support for Architex elements. */

import type { Modifier }  from '../ast/modifiers.js';
import type { StateAPI }  from '../reactive/types.js';
import type { RenderCtx } from './types.js';
import { resolveValue }   from './values.js';

// ── Module-level drag state ──────────────────────────────────────────────────

interface DragData {
  sourceKey:   string;
  sourceIndex: number;
  item:        unknown;
}

let _dragData: DragData | null = null;

// ── Touch drag ghost element ─────────────────────────────────────────────────

let _touchGhost: HTMLElement | null = null;
let _touchDragActive = false;
let _touchLongpressTimer: ReturnType<typeof setTimeout> | null = null;

// ── Draggable modifier ───────────────────────────────────────────────────────

/**
 * Makes an element draggable.
 * Context should contain the item data and list source key for reordering.
 *
 * Usage: `card :: draggable`
 * The element's ctx should contain the item and its index.
 */
export function applyDraggable(
  el:    HTMLElement,
  _mod:  Modifier,
  state: StateAPI,
  ctx:   RenderCtx,
): void {
  el.draggable = true;
  el.style.cursor = 'grab';

  // Determine source info from context
  const itemKey = _findContextListKey(ctx);
  const itemIndex = _findContextIndex(ctx);

  el.addEventListener('dragstart', (e: DragEvent) => {
    _dragData = {
      sourceKey:   itemKey,
      sourceIndex: itemIndex,
      item:        _findContextItem(ctx),
    };
    el.classList.add('arx-dragging');
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', '');
    }
  });

  el.addEventListener('dragend', () => {
    el.classList.remove('arx-dragging');
    _dragData = null;
  });

  // Touch-based drag support (longpress + touchmove)
  el.addEventListener('touchstart', () => {
    _touchDragActive = false;
    _touchLongpressTimer = setTimeout(() => {
      _touchDragActive = true;
      _dragData = {
        sourceKey:   itemKey,
        sourceIndex: itemIndex,
        item:        _findContextItem(ctx),
      };
      el.classList.add('arx-dragging');

      // Create ghost element
      _touchGhost = el.cloneNode(true) as HTMLElement;
      _touchGhost.style.cssText =
        'position:fixed;pointer-events:none;z-index:10001;opacity:0.8;' +
        'transform:scale(1.05);transition:none;';
      _touchGhost.style.width = `${el.offsetWidth}px`;
      document.body.appendChild(_touchGhost);
    }, 500);
  }, { passive: true });

  el.addEventListener('touchmove', (e: TouchEvent) => {
    if (!_touchDragActive || !_touchGhost) {
      if (_touchLongpressTimer) {
        clearTimeout(_touchLongpressTimer);
        _touchLongpressTimer = null;
      }
      return;
    }
    const touch = e.touches[0];
    if (!touch) return;
    _touchGhost.style.left = `${touch.clientX - el.offsetWidth / 2}px`;
    _touchGhost.style.top  = `${touch.clientY - el.offsetHeight / 2}px`;
  }, { passive: true });

  el.addEventListener('touchend', (e: TouchEvent) => {
    if (_touchLongpressTimer) {
      clearTimeout(_touchLongpressTimer);
      _touchLongpressTimer = null;
    }
    if (_touchDragActive && _touchGhost) {
      const touch = e.changedTouches[0];
      if (touch) {
        // Find drop target
        _touchGhost.style.display = 'none';
        const target = document.elementFromPoint(touch.clientX, touch.clientY);
        _touchGhost.style.display = '';
        if (target) {
          target.dispatchEvent(new CustomEvent('arx:touchdrop', {
            bubbles: true,
            detail: { dragData: _dragData },
          }));
        }
      }
      _touchGhost.remove();
      _touchGhost = null;
    }
    el.classList.remove('arx-dragging');
    _touchDragActive = false;
    _dragData = null;
  }, { passive: true });
}

// ── Droppable modifier ───────────────────────────────────────────────────────

/**
 * Makes an element a drop target.
 *
 * Usage: `col :: droppable(~targetList)`
 * When an item is dropped, it is moved from the source list to the target list.
 */
export function applyDroppable(
  el:    HTMLElement,
  mod:   Modifier,
  state: StateAPI,
  ctx:   RenderCtx,
): void {
  const targetArg = mod.args[0];
  const targetKey = targetArg?.kind === 'reactive' ? targetArg.v : null;

  el.addEventListener('dragover', (e: DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
  });

  el.addEventListener('dragenter', () => {
    el.classList.add('arx-drag-over');
  });

  el.addEventListener('dragleave', () => {
    el.classList.remove('arx-drag-over');
  });

  el.addEventListener('drop', (e: DragEvent) => {
    e.preventDefault();
    el.classList.remove('arx-drag-over');
    if (!_dragData || !targetKey) return;

    const sourceArr = state.get(_dragData.sourceKey);
    const targetArr = state.get(targetKey);

    if (Array.isArray(sourceArr) && Array.isArray(targetArr)) {
      // Remove from source
      const newSource = [...sourceArr];
      newSource.splice(_dragData.sourceIndex, 1);
      state.set(_dragData.sourceKey, newSource);

      // Add to target
      const newTarget = [...targetArr, _dragData.item];
      state.set(targetKey, newTarget);
    } else if (Array.isArray(sourceArr) && _dragData.sourceKey === targetKey) {
      // Reorder within same list — move to end
      const newArr = [...sourceArr];
      newArr.splice(_dragData.sourceIndex, 1);
      newArr.push(_dragData.item);
      state.set(targetKey, newArr);
    }

    _dragData = null;
  });

  // Touch drop support
  el.addEventListener('arx:touchdrop', ((e: CustomEvent) => {
    const data = e.detail?.dragData as DragData | null;
    if (!data || !targetKey) return;

    el.classList.remove('arx-drag-over');
    const sourceArr = state.get(data.sourceKey);
    const targetArr = state.get(targetKey);

    if (Array.isArray(sourceArr) && Array.isArray(targetArr)) {
      const newSource = [...sourceArr];
      newSource.splice(data.sourceIndex, 1);
      state.set(data.sourceKey, newSource);

      const newTarget = [...targetArr, data.item];
      state.set(targetKey, newTarget);
    }
  }) as EventListener);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function _findContextListKey(ctx: RenderCtx): string {
  // Look for keys ending in 'Index' to find the list item context
  for (const key of Object.keys(ctx)) {
    if (key.endsWith('Index')) {
      return key.slice(0, -5); // strip 'Index'
    }
  }
  return '';
}

function _findContextIndex(ctx: RenderCtx): number {
  for (const key of Object.keys(ctx)) {
    if (key.endsWith('Index')) {
      return Number(ctx[key] ?? 0);
    }
  }
  return 0;
}

function _findContextItem(ctx: RenderCtx): unknown {
  for (const key of Object.keys(ctx)) {
    if (!key.endsWith('Index') && key !== '__proto__') {
      const indexKey = key + 'Index';
      if (indexKey in ctx) return ctx[key];
    }
  }
  return null;
}

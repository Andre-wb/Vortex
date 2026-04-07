/** Touch gesture recognition for mobile mini-apps. */

import type { StateAPI }  from '../reactive/types.js';
import type { RenderCtx } from './types.js';
import type { Action }    from '../ast/actions.js';
import type { ValueNode } from '../ast/values.js';
import { resolveValue }   from './values.js';

// ── Gesture types ────────────────────────────────────────────────────────────

export type SwipeDir = 'left' | 'right' | 'up' | 'down';

export interface GestureHandler {
  gesture: string;
  direction?: SwipeDir;
  callback: () => void;
}

// ── Swipe detection ──────────────────────────────────────────────────────────

const SWIPE_THRESHOLD = 30;

export function attachSwipe(
  el:        HTMLElement,
  direction: SwipeDir,
  callback:  () => void,
): void {
  let startX = 0;
  let startY = 0;

  el.addEventListener('touchstart', (e: TouchEvent) => {
    const touch = e.touches[0];
    if (!touch) return;
    startX = touch.clientX;
    startY = touch.clientY;
  }, { passive: true });

  el.addEventListener('touchend', (e: TouchEvent) => {
    const touch = e.changedTouches[0];
    if (!touch) return;
    const dx = touch.clientX - startX;
    const dy = touch.clientY - startY;

    let detected = false;
    if (direction === 'left'  && dx < -SWIPE_THRESHOLD && Math.abs(dy) < Math.abs(dx)) detected = true;
    if (direction === 'right' && dx >  SWIPE_THRESHOLD && Math.abs(dy) < Math.abs(dx)) detected = true;
    if (direction === 'up'    && dy < -SWIPE_THRESHOLD && Math.abs(dx) < Math.abs(dy)) detected = true;
    if (direction === 'down'  && dy >  SWIPE_THRESHOLD && Math.abs(dx) < Math.abs(dy)) detected = true;

    if (detected) {
      callback();
      el.dispatchEvent(new CustomEvent(`arx:swipe${direction}`));
    }
  }, { passive: true });
}

// ── Long press detection ─────────────────────────────────────────────────────

const LONGPRESS_MS = 500;

export function attachLongpress(
  el:       HTMLElement,
  callback: () => void,
): void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let moved = false;

  el.addEventListener('touchstart', () => {
    moved = false;
    timer = setTimeout(() => {
      if (!moved) {
        callback();
        el.dispatchEvent(new CustomEvent('arx:longpress'));
      }
    }, LONGPRESS_MS);
  }, { passive: true });

  el.addEventListener('touchmove', () => {
    moved = true;
    if (timer) { clearTimeout(timer); timer = null; }
  }, { passive: true });

  el.addEventListener('touchend', () => {
    if (timer) { clearTimeout(timer); timer = null; }
  }, { passive: true });

  el.addEventListener('touchcancel', () => {
    if (timer) { clearTimeout(timer); timer = null; }
  }, { passive: true });
}

// ── Double tap detection ─────────────────────────────────────────────────────

const DOUBLETAP_MS = 300;

export function attachDoubletap(
  el:       HTMLElement,
  callback: () => void,
): void {
  let lastTap = 0;

  el.addEventListener('touchend', () => {
    const now = Date.now();
    if (now - lastTap < DOUBLETAP_MS) {
      callback();
      el.dispatchEvent(new CustomEvent('arx:doubletap'));
      lastTap = 0;
    } else {
      lastTap = now;
    }
  }, { passive: true });
}

// ── Pinch detection ──────────────────────────────────────────────────────────

export function attachPinch(
  el:       HTMLElement,
  callback: (scale: number) => void,
): void {
  let initialDistance = 0;

  const getDistance = (t1: Touch, t2: Touch): number => {
    const dx = t1.clientX - t2.clientX;
    const dy = t1.clientY - t2.clientY;
    return Math.sqrt(dx * dx + dy * dy);
  };

  el.addEventListener('touchstart', (e: TouchEvent) => {
    if (e.touches.length === 2) {
      initialDistance = getDistance(e.touches[0]!, e.touches[1]!);
    }
  }, { passive: true });

  el.addEventListener('touchmove', (e: TouchEvent) => {
    if (e.touches.length === 2 && initialDistance > 0) {
      const currentDistance = getDistance(e.touches[0]!, e.touches[1]!);
      const scale = currentDistance / initialDistance;
      callback(scale);
      el.dispatchEvent(new CustomEvent('arx:pinch', { detail: { scale } }));
    }
  }, { passive: true });

  el.addEventListener('touchend', () => {
    initialDistance = 0;
  }, { passive: true });
}

// ── Unified gesture attachment from modifiers ────────────────────────────────

/**
 * Attach a gesture handler from a modifier.
 * The modifier name determines the gesture type.
 * For swipe, the direction is extracted from the name or argument.
 */
export function attachGestureFromModifier(
  el:        HTMLElement,
  gestureName: string,
  actionArg: ValueNode | undefined,
  state:     StateAPI,
  _ctx:      RenderCtx,
): void {
  const setReactive = (): void => {
    if (actionArg?.kind === 'reactive') {
      state.set(actionArg.v, true);
    }
  };

  // swipe(left), swipe(right), swipe(up), swipe(down)
  if (gestureName === 'swipe') {
    const dir = actionArg ? String(resolveValue(actionArg, state, _ctx)) : 'left';
    if (dir === 'left' || dir === 'right' || dir === 'up' || dir === 'down') {
      attachSwipe(el, dir, setReactive);
    }
    return;
  }

  // longpress
  if (gestureName === 'longpress') {
    attachLongpress(el, setReactive);
    return;
  }

  // doubletap
  if (gestureName === 'doubletap') {
    attachDoubletap(el, setReactive);
    return;
  }

  // pinch — sets a scale factor into the reactive var
  if (gestureName === 'pinch') {
    attachPinch(el, (scale: number) => {
      if (actionArg?.kind === 'reactive') {
        state.set(actionArg.v, scale);
      }
    });
    return;
  }
}

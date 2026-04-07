/** Attach event handlers and two-way input binding to DOM elements. */

import type { HandlerNode } from '../ast/nodes.js';
import type { ValueNode }   from '../ast/values.js';
import type { StateAPI }    from '../reactive/types.js';
import type { RuntimeHooks, RenderCtx } from './types.js';
import { resolveValue }     from './values.js';
import { showToast }        from './toast.js';
import type { ToastType }   from './toast.js';

export function attachHandler(
  el:    HTMLElement,
  node:  HandlerNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): void {
  // Determine DOM event name
  const rawEvent = node.event ?? (
    el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' ? 'input' : 'click'
  );
  // Map custom event names to DOM events
  const eventMap: Record<string, string> = {
    hover:      'mouseenter',
    hoverend:   'mouseleave',
    blur:       'blur',
    focus:      'focus',
    submit:     'submit',
    keydown:    'keydown',
    keyup:      'keyup',
    dblclick:   'dblclick',
    contextmenu:'contextmenu',
  };
  const domEvent = eventMap[rawEvent] ?? rawEvent;

  // Debounce support — check if element has __arx_debounce set by modifier
  const debounceMs = (el as unknown as Record<string, unknown>).__arx_debounce as number | undefined;
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const handler = (): void => {
    for (const action of node.actions) {
      if (action.kind === 'assign') {
        const cur = state.get(action.var) ?? 0;
        const val = resolveValue(action.val, state, ctx);
        if (action.op === '+=') {
          if (typeof cur === 'string' || typeof val === 'string') {
            state.set(action.var, String(cur) + String(val));
          } else {
            state.set(action.var, (cur as number) + (val as number));
          }
        } else if (action.op === '-=') {
          state.set(action.var, (cur as number) - (val as number));
        } else {
          state.set(action.var, val);
        }
      }

      if (action.kind === 'call') {
        const rArgs = action.args.map(a =>
          'key' in a
            ? { key: (a as { key: string; val: ValueNode }).key, val: resolveValue((a as { key: string; val: ValueNode }).val, state, ctx) }
            : resolveValue(a as ValueNode, state, ctx)
        );

        if (action.fn === 'navigate') {
          const params = (typeof rArgs[1] === 'object' && rArgs[1] !== null)
            ? rArgs[1] as Record<string, unknown>
            : {};
          rt.navigate(String(rArgs[0]), params);
        }
        else if (action.fn === 'back') rt.back();
        else if (action.fn === 'send') {
          const pl: Record<string, unknown> = {};
          for (const a of rArgs) {
            if (a && typeof a === 'object' && 'key' in a) {
              pl[(a as { key: string; val: unknown }).key] = (a as { key: string; val: unknown }).val;
            }
          }
          rt.send(pl);
        }
        else if (action.fn === 'toast') {
          const msg      = String(rArgs[0] ?? '');
          const type     = (rArgs[1] ? String(rArgs[1]) : 'info') as ToastType;
          const duration = typeof rArgs[2] === 'number' ? rArgs[2] : 3000;
          showToast(msg, type, duration);
        }
        else if (action.fn === 'fetch') {
          const url    = String(rArgs[0] ?? '');
          const into   = action.into;
          // Auto-manage loading/error state
          if (into) {
            state.set(`${into}Loading`, true);
            state.set(`${into}Error`, null);
          }
          const result = rt.fetch(url);
          if (into) {
            Promise.resolve(result)
              .then(data => {
                state.set(into, data);
                state.set(`${into}Loading`, false);
              })
              .catch(err => {
                state.set(`${into}Error`, String(err));
                state.set(`${into}Loading`, false);
                console.error(`[Architex] fetch("${url}") failed:`, err);
              });
          }
        }
        // Feature 12: Clipboard copy
        else if (action.fn === 'copy') {
          const text = String(rArgs[0] ?? '');
          navigator.clipboard?.writeText(text).catch(() => {});
        }
        // Feature 13: Web Share API
        else if (action.fn === 'share') {
          const shareData: { title?: string; text?: string; url?: string } = {};
          for (const a of rArgs) {
            if (a && typeof a === 'object' && 'key' in a) {
              const kv = a as { key: string; val: unknown };
              if (kv.key === 'title') shareData.title = String(kv.val ?? '');
              if (kv.key === 'text')  shareData.text  = String(kv.val ?? '');
              if (kv.key === 'url')   shareData.url   = String(kv.val ?? '');
            }
          }
          if (!shareData.title && rArgs[0] && typeof rArgs[0] === 'string') shareData.title = rArgs[0];
          if (!shareData.text  && rArgs[1] && typeof rArgs[1] === 'string') shareData.text  = String(rArgs[1]);
          if (!shareData.url   && rArgs[2] && typeof rArgs[2] === 'string') shareData.url   = String(rArgs[2]);
          navigator.share?.(shareData).catch(() => {});
        }
        // Feature 14: Haptic feedback
        else if (action.fn === 'haptic' || action.fn === 'vibrate') {
          const pattern = typeof rArgs[0] === 'number' ? rArgs[0] : 50;
          navigator.vibrate?.(pattern);
        }
        // Feature 26: Conditional action if(cond, then, else)
        else if (action.fn === 'if') {
          const cond = rArgs[0];
          if (cond) {
            // Execute "then" action — arg[1] should be a funcall ValueNode
            const thenArg = action.args[1];
            if (thenArg && !('key' in thenArg) && (thenArg as ValueNode).kind === 'funcall') {
              const fc = thenArg as Extract<ValueNode, { kind: 'funcall' }>;
              _execFuncall(fc.fn, fc.args, state, ctx, rt);
            }
          } else {
            // Execute "else" action
            const elseArg = action.args[2];
            if (elseArg && !('key' in elseArg) && (elseArg as ValueNode).kind === 'funcall') {
              const fc = elseArg as Extract<ValueNode, { kind: 'funcall' }>;
              _execFuncall(fc.fn, fc.args, state, ctx, rt);
            }
          }
        }
        // Feature 23: Array mutation actions
        else if (action.fn === 'push') {
          const arrKey = action.args[0] && !('key' in action.args[0]) && (action.args[0] as ValueNode).kind === 'reactive'
            ? (action.args[0] as Extract<ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            if (Array.isArray(arr)) {
              state.set(arrKey, [...arr, rArgs[1]]);
            }
          }
        }
        else if (action.fn === 'pop') {
          const arrKey = action.args[0] && !('key' in action.args[0]) && (action.args[0] as ValueNode).kind === 'reactive'
            ? (action.args[0] as Extract<ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            if (Array.isArray(arr)) state.set(arrKey, arr.slice(0, -1));
          }
        }
        else if (action.fn === 'remove') {
          const arrKey = action.args[0] && !('key' in action.args[0]) && (action.args[0] as ValueNode).kind === 'reactive'
            ? (action.args[0] as Extract<ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            const idx = typeof rArgs[1] === 'number' ? rArgs[1] : -1;
            if (Array.isArray(arr) && idx >= 0 && idx < arr.length) {
              const copy = [...arr]; copy.splice(idx, 1); state.set(arrKey, copy);
            }
          }
        }
        else if (action.fn === 'sort') {
          const arrKey = action.args[0] && !('key' in action.args[0]) && (action.args[0] as ValueNode).kind === 'reactive'
            ? (action.args[0] as Extract<ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            if (Array.isArray(arr)) state.set(arrKey, [...arr].sort());
          }
        }
        else if (action.fn === 'reverse') {
          const arrKey = action.args[0] && !('key' in action.args[0]) && (action.args[0] as ValueNode).kind === 'reactive'
            ? (action.args[0] as Extract<ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            if (Array.isArray(arr)) state.set(arrKey, [...arr].reverse());
          }
        }
        // Feature 27: Camera access
        else if (action.fn === 'camera') {
          const into = action.into ?? (typeof rArgs[0] === 'string' ? rArgs[0] : null);
          if (into && typeof navigator !== 'undefined' && navigator.mediaDevices) {
            navigator.mediaDevices.getUserMedia({ video: true }).then(stream => {
              const video = document.createElement('video');
              video.srcObject = stream;
              video.play().catch(() => {});
              // Capture single frame after short delay
              setTimeout(() => {
                const canvas = document.createElement('canvas');
                canvas.width = video.videoWidth || 640;
                canvas.height = video.videoHeight || 480;
                canvas.getContext('2d')?.drawImage(video, 0, 0);
                state.set(into, canvas.toDataURL('image/jpeg'));
                stream.getTracks().forEach(t => t.stop());
              }, 500);
            }).catch(err => state.set(`${into}Error`, String(err)));
          }
        }
        // Feature 28: Geolocation
        else if (action.fn === 'geo' || action.fn === 'geolocation') {
          const into = action.into ?? (typeof rArgs[0] === 'string' ? rArgs[0] : null);
          if (into && typeof navigator !== 'undefined' && navigator.geolocation) {
            state.set(`${into}Loading`, true);
            navigator.geolocation.getCurrentPosition(
              pos => {
                state.set(into, { lat: pos.coords.latitude, lng: pos.coords.longitude, accuracy: pos.coords.accuracy });
                state.set(`${into}Loading`, false);
              },
              err => {
                state.set(`${into}Error`, err.message);
                state.set(`${into}Loading`, false);
              },
            );
          }
        }
        // Feature 29: QR Scanner (BarcodeDetector API)
        else if (action.fn === 'qr' || action.fn === 'scanqr') {
          const into = action.into ?? (typeof rArgs[0] === 'string' ? rArgs[0] : null);
          if (into && typeof navigator !== 'undefined' && navigator.mediaDevices) {
            navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } }).then(stream => {
              const video = document.createElement('video');
              video.srcObject = stream;
              video.play().catch(() => {});
              const tryDetect = (): void => {
                const BD = (globalThis as unknown as Record<string, unknown>)['BarcodeDetector'] as
                  (new (opts: { formats: string[] }) => { detect: (src: HTMLVideoElement) => Promise<{ rawValue: string }[]> }) | undefined;
                if (BD) {
                  const detector = new BD({ formats: ['qr_code'] });
                  detector.detect(video).then(codes => {
                    if (codes.length > 0) {
                      state.set(into, codes[0]!.rawValue);
                      stream.getTracks().forEach(t => t.stop());
                    } else { setTimeout(tryDetect, 500); }
                  }).catch(() => { stream.getTracks().forEach(t => t.stop()); });
                } else {
                  state.set(`${into}Error`, 'BarcodeDetector not supported');
                  stream.getTracks().forEach(t => t.stop());
                }
              };
              setTimeout(tryDetect, 300);
            }).catch(err => state.set(`${into}Error`, String(err)));
          }
        }
        // Feature 30: Audio recording
        else if (action.fn === 'record' || action.fn === 'audioRecord') {
          const into = action.into ?? (typeof rArgs[0] === 'string' ? rArgs[0] : null);
          if (into && typeof navigator !== 'undefined' && navigator.mediaDevices) {
            navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
              const chunks: Blob[] = [];
              const recorder = new MediaRecorder(stream);
              recorder.ondataavailable = e => chunks.push(e.data);
              recorder.onstop = () => {
                const blob = new Blob(chunks, { type: 'audio/webm' });
                state.set(into, URL.createObjectURL(blob));
                stream.getTracks().forEach(t => t.stop());
              };
              recorder.start();
              // Store stop function in state for manual control
              state.set(`${into}Stop`, () => recorder.stop());
              // Auto-stop after duration (default 10s)
              const maxMs = typeof rArgs[1] === 'number' ? rArgs[1] : 10000;
              setTimeout(() => { if (recorder.state === 'recording') recorder.stop(); }, maxMs);
            }).catch(err => state.set(`${into}Error`, String(err)));
          }
        }
        // Toggle: toggle(~boolVar)
        else if (action.fn === 'toggle') {
          const varKey = action.args[0] && !('key' in action.args[0]) && (action.args[0] as ValueNode).kind === 'reactive'
            ? (action.args[0] as Extract<ValueNode, { kind: 'reactive' }>).v : null;
          if (varKey) state.set(varKey, !state.get(varKey));
        }
        // Round 3: Push notification
        else if (action.fn === 'notify') {
          const title = String(rArgs[0] ?? 'Notification');
          const body  = rArgs[1] ? String(rArgs[1]) : undefined;
          const icon  = rArgs[2] ? String(rArgs[2]) : undefined;
          if ('Notification' in globalThis) {
            if (Notification.permission === 'granted') {
              new Notification(title, { body, icon });
            } else if (Notification.permission !== 'denied') {
              Notification.requestPermission().then(perm => {
                if (perm === 'granted') new Notification(title, { body, icon });
              });
            }
          }
        }
        else rt[action.fn]?.(...(rArgs as unknown[]));
      }
    }
  };

  // Throttle support — check if element has __arx_throttle set by modifier
  const throttleMs = (el as unknown as Record<string, unknown>).__arx_throttle as number | undefined;
  let throttleLast = 0;

  if (debounceMs && debounceMs > 0) {
    el.addEventListener(domEvent, () => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(handler, debounceMs);
    });
  } else if (throttleMs && throttleMs > 0) {
    el.addEventListener(domEvent, () => {
      const now = Date.now();
      if (now - throttleLast >= throttleMs) { throttleLast = now; handler(); }
    });
  } else {
    el.addEventListener(domEvent, handler);
  }

  // Two-way binding for text inputs: use first assign action
  const firstAssign = node.actions.find(a => a.kind === 'assign');
  if (el.tagName === 'INPUT' && firstAssign?.kind === 'assign') {
    const input = el as HTMLInputElement;
    const textTypes = new Set(['', 'text', 'email', 'password', 'number', 'search', 'tel', 'url']);
    if (textTypes.has(input.type)) {
      input.addEventListener('input', () => state.set(firstAssign.var, input.value));
      const iv = state.get(firstAssign.var);
      if (iv !== undefined) input.value = String(iv);
      state.subscribe(firstAssign.var, v => { if (input.value !== String(v)) input.value = String(v ?? ''); });
    }
  }
}

/** Execute a funcall as an action (used by conditional if/else branches). */
function _execFuncall(
  fn: string, args: ValueNode[], state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): void {
  const rArgs = args.map(a => resolveValue(a, state, ctx));
  if (fn === 'navigate') rt.navigate(String(rArgs[0]), typeof rArgs[1] === 'object' ? rArgs[1] as Record<string, unknown> : {});
  else if (fn === 'back') rt.back();
  else if (fn === 'toast') {
    showToast(String(rArgs[0] ?? ''), (rArgs[1] ? String(rArgs[1]) : 'info') as ToastType, typeof rArgs[2] === 'number' ? rArgs[2] : 3000);
  }
  else if (fn === 'copy') navigator.clipboard?.writeText(String(rArgs[0] ?? '')).catch(() => {});
  else if (fn === 'haptic' || fn === 'vibrate') navigator.vibrate?.(typeof rArgs[0] === 'number' ? rArgs[0] : 50);
  else if (fn === 'notify') {
    if ('Notification' in globalThis) {
      const t = String(rArgs[0] ?? 'Notification');
      const b = rArgs[1] ? String(rArgs[1]) : undefined;
      if (Notification.permission === 'granted') new Notification(t, { body: b });
      else if (Notification.permission !== 'denied') Notification.requestPermission().then(p => { if (p === 'granted') new Notification(t, { body: b }); });
    }
  }
  else rt[fn]?.(...(rArgs as unknown[]));
}

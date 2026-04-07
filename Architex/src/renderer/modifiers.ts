/** Apply  :: modifier  styles and reactive bindings to a DOM element. */

import type { Modifier }  from '../ast/modifiers.js';
import type { ValueNode } from '../ast/values.js';
import type { StateAPI }  from '../reactive/types.js';
import type { RenderCtx } from './types.js';
import { resolveValue, reactiveKeysOf } from './values.js';
import { attachGestureFromModifier } from './gestures.js';
import { applyDraggable, applyDroppable } from './dragdrop.js';
import { applyResponsiveModifier, applyMediaModifier } from './responsive.js';

function toCSSLen(v: unknown, fallback: string): string {
  if (v == null) return fallback;
  const s = String(v);
  return /[a-z%]/.test(s) ? s : `${s}px`;
}

/** Check if a modifier argument contains reactive references. */
function hasReactiveArgs(args: ValueNode[]): boolean {
  for (const arg of args) {
    for (const _k of reactiveKeysOf(arg)) return true;
  }
  return false;
}

export function applyModifiers(el: HTMLElement, mods: Modifier[], state: StateAPI, ctx: RenderCtx): void {
  for (const mod of mods) {
    const a0 = mod.args[0] ? resolveValue(mod.args[0], state, ctx) : null;
    const a1 = mod.args[1] ? resolveValue(mod.args[1], state, ctx) : null;
    const a2 = mod.args[2] ? resolveValue(mod.args[2], state, ctx) : null;

    switch (mod.name.toLowerCase()) {
      case 'bold':      el.style.fontWeight     = 'bold'; break;
      case 'italic':    el.style.fontStyle      = 'italic'; break;
      case 'underline': el.style.textDecoration = 'underline'; break;
      case 'strike':    el.style.textDecoration = 'line-through'; break;
      case 'shadow':    el.style.boxShadow      = '0 2px 8px rgba(0,0,0,.18)'; break;
      case 'weight':    el.style.fontWeight     = String(a0 ?? 400); break;
      case 'size':      el.style.fontSize       = toCSSLen(a0, '14px'); break;

      case 'grow':      el.style.flex           = '1'; break;
      case 'shrink':    el.style.flexShrink     = '1'; break;
      case 'wrap':      el.style.flexWrap       = 'wrap'; break;
      case 'center':    el.style.textAlign      = 'center'; break;
      case 'left':      el.style.textAlign      = 'left'; break;
      case 'right':     el.style.textAlign      = 'right'; break;

      case 'color':     el.style.color          = String(a0 ?? ''); break;
      case 'bg':        el.style.background     = String(a0 ?? ''); break;
      case 'border': {
        const color  = String(a0 ?? '#ccc');
        const width  = a1 != null ? toCSSLen(a1, '1px') : '1px';
        const bStyle = a2 != null ? String(a2) : 'solid';
        el.style.border = `${width} ${bStyle} ${color}`;
        break;
      }
      case 'radius':    el.style.borderRadius   = toCSSLen(a0, '8px'); break;
      case 'opacity':   el.style.opacity        = String(a0 ?? 1); break;

      case 'w':         el.style.width          = toCSSLen(a0, ''); break;
      case 'h':         el.style.height         = toCSSLen(a0, ''); break;
      case 'pad':       el.style.padding        = toCSSLen(a0, '8px'); break;
      case 'gap':       el.style.gap            = toCSSLen(a0, '8px'); break;
      case 'minw':      el.style.minWidth       = toCSSLen(a0, ''); break;
      case 'maxw':      el.style.maxWidth       = toCSSLen(a0, ''); break;
      case 'minh':      el.style.minHeight      = toCSSLen(a0, ''); break;
      case 'maxh':      el.style.maxHeight      = toCSSLen(a0, ''); break;

      case 'placeholder':
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')
          (el as HTMLInputElement).placeholder = String(a0 ?? '');
        break;
      case 'href': if (el.tagName === 'A')   (el as HTMLAnchorElement).href = String(a0 ?? '#'); break;
      case 'src':  if (el.tagName === 'IMG') (el as HTMLImageElement).src   = String(a0 ?? ''); break;
      case 'alt':  if (el.tagName === 'IMG') (el as HTMLImageElement).alt   = String(a0 ?? ''); break;

      case 'transition': {
        const ms   = typeof a0 === 'number' ? a0 : 300;
        const prop = mod.args[1] ? String(resolveValue(mod.args[1], state, ctx)) : 'all';
        el.style.transition = `${prop} ${ms}ms ease`;
        break;
      }
      case 'animate': {
        const animName = String(a0 ?? '');
        if (animName) {
          // animate(fadeIn) → animation: fadeIn ease
          // animate(fadeIn, 500ms) → animation: fadeIn 500ms ease
          const durArg = mod.args[1] ? String(resolveValue(mod.args[1], state, ctx)) : '';
          const duration = durArg || '0.3s';
          // Parse duration: if it's a number, treat as ms
          const durStr = /^\d+$/.test(duration) ? `${duration}ms` : duration;
          el.style.animation = `${animName} ${durStr} ease`;
        }
        break;
      }
      case 'keyframes': el.style.animationName = String(a0 ?? ''); break;

      // ── hover(transform, duration) ──
      case 'hover': {
        // hover(scale(1.05), 200ms) → on mouseenter scale up, on mouseleave scale back
        const transformArg = String(a0 ?? 'scale(1.05)');
        const hoverDur = mod.args[1] ? String(resolveValue(mod.args[1], state, ctx)) : '200ms';
        const durStr = /^\d+$/.test(hoverDur) ? `${hoverDur}ms` : hoverDur;
        el.style.transition = `transform ${durStr} ease`;
        el.addEventListener('mouseenter', () => { el.style.transform = transformArg; });
        el.addEventListener('mouseleave', () => { el.style.transform = ''; });
        break;
      }

      case 'class': {
        const cls = String(a0 ?? '').trim();
        if (cls) el.className = (el.className + ' ' + cls).trim();
        break;
      }

      case 'role':     el.setAttribute('role', String(a0 ?? '')); break;
      case 'label':    el.setAttribute('aria-label', String(a0 ?? '')); break;
      case 'title':    el.title    = String(a0 ?? ''); break;
      case 'tabindex': el.tabIndex = Number(a0 ?? 0); break;
      case 'aria': {
        const attrName = String(a0 ?? '');
        const attrVal  = mod.args[1] ? String(resolveValue(mod.args[1], state, ctx)) : 'true';
        if (attrName) el.setAttribute('aria-' + attrName, attrVal);
        break;
      }

      case 'visible': {
        const arg = mod.args[0];
        if (arg?.kind === 'reactive') {
          const rootKey = arg.v.split('.')[0]!;
          const u = (): void => { el.style.display = resolveValue(arg, state, ctx) ? '' : 'none'; };
          u(); state.subscribe(rootKey, u);
        } else if (arg) {
          el.style.display = resolveValue(arg, state, ctx) ? '' : 'none';
        }
        break;
      }
      case 'hidden': {
        const arg = mod.args[0];
        if (arg?.kind === 'reactive') {
          const rootKey = arg.v.split('.')[0]!;
          const u = (): void => { el.style.display = resolveValue(arg, state, ctx) ? 'none' : ''; };
          u(); state.subscribe(rootKey, u);
        } else if (arg) {
          el.style.display = resolveValue(arg, state, ctx) ? 'none' : '';
        }
        break;
      }
      case 'disabled': {
        const arg = mod.args[0];
        if (arg?.kind === 'reactive') {
          const rootKey = arg.v.split('.')[0]!;
          const u = (): void => { (el as HTMLInputElement).disabled = !!resolveValue(arg, state, ctx); };
          u(); state.subscribe(rootKey, u);
        } else if (arg) {
          (el as HTMLInputElement).disabled = !!resolveValue(arg, state, ctx);
        }
        break;
      }

      // Margin
      case 'margin':   el.style.margin       = toCSSLen(a0, '0'); break;
      case 'mx':       el.style.marginLeft   = el.style.marginRight  = toCSSLen(a0, '0'); break;
      case 'my':       el.style.marginTop    = el.style.marginBottom = toCSSLen(a0, '0'); break;
      case 'mt':       el.style.marginTop    = toCSSLen(a0, '0'); break;
      case 'mr':       el.style.marginRight  = toCSSLen(a0, '0'); break;
      case 'mb':       el.style.marginBottom = toCSSLen(a0, '0'); break;
      case 'ml':       el.style.marginLeft   = toCSSLen(a0, '0'); break;

      // Overflow / Position
      case 'overflow':  el.style.overflow  = String(a0 ?? 'auto'); break;
      case 'overflowx': el.style.overflowX = String(a0 ?? 'auto'); break;
      case 'overflowy': el.style.overflowY = String(a0 ?? 'auto'); break;
      case 'position':
      case 'pos':       el.style.position  = String(a0 ?? 'relative'); break;
      case 'zindex':
      case 'zi':        el.style.zIndex    = String(a0 ?? 0); break;
      case 'cursor':    el.style.cursor    = String(a0 ?? 'pointer'); break;
      case 'pointer':   el.style.cursor    = 'pointer'; break;

      // Flex layout
      case 'flex':      el.style.flex           = String(a0 ?? '1'); break;
      case 'display':   el.style.display        = String(a0 ?? 'block'); break;
      case 'align':     el.style.alignItems     = String(a0 ?? 'center'); break;
      case 'justify':   el.style.justifyContent = String(a0 ?? 'center'); break;
      case 'self':      el.style.alignSelf      = String(a0 ?? 'auto'); break;
      case 'direction': el.style.flexDirection  = String(a0 ?? 'row'); break;

      // Text selection
      case 'noselect':  el.style.userSelect = 'none'; break;

      // Box-sizing
      case 'box':       el.style.boxSizing = String(a0 ?? 'border-box'); break;

      // Letter/line spacing
      case 'tracking':  el.style.letterSpacing = toCSSLen(a0, '0'); break;
      case 'leading':   el.style.lineHeight    = String(a0 ?? 1.5); break;

      // Text overflow
      case 'ellipsis':  el.style.overflow = 'hidden'; el.style.textOverflow = 'ellipsis'; el.style.whiteSpace = 'nowrap'; break;
      case 'clip':      el.style.overflow = 'hidden'; break;

      // Outline / ring
      case 'outline':   el.style.outline = a0 != null ? `2px solid ${String(a0)}` : '2px solid currentColor'; break;
      case 'ring':      el.style.outline = a0 != null ? `${toCSSLen(a0, '2px')} solid currentColor` : '2px solid currentColor'; break;

      // Object-fit (для img)
      case 'fit':       el.style.objectFit = String(a0 ?? 'cover'); break;

      // Pointer events
      case 'events':    el.style.pointerEvents = String(a0 ?? 'auto'); break;
      case 'noevents':  el.style.pointerEvents = 'none'; break;

      // Aspect ratio
      case 'aspect':    el.style.aspectRatio = String(a0 ?? 'auto'); break;

      // Grid (базовые)
      case 'grid':      el.style.display = 'grid'; if (a0 != null) el.style.gridTemplateColumns = String(a0); break;
      case 'cols':      el.style.gridTemplateColumns = typeof a0 === 'number' ? `repeat(${a0}, 1fr)` : String(a0 ?? ''); break;
      case 'rows':      el.style.gridTemplateRows    = typeof a0 === 'number' ? `repeat(${a0}, 1fr)` : String(a0 ?? ''); break;
      case 'span':      el.style.gridColumn          = `span ${String(a0 ?? 1)}`; break;

      // White-space
      case 'nowrap':    el.style.whiteSpace = 'nowrap'; break;
      case 'prewrap':   el.style.whiteSpace = 'pre-wrap'; break;

      // ── NEW: Format filter — format(type, locale?) ──
      case 'format': {
        const formatType = String(a0 ?? 'number');
        const locale     = a1 != null ? String(a1) : undefined;
        const origText   = el.textContent ?? '';
        const num = parseFloat(origText);
        if (!isNaN(num)) {
          if (formatType === 'currency') {
            const currency = locale ?? 'USD';
            el.textContent = new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(num);
          } else if (formatType === 'percent') {
            el.textContent = new Intl.NumberFormat(locale, { style: 'percent' }).format(num);
          } else if (formatType === 'number') {
            el.textContent = new Intl.NumberFormat(locale).format(num);
          } else if (formatType === 'date') {
            el.textContent = new Intl.DateTimeFormat(locale).format(new Date(num));
          } else if (formatType === 'compact') {
            el.textContent = new Intl.NumberFormat(locale, { notation: 'compact' }).format(num);
          }
        }
        break;
      }

      // ── NEW: Debounce — debounce(ms) ──
      case 'debounce': {
        const ms = typeof a0 === 'number' ? a0 : 300;
        (el as unknown as Record<string, unknown>).__arx_debounce = ms;
        break;
      }

      // ── NEW: Screen transition hint — transition(type) ──
      case 'screen_transition':
      case 'screentransition': {
        el.dataset['arxTransition'] = String(a0 ?? 'fade');
        break;
      }

      // ── Validate modifier — form validation ──
      case 'validate': {
        applyValidation(el, mod, state, ctx);
        break;
      }

      // ── Gesture modifiers ──
      case 'swipe':
      case 'swipeleft':
      case 'swiperight':
      case 'swipeup':
      case 'swipedown': {
        if (mod.name === 'swipe') {
          attachGestureFromModifier(el, 'swipe', mod.args[0], state, ctx);
        } else {
          // Legacy swipeXxx names — convert to swipe + direction
          const dir = mod.name.replace('swipe', '');
          const dirNode = { kind: 'ident' as const, v: dir };
          attachGestureFromModifier(el, 'swipe', dirNode, state, ctx);
        }
        break;
      }
      case 'longpress': {
        attachGestureFromModifier(el, 'longpress', mod.args[0], state, ctx);
        break;
      }
      case 'doubletap': {
        attachGestureFromModifier(el, 'doubletap', mod.args[0], state, ctx);
        break;
      }
      case 'pinch': {
        attachGestureFromModifier(el, 'pinch', mod.args[0], state, ctx);
        break;
      }

      // ── Drag & Drop modifiers ──
      case 'draggable': {
        applyDraggable(el, mod, state, ctx);
        break;
      }
      case 'droppable': {
        applyDroppable(el, mod, state, ctx);
        break;
      }

      // ── Responsive breakpoint modifiers ──
      case 'mobile':
      case 'tablet':
      case 'desktop': {
        applyResponsiveModifier(el, mod, state, ctx);
        break;
      }
      case 'media': {
        applyMediaModifier(el, mod, state, ctx);
        break;
      }

      // ── Feature 15: Enhanced Grid Layout ──
      case 'autogrid': {
        el.style.display = 'grid';
        const minWidth = a0 != null ? toCSSLen(a0, '200px') : '200px';
        el.style.gridTemplateColumns = `repeat(auto-fill, minmax(${minWidth}, 1fr))`;
        if (a1 != null) el.style.gap = toCSSLen(a1, '8px');
        break;
      }
      case 'colstart':  el.style.gridColumnStart = String(a0 ?? 'auto'); break;
      case 'colend':    el.style.gridColumnEnd   = String(a0 ?? 'auto'); break;
      case 'rowstart':  el.style.gridRowStart    = String(a0 ?? 'auto'); break;
      case 'rowend':    el.style.gridRowEnd      = String(a0 ?? 'auto'); break;
      case 'rowspan':   el.style.gridRow         = `span ${String(a0 ?? 1)}`; break;

      // ── Feature 16: Position shortcuts ──
      case 'fixed':    el.style.position = 'fixed'; break;
      case 'absolute': el.style.position = 'absolute'; break;
      case 'relative': el.style.position = 'relative'; break;
      case 'sticky':   el.style.position = 'sticky'; break;
      case 'top':      el.style.top    = toCSSLen(a0, '0'); break;
      case 'bottom':   el.style.bottom = toCSSLen(a0, '0'); break;
      case 'inset':    el.style.inset  = toCSSLen(a0, '0'); break;

      // ── Feature 17: Gradient ──
      case 'gradient': {
        const from = String(a0 ?? '#4f8ef7');
        const to   = String(a1 ?? '#6c5ce7');
        const dir  = a2 != null ? String(a2) : 'to right';
        el.style.background = `linear-gradient(${dir}, ${from}, ${to})`;
        break;
      }

      // ── Feature 18: Blur / Glassmorphism ──
      case 'blur': {
        const amount = a0 != null ? toCSSLen(a0, '4px') : '4px';
        el.style.backdropFilter = `blur(${amount})`;
        el.style.setProperty('-webkit-backdrop-filter', `blur(${amount})`);
        break;
      }
      case 'glass': {
        const blurAmt = a0 != null ? toCSSLen(a0, '10px') : '10px';
        el.style.backdropFilter = `blur(${blurAmt})`;
        el.style.setProperty('-webkit-backdrop-filter', `blur(${blurAmt})`);
        el.style.background = 'rgba(255,255,255,0.15)';
        el.style.border = '1px solid rgba(255,255,255,0.2)';
        break;
      }

      // ── Feature 19: Dark/Light theme ──
      case 'theme': {
        const themeName = String(a0 ?? 'auto');
        el.dataset['arxTheme'] = themeName;
        el.classList.add(`arx-theme-${themeName}`);
        break;
      }
      case 'darkbg':   el.style.setProperty('--arx-bg',    String(a0 ?? '#1a1a2e')); break;
      case 'darkcolor': el.style.setProperty('--arx-color', String(a0 ?? '#eee')); break;

      // ── Feature 20: Scroll snap ──
      case 'scrollsnap': {
        const snapType = String(a0 ?? 'x mandatory');
        el.style.setProperty('scroll-snap-type', snapType);
        el.style.overflowX = 'auto';
        break;
      }
      case 'snapstart': el.style.scrollSnapAlign = 'start'; break;
      case 'snapcenter': el.style.scrollSnapAlign = 'center'; break;
      case 'snapend': el.style.scrollSnapAlign = 'end'; break;

      // ── Feature 22: Throttle ──
      case 'throttle': {
        const ms = typeof a0 === 'number' ? a0 : 300;
        (el as unknown as Record<string, unknown>).__arx_throttle = ms;
        break;
      }

      // ── Round 3: RTL ──
      case 'rtl': el.style.direction = 'rtl'; el.setAttribute('dir', 'rtl'); break;
      case 'ltr': el.style.direction = 'ltr'; el.setAttribute('dir', 'ltr'); break;

      // ── Round 3: Spring physics animation ──
      case 'spring': {
        const prop = String(a0 ?? 'transform');
        const stiffness = typeof a1 === 'number' ? a1 : 300;
        const damping = typeof a2 === 'number' ? a2 : 20;
        el.style.transition = `${prop} ${Math.round(1000 / damping)}ms cubic-bezier(0.175, 0.885, 0.32, 1.${Math.min(stiffness, 999)})`;
        break;
      }

      // ── Round 3: Stagger animation for lists ──
      case 'stagger': {
        const delayMs = typeof a0 === 'number' ? a0 : 50;
        // Find child index via parent
        const parentEl = el.parentElement;
        if (parentEl) {
          const idx = Array.from(parentEl.children).indexOf(el);
          el.style.animationDelay = `${idx * delayMs}ms`;
          el.style.animationFillMode = 'both';
        } else {
          // Will be applied after mount via MutationObserver
          requestAnimationFrame(() => {
            const p = el.parentElement;
            if (p) {
              const idx = Array.from(p.children).indexOf(el);
              el.style.animationDelay = `${idx * delayMs}ms`;
              el.style.animationFillMode = 'both';
            }
          });
        }
        break;
      }

      // ── Round 3: Scroll-driven animation ──
      case 'scrolldriven':
      case 'scrollanimate': {
        const animNameSd = String(a0 ?? 'fadeIn');
        if ('IntersectionObserver' in globalThis) {
          el.style.opacity = '0';
          const observer = new IntersectionObserver((entries) => {
            for (const entry of entries) {
              if (entry.isIntersecting) {
                el.style.opacity = '1';
                el.style.animation = `${animNameSd} 0.5s ease forwards`;
                observer.unobserve(el);
              }
            }
          }, { threshold: 0.1 });
          observer.observe(el);
        }
        break;
      }

      // ── Round 3: Focus management ──
      case 'autofocus': {
        requestAnimationFrame(() => el.focus());
        break;
      }
      case 'focustrap': {
        el.addEventListener('keydown', (e: KeyboardEvent) => {
          if (e.key !== 'Tab') return;
          const focusable = el.querySelectorAll<HTMLElement>(
            'a[href],button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'
          );
          if (focusable.length === 0) return;
          const first = focusable[0]!;
          const last  = focusable[focusable.length - 1]!;
          if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last.focus(); }
          } else {
            if (document.activeElement === last) { e.preventDefault(); first.focus(); }
          }
        });
        break;
      }

      // ── Round 4: Parallax ──
      case 'parallax': {
        const speed = typeof a0 === 'number' ? a0 : 0.5;
        const onScroll = (): void => {
          const rect = el.getBoundingClientRect();
          const offset = (rect.top - window.innerHeight / 2) * speed;
          el.style.transform = `translateY(${offset}px)`;
        };
        window.addEventListener('scroll', onScroll, { passive: true });
        onScroll();
        break;
      }

      // ── Round 4: Masonry layout ──
      case 'masonry': {
        el.style.display = 'block';
        el.style.columnCount = String(a0 ?? 3);
        el.style.columnGap = a1 != null ? toCSSLen(a1, '16px') : '16px';
        // Children need break-inside: avoid
        requestAnimationFrame(() => {
          for (const child of Array.from(el.children) as HTMLElement[]) {
            child.style.breakInside = 'avoid';
            child.style.marginBottom = a1 != null ? toCSSLen(a1, '16px') : '16px';
          }
        });
        break;
      }

      // ── Round 4: Sticky header ──
      case 'stickyheader': {
        el.style.position = 'sticky';
        el.style.top = '0';
        el.style.zIndex = '100';
        const originalBg = el.style.background;
        const observer = new IntersectionObserver(([entry]) => {
          if (entry && !entry.isIntersecting) {
            el.style.boxShadow = '0 2px 8px rgba(0,0,0,.1)';
            if (!originalBg) el.style.background = '#fff';
          } else {
            el.style.boxShadow = '';
            if (!originalBg) el.style.background = '';
          }
        }, { threshold: 1.0 });
        // Create sentinel element above
        const sentinel = document.createElement('div');
        sentinel.style.cssText = 'height:1px;margin-bottom:-1px;pointer-events:none';
        el.parentNode?.insertBefore(sentinel, el);
        observer.observe(sentinel);
        break;
      }

      // ── Round 4: Marquee / scrolling text ──
      case 'marquee': {
        const speedMs = typeof a0 === 'number' ? a0 : 10000;
        el.style.overflow = 'hidden';
        el.style.whiteSpace = 'nowrap';
        const inner = document.createElement('span');
        inner.style.display = 'inline-block';
        inner.style.animation = `arx-marquee ${speedMs}ms linear infinite`;
        // Move all children into inner
        requestAnimationFrame(() => {
          while (el.firstChild) inner.appendChild(el.firstChild);
          el.appendChild(inner);
        });
        break;
      }

      // ── Round 4: Glow effect ──
      case 'glow': {
        const glowColor = String(a0 ?? '#4f8ef7');
        const glowSize = a1 != null ? toCSSLen(a1, '8px') : '8px';
        el.style.boxShadow = `0 0 ${glowSize} ${glowColor}`;
        break;
      }

      // ── Liquid-Glass-PRO integration ──
      case 'lg':
      case 'liquidglass': {
        el.classList.add('lg');
        // Optional variant as first arg: ::lg(frosted) or ::liquidglass(obsidian)
        if (a0 && typeof a0 === 'string') {
          el.classList.add(`lg-v-${a0}`);
        }
        break;
      }
      case 'lgvariant': {
        const variant = String(a0 ?? 'clear');
        el.classList.add('lg', `lg-v-${variant}`);
        break;
      }
      case 'lgtype': {
        // Glass type stored as data attribute for runtime to pick up
        el.dataset['lgType'] = String(a0 ?? 'BK7');
        el.classList.add('lg');
        break;
      }
      case 'lgior': {
        el.dataset['lgIor'] = String(a0 ?? '1.45');
        el.classList.add('lg');
        break;
      }
      case 'lgcaustics': {
        el.dataset['lgCaustics'] = a0 === false || a0 === 0 ? 'false' : 'true';
        el.classList.add('lg');
        break;
      }
      case 'lgnocaustics': {
        el.dataset['lgCaustics'] = 'false';
        el.classList.add('lg');
        break;
      }
      case 'lggrain': {
        el.dataset['lgGrain'] = 'true';
        el.classList.add('lg');
        break;
      }
      case 'lgnograin': {
        el.dataset['lgGrain'] = 'false';
        el.classList.add('lg');
        break;
      }
      case 'lgiridescence': {
        el.dataset['lgIridescence'] = a0 === false || a0 === 0 ? 'false' : 'true';
        el.classList.add('lg');
        break;
      }
      case 'lgbreathe': {
        el.dataset['lgBreathe'] = a0 === false || a0 === 0 ? 'false' : 'true';
        el.classList.add('lg');
        break;
      }
      case 'lginteractive': {
        el.classList.add('lg', 'lg-interactive');
        break;
      }
      case 'lgcard': {
        el.classList.add('lg', 'lg-card');
        break;
      }
      case 'lgpill': {
        el.classList.add('lg', 'lg-pill');
        break;
      }
      case 'lgfab': {
        el.classList.add('lg', 'lg-fab');
        break;
      }
      case 'lgopacity': {
        el.dataset['lgOpacity'] = String(a0 ?? '0.12');
        el.classList.add('lg');
        break;
      }
      case 'lgblur': {
        el.dataset['lgBlur'] = String(a0 ?? '7');
        el.classList.add('lg');
        break;
      }
    }
  }

  // ── Feature 3: Reactive Styling — subscribe to reactive args and re-apply ──
  for (const mod of mods) {
    if (!hasReactiveArgs(mod.args)) continue;
    // Skip modifiers that already handle their own reactivity
    const skip = new Set(['visible', 'hidden', 'disabled', 'validate']);
    if (skip.has(mod.name.toLowerCase())) continue;

    const allKeys = new Set<string>();
    for (const arg of mod.args) {
      for (const k of reactiveKeysOf(arg)) allKeys.add(k);
    }
    if (allKeys.size === 0) continue;

    const reapply = (): void => {
      applyReactiveMod(el, mod, state, ctx);
    };
    for (const k of allKeys) {
      state.subscribe(k, reapply);
    }
  }
}

/** Re-apply a single modifier with current reactive values (for Feature 3). */
function applyReactiveMod(el: HTMLElement, mod: Modifier, state: StateAPI, ctx: RenderCtx): void {
  const a0 = mod.args[0] ? resolveValue(mod.args[0], state, ctx) : null;
  const a1 = mod.args[1] ? resolveValue(mod.args[1], state, ctx) : null;
  const a2 = mod.args[2] ? resolveValue(mod.args[2], state, ctx) : null;

  switch (mod.name.toLowerCase()) {
    case 'color':     el.style.color          = String(a0 ?? ''); break;
    case 'bg':        el.style.background     = String(a0 ?? ''); break;
    case 'size':      el.style.fontSize       = toCSSLen(a0, '14px'); break;
    case 'opacity':   el.style.opacity        = String(a0 ?? 1); break;
    case 'w':         el.style.width          = toCSSLen(a0, ''); break;
    case 'h':         el.style.height         = toCSSLen(a0, ''); break;
    case 'pad':       el.style.padding        = toCSSLen(a0, '8px'); break;
    case 'gap':       el.style.gap            = toCSSLen(a0, '8px'); break;
    case 'weight':    el.style.fontWeight     = String(a0 ?? 400); break;
    case 'radius':    el.style.borderRadius   = toCSSLen(a0, '8px'); break;
    case 'border': {
      const color  = String(a0 ?? '#ccc');
      const width  = a1 != null ? toCSSLen(a1, '1px') : '1px';
      const bStyle = a2 != null ? String(a2) : 'solid';
      el.style.border = `${width} ${bStyle} ${color}`;
      break;
    }
    case 'margin':    el.style.margin         = toCSSLen(a0, '0'); break;
    case 'gradient': {
      const from = String(a0 ?? '#4f8ef7');
      const to   = String(a1 ?? '#6c5ce7');
      const dir  = a2 != null ? String(a2) : 'to right';
      el.style.background = `linear-gradient(${dir}, ${from}, ${to})`;
      break;
    }
    case 'blur': {
      const amount = a0 != null ? toCSSLen(a0, '4px') : '4px';
      el.style.backdropFilter = `blur(${amount})`;
      el.style.setProperty('-webkit-backdrop-filter', `blur(${amount})`);
      break;
    }
    case 'class': {
      // Remove all previous arx-reactive classes, add new one
      const cls = String(a0 ?? '').trim();
      if (cls) el.className = (el.className.replace(/\barx-dyn-\S+/g, '').trim() + ' arx-dyn-' + cls).trim();
      break;
    }
    default: break;
  }
}

// ── Feature 2: Form Validation ──────────────────────────────────────────────

/** Validation rule parsed from modifier args. */
interface ValidationRule {
  type:    string;
  params?: unknown[];
  message: string;
}

/** Parse validate() modifier args into validation rules. */
function parseValidationRules(mod: Modifier, state: StateAPI, ctx: RenderCtx): ValidationRule[] {
  const rules: ValidationRule[] = [];
  for (const arg of mod.args) {
    const v = resolveValue(arg, state, ctx);
    const s = String(v ?? '').toLowerCase();

    if (s === 'required') {
      rules.push({ type: 'required', message: 'This field is required' });
    } else if (s === 'email') {
      rules.push({ type: 'email', message: 'Please enter a valid email' });
    } else if (s === 'url') {
      rules.push({ type: 'url', message: 'Please enter a valid URL' });
    } else if (s === 'phone') {
      rules.push({ type: 'phone', message: 'Please enter a valid phone number' });
    }
    // funcall-style: minlen(3), maxlen(100), range(1, 100), pattern("...")
    if (arg.kind === 'funcall') {
      const fn = arg.fn.toLowerCase();
      const fnArgs = arg.args.map(a => resolveValue(a, state, ctx));
      if (fn === 'minlen') {
        rules.push({ type: 'minlen', params: fnArgs, message: `Minimum length is ${fnArgs[0] ?? 0}` });
      } else if (fn === 'maxlen') {
        rules.push({ type: 'maxlen', params: fnArgs, message: `Maximum length is ${fnArgs[0] ?? 0}` });
      } else if (fn === 'range') {
        rules.push({ type: 'range', params: fnArgs, message: `Value must be between ${fnArgs[0] ?? 0} and ${fnArgs[1] ?? 100}` });
      } else if (fn === 'pattern') {
        rules.push({ type: 'pattern', params: fnArgs, message: 'Value does not match the required pattern' });
      }
    }
  }
  return rules;
}

/** Run a single validation rule against a value. */
function validateSingleRule(value: string, rule: ValidationRule): boolean {
  switch (rule.type) {
    case 'required':
      return value.trim().length > 0;
    case 'email':
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
    case 'url':
      return /^https?:\/\/.+/.test(value);
    case 'phone':
      return /^[+]?[\d\s()-]{7,}$/.test(value);
    case 'minlen': {
      const min = Number(rule.params?.[0] ?? 0);
      return value.length >= min;
    }
    case 'maxlen': {
      const max = Number(rule.params?.[0] ?? Infinity);
      return value.length <= max;
    }
    case 'range': {
      const num = parseFloat(value);
      const lo = Number(rule.params?.[0] ?? -Infinity);
      const hi = Number(rule.params?.[1] ?? Infinity);
      return !isNaN(num) && num >= lo && num <= hi;
    }
    case 'pattern': {
      const pat = String(rule.params?.[0] ?? '.*');
      try { return new RegExp(pat).test(value); }
      catch { return true; }
    }
    default:
      return true;
  }
}

/** Apply validation to an input/textarea element. */
function applyValidation(
  el:    HTMLElement,
  mod:   Modifier,
  state: StateAPI,
  ctx:   RenderCtx,
): void {
  if (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA') return;
  const input = el as HTMLInputElement | HTMLTextAreaElement;
  const rules = parseValidationRules(mod, state, ctx);
  if (rules.length === 0) return;

  let errorSpan: HTMLSpanElement | null = null;

  // Mark element as having validation for form-level checks
  (el as unknown as Record<string, unknown>).__arx_validate = true;

  const runValidation = (): void => {
    const value = input.value;
    let firstError: string | null = null;

    for (const rule of rules) {
      if (!validateSingleRule(value, rule)) {
        firstError = rule.message;
        break;
      }
    }

    if (firstError) {
      el.classList.add('arx-invalid');
      el.classList.remove('arx-valid');
      if (!errorSpan) {
        errorSpan = document.createElement('span');
        errorSpan.className = 'arx-error';
        el.parentNode?.insertBefore(errorSpan, el.nextSibling);
      }
      errorSpan.textContent = firstError;
      (el as unknown as Record<string, unknown>).__arx_valid = false;
    } else {
      el.classList.remove('arx-invalid');
      if (value.length > 0) el.classList.add('arx-valid');
      else el.classList.remove('arx-valid');
      if (errorSpan) {
        errorSpan.textContent = '';
      }
      (el as unknown as Record<string, unknown>).__arx_valid = true;
    }
  };

  input.addEventListener('blur', runValidation);
  input.addEventListener('input', runValidation);

  // Store validation runner on the element for form-level validation
  (el as unknown as Record<string, unknown>).__arx_runValidation = runValidation;
}

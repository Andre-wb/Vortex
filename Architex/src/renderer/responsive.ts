/** Responsive breakpoint modifiers for Architex. */

import type { Modifier }  from '../ast/modifiers.js';
import type { StateAPI }  from '../reactive/types.js';
import type { RenderCtx } from './types.js';
import { resolveValue }   from './values.js';

// ── Responsive CSS class injection ──────────────────────────────────────────

let _responsiveCounter = 0;
let _responsiveSheet: CSSStyleSheet | null = null;

function getResponsiveSheet(): CSSStyleSheet {
  if (_responsiveSheet) return _responsiveSheet;

  let styleEl = document.getElementById('arx-responsive-styles') as HTMLStyleElement | null;
  if (!styleEl) {
    styleEl = document.createElement('style');
    styleEl.id = 'arx-responsive-styles';
    document.head.appendChild(styleEl);
  }
  _responsiveSheet = styleEl.sheet as CSSStyleSheet;
  return _responsiveSheet;
}

// ── Modifier-to-CSS mapping ─────────────────────────────────────────────────

interface CSSProp {
  property: string;
  value:    string;
}

function toCSSLen(v: unknown): string {
  if (v == null) return '';
  const s = String(v);
  return /[a-z%]/.test(s) ? s : `${s}px`;
}

function modToCSSProps(innerMod: Modifier, state: StateAPI, ctx: RenderCtx): CSSProp[] {
  const a0 = innerMod.args[0] ? resolveValue(innerMod.args[0], state, ctx) : null;
  const name = innerMod.name.toLowerCase();
  const props: CSSProp[] = [];

  switch (name) {
    case 'w':       props.push({ property: 'width',          value: toCSSLen(a0) }); break;
    case 'h':       props.push({ property: 'height',         value: toCSSLen(a0) }); break;
    case 'size':    props.push({ property: 'font-size',      value: toCSSLen(a0) }); break;
    case 'pad':     props.push({ property: 'padding',        value: toCSSLen(a0) }); break;
    case 'gap':     props.push({ property: 'gap',            value: toCSSLen(a0) }); break;
    case 'margin':  props.push({ property: 'margin',         value: toCSSLen(a0) }); break;
    case 'hidden':  props.push({ property: 'display',        value: 'none' }); break;
    case 'visible': props.push({ property: 'display',        value: 'block' }); break;
    case 'bold':    props.push({ property: 'font-weight',    value: 'bold' }); break;
    case 'center':  props.push({ property: 'text-align',     value: 'center' }); break;
    case 'cols': {
      const n = typeof a0 === 'number' ? `repeat(${a0}, 1fr)` : String(a0 ?? '');
      props.push({ property: 'grid-template-columns', value: n });
      break;
    }
    case 'direction': props.push({ property: 'flex-direction', value: String(a0 ?? 'row') }); break;
    case 'display':   props.push({ property: 'display', value: String(a0 ?? 'block') }); break;
    default:
      // Generic: treat name as CSS property, a0 as value
      if (a0 != null) props.push({ property: name, value: String(a0) });
      break;
  }

  return props;
}

// ── Breakpoint definitions ──────────────────────────────────────────────────

const BREAKPOINTS: Record<string, string> = {
  mobile:  '(max-width: 767px)',
  tablet:  '(min-width: 768px) and (max-width: 1023px)',
  desktop: '(min-width: 1024px)',
};

// ── Apply responsive modifier ───────────────────────────────────────────────

/**
 * Apply a responsive modifier. The outer modifier (mobile/tablet/desktop)
 * wraps an inner modifier in a media query.
 *
 * Usage: `card :: w(300) mobile(w(100%))`
 *
 * The inner modifier is passed as the first argument with the modifier name
 * as an ident and optional value in parens.
 *
 * Since the parser treats `mobile(w(100%))` as a modifier named "mobile"
 * with a single ident arg "w" potentially followed by more args,
 * we need to reconstruct the inner modifier.
 */
export function applyResponsiveModifier(
  el:        HTMLElement,
  mod:       Modifier,
  state:     StateAPI,
  ctx:       RenderCtx,
): void {
  const breakpointName = mod.name.toLowerCase();
  const mediaQuery = BREAKPOINTS[breakpointName];
  if (!mediaQuery) return;

  // Reconstruct inner modifier from args
  // First arg should be an ident (the inner modifier name)
  // Remaining args are the inner modifier's args
  const firstArg = mod.args[0];
  if (!firstArg || firstArg.kind !== 'ident') return;

  const innerMod: Modifier = {
    name: firstArg.v,
    args: mod.args.slice(1),
  };

  const cssProps = modToCSSProps(innerMod, state, ctx);
  if (cssProps.length === 0) return;

  const className = `arx-r-${_responsiveCounter++}`;
  el.classList.add(className);

  const declarations = cssProps
    .map(p => `${p.property}: ${p.value} !important`)
    .join('; ');

  const rule = `@media ${mediaQuery} { .${className} { ${declarations}; } }`;

  try {
    const sheet = getResponsiveSheet();
    sheet.insertRule(rule, sheet.cssRules.length);
  } catch {
    // Fallback: insert via textContent if insertRule fails
    const styleEl = document.getElementById('arx-responsive-styles');
    if (styleEl) styleEl.textContent += rule;
  }
}

// ── @media directive support via matchMedia ─────────────────────────────────

/**
 * Apply @media directive for conditional rendering.
 * Uses `window.matchMedia()` to reactively show/hide children.
 *
 * The modifier form: `:: media(max, 768)` or `:: media(min, 1024)`
 */
export function applyMediaModifier(
  el:    HTMLElement,
  mod:   Modifier,
  state: StateAPI,
  ctx:   RenderCtx,
): void {
  const type  = mod.args[0] ? String(resolveValue(mod.args[0], state, ctx)) : 'max';
  const value = mod.args[1] ? Number(resolveValue(mod.args[1], state, ctx)) : 768;

  const query = type === 'min'
    ? `(min-width: ${value}px)`
    : `(max-width: ${value}px)`;

  const mql = window.matchMedia(query);

  const update = (): void => {
    el.style.display = mql.matches ? '' : 'none';
  };

  update();

  // Subscribe to media query changes
  if (mql.addEventListener) {
    mql.addEventListener('change', update);
  }
}

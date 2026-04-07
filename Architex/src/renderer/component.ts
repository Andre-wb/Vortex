/** Render a ComponentNode into an HTMLElement. */

import type { ComponentNode, Node } from '../ast/nodes.js';
import type { StateAPI }            from '../reactive/types.js';
import type { RuntimeHooks, RenderCtx } from './types.js';
import { TAG_MAP }                  from './tags.js';
import { resolveValue, bindValue, reactiveKeysOf, toDisplayString } from './values.js';
import { applyModifiers }           from './modifiers.js';
import { attachHandler }            from './handlers.js';
import { renderNode }               from './index.js';

export function renderComponent(
  node: ComponentNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement {
  const nm  = node.name.toLowerCase();

  // ── Special components ──────────────────────────────────────────────────

  // P1 #10 — modal overlay
  if (nm === 'modal') return renderModal(node, state, ctx, rt);

  // P1 #11 — tabs
  if (nm === 'tabs') return renderTabs(node, state, ctx, rt);

  // Toast / snackbar — auto-dismiss notification
  if (nm === 'toast' || nm === 'snackbar') return renderToast(node, state, ctx, rt);

  // Spinner — CSS-only loading animation
  if (nm === 'spinner') return renderSpinner(node, state, ctx);

  // Skeleton — shimmer loading placeholder
  if (nm === 'skeleton') return renderSkeleton(node, state, ctx);

  // Accordion / Collapsible
  if (nm === 'accordion') return renderAccordion(node, state, ctx, rt);

  // Carousel / Swiper
  if (nm === 'carousel') return renderCarousel(node, state, ctx, rt);

  // Bottom Sheet
  if (nm === 'bottomsheet') return renderBottomSheet(node, state, ctx, rt);

  // Date/Time Picker
  if (nm === 'datepicker') return renderDatePicker(node, state, ctx);

  // Search input with debounce
  if (nm === 'search') return renderSearch(node, state, ctx, rt);

  // Avatar
  if (nm === 'avatar') return renderAvatar(node, state, ctx);

  // Chip / Tag
  if (nm === 'chip' || nm === 'tag') return renderChip(node, state, ctx, rt);

  // Stepper / Wizard
  if (nm === 'stepper' || nm === 'wizard') return renderStepper(node, state, ctx, rt);

  // Infinite Scroll
  if (nm === 'infinitescroll') return renderInfiniteScroll(node, state, ctx, rt);

  // Pull to Refresh
  if (nm === 'pullrefresh') return renderPullRefresh(node, state, ctx, rt);

  // ── Round 3 components ──
  if (nm === 'virtuallist')    return renderVirtualList(node, state, ctx, rt);
  if (nm === 'transitiongroup') return renderTransitionGroup(node, state, ctx, rt);
  if (nm === 'richtext' || nm === 'markdown') return renderRichText(node, state, ctx, rt);
  if (nm === 'colorpicker')    return renderColorPicker(node, state, ctx);
  if (nm === 'rating')         return renderRating(node, state, ctx, rt);
  if (nm === 'tooltip' || nm === 'popover') return renderTooltip(node, state, ctx, rt);
  if (nm === 'breadcrumb')     return renderBreadcrumb(node, state, ctx, rt);
  if (nm === 'pagination')     return renderPagination(node, state, ctx, rt);
  if (nm === 'dropdown')       return renderDropdown(node, state, ctx, rt);
  if (nm === 'gallery' || nm === 'lightbox') return renderGallery(node, state, ctx, rt);

  // ── Round 4 components ──
  if (nm === 'sortablelist')   return renderSortableList(node, state, ctx, rt);
  if (nm === 'commandpalette') return renderCommandPalette(node, state, ctx, rt);
  if (nm === 'datatable')      return renderDataTable(node, state, ctx, rt);
  if (nm === 'treeview' || nm === 'tree') return renderTreeView(node, state, ctx, rt);
  if (nm === 'calendar')       return renderCalendar(node, state, ctx, rt);
  if (nm === 'timeline')       return renderTimeline(node, state, ctx, rt);
  if (nm === 'chatbubble' || nm === 'bubble') return renderChatBubble(node, state, ctx, rt);
  if (nm === 'codeeditor' || nm === 'codeblock') return renderCodeEditor(node, state, ctx, rt);
  if (nm === 'signaturepad' || nm === 'signature') return renderSignaturePad(node, state, ctx, rt);
  if (nm === 'confetti')       return renderConfetti(node, state, ctx);
  if (nm === 'typewriter')     return renderTypewriter(node, state, ctx);
  if (nm === 'countup' || nm === 'counter') return renderCountUp(node, state, ctx);
  if (nm === 'otpinput' || nm === 'otp') return renderOTPInput(node, state, ctx);
  if (nm === 'fileupload' || nm === 'dropzone') return renderFileUpload(node, state, ctx, rt);
  if (nm === 'sparkline')      return renderSparkline(node, state, ctx);

  // ── Round 4 batch 2 components ──
  if (nm === 'swipecard' || nm === 'swipe') return renderSwipeCard(node, state, ctx, rt);
  if (nm === 'circularprogress' || nm === 'circleprogress') return renderCircularProgress(node, state, ctx);
  if (nm === 'audioplayer')    return renderAudioPlayer(node, state, ctx, rt);
  if (nm === 'videoplayer')    return renderVideoPlayer(node, state, ctx, rt);
  if (nm === 'qrcode')         return renderQRCode(node, state, ctx);
  if (nm === 'phoneinput')     return renderPhoneInput(node, state, ctx);
  if (nm === 'cropper')        return renderCropper(node, state, ctx);
  if (nm === 'diffviewer' || nm === 'diff') return renderDiffViewer(node, state, ctx);
  if (nm === 'kanban')         return renderKanban(node, state, ctx, rt);
  if (nm === 'meter' || nm === 'gauge') return renderMeter(node, state, ctx);

  // ── Round 5 batch 1 ──
  if (nm === 'chart')              return renderChart(node, state, ctx, rt);
  if (nm === 'heatmap')            return renderHeatmap(node, state, ctx);
  if (nm === 'orgchart')           return renderOrgChart(node, state, ctx, rt);
  if (nm === 'funnel')             return renderFunnel(node, state, ctx);
  if (nm === 'splitpane')          return renderSplitPane(node, state, ctx, rt);
  if (nm === 'drawer' || nm === 'sidebar') return renderDrawer(node, state, ctx, rt);
  if (nm === 'bottomnav')          return renderBottomNav(node, state, ctx, rt);
  if (nm === 'fab' || nm === 'speeddial') return renderFAB(node, state, ctx, rt);
  if (nm === 'appbar' || nm === 'toolbar') return renderAppBar(node, state, ctx, rt);
  if (nm === 'terminal')           return renderTerminal(node, state, ctx, rt);

  // ── Round 5 batch 2 ──
  if (nm === 'autocomplete')     return renderAutocomplete(node, state, ctx, rt);
  if (nm === 'taginput')         return renderTagInput(node, state, ctx);
  if (nm === 'wysiwyg')          return renderWysiwyg(node, state, ctx);
  if (nm === 'rangedual' || nm === 'dualrange') return renderDualRange(node, state, ctx);
  if (nm === 'creditcard')       return renderCreditCard(node, state, ctx);
  if (nm === 'emojipicker')      return renderEmojiPicker(node, state, ctx, rt);
  if (nm === 'mention')          return renderMention(node, state, ctx);
  if (nm === 'reactions')        return renderReactions(node, state, ctx, rt);
  if (nm === 'presence')         return renderPresence(node, state, ctx);
  if (nm === 'thread')           return renderThread(node, state, ctx, rt);

  // User-defined component (@component definition) with LOCAL state isolation
  const compDef = rt.getCompDef?.(nm);
  if (compDef) {
    const def = compDef as import('../ast/nodes.js').ComponentDefNode;

    // Create a scoped state proxy: local ~vars shadow global state
    const localState = createScopedState(state, def.body);

    const defCtx: RenderCtx = { ...ctx };
    def.params.forEach((p, i) => {
      defCtx[p] = node.args[i] ? resolveValue(node.args[i]!, state, ctx) : undefined;
      // Also inject params into local state for reactive access
      localState.set(p, defCtx[p]);
    });

    // Pre-render caller's children for @slot insertion
    const callerChildren: HTMLElement[] = [];
    const namedSlotChildren: Record<string, HTMLElement[]> = {};
    for (const child of node.children) {
      const c = renderNode(child, state, ctx, rt);
      if (c) callerChildren.push(c);
    }

    // Check if the component definition uses any @slot nodes
    const hasSlot = def.body.some(c => c.kind === 'slot');

    const wrapper = document.createElement('div');
    wrapper.className = `arx-comp-${nm}`;
    for (const child of def.body) {
      if (child.kind === 'slot') {
        // Insert caller's children at this @slot position
        const slotName = child.name;
        if (slotName === 'default') {
          for (const c of callerChildren) wrapper.appendChild(c);
        } else {
          const named = namedSlotChildren[slotName];
          if (named) for (const c of named) wrapper.appendChild(c);
        }
      } else {
        const c = renderNode(child, localState, defCtx, rt);
        if (c) wrapper.appendChild(c);
      }
    }

    // If no @slot in component definition, append children at the end (backward compat)
    if (!hasSlot) {
      for (const c of callerChildren) wrapper.appendChild(c);
    }

    applyModifiers(wrapper, node.mods, state, ctx);
    return wrapper;
  }

  // ── Standard element ────────────────────────────────────────────────────

  const tag = TAG_MAP[nm] ?? 'div';
  const el  = document.createElement(tag);
  el.className = `arx-${nm}`;

  // Layout defaults
  if (nm === 'row')    el.style.display = 'flex';
  if (nm === 'col')    { el.style.display = 'flex'; el.style.flexDirection = 'column'; }
  if (nm === 'scroll') el.style.overflowY = 'auto';
  if (nm === 'spacer') el.style.flex = '1';
  if (nm === 'card')   { el.style.borderRadius = '8px'; el.style.padding = '16px'; el.style.boxShadow = '0 2px 8px rgba(0,0,0,.1)'; }

  // Video — set attributes
  if (nm === 'video') {
    const videoEl = el as HTMLVideoElement;
    videoEl.controls = true;
    if (node.args[0]) videoEl.src = String(resolveValue(node.args[0], state, ctx) ?? '');
    // Check modifiers for autoplay, loop, muted, poster
    for (const m of node.mods) {
      if (m.name === 'autoplay')  videoEl.autoplay  = true;
      if (m.name === 'loop')      videoEl.loop      = true;
      if (m.name === 'muted')     videoEl.muted     = true;
      if (m.name === 'controls')  videoEl.controls  = m.args[0] ? !!resolveValue(m.args[0], state, ctx) : true;
      if (m.name === 'poster')    videoEl.poster    = String(resolveValue(m.args[0]!, state, ctx) ?? '');
    }
  }

  // Audio — set attributes
  if (nm === 'audio') {
    const audioEl = el as HTMLAudioElement;
    audioEl.controls = true;
    if (node.args[0]) audioEl.src = String(resolveValue(node.args[0], state, ctx) ?? '');
    for (const m of node.mods) {
      if (m.name === 'autoplay') audioEl.autoplay = true;
      if (m.name === 'loop')     audioEl.loop     = true;
      if (m.name === 'muted')    audioEl.muted    = true;
      if (m.name === 'controls') audioEl.controls = m.args[0] ? !!resolveValue(m.args[0], state, ctx) : true;
    }
  }

  // Source element (for video/audio)
  if (nm === 'source') {
    if (node.args[0]) (el as HTMLSourceElement).src  = String(resolveValue(node.args[0], state, ctx) ?? '');
    if (node.args[1]) (el as HTMLSourceElement).type = String(resolveValue(node.args[1], state, ctx) ?? '');
  }

  // P1 #8 — checkbox / toggle
  if (nm === 'checkbox' || nm === 'toggle') {
    (el as HTMLInputElement).type = 'checkbox';
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    if (stateKey) {
      const update = (): void => { (el as HTMLInputElement).checked = !!(state.get(stateKey)); };
      update();
      state.subscribe(stateKey, update);
      el.addEventListener('change', () => state.set(stateKey, (el as HTMLInputElement).checked));
    }
  }

  // P1 #9 — textarea two-way binding
  else if (nm === 'textarea') {
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    if (stateKey) {
      (el as HTMLTextAreaElement).value = String(state.get(stateKey) ?? '');
      state.subscribe(stateKey, v => { (el as HTMLTextAreaElement).value = String(v ?? ''); });
      el.addEventListener('input', () => state.set(stateKey, (el as HTMLTextAreaElement).value));
    }
    if (node.args[0]?.kind === 'string') (el as HTMLTextAreaElement).placeholder = node.args[0].v;
  }

  // Range slider — two-way binding
  else if (nm === 'range' || nm === 'slider') {
    (el as HTMLInputElement).type = 'range';
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    // Optional min/max from args[1] and args[2]
    if (node.args[1]) (el as HTMLInputElement).min = String(resolveValue(node.args[1], state, ctx) ?? '0');
    if (node.args[2]) (el as HTMLInputElement).max = String(resolveValue(node.args[2], state, ctx) ?? '100');
    if (stateKey) {
      (el as HTMLInputElement).value = String(state.get(stateKey) ?? '0');
      state.subscribe(stateKey, v => { (el as HTMLInputElement).value = String(v ?? '0'); });
      el.addEventListener('input', () => state.set(stateKey, parseFloat((el as HTMLInputElement).value)));
    }
  }

  // Radio button
  else if (nm === 'radio') {
    (el as HTMLInputElement).type = 'radio';
    // args[0]: reactive state var holding the selected value
    // args[1]: this radio's value
    // args[2]: optional group name (name attribute)
    const stateKey   = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    const radioValue = node.args[1] ? String(resolveValue(node.args[1], state, ctx) ?? '') : '';
    const groupName  = node.args[2] ? String(resolveValue(node.args[2], state, ctx) ?? '') : stateKey ?? 'group';

    (el as HTMLInputElement).value = radioValue;
    (el as HTMLInputElement).name  = groupName;

    if (stateKey) {
      const updateChecked = (): void => {
        (el as HTMLInputElement).checked = state.get(stateKey) === radioValue;
      };
      updateChecked();
      state.subscribe(stateKey, updateChecked);
      el.addEventListener('change', () => {
        if ((el as HTMLInputElement).checked) state.set(stateKey, radioValue);
      });
    }
  }

  // Progress bar
  else if (nm === 'progress') {
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    const maxVal   = node.args[1] ? Number(resolveValue(node.args[1], state, ctx) ?? 100) : 100;
    (el as HTMLProgressElement).max = maxVal;
    if (stateKey) {
      const updateProg = (): void => { (el as HTMLProgressElement).value = Number(state.get(stateKey) ?? 0); };
      updateProg();
      state.subscribe(stateKey, updateProg);
    }
  }

  // Form element — with validation support
  else if (nm === 'form') {
    el.addEventListener('submit', e => {
      e.preventDefault();
      // Run all child validations
      const validatedInputs = el.querySelectorAll('input, textarea');
      let allValid = true;
      validatedInputs.forEach(inp => {
        const rec = inp as unknown as Record<string, unknown>;
        if (rec.__arx_validate) {
          const runValidation = rec.__arx_runValidation as (() => void) | undefined;
          if (runValidation) runValidation();
          if (!rec.__arx_valid) allValid = false;
        }
      });
      // Only dispatch arx:submit if all valid
      if (allValid) {
        el.dispatchEvent(new CustomEvent('arx:formvalid', { bubbles: true }));
      }
    });
  }

  // P1 #7 — select two-way binding
  else if (nm === 'select') {
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    // Build options first
    for (const child of node.children) {
      const c = renderNode(child, state, ctx, rt);
      if (c) el.appendChild(c);
    }
    if (stateKey) {
      (el as HTMLSelectElement).value = String(state.get(stateKey) ?? '');
      state.subscribe(stateKey, v => { (el as HTMLSelectElement).value = String(v ?? ''); });
      el.addEventListener('change', () => state.set(stateKey, (el as HTMLSelectElement).value));
    }
    applyModifiers(el, node.mods, state, ctx);
    for (const h of node.handlers) attachHandler(el, h, state, ctx, rt);
    return el;
  }

  // P1 #7 — option element
  else if (nm === 'option') {
    const labelNode = node.args[0];
    const valNode   = node.args[1] ?? labelNode;

    const updateOption = (): void => {
      const label = labelNode ? String(toDisplayString(resolveValue(labelNode, state, ctx)) ?? '') : '';
      const val   = valNode   ? String(toDisplayString(resolveValue(valNode,   state, ctx)) ?? '') : label;
      (el as HTMLOptionElement).value = val;
      el.textContent = label;
    };
    updateOption();

    // Subscribe to reactive args
    if (labelNode?.kind === 'reactive') state.subscribe(labelNode.v.split('.')[0]!, updateOption);
    if (valNode?.kind === 'reactive' && valNode !== labelNode) state.subscribe(valNode.v.split('.')[0]!, updateOption);

    applyModifiers(el, node.mods, state, ctx);
    return el;
  }

  // Standard input
  else if (tag === 'input') {
    // Content from positional args — handled below in main args block
  }

  // ── Content from positional args ─────────────────────────────────────────
  if (node.args.length > 0) {
    const first    = node.args[0]!;
    const resolved = resolveValue(first, state, ctx);

    if (tag === 'input') {
      (el as HTMLInputElement).placeholder = String(resolved ?? '');
    } else if (tag === 'img') {
      (el as HTMLImageElement).src = String(resolved ?? '');
    } else if (tag === 'a' && node.args[1]) {
      (el as HTMLAnchorElement).href = String(resolved ?? '#');
      el.textContent = String(resolveValue(node.args[1], state, ctx) ?? '');
    } else if (nm === 'icon') {
      el.textContent = String(resolved ?? '');
    } else if (nm !== 'checkbox' && nm !== 'toggle' && nm !== 'select' && nm !== 'textarea') {
      // Б9 fix: all args joined live when any arg is reactive/interpolated
      const hasReactive = node.args.some(a => a.kind === 'reactive' || a.kind === 'interpolated');
      if (hasReactive) {
        const resolveAll = (): string => node.args
          .map(a => toDisplayString(resolveValue(a, state, ctx)))
          .filter(s => s !== '').join(' ');
        el.textContent = resolveAll();
        const keys = new Set<string>();
        for (const a of node.args) for (const k of reactiveKeysOf(a)) keys.add(k);
        for (const k of keys) state.subscribe(k, () => { el.textContent = resolveAll(); });
      } else {
        el.textContent = toDisplayString(resolved);
        for (let i = 1; i < node.args.length; i++) {
          const extra = toDisplayString(resolveValue(node.args[i]!, state, ctx));
          if (extra) el.textContent += ' ' + extra;
        }
      }
    }
  }

  applyModifiers(el, node.mods, state, ctx);

  for (const h of node.handlers) attachHandler(el, h, state, ctx, rt);

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) el.appendChild(c);
  }

  return el;
}

// ── P1 #10: Modal overlay ─────────────────────────────────────────────────────

function renderModal(
  node:  ComponentNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement {
  const overlay = document.createElement('div');
  overlay.className = 'arx-modal-overlay';
  overlay.style.cssText =
    'position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;' +
    'align-items:center;justify-content:center;z-index:1000';

  const dialog = document.createElement('div');
  dialog.className = 'arx-modal';
  dialog.style.cssText =
    'background:#fff;border-radius:12px;padding:24px;min-width:280px;' +
    'max-width:90vw;max-height:85vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.2)';

  // Click outside to close (if a handler is attached to the overlay)
  for (const h of node.handlers) attachHandler(overlay, h, state, ctx, rt);
  dialog.addEventListener('click', e => e.stopPropagation());

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) dialog.appendChild(c);
  }

  applyModifiers(overlay, node.mods, state, ctx);
  overlay.appendChild(dialog);
  return overlay;
}

// ── Toast / Snackbar ──────────────────────────────────────────────────────────

function renderToast(
  node:  ComponentNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement {
  const toast = document.createElement('div');
  toast.className = 'arx-toast';
  toast.style.cssText =
    'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);' +
    'background:#323232;color:#fff;padding:12px 24px;border-radius:8px;' +
    'font-size:14px;z-index:2000;box-shadow:0 4px 12px rgba(0,0,0,.3);' +
    'transition:opacity 0.3s ease,transform 0.3s ease;opacity:0;transform:translateX(-50%) translateY(16px)';

  // Content from first arg
  if (node.args[0]) {
    const hasReactive = node.args.some(a => a.kind === 'reactive' || a.kind === 'interpolated');
    if (hasReactive) {
      const resolveAll = (): string => node.args
        .map(a => toDisplayString(resolveValue(a, state, ctx)))
        .filter(s => s !== '').join(' ');
      toast.textContent = resolveAll();
      const keys = new Set<string>();
      for (const a of node.args) for (const k of reactiveKeysOf(a)) keys.add(k);
      for (const k of keys) state.subscribe(k, () => { toast.textContent = resolveAll(); });
    } else {
      toast.textContent = toDisplayString(resolveValue(node.args[0], state, ctx));
    }
  }

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) toast.appendChild(c);
  }

  applyModifiers(toast, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(toast, h, state, ctx, rt);

  // Auto-dismiss: default 3000ms, configurable via duration(ms) modifier
  let duration = 3000;
  for (const m of node.mods) {
    if (m.name === 'duration' && m.args[0]) {
      duration = Number(resolveValue(m.args[0], state, ctx) ?? 3000);
    }
  }

  // Reactive visibility: show when bound state is truthy
  const stateKey = node.args.find(a => a.kind === 'reactive');
  if (stateKey?.kind === 'reactive') {
    const show = (): void => {
      if (state.get(stateKey.v)) {
        toast.style.opacity = '1';
        toast.style.transform = 'translateX(-50%) translateY(0)';
        if (duration > 0) {
          setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(-50%) translateY(16px)';
            setTimeout(() => state.set(stateKey.v, false), 300);
          }, duration);
        }
      } else {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-50%) translateY(16px)';
      }
    };
    show();
    state.subscribe(stateKey.v.split('.')[0]!, show);
  } else {
    // Auto-show on render
    requestAnimationFrame(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(-50%) translateY(0)';
      if (duration > 0) {
        setTimeout(() => {
          toast.style.opacity = '0';
          toast.style.transform = 'translateX(-50%) translateY(16px)';
        }, duration);
      }
    });
  }

  return toast;
}

// ── P1 #11: Tabs ──────────────────────────────────────────────────────────────

function renderTabs(
  node:  ComponentNode,
  state: StateAPI,
  ctx:   RenderCtx,
  rt:    RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-tabs';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const header = document.createElement('div');
  header.className = 'arx-tabs-header';
  header.style.cssText = 'display:flex;border-bottom:2px solid #e0e0e0;margin-bottom:12px';

  const content = document.createElement('div');
  content.className = 'arx-tabs-content';

  // Collect tab definitions from children
  const tabDefs: { label: string; key: string; children: Node[] }[] = [];
  for (const child of node.children) {
    if (child.kind === 'component' && child.name.toLowerCase() === 'tab') {
      const label = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : '';
      const key   = child.args[1] ? String(resolveValue(child.args[1], state, ctx) ?? label) : label;
      tabDefs.push({ label, key, children: child.children });
    }
  }

  // Set initial active tab
  if (stateKey && !state.get(stateKey) && tabDefs.length > 0) {
    state.set(stateKey, tabDefs[0]!.key);
  }

  for (const tab of tabDefs) {
    // Tab button
    const btn = document.createElement('button');
    btn.className = 'arx-tab-btn';
    btn.textContent = tab.label;
    btn.style.cssText =
      'padding:8px 16px;border:none;background:none;cursor:pointer;' +
      'border-bottom:2px solid transparent;margin-bottom:-2px;font-size:14px';

    const updateBtn = (): void => {
      const isActive = state.get(stateKey ?? '') === tab.key;
      btn.style.borderBottomColor = isActive ? '#1976d2' : 'transparent';
      btn.style.color = isActive ? '#1976d2' : 'inherit';
      btn.style.fontWeight = isActive ? '600' : '400';
    };
    updateBtn();
    if (stateKey) state.subscribe(stateKey, updateBtn);
    btn.addEventListener('click', () => { if (stateKey) state.set(stateKey, tab.key); });
    header.appendChild(btn);

    // Tab panel
    const panel = document.createElement('div');
    panel.className = 'arx-tab-panel';
    for (const child of tab.children) {
      const c = renderNode(child, state, ctx, rt);
      if (c) panel.appendChild(c);
    }
    const updatePanel = (): void => {
      panel.style.display = state.get(stateKey ?? '') === tab.key ? '' : 'none';
    };
    updatePanel();
    if (stateKey) state.subscribe(stateKey, updatePanel);
    content.appendChild(panel);
  }

  applyModifiers(container, node.mods, state, ctx);
  container.appendChild(header);
  container.appendChild(content);
  return container;
}

// ── Spinner — CSS-only loading animation ─────────────────────────────────────

function renderSpinner(
  node:  ComponentNode,
  state: StateAPI,
  ctx:   RenderCtx,
): HTMLElement {
  const el = document.createElement('div');
  el.className = 'arx-spinner';

  // Extract size and color from modifiers or args
  let size  = 24;
  let color = '#4f8ef7';

  for (const mod of node.mods) {
    if (mod.name === 'size' && mod.args[0])  size  = Number(resolveValue(mod.args[0], state, ctx) ?? 24);
    if (mod.name === 'color' && mod.args[0]) color = String(resolveValue(mod.args[0], state, ctx) ?? '#4f8ef7');
  }

  // Also check positional args: spinner :: size(32) color(#fff) OR spinner 32 #fff
  if (node.args[0]) {
    const a0 = resolveValue(node.args[0], state, ctx);
    if (typeof a0 === 'number') size = a0;
    else if (typeof a0 === 'string' && a0.startsWith('#')) color = a0;
  }
  if (node.args[1]) {
    const a1 = resolveValue(node.args[1], state, ctx);
    if (typeof a1 === 'string' && a1.startsWith('#')) color = a1;
    else if (typeof a1 === 'number') size = a1;
  }

  el.style.width           = `${size}px`;
  el.style.height          = `${size}px`;
  el.style.borderTopColor  = color;
  el.style.color           = color;

  applyModifiers(el, node.mods, state, ctx);
  return el;
}

// ── Skeleton — shimmer loading placeholder ───────────────────────────────────

function renderSkeleton(
  node:  ComponentNode,
  state: StateAPI,
  ctx:   RenderCtx,
): HTMLElement {
  const el = document.createElement('div');
  el.className = 'arx-skeleton';

  let w      = 200;
  let h      = 16;
  let radius = 4;

  for (const mod of node.mods) {
    if (mod.name === 'w'      && mod.args[0]) w      = Number(resolveValue(mod.args[0], state, ctx) ?? 200);
    if (mod.name === 'h'      && mod.args[0]) h      = Number(resolveValue(mod.args[0], state, ctx) ?? 16);
    if (mod.name === 'radius' && mod.args[0]) radius = Number(resolveValue(mod.args[0], state, ctx) ?? 4);
  }

  // Also check positional args: skeleton 200 16 4
  if (node.args[0]) w      = Number(resolveValue(node.args[0], state, ctx) ?? w);
  if (node.args[1]) h      = Number(resolveValue(node.args[1], state, ctx) ?? h);
  if (node.args[2]) radius = Number(resolveValue(node.args[2], state, ctx) ?? radius);

  el.style.width        = `${w}px`;
  el.style.height       = `${h}px`;
  el.style.borderRadius = `${radius}px`;

  applyModifiers(el, node.mods, state, ctx);
  return el;
}

// ── Scoped state for @component local isolation ─────────────────────────────

import type { Subscriber, Unsubscribe } from '../reactive/types.js';
import type { Node as AstNode } from '../ast/nodes.js';

/**
 * Creates a scoped state that overlays local ~vars on top of a parent state.
 * Local vars are isolated per component instance; reads/writes to unknown keys
 * fall through to the parent state.
 */
function createScopedState(parent: StateAPI, body: AstNode[]): StateAPI {
  const localKeys = new Set<string>();
  const localData: Record<string, unknown> = {};
  const localSubs: Record<string, Set<Subscriber>> = {};

  // Collect locally declared ~vars
  for (const node of body) {
    if (node.kind === 'varDecl') {
      localKeys.add(node.name);
      localData[node.name] = _literalValueQuick(node.expr);
    }
  }

  const notify = (key: string, val: unknown): void => {
    if (localSubs[key]) for (const fn of localSubs[key]!) fn(val, key);
  };

  const scoped: StateAPI = {
    get(key) {
      return localKeys.has(key) ? localData[key] : parent.get(key);
    },
    set(key, val) {
      if (localKeys.has(key)) {
        localData[key] = val;
        notify(key, val);
      } else {
        parent.set(key, val);
      }
    },
    update(key, fn) { scoped.set(key, fn(scoped.get(key))); },
    subscribe(key, fn): Unsubscribe {
      if (localKeys.has(key)) {
        (localSubs[key] ??= new Set()).add(fn);
        return () => localSubs[key]?.delete(fn);
      }
      return parent.subscribe(key, fn);
    },
    watch(key, fn) { return scoped.subscribe(key, fn); },
    computed(key, expr, deps) { parent.computed(key, expr, deps); },
    batch(fn) { parent.batch(fn); },
    snapshot() { return { ...parent.snapshot(), ...localData }; },
    reset(data) { parent.reset(data); },
  };

  return scoped;
}

function _literalValueQuick(node: import('../ast/values.js').ValueNode): unknown {
  switch (node.kind) {
    case 'string':  return node.v;
    case 'number':  return node.v;
    case 'color':   return node.v;
    case 'ident':   return node.v;
    case 'array':   return node.v.map(_literalValueQuick);
    default:        return null;
  }
}

// ── Feature 1: Accordion / Collapsible ────────────────────────────────────────

function renderAccordion(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-accordion';

  for (const child of node.children) {
    if (child.kind !== 'component') { const c = renderNode(child, state, ctx, rt); if (c) container.appendChild(c); continue; }

    const section = document.createElement('div');
    section.className = 'arx-accordion-section';

    const header = document.createElement('div');
    header.className = 'arx-accordion-header';
    header.style.cssText = 'padding:12px 16px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e0e0e0;user-select:none';
    header.textContent = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : child.name;

    const arrow = document.createElement('span');
    arrow.textContent = '▸';
    arrow.style.transition = 'transform 0.2s ease';
    header.appendChild(arrow);

    const body = document.createElement('div');
    body.className = 'arx-accordion-body';
    body.style.cssText = 'overflow:hidden;max-height:0;transition:max-height 0.3s ease;padding:0 16px';

    for (const gc of child.children) {
      const c = renderNode(gc, state, ctx, rt);
      if (c) body.appendChild(c);
    }

    let open = false;
    header.addEventListener('click', () => {
      open = !open;
      body.style.maxHeight = open ? body.scrollHeight + 'px' : '0';
      body.style.padding = open ? '12px 16px' : '0 16px';
      arrow.style.transform = open ? 'rotate(90deg)' : '';
    });

    section.appendChild(header);
    section.appendChild(body);
    container.appendChild(section);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Feature 2: Carousel / Swiper ──────────────────────────────────────────────

function renderCarousel(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-carousel';
  container.style.cssText = 'position:relative;overflow:hidden;width:100%';

  const track = document.createElement('div');
  track.className = 'arx-carousel-track';
  track.style.cssText = 'display:flex;transition:transform 0.3s ease;width:100%';

  const slides: HTMLElement[] = [];
  for (const child of node.children) {
    const slide = document.createElement('div');
    slide.className = 'arx-carousel-slide';
    slide.style.cssText = 'min-width:100%;flex-shrink:0';
    const c = renderNode(child, state, ctx, rt);
    if (c) slide.appendChild(c);
    slides.push(slide);
    track.appendChild(slide);
  }

  let current = 0;
  const total = slides.length;
  const goTo = (idx: number): void => {
    current = ((idx % total) + total) % total;
    track.style.transform = `translateX(-${current * 100}%)`;
    updateDots();
  };

  // Arrows
  const prevBtn = document.createElement('button');
  prevBtn.className = 'arx-carousel-prev';
  prevBtn.textContent = '‹';
  prevBtn.style.cssText = 'position:absolute;left:8px;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.4);color:#fff;border:none;border-radius:50%;width:32px;height:32px;cursor:pointer;font-size:18px;z-index:2';
  prevBtn.addEventListener('click', () => goTo(current - 1));

  const nextBtn = document.createElement('button');
  nextBtn.className = 'arx-carousel-next';
  nextBtn.textContent = '›';
  nextBtn.style.cssText = 'position:absolute;right:8px;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.4);color:#fff;border:none;border-radius:50%;width:32px;height:32px;cursor:pointer;font-size:18px;z-index:2';
  nextBtn.addEventListener('click', () => goTo(current + 1));

  // Dots
  const dots = document.createElement('div');
  dots.className = 'arx-carousel-dots';
  dots.style.cssText = 'display:flex;justify-content:center;gap:6px;padding:8px 0';
  for (let i = 0; i < total; i++) {
    const dot = document.createElement('span');
    dot.style.cssText = 'width:8px;height:8px;border-radius:50%;background:#ccc;cursor:pointer;transition:background 0.2s';
    dot.addEventListener('click', () => goTo(i));
    dots.appendChild(dot);
  }

  const updateDots = (): void => {
    const children = dots.children;
    for (let i = 0; i < children.length; i++) {
      (children[i] as HTMLElement).style.background = i === current ? '#333' : '#ccc';
    }
  };

  // Touch swipe support
  let touchStartX = 0;
  track.addEventListener('touchstart', e => { touchStartX = e.touches[0]!.clientX; }, { passive: true });
  track.addEventListener('touchend', e => {
    const dx = e.changedTouches[0]!.clientX - touchStartX;
    if (Math.abs(dx) > 50) goTo(dx > 0 ? current - 1 : current + 1);
  });

  // Auto-play via modifier
  let autoMs = 0;
  for (const m of node.mods) {
    if (m.name === 'autoplay' && m.args[0]) autoMs = Number(resolveValue(m.args[0], state, ctx) ?? 0);
  }
  if (autoMs > 0) setInterval(() => goTo(current + 1), autoMs);

  container.appendChild(track);
  container.appendChild(prevBtn);
  container.appendChild(nextBtn);
  container.appendChild(dots);
  updateDots();

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Feature 3: Bottom Sheet ───────────────────────────────────────────────────

function renderBottomSheet(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const overlay = document.createElement('div');
  overlay.className = 'arx-bottomsheet-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:1000;display:flex;align-items:flex-end;justify-content:center';

  const sheet = document.createElement('div');
  sheet.className = 'arx-bottomsheet';
  sheet.style.cssText = 'background:#fff;border-radius:16px 16px 0 0;padding:16px;width:100%;max-width:600px;max-height:80vh;overflow-y:auto;transform:translateY(0);transition:transform 0.3s ease;box-shadow:0 -4px 24px rgba(0,0,0,.12)';

  // Drag handle
  const handle = document.createElement('div');
  handle.className = 'arx-bottomsheet-handle';
  handle.style.cssText = 'width:40px;height:4px;background:#ccc;border-radius:2px;margin:0 auto 12px';
  sheet.appendChild(handle);

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) sheet.appendChild(c);
  }

  // Close on overlay click
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  sheet.addEventListener('click', e => e.stopPropagation());

  // Drag down to dismiss
  let dragY = 0;
  handle.addEventListener('touchstart', e => { dragY = e.touches[0]!.clientY; }, { passive: true });
  handle.addEventListener('touchmove', e => {
    const dy = e.touches[0]!.clientY - dragY;
    if (dy > 0) sheet.style.transform = `translateY(${dy}px)`;
  }, { passive: true });
  handle.addEventListener('touchend', e => {
    const dy = e.changedTouches[0]!.clientY - dragY;
    if (dy > 100) { overlay.remove(); }
    else { sheet.style.transform = 'translateY(0)'; }
  });

  // Reactive visibility
  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  if (stateKey) {
    const toggle = (): void => {
      overlay.style.display = state.get(stateKey) ? 'flex' : 'none';
    };
    toggle();
    state.subscribe(stateKey, toggle);
    overlay.addEventListener('click', e => { if (e.target === overlay) state.set(stateKey, false); });
  }

  for (const h of node.handlers) attachHandler(overlay, h, state, ctx, rt);
  overlay.appendChild(sheet);
  applyModifiers(overlay, node.mods, state, ctx);
  return overlay;
}

// ── Feature 4: Date/Time Picker ───────────────────────────────────────────────

function renderDatePicker(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const el = document.createElement('input') as HTMLInputElement;
  el.className = 'arx-datepicker';

  // Determine type: date (default), time, datetime-local
  let inputType = 'date';
  for (const m of node.mods) {
    if (m.name === 'time') inputType = 'time';
    if (m.name === 'datetime') inputType = 'datetime-local';
  }
  el.type = inputType;

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  if (stateKey) {
    el.value = String(state.get(stateKey) ?? '');
    state.subscribe(stateKey, v => { el.value = String(v ?? ''); });
    el.addEventListener('change', () => state.set(stateKey, el.value));
  }

  // Min/max from modifiers
  for (const m of node.mods) {
    if (m.name === 'min' && m.args[0]) el.min = String(resolveValue(m.args[0], state, ctx) ?? '');
    if (m.name === 'max' && m.args[0]) el.max = String(resolveValue(m.args[0], state, ctx) ?? '');
  }

  applyModifiers(el, node.mods, state, ctx);
  return el;
}

// ── Feature 5: Search Input with Debounce ─────────────────────────────────────

function renderSearch(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-search';
  wrapper.style.cssText = 'position:relative;display:flex;align-items:center';

  const icon = document.createElement('span');
  icon.textContent = '🔍';
  icon.style.cssText = 'position:absolute;left:10px;pointer-events:none;font-size:14px';

  const input = document.createElement('input');
  input.type = 'search';
  input.style.cssText = 'padding:8px 12px 8px 32px;border:1px solid #ddd;border-radius:20px;width:100%;outline:none;font-size:14px';
  input.placeholder = node.args[1] ? String(resolveValue(node.args[1], state, ctx) ?? 'Search...') : 'Search...';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  let debounceMs = 300;
  for (const m of node.mods) {
    if (m.name === 'debounce' && m.args[0]) debounceMs = Number(resolveValue(m.args[0], state, ctx) ?? 300);
  }

  let timer: ReturnType<typeof setTimeout> | null = null;
  if (stateKey) {
    input.value = String(state.get(stateKey) ?? '');
    state.subscribe(stateKey, v => { if (input.value !== String(v ?? '')) input.value = String(v ?? ''); });
    input.addEventListener('input', () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => state.set(stateKey, input.value), debounceMs);
    });
  }

  wrapper.appendChild(icon);
  wrapper.appendChild(input);
  for (const h of node.handlers) attachHandler(input, h, state, ctx, rt);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Feature 6: Avatar ─────────────────────────────────────────────────────────

function renderAvatar(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const el = document.createElement('div');
  el.className = 'arx-avatar';

  let size = 40;
  for (const m of node.mods) {
    if (m.name === 'size' && m.args[0]) size = Number(resolveValue(m.args[0], state, ctx) ?? 40);
  }

  el.style.cssText = `width:${size}px;height:${size}px;border-radius:50%;overflow:hidden;display:flex;align-items:center;justify-content:center;background:#e0e0e0;font-weight:600;font-size:${size * 0.4}px;color:#666;flex-shrink:0`;

  const src = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  const name = node.args[1] ? String(resolveValue(node.args[1], state, ctx) ?? '') : '';

  if (src && !src.startsWith('#')) {
    const img = document.createElement('img');
    img.src = src;
    img.style.cssText = 'width:100%;height:100%;object-fit:cover';
    img.onerror = () => { img.remove(); el.textContent = _initials(name || src); };
    el.appendChild(img);
  } else {
    el.textContent = _initials(name || 'U');
    if (src.startsWith('#')) el.style.background = src;
  }

  applyModifiers(el, node.mods, state, ctx);
  return el;
}

function _initials(name: string): string {
  return name.split(/\s+/).map(w => w[0]?.toUpperCase() ?? '').join('').slice(0, 2);
}

// ── Feature 7: Chip / Tag ─────────────────────────────────────────────────────

function renderChip(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const el = document.createElement('span');
  el.className = 'arx-chip';
  el.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:16px;background:#e8eaf6;font-size:13px;line-height:1.4';

  if (node.args[0]) {
    const val = resolveValue(node.args[0], state, ctx);
    el.textContent = toDisplayString(val);
    if (node.args[0].kind === 'reactive') {
      state.subscribe(node.args[0].v.split('.')[0]!, () => {
        const txt = resolveValue(node.args[0]!, state, ctx);
        // Keep dismiss button if present
        const dismiss = el.querySelector('.arx-chip-dismiss');
        el.textContent = toDisplayString(txt);
        if (dismiss) el.appendChild(dismiss);
      });
    }
  }

  // Dismiss button via modifier
  for (const m of node.mods) {
    if (m.name === 'dismiss' || m.name === 'removable') {
      const btn = document.createElement('span');
      btn.className = 'arx-chip-dismiss';
      btn.textContent = '✕';
      btn.style.cssText = 'cursor:pointer;margin-left:4px;font-size:11px;opacity:0.6';
      btn.addEventListener('click', e => { e.stopPropagation(); el.remove(); });
      el.appendChild(btn);
    }
  }

  for (const h of node.handlers) attachHandler(el, h, state, ctx, rt);
  applyModifiers(el, node.mods, state, ctx);
  return el;
}

// ── Feature 8: Stepper / Wizard ───────────────────────────────────────────────

function renderStepper(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-stepper';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  if (stateKey && state.get(stateKey) == null) state.set(stateKey, 0);

  const steps: { label: string; children: import('../ast/nodes.js').Node[] }[] = [];
  for (const child of node.children) {
    if (child.kind === 'component') {
      const label = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : child.name;
      steps.push({ label, children: child.children });
    }
  }

  // Step indicators
  const indicators = document.createElement('div');
  indicators.className = 'arx-stepper-indicators';
  indicators.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:16px';

  for (let i = 0; i < steps.length; i++) {
    const stepEl = document.createElement('div');
    stepEl.style.cssText = 'display:flex;align-items:center;gap:6px';
    const circle = document.createElement('div');
    circle.className = 'arx-stepper-circle';
    circle.textContent = String(i + 1);
    circle.style.cssText = 'width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;transition:all 0.2s';
    const label = document.createElement('span');
    label.textContent = steps[i]!.label;
    label.style.fontSize = '13px';
    stepEl.appendChild(circle);
    stepEl.appendChild(label);
    if (i < steps.length - 1) {
      const line = document.createElement('div');
      line.style.cssText = 'flex:1;height:2px;background:#e0e0e0;min-width:20px';
      stepEl.appendChild(line);
    }
    indicators.appendChild(stepEl);
  }

  // Step content
  const content = document.createElement('div');
  content.className = 'arx-stepper-content';

  const panels: HTMLElement[] = [];
  for (const step of steps) {
    const panel = document.createElement('div');
    for (const child of step.children) {
      const c = renderNode(child, state, ctx, rt);
      if (c) panel.appendChild(c);
    }
    panels.push(panel);
    content.appendChild(panel);
  }

  const updateStep = (): void => {
    const idx = Number(state.get(stateKey ?? '') ?? 0);
    // Update indicators
    const circles = indicators.querySelectorAll('.arx-stepper-circle');
    circles.forEach((c, i) => {
      const el = c as HTMLElement;
      if (i < idx) { el.style.background = '#4caf50'; el.style.color = '#fff'; }
      else if (i === idx) { el.style.background = '#1976d2'; el.style.color = '#fff'; }
      else { el.style.background = '#e0e0e0'; el.style.color = '#666'; }
    });
    // Show/hide panels
    panels.forEach((p, i) => { p.style.display = i === idx ? '' : 'none'; });
  };

  updateStep();
  if (stateKey) state.subscribe(stateKey, updateStep);

  container.appendChild(indicators);
  container.appendChild(content);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Feature 9: Infinite Scroll ────────────────────────────────────────────────

function renderInfiniteScroll(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-infinitescroll';
  container.style.cssText = 'overflow-y:auto;position:relative';

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) container.appendChild(c);
  }

  // Sentinel element at bottom
  const sentinel = document.createElement('div');
  sentinel.className = 'arx-scroll-sentinel';
  sentinel.style.height = '1px';
  container.appendChild(sentinel);

  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        // Fire handlers
        for (const h of node.handlers) {
          for (const action of h.actions) {
            if (action.kind === 'call') {
              const rArgs = action.args.map(a =>
                'key' in a ? a : resolveValue(a as import('../ast/values.js').ValueNode, state, ctx)
              );
              if (action.fn === 'fetch') {
                const url = String(rArgs[0] ?? '');
                const into = action.into;
                if (into) { state.set(`${into}Loading`, true); }
                const result = rt.fetch(url);
                if (into) {
                  Promise.resolve(result).then(data => {
                    state.set(into, data);
                    if (into) state.set(`${into}Loading`, false);
                  }).catch(() => { if (into) state.set(`${into}Loading`, false); });
                }
              } else {
                rt[action.fn]?.(...(rArgs as unknown[]));
              }
            }
            if (action.kind === 'assign') {
              const val = resolveValue(action.val, state, ctx);
              const cur = state.get(action.var) ?? 0;
              if (action.op === '+=') state.set(action.var, (cur as number) + (val as number));
              else if (action.op === '-=') state.set(action.var, (cur as number) - (val as number));
              else state.set(action.var, val);
            }
          }
        }
      }
    }
  }, { root: container, threshold: 0.1 });

  observer.observe(sentinel);

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Feature 10: Pull to Refresh ───────────────────────────────────────────────

function renderPullRefresh(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-pullrefresh';
  container.style.cssText = 'overflow-y:auto;position:relative';

  const indicator = document.createElement('div');
  indicator.className = 'arx-pullrefresh-indicator';
  indicator.textContent = '↓ Pull to refresh';
  indicator.style.cssText = 'text-align:center;padding:12px;font-size:13px;color:#999;height:0;overflow:hidden;transition:height 0.2s';
  container.appendChild(indicator);

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) container.appendChild(c);
  }

  let startY = 0;
  let pulling = false;

  container.addEventListener('touchstart', e => {
    if (container.scrollTop <= 0) {
      startY = e.touches[0]!.clientY;
      pulling = true;
    }
  }, { passive: true });

  container.addEventListener('touchmove', e => {
    if (!pulling) return;
    const dy = e.touches[0]!.clientY - startY;
    if (dy > 0 && dy < 150) {
      indicator.style.height = Math.min(dy * 0.5, 50) + 'px';
    }
  }, { passive: true });

  container.addEventListener('touchend', () => {
    if (!pulling) return;
    pulling = false;
    const h = parseFloat(indicator.style.height);
    if (h > 30) {
      indicator.textContent = '↻ Refreshing...';
      indicator.style.height = '40px';
      // Fire handlers
      for (const handler of node.handlers) {
        for (const action of handler.actions) {
          if (action.kind === 'call') {
            if (action.fn === 'fetch') {
              const url = String(resolveValue(action.args[0] as import('../ast/values.js').ValueNode, state, ctx) ?? '');
              const into = action.into;
              const result = rt.fetch(url);
              if (into) {
                Promise.resolve(result).then(data => { state.set(into, data); }).catch(() => {});
              }
            } else {
              rt[action.fn]?.();
            }
          }
          if (action.kind === 'assign') {
            state.set(action.var, resolveValue(action.val, state, ctx));
          }
        }
      }
      setTimeout(() => {
        indicator.textContent = '↓ Pull to refresh';
        indicator.style.height = '0';
      }, 1000);
    } else {
      indicator.style.height = '0';
    }
  });

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 3 Feature 1: Virtual List ──────────────────────────────────────────

function renderVirtualList(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-virtuallist';

  const itemHeight = 40;
  let visibleCount = 20;
  for (const m of node.mods) {
    if (m.name === 'h' && m.args[0]) visibleCount = Math.ceil(Number(resolveValue(m.args[0], state, ctx) ?? 600) / itemHeight);
  }

  container.style.cssText = `overflow-y:auto;position:relative;height:${visibleCount * itemHeight}px`;

  const sourceArg = node.args[0];
  const getItems = (): unknown[] => {
    if (!sourceArg) return [];
    const v = resolveValue(sourceArg, state, ctx);
    return Array.isArray(v) ? v : [];
  };

  const spacer = document.createElement('div');
  spacer.style.cssText = 'width:1px;pointer-events:none';
  container.appendChild(spacer);

  const viewport = document.createElement('div');
  viewport.style.cssText = 'position:absolute;top:0;left:0;right:0';
  container.appendChild(viewport);

  const render = (): void => {
    const items = getItems();
    spacer.style.height = `${items.length * itemHeight}px`;
    const scrollTop = container.scrollTop;
    const startIdx = Math.floor(scrollTop / itemHeight);
    const endIdx = Math.min(startIdx + visibleCount + 2, items.length);
    viewport.style.transform = `translateY(${startIdx * itemHeight}px)`;
    viewport.innerHTML = '';
    for (let i = startIdx; i < endIdx; i++) {
      const row = document.createElement('div');
      row.style.height = `${itemHeight}px`;
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.textContent = String(items[i] ?? '');
      // Render child template if exists
      if (node.children.length > 0) {
        row.textContent = '';
        const childCtx: RenderCtx = { ...ctx, item: items[i], index: i };
        for (const child of node.children) {
          const c = renderNode(child, state, childCtx, rt);
          if (c) row.appendChild(c);
        }
      }
      viewport.appendChild(row);
    }
  };

  render();
  container.addEventListener('scroll', render);
  if (sourceArg?.kind === 'reactive') {
    state.subscribe(sourceArg.v.split('.')[0]!, render);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 3 Feature 2: Transition Group ──────────────────────────────────────

function renderTransitionGroup(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-transitiongroup';

  let animName = 'fadeIn';
  let duration = '0.3s';
  for (const m of node.mods) {
    if (m.name === 'animate' && m.args[0]) animName = String(resolveValue(m.args[0], state, ctx) ?? 'fadeIn');
    if (m.name === 'duration' && m.args[0]) duration = String(resolveValue(m.args[0], state, ctx) ?? '0.3s');
  }
  if (/^\d+$/.test(duration)) duration = `${duration}ms`;

  const renderChildren = (): void => {
    const existing = new Set<Element>();
    for (const el of Array.from(container.children)) existing.add(el);

    for (const child of node.children) {
      const c = renderNode(child, state, ctx, rt);
      if (c) {
        c.style.animation = `${animName} ${duration} ease`;
        container.appendChild(c);
      }
    }
  };

  renderChildren();

  // Subscribe to reactive sources to re-render with animations
  const reactiveArgs = node.args.filter(a => a.kind === 'reactive');
  for (const a of reactiveArgs) {
    if (a.kind === 'reactive') {
      state.subscribe(a.v.split('.')[0]!, () => {
        // Animate new items
        const newChildren: HTMLElement[] = [];
        for (const child of node.children) {
          const c = renderNode(child, state, ctx, rt);
          if (c) { c.style.animation = `${animName} ${duration} ease`; newChildren.push(c); }
        }
        container.innerHTML = '';
        for (const c of newChildren) container.appendChild(c);
      });
    }
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 3 Feature 3: Rich Text / Markdown ──────────────────────────────────

function renderRichText(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-richtext';

  const getContent = (): string => {
    if (node.args[0]) return String(resolveValue(node.args[0], state, ctx) ?? '');
    return '';
  };

  const renderMd = (md: string): string => {
    // Lightweight markdown renderer
    let html = md
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`(.+?)`/g, '<code>$1</code>')
      .replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2">$1</a>')
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/^---$/gm, '<hr>');
    // Wrap loose <li> in <ul>
    html = html.replace(/(<li>.*?<\/li>)+/gs, '<ul>$&</ul>');
    return `<p>${html}</p>`;
  };

  const update = (): void => {
    container.innerHTML = renderMd(getContent());
  };
  update();

  if (node.args[0]?.kind === 'reactive') {
    state.subscribe(node.args[0].v.split('.')[0]!, update);
  }

  applyModifiers(container, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(container, h, state, ctx, rt);
  return container;
}

// ── Round 3 Feature 4: Color Picker ──────────────────────────────────────────

function renderColorPicker(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-colorpicker';
  wrapper.style.cssText = 'display:inline-flex;align-items:center;gap:8px';

  const input = document.createElement('input');
  input.type = 'color';
  input.style.cssText = 'width:40px;height:40px;border:none;cursor:pointer;background:none;padding:0';

  const label = document.createElement('span');
  label.className = 'arx-colorpicker-label';
  label.style.cssText = 'font-family:monospace;font-size:14px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  if (stateKey) {
    const val = state.get(stateKey);
    input.value = typeof val === 'string' && val.startsWith('#') ? val : '#000000';
    label.textContent = input.value;

    input.addEventListener('input', () => {
      state.set(stateKey, input.value);
      label.textContent = input.value;
    });
    state.subscribe(stateKey, v => {
      const sv = String(v ?? '#000000');
      if (input.value !== sv) input.value = sv;
      label.textContent = sv;
    });
  }

  wrapper.appendChild(input);
  wrapper.appendChild(label);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Round 3 Feature 5: Rating (Stars) ────────────────────────────────────────

function renderRating(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-rating';
  container.style.cssText = 'display:inline-flex;gap:4px;cursor:pointer;font-size:24px';

  const maxStars = node.args[1] ? Number(resolveValue(node.args[1], state, ctx) ?? 5) : 5;
  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const stars: HTMLSpanElement[] = [];
  for (let i = 1; i <= maxStars; i++) {
    const star = document.createElement('span');
    star.style.cssText = 'transition:color 0.15s ease;user-select:none';
    star.textContent = '★';
    star.addEventListener('click', () => { if (stateKey) state.set(stateKey, i); });
    star.addEventListener('mouseenter', () => {
      for (let j = 0; j < maxStars; j++) stars[j]!.style.color = j < i ? '#f1c40f' : '#ddd';
    });
    stars.push(star);
    container.appendChild(star);
  }

  container.addEventListener('mouseleave', () => updateStars());

  const updateStars = (): void => {
    const val = stateKey ? Number(state.get(stateKey) ?? 0) : 0;
    for (let j = 0; j < maxStars; j++) stars[j]!.style.color = j < val ? '#f1c40f' : '#ddd';
  };
  updateStars();
  if (stateKey) state.subscribe(stateKey, updateStars);

  applyModifiers(container, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(container, h, state, ctx, rt);
  return container;
}

// ── Round 3 Feature 6: Tooltip / Popover ─────────────────────────────────────

function renderTooltip(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-tooltip-wrapper';
  wrapper.style.cssText = 'position:relative;display:inline-block';

  const text = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  let position = 'top';
  for (const m of node.mods) {
    if (['top', 'bottom', 'left', 'right'].includes(m.name)) position = m.name;
  }

  // Render children as the trigger
  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) wrapper.appendChild(c);
  }

  const tip = document.createElement('div');
  tip.className = 'arx-tooltip';
  tip.textContent = text;
  tip.style.cssText =
    'position:absolute;background:#333;color:#fff;padding:6px 12px;border-radius:6px;' +
    'font-size:12px;white-space:nowrap;pointer-events:none;opacity:0;transition:opacity 0.15s ease;z-index:1000';

  const posMap: Record<string, string> = {
    top:    'bottom:calc(100% + 8px);left:50%;transform:translateX(-50%)',
    bottom: 'top:calc(100% + 8px);left:50%;transform:translateX(-50%)',
    left:   'right:calc(100% + 8px);top:50%;transform:translateY(-50%)',
    right:  'left:calc(100% + 8px);top:50%;transform:translateY(-50%)',
  };
  tip.style.cssText += ';' + (posMap[position] ?? posMap['top']);

  wrapper.appendChild(tip);

  const isPopover = node.name.toLowerCase() === 'popover';
  if (isPopover) {
    wrapper.addEventListener('click', () => {
      tip.style.opacity = tip.style.opacity === '1' ? '0' : '1';
      tip.style.pointerEvents = tip.style.opacity === '1' ? 'auto' : 'none';
    });
  } else {
    wrapper.addEventListener('mouseenter', () => { tip.style.opacity = '1'; });
    wrapper.addEventListener('mouseleave', () => { tip.style.opacity = '0'; });
  }

  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Round 3 Feature 7: Breadcrumb ────────────────────────────────────────────

function renderBreadcrumb(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const nav = document.createElement('nav');
  nav.className = 'arx-breadcrumb';
  nav.setAttribute('aria-label', 'Breadcrumb');
  nav.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:14px';

  const separator = '›';

  for (let i = 0; i < node.children.length; i++) {
    const child = node.children[i]!;
    const c = renderNode(child, state, ctx, rt);
    if (c) {
      if (i === node.children.length - 1) {
        c.setAttribute('aria-current', 'page');
        c.style.fontWeight = '600';
      }
      nav.appendChild(c);
      if (i < node.children.length - 1) {
        const sep = document.createElement('span');
        sep.className = 'arx-breadcrumb-sep';
        sep.textContent = separator;
        sep.style.color = '#999';
        sep.setAttribute('aria-hidden', 'true');
        nav.appendChild(sep);
      }
    }
  }

  applyModifiers(nav, node.mods, state, ctx);
  return nav;
}

// ── Round 3 Feature 8: Pagination ────────────────────────────────────────────

function renderPagination(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const nav = document.createElement('nav');
  nav.className = 'arx-pagination';
  nav.setAttribute('aria-label', 'Pagination');
  nav.style.cssText = 'display:flex;align-items:center;gap:4px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const totalPages = node.args[1] ? Number(resolveValue(node.args[1], state, ctx) ?? 10) : 10;

  const render = (): void => {
    nav.innerHTML = '';
    const current = stateKey ? Number(state.get(stateKey) ?? 1) : 1;

    // Prev button
    const prev = document.createElement('button');
    prev.textContent = '‹';
    prev.className = 'arx-page-btn';
    prev.style.cssText = 'padding:6px 10px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fff';
    prev.disabled = current <= 1;
    prev.addEventListener('click', () => { if (stateKey && current > 1) state.set(stateKey, current - 1); });
    nav.appendChild(prev);

    // Page numbers (show max 7 with ellipsis)
    const pages: (number | string)[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (current > 3) pages.push('...');
      for (let i = Math.max(2, current - 1); i <= Math.min(totalPages - 1, current + 1); i++) pages.push(i);
      if (current < totalPages - 2) pages.push('...');
      pages.push(totalPages);
    }

    for (const p of pages) {
      const btn = document.createElement('button');
      btn.textContent = String(p);
      btn.className = 'arx-page-btn';
      const isActive = p === current;
      btn.style.cssText = `padding:6px 10px;border:1px solid ${isActive ? '#1976d2' : '#ddd'};border-radius:4px;cursor:pointer;background:${isActive ? '#1976d2' : '#fff'};color:${isActive ? '#fff' : 'inherit'}`;
      if (typeof p === 'number') {
        btn.addEventListener('click', () => { if (stateKey) state.set(stateKey, p); });
      } else {
        btn.disabled = true;
        btn.style.cursor = 'default';
      }
      nav.appendChild(btn);
    }

    // Next button
    const next = document.createElement('button');
    next.textContent = '›';
    next.className = 'arx-page-btn';
    next.style.cssText = 'padding:6px 10px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fff';
    next.disabled = current >= totalPages;
    next.addEventListener('click', () => { if (stateKey && current < totalPages) state.set(stateKey, current + 1); });
    nav.appendChild(next);
  };

  render();
  if (stateKey) state.subscribe(stateKey, render);

  applyModifiers(nav, node.mods, state, ctx);
  return nav;
}

// ── Round 3 Feature 9: Dropdown Menu ─────────────────────────────────────────

function renderDropdown(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-dropdown';
  wrapper.style.cssText = 'position:relative;display:inline-block';

  const trigger = document.createElement('button');
  trigger.className = 'arx-dropdown-trigger';
  trigger.style.cssText = 'padding:8px 16px;border:1px solid #ddd;border-radius:6px;cursor:pointer;background:#fff;display:flex;align-items:center;gap:6px';
  trigger.textContent = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? 'Menu') : 'Menu';

  const arrow = document.createElement('span');
  arrow.textContent = '▾';
  arrow.style.transition = 'transform 0.2s ease';
  trigger.appendChild(arrow);

  const menu = document.createElement('div');
  menu.className = 'arx-dropdown-menu';
  menu.style.cssText =
    'position:absolute;top:calc(100% + 4px);left:0;min-width:160px;background:#fff;' +
    'border:1px solid #e0e0e0;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.12);' +
    'z-index:1000;display:none;overflow:hidden';

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) {
      c.style.padding = c.style.padding || '8px 16px';
      c.style.cursor = 'pointer';
      c.addEventListener('mouseenter', () => { c.style.background = '#f5f5f5'; });
      c.addEventListener('mouseleave', () => { c.style.background = ''; });
      c.addEventListener('click', () => { menu.style.display = 'none'; arrow.style.transform = ''; });
      menu.appendChild(c);
    }
  }

  let open = false;
  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    open = !open;
    menu.style.display = open ? 'block' : 'none';
    arrow.style.transform = open ? 'rotate(180deg)' : '';
  });

  document.addEventListener('click', () => {
    if (open) { open = false; menu.style.display = 'none'; arrow.style.transform = ''; }
  });

  wrapper.appendChild(trigger);
  wrapper.appendChild(menu);
  applyModifiers(wrapper, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(wrapper, h, state, ctx, rt);
  return wrapper;
}

// ── Round 3 Feature 10: Gallery / Lightbox ───────────────────────────────────

function renderGallery(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-gallery';
  container.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px';

  const images: string[] = [];
  const sourceArg = node.args[0];

  if (sourceArg) {
    const val = resolveValue(sourceArg, state, ctx);
    if (Array.isArray(val)) for (const v of val) images.push(String(v));
  }

  const lightboxOverlay = document.createElement('div');
  lightboxOverlay.className = 'arx-lightbox-overlay';
  lightboxOverlay.style.cssText =
    'position:fixed;inset:0;background:rgba(0,0,0,.9);display:none;align-items:center;' +
    'justify-content:center;z-index:10000;cursor:pointer;flex-direction:column';

  const lightboxImg = document.createElement('img');
  lightboxImg.style.cssText = 'max-width:90vw;max-height:80vh;object-fit:contain;border-radius:8px';

  const lightboxCounter = document.createElement('div');
  lightboxCounter.style.cssText = 'color:#fff;margin-top:12px;font-size:14px';

  const lightboxPrev = document.createElement('button');
  lightboxPrev.textContent = '‹';
  lightboxPrev.style.cssText = 'position:absolute;left:16px;top:50%;transform:translateY(-50%);font-size:36px;color:#fff;background:rgba(255,255,255,.15);border:none;border-radius:50%;width:48px;height:48px;cursor:pointer';

  const lightboxNext = document.createElement('button');
  lightboxNext.textContent = '›';
  lightboxNext.style.cssText = 'position:absolute;right:16px;top:50%;transform:translateY(-50%);font-size:36px;color:#fff;background:rgba(255,255,255,.15);border:none;border-radius:50%;width:48px;height:48px;cursor:pointer';

  let currentIdx = 0;
  const showLightbox = (idx: number): void => {
    currentIdx = idx;
    lightboxImg.src = images[idx] ?? '';
    lightboxCounter.textContent = `${idx + 1} / ${images.length}`;
    lightboxOverlay.style.display = 'flex';
  };

  lightboxPrev.addEventListener('click', (e) => { e.stopPropagation(); if (currentIdx > 0) showLightbox(currentIdx - 1); });
  lightboxNext.addEventListener('click', (e) => { e.stopPropagation(); if (currentIdx < images.length - 1) showLightbox(currentIdx + 1); });
  lightboxOverlay.addEventListener('click', () => { lightboxOverlay.style.display = 'none'; });

  lightboxOverlay.appendChild(lightboxPrev);
  lightboxOverlay.appendChild(lightboxImg);
  lightboxOverlay.appendChild(lightboxCounter);
  lightboxOverlay.appendChild(lightboxNext);

  const renderImages = (): void => {
    container.innerHTML = '';
    const src = sourceArg ? resolveValue(sourceArg, state, ctx) : null;
    images.length = 0;
    if (Array.isArray(src)) for (const v of src) images.push(String(v));

    for (let i = 0; i < images.length; i++) {
      const thumb = document.createElement('img');
      thumb.src = images[i]!;
      thumb.style.cssText = 'width:100%;aspect-ratio:1;object-fit:cover;border-radius:6px;cursor:pointer;transition:transform 0.15s ease';
      thumb.addEventListener('mouseenter', () => { thumb.style.transform = 'scale(1.05)'; });
      thumb.addEventListener('mouseleave', () => { thumb.style.transform = ''; });
      const idx = i;
      thumb.addEventListener('click', () => showLightbox(idx));
      container.appendChild(thumb);
    }
    container.appendChild(lightboxOverlay);
  };

  renderImages();
  if (sourceArg?.kind === 'reactive') {
    state.subscribe(sourceArg.v.split('.')[0]!, renderImages);
  }

  // Also render child nodes if no source arg
  if (!sourceArg) {
    for (const child of node.children) {
      const c = renderNode(child, state, ctx, rt);
      if (c) container.appendChild(c);
    }
    container.appendChild(lightboxOverlay);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 1: Sortable List ─────────────────────────────────────────

function renderSortableList(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-sortablelist';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const renderItems = (): void => {
    container.innerHTML = '';
    const items = stateKey ? (state.get(stateKey) as unknown[]) ?? [] : [];
    if (!Array.isArray(items)) return;

    items.forEach((item, idx) => {
      const row = document.createElement('div');
      row.className = 'arx-sortable-item';
      row.draggable = true;
      row.style.cssText = 'padding:10px 12px;border:1px solid #e0e0e0;border-radius:6px;margin-bottom:4px;cursor:grab;background:#fff;display:flex;align-items:center;gap:8px;transition:transform 0.15s ease,box-shadow 0.15s ease';

      const grip = document.createElement('span');
      grip.textContent = '⠿';
      grip.style.cssText = 'color:#999;font-size:16px';
      row.appendChild(grip);

      if (node.children.length > 0) {
        const childCtx: RenderCtx = { ...ctx, item, index: idx };
        for (const child of node.children) {
          const c = renderNode(child, state, childCtx, rt);
          if (c) row.appendChild(c);
        }
      } else {
        const txt = document.createElement('span');
        txt.textContent = String(item ?? '');
        row.appendChild(txt);
      }

      row.addEventListener('dragstart', (e) => {
        e.dataTransfer?.setData('text/plain', String(idx));
        row.style.opacity = '0.5';
      });
      row.addEventListener('dragend', () => { row.style.opacity = '1'; });
      row.addEventListener('dragover', (e) => { e.preventDefault(); row.style.borderColor = '#4f8ef7'; });
      row.addEventListener('dragleave', () => { row.style.borderColor = '#e0e0e0'; });
      row.addEventListener('drop', (e) => {
        e.preventDefault();
        row.style.borderColor = '#e0e0e0';
        const fromIdx = parseInt(e.dataTransfer?.getData('text/plain') ?? '-1', 10);
        if (stateKey && fromIdx >= 0 && fromIdx !== idx) {
          const arr = [...(state.get(stateKey) as unknown[] ?? [])];
          const [moved] = arr.splice(fromIdx, 1);
          arr.splice(idx, 0, moved);
          state.set(stateKey, arr);
        }
      });

      container.appendChild(row);
    });
  };

  renderItems();
  if (stateKey) state.subscribe(stateKey, renderItems);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 2: Command Palette ───────────────────────────────────────

function renderCommandPalette(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const overlay = document.createElement('div');
  overlay.className = 'arx-cmdpalette-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:flex-start;justify-content:center;z-index:10000;padding-top:15vh';

  const dialog = document.createElement('div');
  dialog.className = 'arx-cmdpalette';
  dialog.style.cssText = 'background:#fff;border-radius:12px;width:90%;max-width:560px;box-shadow:0 16px 48px rgba(0,0,0,.2);overflow:hidden';

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = 'Type a command…';
  input.style.cssText = 'width:100%;padding:16px 20px;border:none;font-size:16px;outline:none;box-sizing:border-box;border-bottom:1px solid #e0e0e0';

  const results = document.createElement('div');
  results.className = 'arx-cmdpalette-results';
  results.style.cssText = 'max-height:300px;overflow-y:auto';

  dialog.appendChild(input);
  dialog.appendChild(results);
  overlay.appendChild(dialog);

  // Collect commands from children
  const commands: { label: string; child: typeof node.children[0] }[] = [];
  for (const child of node.children) {
    if (child.kind === 'component') {
      const label = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : child.name;
      commands.push({ label, child });
    }
  }

  const renderResults = (query: string): void => {
    results.innerHTML = '';
    const filtered = query ? commands.filter(c => c.label.toLowerCase().includes(query.toLowerCase())) : commands;
    for (const cmd of filtered) {
      const item = document.createElement('div');
      item.style.cssText = 'padding:10px 20px;cursor:pointer;transition:background 0.1s ease';
      item.textContent = cmd.label;
      item.addEventListener('mouseenter', () => { item.style.background = '#f5f5f5'; });
      item.addEventListener('mouseleave', () => { item.style.background = ''; });
      item.addEventListener('click', () => {
        overlay.style.display = 'none';
        // Execute handlers on the child
        if (cmd.child.kind === 'component') {
          for (const h of cmd.child.handlers) {
            for (const action of h.actions) {
              if (action.kind === 'call') {
                const rArgs = action.args.map(a => 'key' in a ? a : resolveValue(a as import('../ast/values.js').ValueNode, state, ctx));
                if (action.fn === 'navigate') rt.navigate(String(rArgs[0]), {});
              }
            }
          }
        }
      });
      results.appendChild(item);
    }
  };

  renderResults('');
  input.addEventListener('input', () => renderResults(input.value));

  // Visibility via reactive arg or Ctrl+K
  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const show = (): void => { overlay.style.display = 'flex'; input.value = ''; renderResults(''); requestAnimationFrame(() => input.focus()); };
  const hide = (): void => { overlay.style.display = 'none'; };

  if (stateKey) {
    const update = (): void => { if (state.get(stateKey)) show(); else hide(); };
    update();
    state.subscribe(stateKey, update);
  }

  overlay.addEventListener('click', (e) => { if (e.target === overlay) { hide(); if (stateKey) state.set(stateKey, false); } });
  input.addEventListener('keydown', (e) => { if (e.key === 'Escape') { hide(); if (stateKey) state.set(stateKey, false); } });

  applyModifiers(overlay, node.mods, state, ctx);
  return overlay;
}

// ── Round 4 Feature 3: Data Table ────────────────────────────────────────────

function renderDataTable(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-datatable';
  wrapper.style.cssText = 'overflow-x:auto;border:1px solid #e0e0e0;border-radius:8px';

  const sourceArg = node.args[0];
  const stateKey = sourceArg?.kind === 'reactive' ? sourceArg.v : null;

  const render = (): void => {
    wrapper.innerHTML = '';
    const data = stateKey ? state.get(stateKey) : sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (!Array.isArray(data) || data.length === 0) {
      wrapper.textContent = 'No data';
      return;
    }

    const table = document.createElement('table');
    table.style.cssText = 'width:100%;border-collapse:collapse;font-size:14px';

    // Extract columns from first row
    const firstRow = data[0] as Record<string, unknown>;
    const cols = typeof firstRow === 'object' && firstRow !== null ? Object.keys(firstRow) : ['value'];

    // Header
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    let sortCol = '';
    let sortAsc = true;

    for (const col of cols) {
      const th = document.createElement('th');
      th.textContent = col;
      th.style.cssText = 'padding:10px 12px;text-align:left;background:#f8f9fa;border-bottom:2px solid #e0e0e0;cursor:pointer;user-select:none;font-weight:600';
      th.addEventListener('click', () => {
        if (sortCol === col) sortAsc = !sortAsc;
        else { sortCol = col; sortAsc = true; }
        if (stateKey) {
          const arr = [...(state.get(stateKey) as Record<string, unknown>[])];
          arr.sort((a, b) => {
            const va = a[col], vb = b[col];
            const cmp = String(va ?? '').localeCompare(String(vb ?? ''), undefined, { numeric: true });
            return sortAsc ? cmp : -cmp;
          });
          state.set(stateKey, arr);
        }
      });
      hr.appendChild(th);
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    // Body
    const tbody = document.createElement('tbody');
    for (const row of data) {
      const tr = document.createElement('tr');
      tr.style.cssText = 'border-bottom:1px solid #eee';
      tr.addEventListener('mouseenter', () => { tr.style.background = '#f8f9fa'; });
      tr.addEventListener('mouseleave', () => { tr.style.background = ''; });
      if (typeof row === 'object' && row !== null) {
        for (const col of cols) {
          const td = document.createElement('td');
          td.textContent = String((row as Record<string, unknown>)[col] ?? '');
          td.style.cssText = 'padding:8px 12px';
          tr.appendChild(td);
        }
      } else {
        const td = document.createElement('td');
        td.textContent = String(row);
        td.style.cssText = 'padding:8px 12px';
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrapper.appendChild(table);
  };

  render();
  if (stateKey) state.subscribe(stateKey, render);
  applyModifiers(wrapper, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(wrapper, h, state, ctx, rt);
  return wrapper;
}

// ── Round 4 Feature 4: Tree View ─────────────────────────────────────────────

function renderTreeView(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-treeview';
  container.style.cssText = 'font-size:14px';

  const sourceArg = node.args[0];

  interface TreeItem { label: string; children?: TreeItem[]; icon?: string }

  const buildTree = (items: TreeItem[], depth: number): HTMLElement => {
    const ul = document.createElement('div');
    ul.style.paddingLeft = depth > 0 ? '20px' : '0';

    for (const item of items) {
      const row = document.createElement('div');
      row.style.cssText = 'padding:4px 8px;cursor:pointer;display:flex;align-items:center;gap:6px;border-radius:4px';
      row.addEventListener('mouseenter', () => { row.style.background = '#f5f5f5'; });
      row.addEventListener('mouseleave', () => { row.style.background = ''; });

      const hasKids = item.children && item.children.length > 0;
      const arrow = document.createElement('span');
      arrow.textContent = hasKids ? '▸' : '  ';
      arrow.style.cssText = 'width:16px;font-size:12px;transition:transform 0.15s ease;flex-shrink:0';
      row.appendChild(arrow);

      if (item.icon) {
        const ico = document.createElement('span');
        ico.textContent = item.icon;
        ico.style.cssText = 'font-size:14px;flex-shrink:0';
        row.appendChild(ico);
      }

      const lbl = document.createElement('span');
      lbl.textContent = item.label;
      row.appendChild(lbl);

      ul.appendChild(row);

      if (hasKids) {
        const childContainer = buildTree(item.children!, depth + 1);
        childContainer.style.display = 'none';
        ul.appendChild(childContainer);
        let open = false;
        row.addEventListener('click', () => {
          open = !open;
          childContainer.style.display = open ? 'block' : 'none';
          arrow.style.transform = open ? 'rotate(90deg)' : '';
        });
      }
    }
    return ul;
  };

  const render = (): void => {
    container.innerHTML = '';
    const data = sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (Array.isArray(data)) {
      container.appendChild(buildTree(data as TreeItem[], 0));
    }
  };

  render();
  if (sourceArg?.kind === 'reactive') state.subscribe(sourceArg.v.split('.')[0]!, render);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 5: Calendar ──────────────────────────────────────────────

function renderCalendar(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-calendar';
  container.style.cssText = 'border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;width:fit-content';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  let viewDate = new Date();

  const render = (): void => {
    container.innerHTML = '';
    const year = viewDate.getFullYear();
    const month = viewDate.getMonth();
    const selected = stateKey ? String(state.get(stateKey) ?? '') : '';

    // Header with nav
    const header = document.createElement('div');
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:#f8f9fa';
    const prevBtn = document.createElement('button');
    prevBtn.textContent = '‹';
    prevBtn.style.cssText = 'border:none;background:none;font-size:20px;cursor:pointer;padding:4px 8px';
    prevBtn.addEventListener('click', () => { viewDate.setMonth(viewDate.getMonth() - 1); render(); });
    const nextBtn = document.createElement('button');
    nextBtn.textContent = '›';
    nextBtn.style.cssText = 'border:none;background:none;font-size:20px;cursor:pointer;padding:4px 8px';
    nextBtn.addEventListener('click', () => { viewDate.setMonth(viewDate.getMonth() + 1); render(); });
    const title = document.createElement('span');
    title.style.fontWeight = '600';
    const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    title.textContent = `${monthNames[month]} ${year}`;
    header.appendChild(prevBtn);
    header.appendChild(title);
    header.appendChild(nextBtn);
    container.appendChild(header);

    // Day names
    const dayRow = document.createElement('div');
    dayRow.style.cssText = 'display:grid;grid-template-columns:repeat(7,1fr);text-align:center;font-size:12px;color:#999;padding:8px 4px';
    for (const d of ['Su','Mo','Tu','We','Th','Fr','Sa']) {
      const dd = document.createElement('div');
      dd.textContent = d;
      dayRow.appendChild(dd);
    }
    container.appendChild(dayRow);

    // Days grid
    const grid = document.createElement('div');
    grid.style.cssText = 'display:grid;grid-template-columns:repeat(7,1fr);gap:2px;padding:4px';
    const firstDay = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const today = new Date().toISOString().slice(0, 10);

    for (let i = 0; i < firstDay; i++) {
      grid.appendChild(document.createElement('div'));
    }
    for (let d = 1; d <= daysInMonth; d++) {
      const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      const cell = document.createElement('div');
      cell.textContent = String(d);
      const isToday = dateStr === today;
      const isSelected = dateStr === selected;
      cell.style.cssText = `padding:8px;text-align:center;border-radius:50%;cursor:pointer;font-size:13px;transition:all 0.1s ease;${isSelected ? 'background:#1976d2;color:#fff;' : isToday ? 'border:1px solid #1976d2;' : ''}`;
      cell.addEventListener('mouseenter', () => { if (!isSelected) cell.style.background = '#eee'; });
      cell.addEventListener('mouseleave', () => { if (!isSelected) cell.style.background = ''; });
      cell.addEventListener('click', () => { if (stateKey) state.set(stateKey, dateStr); });
      grid.appendChild(cell);
    }
    container.appendChild(grid);
  };

  render();
  if (stateKey) state.subscribe(stateKey, render);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 6: Timeline ──────────────────────────────────────────────

function renderTimeline(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-timeline';
  container.style.cssText = 'position:relative;padding-left:32px';

  // Vertical line
  const line = document.createElement('div');
  line.style.cssText = 'position:absolute;left:12px;top:0;bottom:0;width:2px;background:#e0e0e0';
  container.appendChild(line);

  for (const child of node.children) {
    const item = document.createElement('div');
    item.className = 'arx-timeline-item';
    item.style.cssText = 'position:relative;padding-bottom:24px';

    // Dot
    const dot = document.createElement('div');
    dot.style.cssText = 'position:absolute;left:-26px;top:4px;width:12px;height:12px;border-radius:50%;background:#1976d2;border:2px solid #fff;box-shadow:0 0 0 2px #1976d2';
    item.appendChild(dot);

    const c = renderNode(child, state, ctx, rt);
    if (c) item.appendChild(c);
    container.appendChild(item);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 7: Chat Bubble ───────────────────────────────────────────

function renderChatBubble(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const bubble = document.createElement('div');
  bubble.className = 'arx-chatbubble';

  let isRight = false;
  for (const m of node.mods) {
    if (m.name === 'right' || m.name === 'sent') isRight = true;
    if (m.name === 'left' || m.name === 'received') isRight = false;
  }

  bubble.style.cssText = `max-width:75%;padding:10px 14px;border-radius:16px;font-size:14px;line-height:1.4;word-wrap:break-word;margin-bottom:4px;${
    isRight
      ? 'background:#1976d2;color:#fff;margin-left:auto;border-bottom-right-radius:4px'
      : 'background:#f0f0f0;color:#333;margin-right:auto;border-bottom-left-radius:4px'
  }`;

  if (node.args[0]) {
    const hasReactive = node.args.some(a => a.kind === 'reactive' || a.kind === 'interpolated');
    if (hasReactive) {
      const resolve = (): string => node.args.map(a => toDisplayString(resolveValue(a, state, ctx))).filter(Boolean).join(' ');
      bubble.textContent = resolve();
      const keys = new Set<string>();
      for (const a of node.args) for (const k of reactiveKeysOf(a)) keys.add(k);
      for (const k of keys) state.subscribe(k, () => { bubble.textContent = resolve(); });
    } else {
      bubble.textContent = toDisplayString(resolveValue(node.args[0], state, ctx));
    }
  }

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) bubble.appendChild(c);
  }

  applyModifiers(bubble, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(bubble, h, state, ctx, rt);
  return bubble;
}

// ── Round 4 Feature 8: Code Editor / Code Block ──────────────────────────────

function renderCodeEditor(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-codeeditor';
  wrapper.style.cssText = 'position:relative;border-radius:8px;overflow:hidden;border:1px solid #e0e0e0';

  const header = document.createElement('div');
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#f5f5f5;font-size:12px;color:#666';

  let lang = 'code';
  for (const m of node.mods) {
    if (['js','ts','python','rust','html','css','json','go','java','kotlin','swift'].includes(m.name)) lang = m.name;
  }
  header.textContent = lang;

  const copyBtn = document.createElement('button');
  copyBtn.textContent = 'Copy';
  copyBtn.style.cssText = 'border:none;background:#e0e0e0;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:11px';
  header.appendChild(copyBtn);

  const pre = document.createElement('pre');
  pre.style.cssText = 'margin:0;padding:16px;background:#1e1e2e;color:#cdd6f4;font-family:monospace;font-size:13px;overflow-x:auto;line-height:1.5;tab-size:2';

  const code = document.createElement('code');
  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const content = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  code.textContent = content;
  pre.appendChild(code);

  copyBtn.addEventListener('click', () => {
    navigator.clipboard?.writeText(code.textContent ?? '').then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    }).catch(() => {});
  });

  if (stateKey) {
    state.subscribe(stateKey, v => { code.textContent = String(v ?? ''); });
  }

  wrapper.appendChild(header);
  wrapper.appendChild(pre);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Round 4 Feature 9: Signature Pad ─────────────────────────────────────────

function renderSignaturePad(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-signaturepad';
  wrapper.style.cssText = 'display:inline-block;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden';

  const canvas = document.createElement('canvas');
  canvas.width = 400;
  canvas.height = 200;
  canvas.style.cssText = 'display:block;cursor:crosshair;background:#fff';

  for (const m of node.mods) {
    if (m.name === 'w' && m.args[0]) canvas.width = Number(resolveValue(m.args[0], state, ctx) ?? 400);
    if (m.name === 'h' && m.args[0]) canvas.height = Number(resolveValue(m.args[0], state, ctx) ?? 200);
  }

  const canvasCtx = canvas.getContext('2d');
  if (canvasCtx) {
    canvasCtx.lineWidth = 2;
    canvasCtx.lineCap = 'round';
    canvasCtx.strokeStyle = '#000';
  }
  let drawing = false;
  let lastX = 0, lastY = 0;

  canvas.addEventListener('mousedown', (e) => { drawing = true; [lastX, lastY] = [e.offsetX, e.offsetY]; });
  canvas.addEventListener('mousemove', (e) => {
    if (!drawing || !canvasCtx) return;
    canvasCtx.beginPath();
    canvasCtx.moveTo(lastX, lastY);
    canvasCtx.lineTo(e.offsetX, e.offsetY);
    canvasCtx.stroke();
    [lastX, lastY] = [e.offsetX, e.offsetY];
  });
  canvas.addEventListener('mouseup', () => {
    drawing = false;
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    if (stateKey) state.set(stateKey, canvas.toDataURL());
  });
  canvas.addEventListener('mouseleave', () => { drawing = false; });

  // Touch support
  canvas.addEventListener('touchstart', (e) => {
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const t = e.touches[0]!;
    drawing = true;
    lastX = t.clientX - rect.left;
    lastY = t.clientY - rect.top;
  });
  canvas.addEventListener('touchmove', (e) => {
    e.preventDefault();
    if (!drawing || !canvasCtx) return;
    const rect = canvas.getBoundingClientRect();
    const t = e.touches[0]!;
    const x = t.clientX - rect.left;
    const y = t.clientY - rect.top;
    canvasCtx.beginPath();
    canvasCtx.moveTo(lastX, lastY);
    canvasCtx.lineTo(x, y);
    canvasCtx.stroke();
    [lastX, lastY] = [x, y];
  });
  canvas.addEventListener('touchend', () => {
    drawing = false;
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    if (stateKey) state.set(stateKey, canvas.toDataURL());
  });

  // Clear button
  const clearBtn = document.createElement('button');
  clearBtn.textContent = 'Clear';
  clearBtn.style.cssText = 'display:block;width:100%;padding:8px;border:none;background:#f5f5f5;cursor:pointer;font-size:13px;border-top:1px solid #e0e0e0';
  clearBtn.addEventListener('click', () => {
    canvasCtx?.clearRect(0, 0, canvas.width, canvas.height);
    const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
    if (stateKey) state.set(stateKey, '');
  });

  wrapper.appendChild(canvas);
  wrapper.appendChild(clearBtn);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Round 4 Feature 10: Confetti ─────────────────────────────────────────────

function renderConfetti(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-confetti';
  container.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:99999;overflow:hidden';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const colors = ['#e74c3c','#3498db','#2ecc71','#f1c40f','#9b59b6','#e67e22','#1abc9c'];

  const burst = (): void => {
    for (let i = 0; i < 60; i++) {
      const piece = document.createElement('div');
      const color = colors[Math.floor(Math.random() * colors.length)]!;
      const size = 6 + Math.random() * 6;
      const x = 40 + Math.random() * 20;
      const rotation = Math.random() * 360;
      piece.style.cssText = `position:absolute;width:${size}px;height:${size}px;background:${color};left:${x}%;top:-10px;border-radius:${Math.random() > 0.5 ? '50%' : '2px'};opacity:1;transform:rotate(${rotation}deg)`;
      container.appendChild(piece);
      const xDrift = -200 + Math.random() * 400;
      const duration = 1500 + Math.random() * 2000;
      piece.animate([
        { transform: `translate(0,0) rotate(${rotation}deg)`, opacity: 1 },
        { transform: `translate(${xDrift}px, ${window.innerHeight + 50}px) rotate(${rotation + 720}deg)`, opacity: 0 },
      ], { duration, easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)' }).onfinish = () => piece.remove();
    }
  };

  if (stateKey) {
    state.subscribe(stateKey, v => { if (v) { burst(); setTimeout(() => state.set(stateKey, false), 100); } });
  } else {
    requestAnimationFrame(burst);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 11: Typewriter ───────────────────────────────────────────

function renderTypewriter(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const el = document.createElement('span');
  el.className = 'arx-typewriter';

  const text = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  let speed = 50;
  for (const m of node.mods) {
    if (m.name === 'speed' && m.args[0]) speed = Number(resolveValue(m.args[0], state, ctx) ?? 50);
  }

  let idx = 0;
  const type = (): void => {
    if (idx <= text.length) {
      el.textContent = text.slice(0, idx);
      idx++;
      setTimeout(type, speed);
    }
  };
  type();

  // Re-type on reactive change
  if (node.args[0]?.kind === 'reactive') {
    state.subscribe(node.args[0].v.split('.')[0]!, () => {
      const newText = String(resolveValue(node.args[0]!, state, ctx) ?? '');
      el.textContent = '';
      idx = 0;
      const retype = (): void => {
        if (idx <= newText.length) { el.textContent = newText.slice(0, idx); idx++; setTimeout(retype, speed); }
      };
      retype();
    });
  }

  el.style.borderRight = '2px solid currentColor';
  el.style.paddingRight = '2px';
  applyModifiers(el, node.mods, state, ctx);
  return el;
}

// ── Round 4 Feature 12: Count Up Animation ───────────────────────────────────

function renderCountUp(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const el = document.createElement('span');
  el.className = 'arx-countup';

  const target = node.args[0] ? Number(resolveValue(node.args[0], state, ctx) ?? 0) : 0;
  let duration = 1000;
  for (const m of node.mods) {
    if (m.name === 'duration' && m.args[0]) duration = Number(resolveValue(m.args[0], state, ctx) ?? 1000);
  }

  const animate = (to: number): void => {
    const start = performance.now();
    const from = 0;
    const tick = (now: number): void => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      const current = from + (to - from) * eased;
      el.textContent = Number.isInteger(to) ? String(Math.round(current)) : current.toFixed(1);
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  animate(target);

  if (node.args[0]?.kind === 'reactive') {
    state.subscribe(node.args[0].v.split('.')[0]!, () => {
      const v = Number(resolveValue(node.args[0]!, state, ctx) ?? 0);
      animate(v);
    });
  }

  applyModifiers(el, node.mods, state, ctx);
  return el;
}

// ── Round 4 Feature 13: OTP Input ────────────────────────────────────────────

function renderOTPInput(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-otpinput';
  container.style.cssText = 'display:flex;gap:8px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const length = node.args[1] ? Number(resolveValue(node.args[1], state, ctx) ?? 6) : 6;

  const inputs: HTMLInputElement[] = [];

  for (let i = 0; i < length; i++) {
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.maxLength = 1;
    inp.inputMode = 'numeric';
    inp.style.cssText = 'width:42px;height:48px;text-align:center;font-size:20px;font-weight:600;border:2px solid #ddd;border-radius:8px;outline:none;transition:border-color 0.15s ease';
    inp.addEventListener('focus', () => { inp.style.borderColor = '#1976d2'; inp.select(); });
    inp.addEventListener('blur', () => { inp.style.borderColor = '#ddd'; });
    inp.addEventListener('input', () => {
      if (inp.value.length === 1 && i < length - 1) inputs[i + 1]!.focus();
      if (stateKey) state.set(stateKey, inputs.map(x => x.value).join(''));
    });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !inp.value && i > 0) inputs[i - 1]!.focus();
    });
    // Handle paste
    inp.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = e.clipboardData?.getData('text') ?? '';
      for (let j = 0; j < Math.min(pasted.length, length - i); j++) {
        inputs[i + j]!.value = pasted[j]!;
      }
      const focusIdx = Math.min(i + pasted.length, length - 1);
      inputs[focusIdx]!.focus();
      if (stateKey) state.set(stateKey, inputs.map(x => x.value).join(''));
    });
    inputs.push(inp);
    container.appendChild(inp);
  }

  // Pre-fill from state
  if (stateKey) {
    const val = String(state.get(stateKey) ?? '');
    for (let i = 0; i < Math.min(val.length, length); i++) inputs[i]!.value = val[i]!;
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 14: File Upload / Dropzone ───────────────────────────────

function renderFileUpload(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-fileupload';
  container.style.cssText = 'border:2px dashed #ccc;border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:all 0.2s ease';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const label = document.createElement('div');
  label.style.cssText = 'color:#666;font-size:14px';
  label.innerHTML = '<div style="font-size:32px;margin-bottom:8px">📁</div>Drop files here or click to browse';

  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.multiple = true;
  fileInput.style.display = 'none';

  for (const m of node.mods) {
    if (m.name === 'accept' && m.args[0]) fileInput.accept = String(resolveValue(m.args[0], state, ctx) ?? '');
  }

  const processFiles = (files: FileList): void => {
    const fileInfos: { name: string; size: number; type: string; dataUrl?: string }[] = [];
    Array.from(files).forEach(f => {
      const info: typeof fileInfos[0] = { name: f.name, size: f.size, type: f.type };
      fileInfos.push(info);
      const reader = new FileReader();
      reader.onload = () => {
        info.dataUrl = reader.result as string;
        if (stateKey) state.set(stateKey, [...fileInfos]);
      };
      reader.readAsDataURL(f);
    });
    if (stateKey) state.set(stateKey, fileInfos);
  };

  fileInput.addEventListener('change', () => { if (fileInput.files?.length) processFiles(fileInput.files); });
  container.addEventListener('click', () => fileInput.click());

  container.addEventListener('dragover', (e) => { e.preventDefault(); container.style.borderColor = '#1976d2'; container.style.background = '#f0f7ff'; });
  container.addEventListener('dragleave', () => { container.style.borderColor = '#ccc'; container.style.background = ''; });
  container.addEventListener('drop', (e) => {
    e.preventDefault();
    container.style.borderColor = '#ccc';
    container.style.background = '';
    if (e.dataTransfer?.files.length) processFiles(e.dataTransfer.files);
  });

  container.appendChild(label);
  container.appendChild(fileInput);
  applyModifiers(container, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(container, h, state, ctx, rt);
  return container;
}

// ── Round 4 Feature 15: Sparkline ────────────────────────────────────────────

function renderSparkline(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-sparkline';
  wrapper.style.cssText = 'display:inline-block';

  const canvas = document.createElement('canvas');
  let w = 120, h = 32;
  for (const m of node.mods) {
    if (m.name === 'w' && m.args[0]) w = Number(resolveValue(m.args[0], state, ctx) ?? 120);
    if (m.name === 'h' && m.args[0]) h = Number(resolveValue(m.args[0], state, ctx) ?? 32);
  }
  canvas.width = w;
  canvas.height = h;
  canvas.style.cssText = `width:${w}px;height:${h}px;display:block`;

  const sourceArg = node.args[0];

  const draw = (): void => {
    const data = sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (!Array.isArray(data) || data.length < 2) return;
    const nums = data.map(Number);
    const min = Math.min(...nums);
    const max = Math.max(...nums);
    const range = max - min || 1;
    const c = canvas.getContext('2d');
    if (!c) return;
    c.clearRect(0, 0, w, h);
    c.beginPath();
    c.strokeStyle = '#1976d2';
    c.lineWidth = 1.5;
    for (let i = 0; i < nums.length; i++) {
      const x = (i / (nums.length - 1)) * w;
      const y = h - ((nums[i]! - min) / range) * (h - 4) - 2;
      if (i === 0) c.moveTo(x, y);
      else c.lineTo(x, y);
    }
    c.stroke();
  };

  draw();
  if (sourceArg?.kind === 'reactive') state.subscribe(sourceArg.v.split('.')[0]!, draw);

  wrapper.appendChild(canvas);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Round 4 Feature 16: Swipe Card ───────────────────────────────────────────

function renderSwipeCard(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-swipecard';
  container.style.cssText = 'position:relative;width:300px;height:400px;perspective:800px';

  const cards: HTMLElement[] = [];
  for (const child of [...node.children].reverse()) {
    const card = document.createElement('div');
    card.className = 'arx-swipecard-item';
    card.style.cssText = 'position:absolute;inset:0;border-radius:12px;background:#fff;box-shadow:0 4px 16px rgba(0,0,0,.12);overflow:hidden;transition:transform 0.3s ease;cursor:grab;touch-action:none';
    const c = renderNode(child, state, ctx, rt);
    if (c) card.appendChild(c);

    let startX = 0, currentX = 0, isDragging = false;
    card.addEventListener('pointerdown', (e) => { isDragging = true; startX = e.clientX; card.style.transition = 'none'; card.setPointerCapture(e.pointerId); });
    card.addEventListener('pointermove', (e) => {
      if (!isDragging) return;
      currentX = e.clientX - startX;
      card.style.transform = `translateX(${currentX}px) rotate(${currentX * 0.05}deg)`;
      card.style.opacity = String(1 - Math.abs(currentX) / 400);
    });
    card.addEventListener('pointerup', () => {
      isDragging = false;
      card.style.transition = 'transform 0.3s ease, opacity 0.3s ease';
      if (Math.abs(currentX) > 120) {
        card.style.transform = `translateX(${currentX > 0 ? 600 : -600}px) rotate(${currentX > 0 ? 30 : -30}deg)`;
        card.style.opacity = '0';
        setTimeout(() => card.remove(), 300);
      } else {
        card.style.transform = '';
        card.style.opacity = '1';
      }
      currentX = 0;
    });

    cards.push(card);
    container.appendChild(card);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 17: Circular Progress ────────────────────────────────────

function renderCircularProgress(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-circularprogress';
  container.style.cssText = 'display:inline-block;position:relative';

  let size = 80, stroke = 6;
  let color = '#1976d2', trackColor = '#e0e0e0';
  for (const m of node.mods) {
    if (m.name === 'size' && m.args[0]) size = Number(resolveValue(m.args[0], state, ctx) ?? 80);
    if (m.name === 'stroke' && m.args[0]) stroke = Number(resolveValue(m.args[0], state, ctx) ?? 6);
    if (m.name === 'color' && m.args[0]) color = String(resolveValue(m.args[0], state, ctx) ?? '#1976d2');
  }

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const maxVal = node.args[1] ? Number(resolveValue(node.args[1], state, ctx) ?? 100) : 100;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.style.transform = 'rotate(-90deg)';

  const track = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  track.setAttribute('cx', String(size / 2));
  track.setAttribute('cy', String(size / 2));
  track.setAttribute('r', String(radius));
  track.setAttribute('fill', 'none');
  track.setAttribute('stroke', trackColor);
  track.setAttribute('stroke-width', String(stroke));

  const progressCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  progressCircle.setAttribute('cx', String(size / 2));
  progressCircle.setAttribute('cy', String(size / 2));
  progressCircle.setAttribute('r', String(radius));
  progressCircle.setAttribute('fill', 'none');
  progressCircle.setAttribute('stroke', color);
  progressCircle.setAttribute('stroke-width', String(stroke));
  progressCircle.setAttribute('stroke-linecap', 'round');
  progressCircle.setAttribute('stroke-dasharray', String(circumference));
  progressCircle.style.transition = 'stroke-dashoffset 0.4s ease';

  svg.appendChild(track);
  svg.appendChild(progressCircle);

  // Center label
  const label = document.createElement('div');
  label.style.cssText = `position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:${Math.round(size / 4)}px;font-weight:600`;

  const update = (): void => {
    const val = stateKey ? Number(state.get(stateKey) ?? 0) : (node.args[0] ? Number(resolveValue(node.args[0], state, ctx) ?? 0) : 0);
    const pct = Math.min(Math.max(val / maxVal, 0), 1);
    progressCircle.setAttribute('stroke-dashoffset', String(circumference * (1 - pct)));
    label.textContent = `${Math.round(pct * 100)}%`;
  };
  update();
  if (stateKey) state.subscribe(stateKey, update);

  container.appendChild(svg);
  container.appendChild(label);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 18: Audio Player ─────────────────────────────────────────

function renderAudioPlayer(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-audioplayer';
  container.style.cssText = 'display:flex;align-items:center;gap:12px;padding:12px 16px;background:#f8f9fa;border-radius:12px;border:1px solid #e0e0e0';

  const src = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  const audio = new Audio(src);

  const playBtn = document.createElement('button');
  playBtn.textContent = '\u25B6';
  playBtn.style.cssText = 'width:36px;height:36px;border-radius:50%;border:none;background:#1976d2;color:#fff;cursor:pointer;font-size:14px;flex-shrink:0';

  const progressWrap = document.createElement('div');
  progressWrap.style.cssText = 'flex:1;height:6px;background:#ddd;border-radius:3px;cursor:pointer;position:relative';
  const progressBar = document.createElement('div');
  progressBar.style.cssText = 'height:100%;background:#1976d2;border-radius:3px;width:0;transition:width 0.1s linear';
  progressWrap.appendChild(progressBar);

  const timeLabel = document.createElement('span');
  timeLabel.style.cssText = 'font-size:12px;color:#666;min-width:40px;text-align:right';
  timeLabel.textContent = '0:00';

  let playing = false;
  playBtn.addEventListener('click', () => {
    if (playing) { audio.pause(); playBtn.textContent = '\u25B6'; }
    else { audio.play().catch(() => {}); playBtn.textContent = '\u23F8'; }
    playing = !playing;
  });

  audio.addEventListener('timeupdate', () => {
    if (audio.duration) {
      progressBar.style.width = `${(audio.currentTime / audio.duration) * 100}%`;
      const mins = Math.floor(audio.currentTime / 60);
      const secs = Math.floor(audio.currentTime % 60);
      timeLabel.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
    }
  });
  audio.addEventListener('ended', () => { playing = false; playBtn.textContent = '\u25B6'; progressBar.style.width = '0'; });

  progressWrap.addEventListener('click', (e) => {
    const rect = progressWrap.getBoundingClientRect();
    const pct = (e.clientX - rect.left) / rect.width;
    if (audio.duration) audio.currentTime = pct * audio.duration;
  });

  if (node.args[0]?.kind === 'reactive') {
    state.subscribe(node.args[0].v.split('.')[0]!, () => {
      audio.src = String(resolveValue(node.args[0]!, state, ctx) ?? '');
    });
  }

  container.appendChild(playBtn);
  container.appendChild(progressWrap);
  container.appendChild(timeLabel);
  applyModifiers(container, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(container, h, state, ctx, rt);
  return container;
}

// ── Round 4 Feature 19: Video Player with Overlay ────────────────────────────

function renderVideoPlayer(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-videoplayer';
  container.style.cssText = 'position:relative;border-radius:12px;overflow:hidden;background:#000;display:inline-block';

  const video = document.createElement('video');
  video.style.cssText = 'display:block;width:100%;max-width:100%';
  if (node.args[0]) video.src = String(resolveValue(node.args[0], state, ctx) ?? '');
  for (const m of node.mods) {
    if (m.name === 'autoplay') video.autoplay = true;
    if (m.name === 'loop') video.loop = true;
    if (m.name === 'muted') video.muted = true;
    if (m.name === 'poster' && m.args[0]) video.poster = String(resolveValue(m.args[0], state, ctx) ?? '');
  }

  // Custom controls overlay
  const controls = document.createElement('div');
  controls.style.cssText = 'position:absolute;bottom:0;left:0;right:0;padding:8px 12px;background:linear-gradient(transparent,rgba(0,0,0,.7));display:flex;align-items:center;gap:8px;opacity:0;transition:opacity 0.2s ease';
  container.addEventListener('mouseenter', () => { controls.style.opacity = '1'; });
  container.addEventListener('mouseleave', () => { controls.style.opacity = '0'; });

  const vpPlayBtn = document.createElement('button');
  vpPlayBtn.textContent = '\u25B6';
  vpPlayBtn.style.cssText = 'border:none;background:none;color:#fff;font-size:18px;cursor:pointer;padding:4px';
  let vpPlaying = false;
  vpPlayBtn.addEventListener('click', () => {
    if (vpPlaying) { video.pause(); vpPlayBtn.textContent = '\u25B6'; }
    else { video.play().catch(() => {}); vpPlayBtn.textContent = '\u23F8'; }
    vpPlaying = !vpPlaying;
  });

  const vpProgress = document.createElement('div');
  vpProgress.style.cssText = 'flex:1;height:4px;background:rgba(255,255,255,.3);border-radius:2px;cursor:pointer';
  const vpBar = document.createElement('div');
  vpBar.style.cssText = 'height:100%;background:#fff;border-radius:2px;width:0;transition:width 0.1s linear';
  vpProgress.appendChild(vpBar);

  video.addEventListener('timeupdate', () => { if (video.duration) vpBar.style.width = `${(video.currentTime / video.duration) * 100}%`; });
  video.addEventListener('ended', () => { vpPlaying = false; vpPlayBtn.textContent = '\u25B6'; });
  vpProgress.addEventListener('click', (e) => {
    const rect = vpProgress.getBoundingClientRect();
    if (video.duration) video.currentTime = ((e.clientX - rect.left) / rect.width) * video.duration;
  });

  const vpTime = document.createElement('span');
  vpTime.style.cssText = 'color:#fff;font-size:11px;min-width:36px';
  video.addEventListener('timeupdate', () => {
    const mins = Math.floor(video.currentTime / 60);
    const secs = Math.floor(video.currentTime % 60);
    vpTime.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
  });

  const fsBtn = document.createElement('button');
  fsBtn.textContent = '\u26F6';
  fsBtn.style.cssText = 'border:none;background:none;color:#fff;font-size:16px;cursor:pointer;padding:4px';
  fsBtn.addEventListener('click', () => { container.requestFullscreen?.().catch(() => {}); });

  controls.appendChild(vpPlayBtn);
  controls.appendChild(vpProgress);
  controls.appendChild(vpTime);
  controls.appendChild(fsBtn);

  container.appendChild(video);
  container.appendChild(controls);
  applyModifiers(container, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(container, h, state, ctx, rt);
  return container;
}

// ── Round 4 Feature 20: QR Code Generator ────────────────────────────────────

function renderQRCode(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-qrcode';
  container.style.cssText = 'display:inline-block';

  let qrSize = 150;
  for (const m of node.mods) {
    if (m.name === 'size' && m.args[0]) qrSize = Number(resolveValue(m.args[0], state, ctx) ?? 150);
  }

  const canvas = document.createElement('canvas');
  canvas.width = qrSize;
  canvas.height = qrSize;
  canvas.style.cssText = `width:${qrSize}px;height:${qrSize}px;display:block;image-rendering:pixelated`;

  const drawQR = (text: string): void => {
    // Simple QR-like matrix generation (visual pattern, not a real QR encoder)
    const ctx2d = canvas.getContext('2d');
    if (!ctx2d) return;
    const modules = 21; // QR version 1
    const cellSize = qrSize / modules;
    ctx2d.fillStyle = '#fff';
    ctx2d.fillRect(0, 0, qrSize, qrSize);
    ctx2d.fillStyle = '#000';

    // Generate deterministic pattern from text hash
    let hash = 0;
    for (let i = 0; i < text.length; i++) hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;

    // Draw finder patterns (corners)
    const drawFinder = (ox: number, oy: number): void => {
      for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) {
        const isBorder = x === 0 || x === 6 || y === 0 || y === 6;
        const isCenter = x >= 2 && x <= 4 && y >= 2 && y <= 4;
        if (isBorder || isCenter) ctx2d!.fillRect((ox + x) * cellSize, (oy + y) * cellSize, cellSize, cellSize);
      }
    };
    drawFinder(0, 0);
    drawFinder(modules - 7, 0);
    drawFinder(0, modules - 7);

    // Data area — seeded pseudo-random from hash
    let seed = Math.abs(hash);
    for (let y = 0; y < modules; y++) for (let x = 0; x < modules; x++) {
      // Skip finder regions
      if ((x < 8 && y < 8) || (x >= modules - 8 && y < 8) || (x < 8 && y >= modules - 8)) continue;
      seed = (seed * 16807 + 7) % 2147483647;
      if (seed % 3 === 0) ctx2d.fillRect(x * cellSize, y * cellSize, cellSize, cellSize);
    }
  };

  const qrText = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  drawQR(qrText);

  if (node.args[0]?.kind === 'reactive') {
    state.subscribe(node.args[0].v.split('.')[0]!, () => {
      drawQR(String(resolveValue(node.args[0]!, state, ctx) ?? ''));
    });
  }

  container.appendChild(canvas);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 21: Phone Input ──────────────────────────────────────────

function renderPhoneInput(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-phoneinput';
  wrapper.style.cssText = 'display:flex;align-items:center;border:1px solid #ddd;border-radius:8px;overflow:hidden';

  const phoneStateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const prefix = document.createElement('select');
  prefix.style.cssText = 'border:none;background:#f8f9fa;padding:10px;font-size:14px;outline:none;cursor:pointer';
  const codes = ['+1','+7','+44','+49','+33','+39','+34','+81','+86','+91','+380','+375','+998','+996'];
  for (const code of codes) {
    const opt = document.createElement('option');
    opt.value = code;
    opt.textContent = code;
    prefix.appendChild(opt);
  }

  const phoneInput = document.createElement('input');
  phoneInput.type = 'tel';
  phoneInput.placeholder = 'Phone number';
  phoneInput.style.cssText = 'border:none;flex:1;padding:10px;font-size:14px;outline:none';

  const updatePhone = (): void => {
    if (phoneStateKey) state.set(phoneStateKey, prefix.value + phoneInput.value);
  };
  prefix.addEventListener('change', updatePhone);
  phoneInput.addEventListener('input', () => {
    // Format: only digits, spaces, dashes
    phoneInput.value = phoneInput.value.replace(/[^0-9\s\-()]/g, '');
    updatePhone();
  });

  if (phoneStateKey) {
    const val = String(state.get(phoneStateKey) ?? '');
    const found = codes.find(c => val.startsWith(c));
    if (found) { prefix.value = found; phoneInput.value = val.slice(found.length); }
  }

  wrapper.appendChild(prefix);
  wrapper.appendChild(phoneInput);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── Round 4 Feature 22: Image Cropper ────────────────────────────────────────

function renderCropper(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-cropper';
  container.style.cssText = 'position:relative;display:inline-block;overflow:hidden;cursor:crosshair';

  const cropSrc = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
  const cropStateKey = node.args[1]?.kind === 'reactive' ? node.args[1].v : null;

  const img = document.createElement('img');
  img.src = cropSrc;
  img.style.cssText = 'display:block;max-width:400px;user-select:none;-webkit-user-drag:none';

  const cropBox = document.createElement('div');
  cropBox.style.cssText = 'position:absolute;border:2px dashed #fff;box-shadow:0 0 0 9999px rgba(0,0,0,0.5);cursor:move;min-width:20px;min-height:20px';

  let cropX = 50, cropY = 50, cropW = 150, cropH = 150;
  const updateBox = (): void => {
    cropBox.style.left = `${cropX}px`;
    cropBox.style.top = `${cropY}px`;
    cropBox.style.width = `${cropW}px`;
    cropBox.style.height = `${cropH}px`;
  };
  updateBox();

  let cropDragging = false, cropStartDX = 0, cropStartDY = 0;
  cropBox.addEventListener('pointerdown', (e) => {
    cropDragging = true; cropStartDX = e.clientX - cropX; cropStartDY = e.clientY - cropY;
    cropBox.setPointerCapture(e.pointerId);
  });
  cropBox.addEventListener('pointermove', (e) => {
    if (!cropDragging) return;
    cropX = Math.max(0, e.clientX - cropStartDX);
    cropY = Math.max(0, e.clientY - cropStartDY);
    updateBox();
  });
  cropBox.addEventListener('pointerup', () => {
    cropDragging = false;
    // Export cropped region
    if (cropStateKey && img.naturalWidth) {
      const scaleX = img.naturalWidth / img.clientWidth;
      const scaleY = img.naturalHeight / img.clientHeight;
      const cvs = document.createElement('canvas');
      cvs.width = cropW * scaleX;
      cvs.height = cropH * scaleY;
      cvs.getContext('2d')?.drawImage(img, cropX * scaleX, cropY * scaleY, cropW * scaleX, cropH * scaleY, 0, 0, cvs.width, cvs.height);
      state.set(cropStateKey, cvs.toDataURL());
    }
  });

  container.appendChild(img);
  container.appendChild(cropBox);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 23: Diff Viewer ──────────────────────────────────────────

function renderDiffViewer(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-diffviewer';
  container.style.cssText = 'font-family:monospace;font-size:13px;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden';

  const renderDiff = (): void => {
    container.innerHTML = '';
    const textA = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '') : '';
    const textB = node.args[1] ? String(resolveValue(node.args[1], state, ctx) ?? '') : '';
    const linesA = textA.split('\n');
    const linesB = textB.split('\n');
    const maxLen = Math.max(linesA.length, linesB.length);

    for (let i = 0; i < maxLen; i++) {
      const a = linesA[i] ?? '';
      const b = linesB[i] ?? '';
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;border-bottom:1px solid #f0f0f0';

      const lineNum = document.createElement('span');
      lineNum.textContent = String(i + 1);
      lineNum.style.cssText = 'width:32px;text-align:right;padding:2px 8px;color:#999;background:#f8f9fa;flex-shrink:0;user-select:none';

      const content = document.createElement('span');
      content.style.cssText = 'padding:2px 12px;flex:1;white-space:pre-wrap';

      if (a === b) {
        content.textContent = a;
      } else if (!a && b) {
        content.textContent = '+ ' + b;
        row.style.background = '#e6ffed';
        content.style.color = '#22863a';
      } else if (a && !b) {
        content.textContent = '- ' + a;
        row.style.background = '#ffeef0';
        content.style.color = '#cb2431';
      } else {
        content.innerHTML = `<span style="background:#ffeef0;color:#cb2431;text-decoration:line-through">- ${a}</span><br><span style="background:#e6ffed;color:#22863a">+ ${b}</span>`;
      }

      row.appendChild(lineNum);
      row.appendChild(content);
      container.appendChild(row);
    }
  };

  renderDiff();
  for (const arg of node.args) {
    if (arg?.kind === 'reactive') state.subscribe(arg.v.split('.')[0]!, renderDiff);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 24: Kanban Board ─────────────────────────────────────────

function renderKanban(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-kanban';
  container.style.cssText = 'display:flex;gap:16px;overflow-x:auto;padding:8px';

  // Each child is a column
  for (const child of node.children) {
    if (child.kind !== 'component') continue;
    const col = document.createElement('div');
    col.className = 'arx-kanban-col';
    col.style.cssText = 'min-width:250px;background:#f5f7fa;border-radius:8px;padding:12px;flex-shrink:0';

    const colTitle = document.createElement('div');
    colTitle.style.cssText = 'font-weight:600;margin-bottom:8px;font-size:14px';
    colTitle.textContent = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : child.name;
    col.appendChild(colTitle);

    const cardContainer = document.createElement('div');
    cardContainer.style.cssText = 'display:flex;flex-direction:column;gap:8px;min-height:40px';

    cardContainer.addEventListener('dragover', (e) => { e.preventDefault(); cardContainer.style.background = 'rgba(25,118,210,0.05)'; });
    cardContainer.addEventListener('dragleave', () => { cardContainer.style.background = ''; });
    cardContainer.addEventListener('drop', (e) => {
      e.preventDefault();
      cardContainer.style.background = '';
      const data = e.dataTransfer?.getData('text/plain');
      if (data) {
        const draggedEl = document.querySelector(`[data-arx-kanban-id="${data}"]`);
        if (draggedEl) cardContainer.appendChild(draggedEl);
      }
    });

    for (const gc of child.children) {
      const card = document.createElement('div');
      card.draggable = true;
      const cardId = 'k-' + Math.random().toString(36).slice(2, 8);
      card.setAttribute('data-arx-kanban-id', cardId);
      card.style.cssText = 'background:#fff;padding:10px 12px;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.08);cursor:grab;font-size:13px;transition:box-shadow 0.15s ease';
      card.addEventListener('dragstart', (ev) => { ev.dataTransfer?.setData('text/plain', cardId); card.style.opacity = '0.5'; });
      card.addEventListener('dragend', () => { card.style.opacity = '1'; });
      card.addEventListener('mouseenter', () => { card.style.boxShadow = '0 2px 8px rgba(0,0,0,.15)'; });
      card.addEventListener('mouseleave', () => { card.style.boxShadow = '0 1px 4px rgba(0,0,0,.08)'; });

      const c = renderNode(gc, state, ctx, rt);
      if (c) card.appendChild(c);
      cardContainer.appendChild(card);
    }

    col.appendChild(cardContainer);
    container.appendChild(col);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── Round 4 Feature 25: Meter / Gauge ────────────────────────────────────────

function renderMeter(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-meter';
  container.style.cssText = 'display:inline-block;position:relative;text-align:center';

  let meterSize = 120;
  let meterColor = '#1976d2';
  for (const m of node.mods) {
    if (m.name === 'size' && m.args[0]) meterSize = Number(resolveValue(m.args[0], state, ctx) ?? 120);
    if (m.name === 'color' && m.args[0]) meterColor = String(resolveValue(m.args[0], state, ctx) ?? '#1976d2');
  }

  const meterStateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const meterMax = node.args[1] ? Number(resolveValue(node.args[1], state, ctx) ?? 100) : 100;

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', String(meterSize));
  svg.setAttribute('height', String(Math.round(meterSize * 0.65)));
  svg.setAttribute('viewBox', `0 0 ${meterSize} ${Math.round(meterSize * 0.65)}`);

  const meterCx = meterSize / 2, meterCy = meterSize * 0.6;
  const meterRadius = meterSize * 0.4;
  const meterStartAngle = Math.PI;
  const meterEndAngle = 0;

  // Background arc
  const bgArc = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  const bgD = describeMeterArc(meterCx, meterCy, meterRadius, meterStartAngle, meterEndAngle);
  bgArc.setAttribute('d', bgD);
  bgArc.setAttribute('fill', 'none');
  bgArc.setAttribute('stroke', '#e0e0e0');
  bgArc.setAttribute('stroke-width', '8');
  bgArc.setAttribute('stroke-linecap', 'round');
  svg.appendChild(bgArc);

  // Value arc
  const valArc = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  valArc.setAttribute('fill', 'none');
  valArc.setAttribute('stroke', meterColor);
  valArc.setAttribute('stroke-width', '8');
  valArc.setAttribute('stroke-linecap', 'round');
  valArc.style.transition = 'all 0.4s ease';
  svg.appendChild(valArc);

  const meterLabel = document.createElement('div');
  meterLabel.style.cssText = `font-size:${Math.round(meterSize / 5)}px;font-weight:600;margin-top:-${Math.round(meterSize * 0.15)}px`;

  const updateMeter = (): void => {
    const val = meterStateKey ? Number(state.get(meterStateKey) ?? 0) : (node.args[0] ? Number(resolveValue(node.args[0], state, ctx) ?? 0) : 0);
    const pct = Math.min(Math.max(val / meterMax, 0), 1);
    const angle = meterStartAngle + (meterEndAngle - meterStartAngle) * pct;
    valArc.setAttribute('d', describeMeterArc(meterCx, meterCy, meterRadius, meterStartAngle, angle));
    meterLabel.textContent = String(Math.round(val));
  };
  updateMeter();
  if (meterStateKey) state.subscribe(meterStateKey, updateMeter);

  container.appendChild(svg);
  container.appendChild(meterLabel);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

/** Helper: SVG arc path descriptor for meter/gauge */
function describeMeterArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number): string {
  const x1 = cx + r * Math.cos(startAngle);
  const y1 = cy + r * Math.sin(startAngle);
  const x2 = cx + r * Math.cos(endAngle);
  const y2 = cy + r * Math.sin(endAngle);
  const largeArc = Math.abs(endAngle - startAngle) > Math.PI ? 1 : 0;
  const sweep = endAngle > startAngle ? 1 : 0;
  return `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} ${sweep} ${x2} ${y2}`;
}

// ── R5 Feature 11: Autocomplete ──────────────────────────────────────────────

function renderAutocomplete(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-autocomplete';
  wrapper.style.cssText = 'position:relative;display:inline-block;width:100%';

  const input = document.createElement('input');
  input.type = 'text';
  input.style.cssText = 'width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px;outline:none;box-sizing:border-box';
  input.placeholder = node.args[1] ? String(resolveValue(node.args[1], state, ctx) ?? 'Search…') : 'Search…';

  const dropdown = document.createElement('div');
  dropdown.style.cssText = 'position:absolute;top:100%;left:0;right:0;max-height:200px;overflow-y:auto;background:#fff;border:1px solid #e0e0e0;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.1);z-index:100;display:none;margin-top:4px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const optionsArg = node.args[2] ?? node.args[1];

  const getOptions = (): string[] => {
    if (optionsArg) {
      const v = resolveValue(optionsArg, state, ctx);
      if (Array.isArray(v)) return v.map(String);
    }
    return [];
  };

  const render = (query: string): void => {
    dropdown.innerHTML = '';
    const opts = getOptions().filter(o => o.toLowerCase().includes(query.toLowerCase()));
    if (opts.length === 0 || !query) { dropdown.style.display = 'none'; return; }
    dropdown.style.display = 'block';
    for (const opt of opts.slice(0, 10)) {
      const item = document.createElement('div');
      item.textContent = opt;
      item.style.cssText = 'padding:8px 12px;cursor:pointer;font-size:14px;transition:background 0.1s ease';
      item.addEventListener('mouseenter', () => { item.style.background = '#f5f5f5'; });
      item.addEventListener('mouseleave', () => { item.style.background = ''; });
      item.addEventListener('mousedown', (e) => {
        e.preventDefault();
        input.value = opt;
        if (stateKey) state.set(stateKey, opt);
        dropdown.style.display = 'none';
      });
      dropdown.appendChild(item);
    }
  };

  input.addEventListener('input', () => { render(input.value); if (stateKey) state.set(stateKey, input.value); });
  input.addEventListener('focus', () => { if (input.value) render(input.value); });
  input.addEventListener('blur', () => { setTimeout(() => { dropdown.style.display = 'none'; }, 150); });

  if (stateKey) {
    const v = state.get(stateKey);
    if (v) input.value = String(v);
  }

  wrapper.appendChild(input);
  wrapper.appendChild(dropdown);
  applyModifiers(wrapper, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(wrapper, h, state, ctx, rt);
  return wrapper;
}

// ── R5 Feature 12: Tag Input ─────────────────────────────────────────────────

function renderTagInput(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-taginput';
  container.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;padding:8px;border:1px solid #ddd;border-radius:8px;align-items:center;cursor:text;min-height:40px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = 'Add tag…';
  input.style.cssText = 'border:none;outline:none;font-size:14px;flex:1;min-width:80px;padding:4px';

  const renderTags = (): void => {
    container.querySelectorAll('.arx-tag-chip').forEach(el => el.remove());
    const tags = stateKey ? (state.get(stateKey) as string[]) ?? [] : [];
    if (!Array.isArray(tags)) return;
    for (let i = 0; i < tags.length; i++) {
      const chip = document.createElement('span');
      chip.className = 'arx-tag-chip';
      chip.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#e3f2fd;color:#1976d2;border-radius:16px;font-size:13px';
      chip.textContent = String(tags[i]);
      const x = document.createElement('span');
      x.textContent = '×';
      x.style.cssText = 'cursor:pointer;font-weight:bold;margin-left:2px';
      const idx = i;
      x.addEventListener('click', () => {
        if (stateKey) {
          const arr = [...((state.get(stateKey) as string[]) ?? [])];
          arr.splice(idx, 1);
          state.set(stateKey, arr);
        }
      });
      chip.appendChild(x);
      container.insertBefore(chip, input);
    }
  };

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && input.value.trim()) {
      e.preventDefault();
      if (stateKey) {
        const tags = [...((state.get(stateKey) as string[]) ?? [])];
        if (!tags.includes(input.value.trim())) {
          tags.push(input.value.trim());
          state.set(stateKey, tags);
        }
      }
      input.value = '';
    } else if (e.key === 'Backspace' && !input.value && stateKey) {
      const tags = [...((state.get(stateKey) as string[]) ?? [])];
      if (tags.length > 0) { tags.pop(); state.set(stateKey, tags); }
    }
  });

  container.addEventListener('click', () => input.focus());
  renderTags();
  if (stateKey) state.subscribe(stateKey, renderTags);

  container.appendChild(input);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 13: WYSIWYG Editor ────────────────────────────────────────────

function renderWysiwyg(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-wysiwyg';
  container.style.cssText = 'border:1px solid #ddd;border-radius:8px;overflow:hidden';

  const toolbar = document.createElement('div');
  toolbar.style.cssText = 'display:flex;gap:2px;padding:6px 8px;background:#f8f9fa;border-bottom:1px solid #ddd;flex-wrap:wrap';

  const actions: [string, string, string?][] = [
    ['B', 'bold'], ['I', 'italic'], ['U', 'underline'], ['S', 'strikeThrough'],
    ['H1', 'formatBlock', 'h1'], ['H2', 'formatBlock', 'h2'],
    ['UL', 'insertUnorderedList'], ['OL', 'insertOrderedList'],
    ['—', 'insertHorizontalRule'], ['✗', 'removeFormat'],
  ];

  for (const [label, cmd, val] of actions) {
    const btn = document.createElement('button');
    btn.textContent = label;
    btn.style.cssText = 'padding:4px 8px;border:1px solid #ddd;border-radius:4px;background:#fff;cursor:pointer;font-size:12px;font-weight:600;min-width:28px';
    btn.addEventListener('click', (e) => { e.preventDefault(); document.execCommand(cmd, false, val); });
    toolbar.appendChild(btn);
  }

  const editor = document.createElement('div');
  editor.contentEditable = 'true';
  editor.style.cssText = 'min-height:150px;padding:12px;outline:none;font-size:14px;line-height:1.6';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  if (stateKey) {
    editor.innerHTML = String(state.get(stateKey) ?? '');
    editor.addEventListener('input', () => state.set(stateKey, editor.innerHTML));
    state.subscribe(stateKey, v => { if (editor.innerHTML !== String(v ?? '')) editor.innerHTML = String(v ?? ''); });
  }

  container.appendChild(toolbar);
  container.appendChild(editor);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 14: Dual Range Slider ─────────────────────────────────────────

function renderDualRange(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-dualrange';
  container.style.cssText = 'position:relative;height:40px;display:flex;align-items:center;padding:0 8px';

  const minKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const maxKey = node.args[1]?.kind === 'reactive' ? node.args[1].v : null;
  const rangeMin = node.args[2] ? Number(resolveValue(node.args[2], state, ctx) ?? 0) : 0;
  const rangeMax = node.args[3] ? Number(resolveValue(node.args[3], state, ctx) ?? 100) : 100;

  const track = document.createElement('div');
  track.style.cssText = 'position:absolute;left:8px;right:8px;height:4px;background:#ddd;border-radius:2px';
  const fill = document.createElement('div');
  fill.style.cssText = 'position:absolute;height:100%;background:#1976d2;border-radius:2px';
  track.appendChild(fill);

  const makeThumb = (): HTMLElement => {
    const t = document.createElement('div');
    t.style.cssText = 'width:20px;height:20px;border-radius:50%;background:#1976d2;position:absolute;top:50%;transform:translate(-50%,-50%);cursor:grab;box-shadow:0 2px 4px rgba(0,0,0,.2);z-index:2';
    return t;
  };
  const thumbL = makeThumb();
  const thumbR = makeThumb();

  const update = (): void => {
    const minVal = minKey ? Number(state.get(minKey) ?? rangeMin) : rangeMin;
    const maxVal = maxKey ? Number(state.get(maxKey) ?? rangeMax) : rangeMax;
    const pctL = ((minVal - rangeMin) / (rangeMax - rangeMin)) * 100;
    const pctR = ((maxVal - rangeMin) / (rangeMax - rangeMin)) * 100;
    thumbL.style.left = `${pctL}%`;
    thumbR.style.left = `${pctR}%`;
    fill.style.left = `${pctL}%`;
    fill.style.width = `${pctR - pctL}%`;
  };

  const addDrag = (thumb: HTMLElement, key: string | null): void => {
    let dragging = false;
    thumb.addEventListener('pointerdown', (e) => { dragging = true; thumb.setPointerCapture(e.pointerId); thumb.style.cursor = 'grabbing'; });
    thumb.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      const rect = track.getBoundingClientRect();
      const pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      const val = Math.round(rangeMin + pct * (rangeMax - rangeMin));
      if (key) state.set(key, val);
    });
    thumb.addEventListener('pointerup', () => { dragging = false; thumb.style.cursor = 'grab'; });
  };
  addDrag(thumbL, minKey);
  addDrag(thumbR, maxKey);

  update();
  if (minKey) state.subscribe(minKey, update);
  if (maxKey) state.subscribe(maxKey, update);

  container.appendChild(track);
  container.appendChild(thumbL);
  container.appendChild(thumbR);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 15: Credit Card Input ─────────────────────────────────────────

function renderCreditCard(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-creditcard';
  container.style.cssText = 'display:flex;flex-direction:column;gap:8px;max-width:360px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const makeInput = (placeholder: string, maxLen: number, format?: (v: string) => string): HTMLInputElement => {
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.placeholder = placeholder;
    inp.maxLength = maxLen;
    inp.style.cssText = 'padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:16px;font-family:monospace;outline:none;width:100%;box-sizing:border-box';
    inp.addEventListener('focus', () => { inp.style.borderColor = '#1976d2'; });
    inp.addEventListener('blur', () => { inp.style.borderColor = '#ddd'; });
    if (format) inp.addEventListener('input', () => { const pos = inp.selectionStart; inp.value = format(inp.value); inp.selectionStart = inp.selectionEnd = pos; });
    return inp;
  };

  const numInput = makeInput('1234 5678 9012 3456', 19, v => v.replace(/\D/g, '').replace(/(.{4})/g, '$1 ').trim());
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:8px';
  const expInput = makeInput('MM/YY', 5, v => v.replace(/\D/g, '').replace(/^(\d{2})(\d)/, '$1/$2'));
  const cvvInput = makeInput('CVV', 4, v => v.replace(/\D/g, ''));
  cvvInput.type = 'password';
  row.appendChild(expInput);
  row.appendChild(cvvInput);

  // Luhn validation indicator
  const indicator = document.createElement('div');
  indicator.style.cssText = 'font-size:12px;padding:2px 0;min-height:16px';

  const luhnCheck = (num: string): boolean => {
    const digits = num.replace(/\D/g, '');
    if (digits.length < 13) return false;
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = parseInt(digits[i]!, 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  };

  const updateState = (): void => {
    if (stateKey) {
      state.set(stateKey, {
        number: numInput.value.replace(/\s/g, ''),
        expiry: expInput.value,
        cvv: cvvInput.value,
        valid: luhnCheck(numInput.value),
      });
    }
    const valid = luhnCheck(numInput.value);
    indicator.textContent = numInput.value.replace(/\D/g, '').length >= 13 ? (valid ? '✓ Valid' : '✗ Invalid') : '';
    indicator.style.color = valid ? '#2ecc71' : '#e74c3c';
  };

  numInput.addEventListener('input', updateState);
  expInput.addEventListener('input', updateState);
  cvvInput.addEventListener('input', updateState);

  container.appendChild(numInput);
  container.appendChild(row);
  container.appendChild(indicator);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 16: Emoji Picker ──────────────────────────────────────────────

function renderEmojiPicker(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-emojipicker';
  container.style.cssText = 'border:1px solid #e0e0e0;border-radius:12px;overflow:hidden;width:320px;background:#fff';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  const categories: [string, string[]][] = [
    ['Smileys', ['😀','😃','😄','😁','😆','😅','🤣','😂','🙂','😊','😇','🥰','😍','🤩','😘','😗','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','🤐','🤨','😑','😶','😏','😒','🙄','😬','🤥']],
    ['Gestures', ['👋','🤚','🖐','✋','🖖','👌','🤌','🤏','✌️','🤞','🤟','🤘','🤙','👈','👉','👆','🖕','👇','☝️','👍','👎','✊','👊','🤛','🤜','👏','🙌','👐','🤲','🤝','🙏']],
    ['Hearts', ['❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❤️‍🔥','❤️‍🩹','💕','💞','💓','💗','💖','💝','💘','💌']],
    ['Objects', ['⭐','🌟','✨','💫','🔥','💯','🎉','🎊','🏆','🥇','🎯','🚀','💡','🔔','🎵','🎶','💎','🔑','🔒','📌']],
    ['Nature', ['🌸','🌺','🌻','🌹','🌷','🌼','🍀','🌿','🍁','🍂','🌳','🌴','🌵','🌊','🌈','☀️','🌙','⭐','❄️','🔥']],
  ];

  // Tabs
  const tabs = document.createElement('div');
  tabs.style.cssText = 'display:flex;border-bottom:1px solid #e0e0e0';
  let activeCategory = 0;

  const grid = document.createElement('div');
  grid.style.cssText = 'display:grid;grid-template-columns:repeat(8,1fr);gap:2px;padding:8px;max-height:200px;overflow-y:auto';

  const renderCategory = (idx: number): void => {
    grid.innerHTML = '';
    const emojis = categories[idx]![1];
    for (const emoji of emojis) {
      const btn = document.createElement('button');
      btn.textContent = emoji;
      btn.style.cssText = 'font-size:22px;border:none;background:none;cursor:pointer;padding:4px;border-radius:4px;transition:background 0.1s ease';
      btn.addEventListener('mouseenter', () => { btn.style.background = '#f0f0f0'; });
      btn.addEventListener('mouseleave', () => { btn.style.background = ''; });
      btn.addEventListener('click', () => {
        if (stateKey) {
          const cur = String(state.get(stateKey) ?? '');
          state.set(stateKey, cur + emoji);
        }
      });
      grid.appendChild(btn);
    }
  };

  for (let i = 0; i < categories.length; i++) {
    const tab = document.createElement('button');
    tab.textContent = categories[i]![1][0]!;
    tab.style.cssText = 'flex:1;border:none;background:none;padding:8px;cursor:pointer;font-size:18px;border-bottom:2px solid transparent';
    const idx = i;
    tab.addEventListener('click', () => {
      activeCategory = idx;
      renderCategory(idx);
      tabs.querySelectorAll('button').forEach((b, j) => {
        (b as HTMLElement).style.borderBottomColor = j === idx ? '#1976d2' : 'transparent';
      });
    });
    if (i === 0) tab.style.borderBottomColor = '#1976d2';
    tabs.appendChild(tab);
  }

  renderCategory(0);
  container.appendChild(tabs);
  container.appendChild(grid);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 17: Mention Input ─────────────────────────────────────────────

function renderMention(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-mention';
  wrapper.style.cssText = 'position:relative';

  const input = document.createElement('input');
  input.type = 'text';
  input.style.cssText = 'width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px;outline:none;box-sizing:border-box';
  input.placeholder = '@mention someone…';

  const dropdown = document.createElement('div');
  dropdown.style.cssText = 'position:absolute;top:100%;left:0;right:0;max-height:160px;overflow-y:auto;background:#fff;border:1px solid #e0e0e0;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);z-index:100;display:none;margin-top:4px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const usersArg = node.args[1];

  input.addEventListener('input', () => {
    if (stateKey) state.set(stateKey, input.value);
    const val = input.value;
    const atIdx = val.lastIndexOf('@');
    if (atIdx >= 0 && atIdx === val.length - 1 || (atIdx >= 0 && !/\s/.test(val.slice(atIdx + 1)))) {
      const query = val.slice(atIdx + 1).toLowerCase();
      const users = usersArg ? resolveValue(usersArg, state, ctx) : [];
      if (Array.isArray(users)) {
        const filtered = users.map(String).filter(u => u.toLowerCase().includes(query)).slice(0, 8);
        dropdown.innerHTML = '';
        if (filtered.length > 0) {
          dropdown.style.display = 'block';
          for (const user of filtered) {
            const item = document.createElement('div');
            item.style.cssText = 'padding:8px 12px;cursor:pointer;font-size:14px;display:flex;align-items:center;gap:8px';
            item.innerHTML = `<span style="width:28px;height:28px;border-radius:50%;background:#e3f2fd;display:flex;align-items:center;justify-content:center;font-size:12px;color:#1976d2">@</span>${user}`;
            item.addEventListener('mouseenter', () => { item.style.background = '#f5f5f5'; });
            item.addEventListener('mouseleave', () => { item.style.background = ''; });
            item.addEventListener('mousedown', (e) => {
              e.preventDefault();
              input.value = val.slice(0, atIdx) + '@' + user + ' ';
              if (stateKey) state.set(stateKey, input.value);
              dropdown.style.display = 'none';
            });
            dropdown.appendChild(item);
          }
        } else dropdown.style.display = 'none';
      }
    } else dropdown.style.display = 'none';
  });
  input.addEventListener('blur', () => { setTimeout(() => { dropdown.style.display = 'none'; }, 150); });

  wrapper.appendChild(input);
  wrapper.appendChild(dropdown);
  applyModifiers(wrapper, node.mods, state, ctx);
  return wrapper;
}

// ── R5 Feature 18: Reactions Bar ─────────────────────────────────────────────

function renderReactions(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-reactions';
  container.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const emojis = ['👍','❤️','😂','😮','😢','🔥','🎉','👏'];

  const render = (): void => {
    container.innerHTML = '';
    const data = stateKey ? (state.get(stateKey) as Record<string, number>) ?? {} : {};

    for (const emoji of emojis) {
      const btn = document.createElement('button');
      const count = (typeof data === 'object' && data !== null) ? ((data as Record<string, number>)[emoji] ?? 0) : 0;
      btn.textContent = `${emoji}${count > 0 ? ' ' + count : ''}`;
      const isActive = count > 0;
      btn.style.cssText = `padding:4px 10px;border-radius:16px;border:1px solid ${isActive ? '#1976d2' : '#e0e0e0'};background:${isActive ? '#e3f2fd' : '#fff'};cursor:pointer;font-size:14px;transition:all 0.15s ease`;
      btn.addEventListener('mouseenter', () => { btn.style.borderColor = '#1976d2'; });
      btn.addEventListener('mouseleave', () => { if (!isActive) btn.style.borderColor = '#e0e0e0'; });
      btn.addEventListener('click', () => {
        if (stateKey) {
          const cur = { ...((state.get(stateKey) as Record<string, number>) ?? {}) };
          cur[emoji] = (cur[emoji] ?? 0) + 1;
          state.set(stateKey, cur);
        }
      });
      container.appendChild(btn);
    }
  };

  render();
  if (stateKey) state.subscribe(stateKey, render);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 19: Presence Indicator ────────────────────────────────────────

function renderPresence(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('span');
  container.className = 'arx-presence';
  container.style.cssText = 'display:inline-flex;align-items:center;gap:6px;font-size:13px';

  const dot = document.createElement('span');
  dot.style.cssText = 'width:10px;height:10px;border-radius:50%;display:inline-block;transition:background 0.3s ease';

  const label = document.createElement('span');

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const statusMap: Record<string, [string, string]> = {
    online:  ['#2ecc71', 'Online'],
    offline: ['#999',    'Offline'],
    away:    ['#f1c40f', 'Away'],
    busy:    ['#e74c3c', 'Busy'],
    dnd:     ['#e74c3c', 'Do Not Disturb'],
  };

  const update = (): void => {
    const val = stateKey ? String(state.get(stateKey) ?? 'offline') : 'offline';
    const [color, text] = statusMap[val] ?? statusMap['offline']!;
    dot.style.background = color;
    label.textContent = text;
  };
  update();
  if (stateKey) state.subscribe(stateKey, update);

  container.appendChild(dot);
  container.appendChild(label);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 20: Comment Thread ────────────────────────────────────────────

function renderThread(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-thread';
  container.style.cssText = 'display:flex;flex-direction:column;gap:12px';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  interface Comment { author: string; text: string; time?: string; replies?: Comment[] }

  const renderComment = (comment: Comment, depth: number): HTMLElement => {
    const item = document.createElement('div');
    item.style.cssText = `margin-left:${depth * 24}px;border-left:${depth > 0 ? '2px solid #e0e0e0' : 'none'};padding-left:${depth > 0 ? '12px' : '0'}`;

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:4px';
    const avatar = document.createElement('span');
    avatar.style.cssText = 'width:28px;height:28px;border-radius:50%;background:#e3f2fd;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;color:#1976d2';
    avatar.textContent = (comment.author || '?')[0]!.toUpperCase();
    const name = document.createElement('span');
    name.style.cssText = 'font-weight:600;font-size:13px';
    name.textContent = comment.author || 'Anonymous';
    const time = document.createElement('span');
    time.style.cssText = 'color:#999;font-size:11px';
    time.textContent = comment.time || '';
    header.appendChild(avatar);
    header.appendChild(name);
    header.appendChild(time);

    const body = document.createElement('div');
    body.style.cssText = 'font-size:14px;line-height:1.5;margin-bottom:4px';
    body.textContent = comment.text;

    item.appendChild(header);
    item.appendChild(body);

    if (comment.replies) {
      for (const reply of comment.replies) {
        item.appendChild(renderComment(reply, depth + 1));
      }
    }
    return item;
  };

  const render = (): void => {
    container.innerHTML = '';
    const data = stateKey ? state.get(stateKey) : [];
    if (Array.isArray(data)) {
      for (const comment of data as Comment[]) {
        container.appendChild(renderComment(comment, 0));
      }
    }
  };

  render();
  if (stateKey) state.subscribe(stateKey, render);

  // Also render static children
  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) container.appendChild(c);
  }

  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 1: Chart (bar/line/pie/donut) ────────────────────────────────

function renderChart(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'arx-chart';
  const canvas = document.createElement('canvas');
  let w = 400, h = 250;
  for (const m of node.mods) {
    if (m.name === 'w' && m.args[0]) w = Number(resolveValue(m.args[0], state, ctx) ?? 400);
    if (m.name === 'h' && m.args[0]) h = Number(resolveValue(m.args[0], state, ctx) ?? 250);
  }
  canvas.width = w; canvas.height = h;
  canvas.style.cssText = `width:${w}px;height:${h}px;display:block`;

  let chartType = 'bar';
  for (const m of node.mods) {
    if (['bar','line','pie','donut','area'].includes(m.name)) chartType = m.name;
  }

  const sourceArg = node.args[0];
  const colors = ['#4f8ef7','#e74c3c','#2ecc71','#f1c40f','#9b59b6','#e67e22','#1abc9c','#34495e'];

  const draw = (): void => {
    const data = sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (!Array.isArray(data)) return;
    const c = canvas.getContext('2d');
    if (!c) return;
    c.clearRect(0, 0, w, h);

    if (chartType === 'pie' || chartType === 'donut') {
      const nums = data.map(d => typeof d === 'object' && d !== null ? Number((d as Record<string,unknown>)['value'] ?? d) : Number(d));
      const total = nums.reduce((s, n) => s + n, 0) || 1;
      let angle = -Math.PI / 2;
      const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 10;
      for (let i = 0; i < nums.length; i++) {
        const slice = (nums[i]! / total) * Math.PI * 2;
        c.beginPath();
        c.moveTo(cx, cy);
        c.arc(cx, cy, r, angle, angle + slice);
        c.fillStyle = colors[i % colors.length]!;
        c.fill();
        angle += slice;
      }
      if (chartType === 'donut') {
        c.beginPath();
        c.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
        c.fillStyle = '#fff';
        c.fill();
      }
    } else {
      const nums = data.map(d => typeof d === 'object' && d !== null ? Number((d as Record<string,unknown>)['value'] ?? d) : Number(d));
      const max = Math.max(...nums, 1);
      const pad = 40;
      const barW = (w - pad * 2) / nums.length;

      // Axes
      c.strokeStyle = '#ddd'; c.lineWidth = 1;
      c.beginPath(); c.moveTo(pad, 10); c.lineTo(pad, h - pad); c.lineTo(w - 10, h - pad); c.stroke();

      if (chartType === 'line' || chartType === 'area') {
        c.beginPath();
        c.strokeStyle = colors[0]!; c.lineWidth = 2;
        for (let i = 0; i < nums.length; i++) {
          const x = pad + barW * i + barW / 2;
          const y = h - pad - (nums[i]! / max) * (h - pad - 20);
          if (i === 0) c.moveTo(x, y); else c.lineTo(x, y);
        }
        if (chartType === 'area') {
          c.lineTo(pad + barW * (nums.length - 1) + barW / 2, h - pad);
          c.lineTo(pad + barW / 2, h - pad);
          c.closePath();
          c.fillStyle = colors[0]! + '30';
          c.fill();
        }
        c.strokeStyle = colors[0]!; c.lineWidth = 2; c.stroke();
        // Dots
        for (let i = 0; i < nums.length; i++) {
          const x = pad + barW * i + barW / 2;
          const y = h - pad - (nums[i]! / max) * (h - pad - 20);
          c.beginPath(); c.arc(x, y, 3, 0, Math.PI * 2); c.fillStyle = colors[0]!; c.fill();
        }
      } else {
        // Bar
        for (let i = 0; i < nums.length; i++) {
          const barH = (nums[i]! / max) * (h - pad - 20);
          const x = pad + barW * i + 4;
          c.fillStyle = colors[i % colors.length]!;
          c.fillRect(x, h - pad - barH, barW - 8, barH);
        }
      }

      // Labels
      c.fillStyle = '#999'; c.font = '11px sans-serif'; c.textAlign = 'center';
      for (let i = 0; i < data.length; i++) {
        const label = typeof data[i] === 'object' && data[i] !== null ? String((data[i] as Record<string,unknown>)['label'] ?? i) : String(i);
        c.fillText(label, pad + barW * i + barW / 2, h - pad + 14);
      }
    }
  };
  draw();
  if (sourceArg?.kind === 'reactive') state.subscribe(sourceArg.v.split('.')[0]!, draw);

  wrapper.appendChild(canvas);
  applyModifiers(wrapper, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(wrapper, h, state, ctx, rt);
  return wrapper;
}

// ── R5 Feature 2: Heatmap ────────────────────────────────────────────────────

function renderHeatmap(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-heatmap';
  container.style.cssText = 'display:inline-block';

  const sourceArg = node.args[0];
  let cellSize = 14;
  for (const m of node.mods) {
    if (m.name === 'size' && m.args[0]) cellSize = Number(resolveValue(m.args[0], state, ctx) ?? 14);
  }

  const draw = (): void => {
    container.innerHTML = '';
    const data = sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (!Array.isArray(data)) return;
    const flat = data.flat().map(Number);
    const max = Math.max(...flat, 1);
    const cols = Array.isArray(data[0]) ? (data[0] as unknown[]).length : Math.ceil(Math.sqrt(flat.length));

    const grid = document.createElement('div');
    grid.style.cssText = `display:grid;grid-template-columns:repeat(${cols},${cellSize}px);gap:2px`;
    for (const val of flat) {
      const cell = document.createElement('div');
      const intensity = val / max;
      const r = Math.round(255 * intensity);
      const g = Math.round(100 * (1 - intensity));
      const b = Math.round(100 * (1 - intensity));
      cell.style.cssText = `width:${cellSize}px;height:${cellSize}px;border-radius:2px;background:rgb(${r},${g},${b})`;
      cell.title = String(val);
      grid.appendChild(cell);
    }
    container.appendChild(grid);
  };
  draw();
  if (sourceArg?.kind === 'reactive') state.subscribe(sourceArg.v.split('.')[0]!, draw);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 3: Org Chart ──────────────────────────────────────────────────

function renderOrgChart(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-orgchart';
  container.style.cssText = 'display:flex;flex-direction:column;align-items:center;gap:0;overflow-x:auto';

  interface OrgNode { label: string; children?: OrgNode[] }
  const sourceArg = node.args[0];

  const buildLevel = (nodes: OrgNode[]): HTMLElement => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;justify-content:center;gap:24px';
    for (const n of nodes) {
      const col = document.createElement('div');
      col.style.cssText = 'display:flex;flex-direction:column;align-items:center';
      const box = document.createElement('div');
      box.textContent = n.label;
      box.style.cssText = 'padding:8px 16px;border:2px solid #1976d2;border-radius:8px;background:#fff;font-size:13px;font-weight:500;white-space:nowrap';
      col.appendChild(box);
      if (n.children && n.children.length > 0) {
        const line = document.createElement('div');
        line.style.cssText = 'width:2px;height:20px;background:#ccc';
        col.appendChild(line);
        col.appendChild(buildLevel(n.children));
      }
      row.appendChild(col);
    }
    return row;
  };

  const draw = (): void => {
    container.innerHTML = '';
    const data = sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (Array.isArray(data)) container.appendChild(buildLevel(data as OrgNode[]));
  };
  draw();
  if (sourceArg?.kind === 'reactive') state.subscribe(sourceArg.v.split('.')[0]!, draw);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 4: Funnel ─────────────────────────────────────────────────────

function renderFunnel(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-funnel';
  container.style.cssText = 'display:flex;flex-direction:column;align-items:center;gap:2px';

  const sourceArg = node.args[0];
  const colors = ['#4f8ef7','#3498db','#2ecc71','#f1c40f','#e67e22','#e74c3c','#9b59b6'];

  const draw = (): void => {
    container.innerHTML = '';
    const data = sourceArg ? resolveValue(sourceArg, state, ctx) : [];
    if (!Array.isArray(data)) return;
    const items = data.map(d => typeof d === 'object' && d !== null ? d as Record<string,unknown> : { label: String(d), value: Number(d) });
    const maxVal = Math.max(...items.map(i => Number(i['value'] ?? 1)), 1);

    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      const val = Number(item['value'] ?? 1);
      const pct = (val / maxVal) * 100;
      const row = document.createElement('div');
      row.style.cssText = `width:${pct}%;padding:12px 16px;background:${colors[i % colors.length]};color:#fff;text-align:center;border-radius:4px;font-size:13px;font-weight:500;transition:width 0.3s ease;min-width:80px`;
      row.textContent = `${item['label'] ?? ''} (${val})`;
      container.appendChild(row);
    }
  };
  draw();
  if (sourceArg?.kind === 'reactive') state.subscribe(sourceArg.v.split('.')[0]!, draw);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 5: Split Pane ─────────────────────────────────────────────────

function renderSplitPane(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-splitpane';

  let vertical = false;
  for (const m of node.mods) {
    if (m.name === 'vertical' || m.name === 'col') vertical = true;
  }
  container.style.cssText = `display:flex;flex-direction:${vertical ? 'column' : 'row'};width:100%;height:100%;overflow:hidden`;

  const left = document.createElement('div');
  left.style.cssText = `flex:1;overflow:auto;min-${vertical ? 'height' : 'width'}:50px`;
  const right = document.createElement('div');
  right.style.cssText = `flex:1;overflow:auto;min-${vertical ? 'height' : 'width'}:50px`;

  const divider = document.createElement('div');
  divider.style.cssText = `${vertical ? 'height:6px;cursor:row-resize;width:100%' : 'width:6px;cursor:col-resize;height:100%'};background:#e0e0e0;flex-shrink:0;transition:background 0.15s ease`;
  divider.addEventListener('mouseenter', () => { divider.style.background = '#1976d2'; });
  divider.addEventListener('mouseleave', () => { if (!dragging) divider.style.background = '#e0e0e0'; });

  // Distribute children: first half -> left, second half -> right
  const mid = Math.ceil(node.children.length / 2);
  for (let i = 0; i < node.children.length; i++) {
    const c = renderNode(node.children[i]!, state, ctx, rt);
    if (c) (i < mid ? left : right).appendChild(c);
  }

  let dragging = false;
  divider.addEventListener('mousedown', () => { dragging = true; divider.style.background = '#1976d2'; });
  document.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const rect = container.getBoundingClientRect();
    if (vertical) {
      const pct = ((e.clientY - rect.top) / rect.height) * 100;
      left.style.flex = `0 0 ${pct}%`;
      right.style.flex = `0 0 ${100 - pct}%`;
    } else {
      const pct = ((e.clientX - rect.left) / rect.width) * 100;
      left.style.flex = `0 0 ${pct}%`;
      right.style.flex = `0 0 ${100 - pct}%`;
    }
  });
  document.addEventListener('mouseup', () => { dragging = false; divider.style.background = '#e0e0e0'; });

  container.appendChild(left);
  container.appendChild(divider);
  container.appendChild(right);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 6: Drawer / Sidebar ───────────────────────────────────────────

function renderDrawer(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const overlay = document.createElement('div');
  overlay.className = 'arx-drawer-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:1000;display:none;transition:opacity 0.3s ease;opacity:0';

  let side = 'left';
  let drawerW = '280px';
  for (const m of node.mods) {
    if (m.name === 'right') side = 'right';
    if (m.name === 'w' && m.args[0]) drawerW = String(resolveValue(m.args[0], state, ctx)) + (String(resolveValue(m.args[0], state, ctx)).includes('px') ? '' : 'px');
  }

  const panel = document.createElement('div');
  panel.className = 'arx-drawer';
  panel.style.cssText = `position:fixed;top:0;${side}:0;bottom:0;width:${drawerW};background:#fff;z-index:1001;transform:translateX(${side === 'left' ? '-100%' : '100%'});transition:transform 0.3s ease;overflow-y:auto;box-shadow:0 0 24px rgba(0,0,0,.2);padding:16px`;

  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) panel.appendChild(c);
  }

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;
  const show = (): void => { overlay.style.display = 'block'; requestAnimationFrame(() => { overlay.style.opacity = '1'; panel.style.transform = 'translateX(0)'; }); };
  const hide = (): void => { panel.style.transform = `translateX(${side === 'left' ? '-100%' : '100%'})`; overlay.style.opacity = '0'; setTimeout(() => { overlay.style.display = 'none'; }, 300); };

  if (stateKey) {
    const update = (): void => { state.get(stateKey) ? show() : hide(); };
    update();
    state.subscribe(stateKey, update);
  }
  overlay.addEventListener('click', () => { hide(); if (stateKey) state.set(stateKey, false); });

  overlay.appendChild(panel);
  applyModifiers(overlay, node.mods, state, ctx);
  return overlay;
}

// ── R5 Feature 7: Bottom Navigation ──────────────────────────────────────────

function renderBottomNav(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const nav = document.createElement('nav');
  nav.className = 'arx-bottomnav';
  nav.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#fff;display:flex;justify-content:space-around;align-items:center;height:56px;box-shadow:0 -2px 8px rgba(0,0,0,.1);z-index:500';

  const stateKey = node.args[0]?.kind === 'reactive' ? node.args[0].v : null;

  for (const child of node.children) {
    if (child.kind !== 'component') continue;
    const btn = document.createElement('button');
    btn.style.cssText = 'flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;border:none;background:none;padding:8px 0;cursor:pointer;font-size:11px;color:#666;transition:color 0.15s ease';

    const icon = document.createElement('span');
    icon.style.fontSize = '20px';
    icon.textContent = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : '\u25CF';
    const label = document.createElement('span');
    label.textContent = child.args[1] ? String(resolveValue(child.args[1], state, ctx) ?? '') : child.name;

    const key = child.args[2] ? String(resolveValue(child.args[2], state, ctx) ?? child.name) : child.name;

    const updateActive = (): void => {
      const isActive = stateKey ? state.get(stateKey) === key : false;
      btn.style.color = isActive ? '#1976d2' : '#666';
      icon.style.transform = isActive ? 'scale(1.15)' : '';
    };
    updateActive();
    if (stateKey) state.subscribe(stateKey, updateActive);

    btn.addEventListener('click', () => {
      if (stateKey) state.set(stateKey, key);
      for (const h of child.handlers) {
        for (const action of h.actions) {
          if (action.kind === 'call' && action.fn === 'navigate') {
            const target = action.args[0] && !('key' in action.args[0]) ? resolveValue(action.args[0] as import('../ast/values.js').ValueNode, state, ctx) : null;
            if (target) rt.navigate(String(target), {});
          }
        }
      }
    });

    btn.appendChild(icon);
    btn.appendChild(label);
    nav.appendChild(btn);
  }

  applyModifiers(nav, node.mods, state, ctx);
  return nav;
}

// ── R5 Feature 8: FAB / Speed Dial ───────────────────────────────────────────

function renderFAB(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-fab-container';
  container.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:500;display:flex;flex-direction:column-reverse;align-items:center;gap:12px';

  const mainBtn = document.createElement('button');
  mainBtn.className = 'arx-fab-main';
  mainBtn.style.cssText = 'width:56px;height:56px;border-radius:50%;border:none;background:#1976d2;color:#fff;font-size:24px;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.25);transition:transform 0.2s ease,background 0.2s ease;display:flex;align-items:center;justify-content:center';
  mainBtn.textContent = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? '+') : '+';

  const subBtns: HTMLElement[] = [];
  for (const child of node.children) {
    if (child.kind !== 'component') continue;
    const sub = document.createElement('button');
    sub.style.cssText = 'width:40px;height:40px;border-radius:50%;border:none;background:#fff;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.15);font-size:16px;display:none;transform:scale(0);transition:all 0.2s ease;display:flex;align-items:center;justify-content:center';
    sub.textContent = child.args[0] ? String(resolveValue(child.args[0], state, ctx) ?? '') : '\u25CF';
    sub.title = child.args[1] ? String(resolveValue(child.args[1], state, ctx) ?? '') : '';
    for (const h of child.handlers) attachHandler(sub, h, state, ctx, rt);
    subBtns.push(sub);
    container.insertBefore(sub, container.firstChild);
  }

  let open = false;
  mainBtn.addEventListener('click', () => {
    open = !open;
    mainBtn.style.transform = open ? 'rotate(45deg)' : '';
    subBtns.forEach((b, i) => {
      if (open) {
        b.style.display = 'flex';
        setTimeout(() => { b.style.transform = 'scale(1)'; }, i * 50);
      } else {
        b.style.transform = 'scale(0)';
        setTimeout(() => { b.style.display = 'none'; }, 200);
      }
    });
  });

  for (const h of node.handlers) attachHandler(mainBtn, h, state, ctx, rt);
  container.appendChild(mainBtn);
  applyModifiers(container, node.mods, state, ctx);
  return container;
}

// ── R5 Feature 9: App Bar / Toolbar ──────────────────────────────────────────

function renderAppBar(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const bar = document.createElement('div');
  bar.className = 'arx-appbar';
  bar.style.cssText = 'display:flex;align-items:center;padding:8px 16px;background:#1976d2;color:#fff;gap:12px;min-height:48px;box-shadow:0 2px 8px rgba(0,0,0,.15)';

  // First arg = title
  if (node.args[0]) {
    const title = document.createElement('h1');
    title.style.cssText = 'font-size:18px;font-weight:600;margin:0;flex:1';
    const hasReactive = node.args[0].kind === 'reactive' || node.args[0].kind === 'interpolated';
    if (hasReactive) {
      title.textContent = toDisplayString(resolveValue(node.args[0], state, ctx));
      for (const k of reactiveKeysOf(node.args[0])) state.subscribe(k, () => { title.textContent = toDisplayString(resolveValue(node.args[0]!, state, ctx)); });
    } else {
      title.textContent = toDisplayString(resolveValue(node.args[0], state, ctx));
    }
    bar.appendChild(title);
  }

  // Children become action buttons
  for (const child of node.children) {
    const c = renderNode(child, state, ctx, rt);
    if (c) { c.style.color = c.style.color || '#fff'; bar.appendChild(c); }
  }

  applyModifiers(bar, node.mods, state, ctx);
  return bar;
}

// ── R5 Feature 10: Terminal Emulator ─────────────────────────────────────────

function renderTerminal(
  node: ComponentNode, state: StateAPI, ctx: RenderCtx, rt: RuntimeHooks,
): HTMLElement {
  const container = document.createElement('div');
  container.className = 'arx-terminal';
  container.style.cssText = 'background:#1e1e2e;color:#cdd6f4;border-radius:12px;overflow:hidden;font-family:monospace;font-size:13px';

  // Title bar
  const titleBar = document.createElement('div');
  titleBar.style.cssText = 'display:flex;align-items:center;padding:8px 12px;background:#181825;gap:6px';
  for (const c of ['#ff5f56','#ffbd2e','#27c93f']) {
    const dot = document.createElement('span');
    dot.style.cssText = `width:12px;height:12px;border-radius:50%;background:${c}`;
    titleBar.appendChild(dot);
  }
  const titleText = document.createElement('span');
  titleText.style.cssText = 'margin-left:8px;font-size:12px;color:#888';
  titleText.textContent = node.args[0] ? String(resolveValue(node.args[0], state, ctx) ?? 'terminal') : 'terminal';
  titleBar.appendChild(titleText);
  container.appendChild(titleBar);

  const output = document.createElement('div');
  output.style.cssText = 'padding:12px;max-height:300px;overflow-y:auto;line-height:1.6';

  const stateKey = node.args[1]?.kind === 'reactive' ? node.args[1].v : null;
  // Pre-fill output from state
  if (stateKey) {
    const hist = state.get(stateKey);
    if (Array.isArray(hist)) {
      for (const line of hist) {
        const div = document.createElement('div');
        div.textContent = String(line);
        output.appendChild(div);
      }
    }
  }

  // Input line
  const inputLine = document.createElement('div');
  inputLine.style.cssText = 'display:flex;align-items:center;padding:8px 12px;border-top:1px solid #313244;gap:6px';
  const prompt = document.createElement('span');
  prompt.textContent = '$ ';
  prompt.style.color = '#a6e3a1';
  const input = document.createElement('input');
  input.type = 'text';
  input.style.cssText = 'flex:1;background:none;border:none;color:#cdd6f4;font-family:monospace;font-size:13px;outline:none';

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && input.value.trim()) {
      const cmd = input.value.trim();
      const cmdLine = document.createElement('div');
      cmdLine.innerHTML = `<span style="color:#a6e3a1">$ </span>${cmd}`;
      output.appendChild(cmdLine);

      // Built-in commands
      const resultLine = document.createElement('div');
      if (cmd === 'clear') { output.innerHTML = ''; }
      else if (cmd === 'help') { resultLine.textContent = 'Available: clear, help, echo, date, version'; output.appendChild(resultLine); }
      else if (cmd.startsWith('echo ')) { resultLine.textContent = cmd.slice(5); output.appendChild(resultLine); }
      else if (cmd === 'date') { resultLine.textContent = new Date().toLocaleString(); output.appendChild(resultLine); }
      else if (cmd === 'version') { resultLine.textContent = 'Architex Terminal v1.0'; output.appendChild(resultLine); }
      else { resultLine.style.color = '#f38ba8'; resultLine.textContent = `command not found: ${cmd}`; output.appendChild(resultLine); }

      if (stateKey) {
        const hist = (state.get(stateKey) as string[]) ?? [];
        state.set(stateKey, [...hist, `$ ${cmd}`]);
      }
      input.value = '';
      output.scrollTop = output.scrollHeight;
    }
  });

  inputLine.appendChild(prompt);
  inputLine.appendChild(input);
  container.appendChild(output);
  container.appendChild(inputLine);

  applyModifiers(container, node.mods, state, ctx);
  for (const h of node.handlers) attachHandler(container, h, state, ctx, rt);
  return container;
}

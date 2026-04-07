/** ArchiRuntime — parse → state → render → navigate → lifecycle. */

import { scanLines }        from '../lexer/scanner.js';
import { buildTree }        from '../parser/tree.js';
import type { ScreenNode, LifecycleNode, ComponentDefNode, ImportNode, ThemeNode, StyleNode, HotkeyNode, TimerNode, WsNode, SseNode, RouteNode, DebugNode, CatchNode, OfflineNode, I18nNode, A11yNode, LiquidGlassNode, AnimationNode, TransitionNode, WorkerNode, PermissionNode, FsmNode, VoiceNode, BiometricNode, CronNode, SyncNode } from '../ast/nodes.js';
import type { Action }      from '../ast/actions.js';
import type { ValueNode }   from '../ast/values.js';
import type { StateAPI }    from '../reactive/types.js';
import type { RuntimeHooks } from '../renderer/types.js';
import { renderNode }       from '../renderer/index.js';
import { showToast }        from '../renderer/toast.js';
import type { ToastType }   from '../renderer/toast.js';
import { initState, evalExpr } from './init.js';
import type { ArchiOptions, ArchiError } from './types.js';

interface HistoryEntry {
  screen: string;
  params: Record<string, unknown>;
}

interface Lifecycle {
  mount:   Action[];
  unmount: Action[];
}

export class ArchiRuntime {
  private readonly _src:       string;
  private readonly _container: HTMLElement;
  private readonly _opts:      ArchiOptions;

  private _screens:    Map<string, ScreenNode>   = new Map();
  private _lifecycles: Map<string, Lifecycle>    = new Map();
  private _compDefs:   Map<string, ComponentDefNode> = new Map();
  private _imports:    ImportNode[]             = [];
  private _themes:     ThemeNode[]             = [];
  private _state:      StateAPI | null           = null;
  private _current:    string | null            = null;
  private _currentParams: Record<string, unknown> = {};
  /** P3 #21 — screen history stack */
  private _history:    HistoryEntry[]           = [];
  private _destroyed = false;
  /** Screen transition type: fade | slide-left | slide-right | slide-up | none */
  private _transition = 'fade';
  private _styleInjected = false;
  /** Unique instance ID for scoped CSS */
  private _instanceId = 'arx-' + Math.random().toString(36).slice(2, 8);
  /** Injected scoped style elements for cleanup */
  private _scopedStyles: HTMLStyleElement[] = [];
  /** Active timer IDs for @timer cleanup */
  private _timers: ReturnType<typeof setInterval>[] = [];
  /** Active @hotkey listener refs for cleanup */
  private _hotkeyCleanups: (() => void)[] = [];
  /** Current theme: 'light' | 'dark' */
  private _theme: 'light' | 'dark' = 'light';
  /** Active WebSocket connections */
  private _websockets: WebSocket[] = [];
  /** Active EventSource (SSE) connections */
  private _eventSources: EventSource[] = [];
  /** URL routes for deep linking */
  private _routes: Map<string, string> = new Map();
  /** i18n translations: locale → key → value */
  private _i18nData: Record<string, Record<string, string>> = {};
  private _i18nLocale = 'en';
  /** Debug mode */
  private _debug = false;
  /** Liquid-Glass-PRO initialized */
  private _lgInitialized = false;
  /** Undo/redo state stack */
  private _undoStack: Record<string, unknown>[] = [];
  private _redoStack: Record<string, unknown>[] = [];
  /** Web Workers */
  private _workers: Worker[] = [];
  /** Voice recognition instance */
  private _voiceRecognition: unknown = null;
  /** BroadcastChannel for @sync */
  private _syncChannel: BroadcastChannel | null = null;
  /** Cron intervals */
  private _cronTimers: ReturnType<typeof setInterval>[] = [];
  /** Offline handler registered */
  private _offlineHandler: (() => void) | null = null;
  private _onlineHandler: (() => void) | null = null;

  constructor(src: string, opts: ArchiOptions) {
    this._src       = src;
    this._container = opts.container;
    this._opts      = opts;
  }

  // ── Boot ───────────────────────────────────────────────────────────────────

  start(screenName?: string): this {
    this._destroyed = false; // allow re-start after destroy
    const { nodes: ast, errors } = buildTree(scanLines(this._src));
    for (const err of errors) {
      this._error('parse', err.message, err.line);
    }

    // Collect @import and @theme nodes
    this._imports = [];
    this._themes  = [];
    for (const node of ast) {
      if (node.kind === 'import') this._imports.push(node);
      if (node.kind === 'theme')  this._themes.push(node);
    }

    // Inject transition/animation CSS once
    if (!this._styleInjected) {
      this._injectStyles();
      this._styleInjected = true;
    }

    // Apply @theme CSS custom properties to container
    for (const theme of this._themes) {
      for (const v of theme.vars) {
        const val = this._literalVal(v.expr);
        this._container.style.setProperty(`--arx-${v.name}`, String(val ?? ''));
      }
    }

    // Process @style nodes — inject scoped CSS
    this._container.classList.add(this._instanceId);
    for (const s of this._scopedStyles) s.remove();
    this._scopedStyles = [];
    for (const node of ast) {
      if (node.kind === 'style') {
        this._injectScopedStyle(node);
      }
    }

    for (const node of ast) {
      if (node.kind === 'screen') {
        this._screens.set(node.name, node);
        // P3 #23 — collect lifecycle hooks per screen
        const lc: Lifecycle = { mount: [], unmount: [] };
        for (const child of node.body) {
          if (child.kind === 'lifecycle') {
            if (child.hook === 'mount')   lc.mount.push(...child.actions);
            if (child.hook === 'unmount') lc.unmount.push(...child.actions);
          }
        }
        if (lc.mount.length || lc.unmount.length) this._lifecycles.set(node.name, lc);
      }
    }

    this._state = initState(ast);

    // Collect user-defined components
    this._compDefs.clear();
    for (const node of ast) {
      if (node.kind === 'compDef') {
        this._compDefs.set(node.name.toLowerCase(), node);
      }
    }

    // Set up @watch subscriptions via _runActions (supports navigate/fetch/send)
    const setupWatches = (nodes: typeof ast): void => {
      for (const node of nodes) {
        if (node.kind === 'watch') {
          this._state!.subscribe(node.target, () => this._runActions(node.actions));
        }
        if (node.kind === 'screen') setupWatches(node.body);
      }
    };
    setupWatches(ast);

    // Set up @hotkey listeners
    this._hotkeyCleanups.forEach(fn => fn());
    this._hotkeyCleanups = [];
    for (const node of ast) {
      if (node.kind === 'hotkey') this._setupHotkey(node);
    }

    // Set up @timer intervals
    this._timers.forEach(id => clearInterval(id));
    this._timers = [];
    for (const node of ast) {
      if (node.kind === 'timer') {
        const id = setInterval(() => this._runActions(node.actions), node.interval);
        this._timers.push(id);
      }
    }

    // Set up @ws WebSocket connections
    this._websockets.forEach(ws => ws.close());
    this._websockets = [];
    for (const node of ast) {
      if (node.kind === 'ws') this._setupWebSocket(node as WsNode);
    }

    // Set up @sse Server-Sent Events
    this._eventSources.forEach(es => es.close());
    this._eventSources = [];
    for (const node of ast) {
      if (node.kind === 'sse') this._setupSSE(node as SseNode);
    }

    // Set up @route URL deep links
    this._routes.clear();
    for (const node of ast) {
      if (node.kind === 'route') {
        const r = node as RouteNode;
        this._routes.set(r.path, r.screen);
      }
    }
    if (this._routes.size > 0) this._setupRouting();

    // Set up @i18n
    for (const node of ast) {
      if (node.kind === 'i18n') {
        const i = node as I18nNode;
        this._i18nLocale = i.locale;
        if (i.path && this._opts.resolve) {
          this._opts.resolve(i.path).then(data => {
            try {
              this._i18nData[i.locale] = JSON.parse(data);
              this._state?.set('_i18n', this._i18nData[this._i18nLocale] ?? {});
              this._state?.set('_locale', this._i18nLocale);
            } catch { /* invalid JSON */ }
          }).catch(() => {});
        }
      }
    }

    // Set up @debug
    for (const node of ast) {
      if (node.kind === 'debug') {
        this._debug = true;
        if ((node as DebugNode).expr) {
          const expr = (node as DebugNode).expr!;
          const deps = this._collectReactiveDeps(expr);
          for (const d of deps) {
            this._state!.subscribe(d, () => {
              console.log(`[Architex debug] ~${d} =`, this._state!.get(d));
            });
          }
        }
      }
    }

    // Set up @offline detection
    if (this._offlineHandler) { window.removeEventListener('offline', this._offlineHandler); this._offlineHandler = null; }
    if (this._onlineHandler) { window.removeEventListener('online', this._onlineHandler); this._onlineHandler = null; }
    const hasOffline = ast.some(n => n.kind === 'offline');
    if (hasOffline) {
      this._state!.set('_online', navigator.onLine);
      this._offlineHandler = () => this._state!.set('_online', false);
      this._onlineHandler = () => this._state!.set('_online', true);
      window.addEventListener('offline', this._offlineHandler);
      window.addEventListener('online', this._onlineHandler);
    }

    // Set up @liquidglass — Liquid-Glass-PRO initialization
    for (const node of ast) {
      if (node.kind === 'liquidglass') {
        this._initLiquidGlass(node.config);
        break; // only one @liquidglass directive
      }
    }

    // Set up @worker
    this._workers.forEach(w => w.terminate());
    this._workers = [];
    for (const node of ast) {
      if (node.kind === 'worker') this._setupWorker(node as WorkerNode);
    }

    // Set up @voice commands
    for (const node of ast) {
      if (node.kind === 'voice') this._setupVoice(node as VoiceNode);
    }

    // Set up @sync — BroadcastChannel cross-tab
    this._syncChannel?.close();
    this._syncChannel = null;
    for (const node of ast) {
      if (node.kind === 'sync') this._setupSync(node as SyncNode);
    }

    // Set up @cron scheduled tasks
    this._cronTimers.forEach(id => clearInterval(id));
    this._cronTimers = [];
    for (const node of ast) {
      if (node.kind === 'cron') {
        const c = node as CronNode;
        const ms = this._parseCronToMs(c.pattern);
        if (ms > 0) {
          const id = setInterval(() => this._runActions(c.actions), ms);
          this._cronTimers.push(id);
        }
      }
    }

    // Set up @animation — inject custom keyframes
    for (const node of ast) {
      if (node.kind === 'animation') {
        this._injectAnimation(node as AnimationNode);
      }
    }

    // Initialize undo/redo system
    this._undoStack = [];
    this._redoStack = [];
    if (this._state) {
      // Capture initial state for undo
      this._undoStack.push(this._state.snapshot());
    }

    const first = screenName ?? this._screens.keys().next().value ?? null;
    if (first) this.navigate(first);
    return this;
  }

  // ── Navigation ─────────────────────────────────────────────────────────────

  /**
   * Navigate to a named screen.
   * @param screenName  Target screen name.
   * @param params      Values injected into RenderCtx (P3 #22) and state.
   * @param pushHistory Internal flag — false when called from back().
   */
  navigate(
    screenName:  string,
    params:      Record<string, unknown> = {},
    pushHistory  = true,
  ): void {
    if (this._destroyed) return;
    const screen = this._screens.get(screenName);
    if (!screen) { this._error('navigate', `Screen "${screenName}" not found`); return; }

    // P3 #23 — run unmount lifecycle for the outgoing screen
    if (this._current) {
      const lc = this._lifecycles.get(this._current);
      if (lc?.unmount.length) this._runActions(lc.unmount);
    }

    // P3 #21 — push current screen to history
    if (pushHistory && this._current !== null) {
      this._history.push({ screen: this._current, params: this._currentParams });
    }

    // Write params to state so ~param reactive refs work
    if (Object.keys(params).length > 0) {
      this._state!.batch(() => {
        for (const [k, v] of Object.entries(params)) this._state!.set(k, v);
      });
    }

    // P3 #22 — pass params as RenderCtx so ident-based access also works
    const el = renderNode(screen, this._state!, params, this._rt());

    // Screen transition animation
    const transition = this._transition;
    if (transition !== 'none' && this._current !== null && el) {
      const old = this._container.firstElementChild as HTMLElement | null;
      if (old) {
        old.classList.add(`arx-transition-${transition}-out`);
        el.classList.add(`arx-transition-${transition}-in`);
        this._container.appendChild(el);
        old.addEventListener('animationend', () => old.remove(), { once: true });
        // Fallback removal
        setTimeout(() => { if (old.parentNode) old.remove(); }, 400);
      } else {
        this._container.innerHTML = '';
        this._container.appendChild(el);
      }
    } else {
      this._container.innerHTML = '';
      if (el) this._container.appendChild(el);
    }
    this._current       = screenName;
    this._currentParams = params;

    // P3 #23 — run mount lifecycle for the incoming screen
    const lc = this._lifecycles.get(screenName);
    if (lc?.mount.length) this._runActions(lc.mount);
  }

  /** P3 #21 — go back to the previous screen. */
  back(): void {
    if (this._history.length === 0) return;
    const prev = this._history.pop()!;
    this.navigate(prev.screen, prev.params, false);
  }

  /** Stop the runtime: clear DOM, reset state, clear history. */
  destroy(): void {
    if (this._destroyed) return;
    this._destroyed = true;

    // Run unmount for current screen
    if (this._current) {
      const lc = this._lifecycles.get(this._current);
      if (lc?.unmount.length) this._runActions(lc.unmount);
    }

    this._container.innerHTML = '';
    this._container.classList.remove(this._instanceId);
    for (const s of this._scopedStyles) s.remove();
    this._scopedStyles = [];
    // Clean up timers and hotkeys
    this._timers.forEach(id => clearInterval(id));
    this._timers = [];
    this._hotkeyCleanups.forEach(fn => fn());
    this._hotkeyCleanups = [];
    // Clean up WebSockets and SSE
    this._websockets.forEach(ws => ws.close());
    this._websockets = [];
    this._eventSources.forEach(es => es.close());
    this._eventSources = [];
    this._routes.clear();
    if (this._offlineHandler) { window.removeEventListener('offline', this._offlineHandler); this._offlineHandler = null; }
    if (this._onlineHandler) { window.removeEventListener('online', this._onlineHandler); this._onlineHandler = null; }
    // Cleanup Liquid-Glass-PRO
    if (this._lgInitialized) {
      const lgLib = (globalThis as unknown as Record<string, unknown>)['LiquidGlassPro'] as
        { destroyLiquidGlass?: () => void } | undefined;
      lgLib?.destroyLiquidGlass?.();
      this._lgInitialized = false;
    }
    this._workers.forEach(w => w.terminate());
    this._workers = [];
    if (this._voiceRecognition) {
      (this._voiceRecognition as { stop?: () => void }).stop?.();
      this._voiceRecognition = null;
    }
    this._syncChannel?.close();
    this._syncChannel = null;
    this._cronTimers.forEach(id => clearInterval(id));
    this._cronTimers = [];
    this._undoStack = [];
    this._redoStack = [];
    this._screens.clear();
    this._lifecycles.clear();
    this._history = [];
    this._current = null;
    this._currentParams = {};
  }

  // ── Public helpers ──────────────────────────────────────────────────────────

  get(key: string): unknown                          { return this._state?.get(key); }
  set(key: string, val: unknown): void               { this._state?.set(key, val); }
  subscribe(key: string, fn: (v: unknown) => void)   { return this._state?.subscribe(key, fn); }

  get screens():       string[]      { return [...this._screens.keys()]; }
  get currentScreen(): string | null { return this._current; }
  /** P3 #21 — true when back() can navigate. */
  get canGoBack():     boolean       { return !this._destroyed && this._history.length > 0; }
  get isDestroyed():   boolean       { return this._destroyed; }

  // ── @import Module System ──────────────────────────────────────────────────

  /**
   * Async initializer -- processes @import directives before rendering.
   * Call `await runtime.init()` before `runtime.start()` if you use @import
   * and have provided a `resolve` callback in options.
   *
   * Returns `this` for chaining: `await runtime.init(); runtime.start();`
   */
  async init(): Promise<this> {
    const { nodes: ast } = buildTree(scanLines(this._src));
    const imports = ast.filter((n): n is ImportNode => n.kind === 'import');

    if (imports.length === 0) return this;

    if (!this._opts.resolve) {
      console.warn('[Architex] @import found but no `resolve` callback provided in options. Imports will be skipped.');
      return this;
    }

    const processed = new Set<string>();
    for (const imp of imports) {
      await this._processImport(imp.path, processed);
    }

    return this;
  }

  /**
   * Process a single @import: resolve the source, parse it, merge definitions.
   * Tracks processed paths to avoid circular imports.
   */
  private async _processImport(path: string, processed: Set<string>): Promise<void> {
    if (processed.has(path)) return;
    processed.add(path);

    const resolve = this._opts.resolve;
    if (!resolve) return;

    let importedSrc: string;
    try {
      importedSrc = await resolve(path);
    } catch (e: unknown) {
      this._error('import', `Failed to resolve "${path}": ${String(e)}`);
      return;
    }

    const { nodes, errors } = buildTree(scanLines(importedSrc));
    for (const err of errors) {
      this._error('import', `In "${path}": ${err.message}`, err.line);
    }

    // Recursively process nested imports
    for (const node of nodes) {
      if (node.kind === 'import') {
        await this._processImport(node.path, processed);
      }
    }

    // Merge imported definitions into this runtime's source
    // We prepend the imported source to our own so that start() picks up
    // the imported screens, components, variables, and themes.
    (this as unknown as { _src: string })._src = importedSrc + '\n' + this._src;
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  private _error(kind: string, message: string, line?: number): void {
    const err: ArchiError = { kind, message, ...(line !== undefined ? { line } : {}) };
    if (this._opts.onError) {
      this._opts.onError(err);
    } else {
      console.error(`[Architex] ${kind}: ${message}${line !== undefined ? ` (line ${line})` : ''}`);
    }
  }

  /** Build the RuntimeHooks object used during rendering. */
  private _rt(): RuntimeHooks {
    return {
      navigate:   (n, p)    => this.navigate(n, p),
      back:       ()        => this.back(),
      send:       (pl)      => this._opts.send?.(pl),
      fetch:      (url)     => this._opts.fetch?.(url, this._state!) ?? Promise.resolve(null),
      getCompDef: (name: unknown) => this._compDefs.get(String(name)),
    };
  }

  /** Set the screen transition type. */
  setTransition(type: 'fade' | 'slide-left' | 'slide-right' | 'slide-up' | 'none'): void {
    this._transition = type;
  }

  /** Feature 19: Toggle between light/dark theme. */
  toggleTheme(): void {
    this._theme = this._theme === 'light' ? 'dark' : 'light';
    this._container.classList.remove('arx-theme-light', 'arx-theme-dark');
    this._container.classList.add(`arx-theme-${this._theme}`);
    this._state?.set('_theme', this._theme);
  }

  /** Get current theme. */
  get theme(): string { return this._theme; }

  /** Feature 11: Register @hotkey listener. */
  private _setupHotkey(node: HotkeyNode): void {
    const combo = node.keys.toLowerCase().split('+').map(k => k.trim());
    const listener = (e: KeyboardEvent): void => {
      const pressed: string[] = [];
      if (e.ctrlKey || e.metaKey) pressed.push('ctrl');
      if (e.altKey)   pressed.push('alt');
      if (e.shiftKey) pressed.push('shift');
      pressed.push(e.key.toLowerCase());
      // Check if all keys in combo are pressed
      if (combo.every(k => pressed.includes(k)) && combo.length === pressed.length) {
        e.preventDefault();
        this._runActions(node.actions);
      }
    };
    document.addEventListener('keydown', listener);
    this._hotkeyCleanups.push(() => document.removeEventListener('keydown', listener));
  }

  /** Liquid-Glass-PRO initialization with config from @liquidglass directive */
  private _initLiquidGlass(config: Record<string, unknown>): void {
    // Access the globally loaded Liquid-Glass-PRO library
    const lg = (globalThis as unknown as Record<string, unknown>)['LiquidGlassPro'] as
      Record<string, unknown> | undefined;

    if (!lg || typeof lg['initLiquidGlass'] !== 'function') {
      // Try window.initLiquidGlass (script tag loaded)
      const win = globalThis as unknown as Record<string, unknown>;
      const initFn = win['initLiquidGlass'] as ((opts: Record<string, unknown>) => void) | undefined;
      if (initFn) {
        const opts: Record<string, unknown> = {
          selector: '.lg',
          ...config,
        };
        // Convert string booleans from DSL parser
        for (const key of ['caustics', 'grain', 'iridescence', 'breathe']) {
          if (typeof opts[key] === 'string') {
            opts[key] = opts[key] !== 'false' && opts[key] !== '0';
          }
        }
        // Convert string numbers
        for (const key of ['ior', 'refractionStrength', 'aberrationStrength', 'bgCaptureInterval', 'bgCaptureScale', 'glassOpacity', 'glassSaturation']) {
          if (typeof opts[key] === 'string') {
            const num = parseFloat(opts[key] as string);
            if (!isNaN(num)) opts[key] = num;
          }
        }
        initFn(opts);
        this._lgInitialized = true;
        if (this._debug) console.log('[Architex] Liquid-Glass-PRO initialized', opts);
      } else {
        this._error('liquidglass', 'Liquid-Glass-PRO library not loaded. Include liquid-glass-pro.js before Architex.');
      }
      return;
    }

    const initFn = lg['initLiquidGlass'] as (opts: Record<string, unknown>) => void;
    const opts: Record<string, unknown> = { selector: '.lg', ...config };
    for (const key of ['caustics', 'grain', 'iridescence', 'breathe']) {
      if (typeof opts[key] === 'string') opts[key] = opts[key] !== 'false' && opts[key] !== '0';
    }
    for (const key of ['ior', 'refractionStrength', 'aberrationStrength', 'bgCaptureInterval', 'bgCaptureScale', 'glassOpacity', 'glassSaturation']) {
      if (typeof opts[key] === 'string') { const num = parseFloat(opts[key] as string); if (!isNaN(num)) opts[key] = num; }
    }
    initFn(opts);
    this._lgInitialized = true;
    if (this._debug) console.log('[Architex] Liquid-Glass-PRO initialized', opts);
  }

  /** Feature 21: @animation — inject custom keyframes CSS */
  private _injectAnimation(node: AnimationNode): void {
    // Build keyframes from VarDecl children: ~0 = "opacity: 0", ~50 = "transform: scale(1.1)", ~100 = "opacity: 1"
    const frames: string[] = [];
    for (const child of node.body) {
      if (child.kind === 'varDecl') {
        const pct = child.name; // "0", "50", "100"
        const val = child.expr.kind === 'string' ? child.expr.v : '';
        frames.push(`${pct}% { ${val} }`);
      }
    }
    if (frames.length > 0) {
      const css = `@keyframes ${node.name} { ${frames.join(' ')} }`;
      const style = document.createElement('style');
      style.textContent = css;
      document.head.appendChild(style);
      this._scopedStyles.push(style);
    }
  }

  /** Feature 23: @worker setup */
  private _setupWorker(node: WorkerNode): void {
    try {
      const worker = new Worker(node.src);
      worker.onmessage = (ev) => {
        if (node.target) {
          this._state?.set(node.target, ev.data);
        }
      };
      worker.onerror = (err) => {
        this._error('worker', `Worker error: ${err.message}`);
      };
      this._workers.push(worker);
    } catch (e) {
      this._error('worker', `Failed to create Worker: ${String(e)}`);
    }
  }

  /** Feature 27: @voice — Web Speech API voice commands */
  private _setupVoice(node: VoiceNode): void {
    const SpeechRecognition = (globalThis as unknown as Record<string, unknown>)['SpeechRecognition'] ??
      (globalThis as unknown as Record<string, unknown>)['webkitSpeechRecognition'];
    if (!SpeechRecognition) {
      this._error('voice', 'SpeechRecognition API not available');
      return;
    }
    const recognition = new (SpeechRecognition as new () => {
      continuous: boolean; interimResults: boolean;
      onresult: ((e: { results: { item: (i: number) => { transcript: string }; length: number }[] }) => void) | null;
      onerror: ((e: { error: string }) => void) | null;
      start: () => void; stop: () => void;
    })();
    recognition.continuous = true;
    recognition.interimResults = false;
    recognition.onresult = (e) => {
      const last = e.results[e.results.length - 1];
      if (last) {
        const transcript = last.item(0).transcript.toLowerCase().trim();
        this._state?.set('_voiceTranscript', transcript);
        // Match against commands
        for (const cmd of node.commands) {
          if (cmd.phrase && transcript.includes(cmd.phrase.toLowerCase())) {
            this._runActions(cmd.actions);
          }
        }
      }
    };
    recognition.onerror = (e) => {
      if (this._debug) console.warn('[Architex] Voice error:', e.error);
    };
    recognition.start();
    this._voiceRecognition = recognition;
  }

  /** Feature 30: @sync — BroadcastChannel cross-tab sync */
  private _setupSync(node: SyncNode): void {
    if (!('BroadcastChannel' in globalThis)) return;
    this._syncChannel = new BroadcastChannel('architex-sync');
    const vars = node.vars;
    // Listen for changes from other tabs
    this._syncChannel.onmessage = (ev) => {
      const data = ev.data as { key: string; value: unknown } | null;
      if (data && vars.includes(data.key)) {
        this._state?.set(data.key, data.value);
      }
    };
    // Publish local changes
    for (const varName of vars) {
      this._state?.subscribe(varName, (val) => {
        this._syncChannel?.postMessage({ key: varName, value: val });
      });
    }
  }

  /** Parse cron pattern to milliseconds (simplified: supports "5s", "1m", "500ms", or bare number as ms) */
  private _parseCronToMs(pattern: string): number {
    const p = pattern.trim();
    if (p.endsWith('ms')) return parseInt(p, 10);
    if (p.endsWith('s')) return parseFloat(p) * 1000;
    if (p.endsWith('m')) return parseFloat(p) * 60000;
    if (p.endsWith('h')) return parseFloat(p) * 3600000;
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  }

  /** Feature 26: Undo/Redo */
  undo(): void {
    if (this._undoStack.length <= 1) return; // keep initial state
    const current = this._undoStack.pop()!;
    this._redoStack.push(current);
    const prev = this._undoStack[this._undoStack.length - 1]!;
    this._state?.reset(prev);
  }

  redo(): void {
    if (this._redoStack.length === 0) return;
    const next = this._redoStack.pop()!;
    this._undoStack.push(next);
    this._state?.reset(next);
  }

  /** Snapshot current state for undo stack (call after meaningful state changes) */
  checkpoint(): void {
    if (!this._state) return;
    this._undoStack.push(this._state.snapshot());
    this._redoStack = [];
    // Limit stack size
    if (this._undoStack.length > 50) this._undoStack.shift();
  }

  get canUndo(): boolean { return this._undoStack.length > 1; }
  get canRedo(): boolean { return this._redoStack.length > 0; }

  /** Send message to Web Worker */
  postToWorker(index: number, data: unknown): void {
    this._workers[index]?.postMessage(data);
  }

  /** Feature 11: WebSocket setup */
  private _setupWebSocket(node: WsNode): void {
    try {
      const ws = new WebSocket(node.url);
      ws.onmessage = (ev) => {
        if (node.target) {
          try { this._state?.set(node.target, JSON.parse(ev.data as string)); }
          catch { this._state?.set(node.target, ev.data); }
        }
        if (node.actions.length > 0) this._runActions(node.actions);
      };
      ws.onopen = () => { if (this._debug) console.log(`[Architex] WebSocket connected: ${node.url}`); };
      ws.onerror = () => { if (this._debug) console.error(`[Architex] WebSocket error: ${node.url}`); };
      this._websockets.push(ws);
    } catch (e) {
      this._error('ws', `Failed to connect WebSocket: ${String(e)}`);
    }
  }

  /** Feature 12: SSE setup */
  private _setupSSE(node: SseNode): void {
    try {
      const es = new EventSource(node.url);
      es.onmessage = (ev) => {
        if (node.target) {
          try { this._state?.set(node.target, JSON.parse(ev.data as string)); }
          catch { this._state?.set(node.target, ev.data); }
        }
      };
      es.onerror = () => { if (this._debug) console.error(`[Architex] SSE error: ${node.url}`); };
      this._eventSources.push(es);
    } catch (e) {
      this._error('sse', `Failed to connect SSE: ${String(e)}`);
    }
  }

  /** Feature 30: URL routing / deep links */
  private _setupRouting(): void {
    const matchRoute = (): void => {
      const path = window.location.hash.replace('#', '') || window.location.pathname;
      for (const [pattern, screen] of this._routes) {
        if (path === pattern || path.startsWith(pattern + '/')) {
          this.navigate(screen);
          return;
        }
      }
    };
    window.addEventListener('hashchange', matchRoute);
    // Check current URL on startup
    const path = window.location.hash.replace('#', '') || window.location.pathname;
    if (path && path !== '/') matchRoute();
  }

  /** Helper: collect reactive deps from a ValueNode */
  private _collectReactiveDeps(node: import('../ast/values.js').ValueNode): string[] {
    if (node.kind === 'reactive') return [node.v.split('.')[0]!];
    if (node.kind === 'binary') return [...this._collectReactiveDeps(node.left), ...this._collectReactiveDeps(node.right)];
    if (node.kind === 'unary') return this._collectReactiveDeps(node.operand);
    if (node.kind === 'ternary') return [...this._collectReactiveDeps(node.condition), ...this._collectReactiveDeps(node.then), ...this._collectReactiveDeps(node.else_)];
    if (node.kind === 'funcall') return node.args.flatMap(a => this._collectReactiveDeps(a));
    if (node.kind === 'interpolated') return node.parts.flatMap(p => typeof p === 'string' ? [] : this._collectReactiveDeps(p));
    return [];
  }

  /** Feature 25: DevTools inspect */
  inspect(): Record<string, unknown> {
    return {
      screens: [...this._screens.keys()],
      current: this._current,
      state: this._state?.snapshot() ?? {},
      history: this._history.map(h => h.screen),
      routes: Object.fromEntries(this._routes),
      theme: this._theme,
      locale: this._i18nLocale,
      debug: this._debug,
      online: navigator.onLine,
      websockets: this._websockets.length,
      eventSources: this._eventSources.length,
    };
  }

  /** Feature 17: i18n — set locale */
  setLocale(locale: string): void {
    this._i18nLocale = locale;
    this._state?.set('_locale', locale);
    this._state?.set('_i18n', this._i18nData[locale] ?? {});
  }

  /** Feature 17: i18n — translate key */
  t(key: string): string {
    const dict = this._i18nData[this._i18nLocale];
    return dict?.[key] ?? key;
  }

  /** Feature 17: i18n — load translations */
  loadTranslations(locale: string, data: Record<string, string>): void {
    this._i18nData[locale] = data;
    if (locale === this._i18nLocale) {
      this._state?.set('_i18n', data);
    }
  }

  /** Feature 14: IndexedDB persistence */
  async persistToIndexedDB(key: string, varName: string): Promise<void> {
    if (!('indexedDB' in globalThis)) return;
    const db = await _openArxDB();
    const stored = await _idbGet(db, key);
    if (stored !== undefined) this._state?.set(varName, stored);
    this._state?.subscribe(varName, (val) => { _idbSet(db, key, val); });
  }

  /** Feature 15: Form state manager — bind form fields to state */
  bindForm(prefix: string, fields: string[]): void {
    for (const field of fields) {
      const key = `${prefix}.${field}`;
      if (this._state?.get(key) === undefined) {
        this._state?.set(key, '');
      }
    }
  }

  /** Feature 28: Request push notification permission */
  async requestNotificationPermission(): Promise<string> {
    if (!('Notification' in globalThis)) return 'unsupported';
    return Notification.requestPermission();
  }

  /** Feature 27: Hot reload — re-parse and re-render in place */
  hotReload(newSrc: string): void {
    const oldScreen = this._current;
    const oldParams = { ...this._currentParams };
    // Preserve state snapshot
    const snapshot = this._state?.snapshot() ?? {};
    // Update source
    (this as unknown as { _src: string })._src = newSrc;
    // Re-init
    this._styleInjected = false;
    this.start(oldScreen ?? undefined);
    // Restore state
    for (const [k, v] of Object.entries(snapshot)) {
      this._state?.set(k, v);
    }
  }


  /** Liquid-Glass-PRO: change glass variant at runtime */
  setGlassVariant(variant: string): void {
    const fn = (globalThis as unknown as Record<string, unknown>)['setGlassVariant'] as ((v: string) => void) | undefined;
    fn?.(variant);
  }

  /** Liquid-Glass-PRO: change glass type at runtime */
  setGlassType(type: string): void {
    const fn = (globalThis as unknown as Record<string, unknown>)['setGlassType'] as ((t: string) => void) | undefined;
    fn?.(type);
  }

  /** Liquid-Glass-PRO: force background re-capture */
  refreshGlass(): void {
    const fn = (globalThis as unknown as Record<string, unknown>)['refreshBackground'] as (() => Promise<void>) | undefined;
    fn?.();
  }

  /** Liquid-Glass-PRO: get available glass variants */
  get glassVariants(): Record<string, unknown> | null {
    const fn = (globalThis as unknown as Record<string, unknown>)['getGlassVariants'] as (() => Record<string, unknown>) | undefined;
    return fn?.() ?? null;
  }

  /** Get collected @import paths (for external loader integration). */
  get imports(): string[] { return this._imports.map(i => i.path); }

  /** Inject built-in CSS for transitions, animations, and validation. */
  private _injectStyles(): void {
    if (document.getElementById('arx-builtin-styles')) return;
    const style = document.createElement('style');
    style.id = 'arx-builtin-styles';
    style.textContent = `
      @keyframes arx-fade-in { from { opacity: 0; } to { opacity: 1; } }
      @keyframes arx-fade-out { from { opacity: 1; } to { opacity: 0; } }
      @keyframes arx-slide-left-in { from { transform: translateX(100%); } to { transform: translateX(0); } }
      @keyframes arx-slide-left-out { from { transform: translateX(0); } to { transform: translateX(-100%); } }
      @keyframes arx-slide-right-in { from { transform: translateX(-100%); } to { transform: translateX(0); } }
      @keyframes arx-slide-right-out { from { transform: translateX(0); } to { transform: translateX(100%); } }
      @keyframes arx-slide-up-in { from { transform: translateY(100%); } to { transform: translateY(0); } }
      @keyframes arx-slide-up-out { from { transform: translateY(0); } to { transform: translateY(-100%); } }
      @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
      @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }
      @keyframes slideLeft { from { transform: translateX(100%); } to { transform: translateX(0); } }
      @keyframes slideRight { from { transform: translateX(-100%); } to { transform: translateX(0); } }
      @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
      @keyframes scaleIn { from { transform: scale(0.9); opacity: 0; } to { transform: scale(1); opacity: 1; } }
      @keyframes bounce { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
      @keyframes shake { 0%,100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }
      @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
      @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      .arx-transition-fade-in { animation: arx-fade-in 0.25s ease; }
      .arx-transition-fade-out { animation: arx-fade-out 0.25s ease forwards; }
      .arx-transition-slide-left-in { animation: arx-slide-left-in 0.3s ease; }
      .arx-transition-slide-left-out { animation: arx-slide-left-out 0.3s ease forwards; }
      .arx-transition-slide-right-in { animation: arx-slide-right-in 0.3s ease; }
      .arx-transition-slide-right-out { animation: arx-slide-right-out 0.3s ease forwards; }
      .arx-transition-slide-up-in { animation: arx-slide-up-in 0.3s ease; }
      .arx-transition-slide-up-out { animation: arx-slide-up-out 0.3s ease forwards; }
      .arx-screen { position: relative; }
      .arx-invalid { border-color: #e74c3c !important; }
      .arx-error { color: #e74c3c; font-size: 12px; margin-top: 2px; display: block; }
      .arx-valid { border-color: #2ecc71 !important; }

      /* Drag & Drop */
      .arx-dragging { opacity: 0.5; }
      .arx-drag-over { outline: 2px dashed #4f8ef7; outline-offset: 2px; }

      /* Spinner */
      .arx-spinner {
        width: 24px; height: 24px;
        border: 3px solid rgba(0,0,0,0.1);
        border-top-color: currentColor;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
        display: inline-block;
        box-sizing: border-box;
      }

      /* Skeleton */
      .arx-skeleton {
        background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
        background-size: 200% 100%;
        animation: shimmer 1.5s infinite;
        border-radius: 4px;
      }
      @keyframes shimmer { from { background-position: 200% 0; } to { background-position: -200% 0; } }

      /* Toast notifications */
      .arx-toast-container {
        position: fixed; top: 16px; right: 16px;
        display: flex; flex-direction: column; gap: 8px;
        z-index: 10000; pointer-events: none;
      }
      .arx-toast {
        padding: 12px 20px; border-radius: 8px; color: #fff;
        font-size: 14px; pointer-events: auto;
        animation: fadeIn 0.3s ease, fadeOut 0.3s ease forwards;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        max-width: 320px;
      }
      .arx-toast-success { background: #2ecc71; }
      .arx-toast-error { background: #e74c3c; }
      .arx-toast-warning { background: #f39c12; }
      .arx-toast-info { background: #3498db; }

      /* Feature 1: Accordion */
      .arx-accordion { border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; }
      .arx-accordion-section + .arx-accordion-section { border-top: 1px solid #e0e0e0; }
      .arx-accordion-header:hover { background: rgba(0,0,0,0.03); }

      /* Feature 2: Carousel */
      .arx-carousel { border-radius: 8px; }
      .arx-carousel-prev:hover, .arx-carousel-next:hover { background: rgba(0,0,0,.6); }

      /* Feature 3: Bottom Sheet */
      .arx-bottomsheet-overlay { animation: arx-fade-in 0.2s ease; }

      /* Feature 5: Search */
      .arx-search input:focus { border-color: #4f8ef7; box-shadow: 0 0 0 2px rgba(79,142,247,0.2); }

      /* Feature 7: Chip */
      .arx-chip { transition: all 0.15s ease; }
      .arx-chip:hover { filter: brightness(0.95); }

      /* Feature 8: Stepper */
      .arx-stepper-circle { transition: all 0.2s ease; }

      /* Feature 10: Pull to Refresh */
      .arx-pullrefresh-indicator { transition: height 0.2s ease; }

      /* Feature 19: Dark theme */
      .arx-theme-dark {
        background: #1a1a2e !important;
        color: #e0e0e0 !important;
      }
      .arx-theme-dark .arx-card {
        background: #16213e;
        box-shadow: 0 2px 8px rgba(0,0,0,.3);
      }
      .arx-theme-dark input,
      .arx-theme-dark textarea,
      .arx-theme-dark select {
        background: #16213e;
        color: #e0e0e0;
        border-color: #333;
      }
      .arx-theme-dark .arx-accordion { border-color: #333; }
      .arx-theme-dark .arx-accordion-header { border-color: #333; }
      .arx-theme-dark .arx-accordion-header:hover { background: rgba(255,255,255,0.05); }
      .arx-theme-dark .arx-chip { background: #2d2d4e; color: #ccc; }
      .arx-theme-dark .arx-tabs-header { border-color: #333; }
      .arx-theme-dark .arx-bottomsheet { background: #1a1a2e; color: #e0e0e0; }
      .arx-theme-dark .arx-modal { background: #1a1a2e; color: #e0e0e0; }
      .arx-theme-dark .arx-search input { background: #16213e; color: #e0e0e0; border-color: #444; }
      .arx-theme-dark .arx-skeleton {
        background: linear-gradient(90deg, #2d2d4e 25%, #3d3d6e 50%, #2d2d4e 75%);
        background-size: 200% 100%;
      }

      /* Round 3: Tooltip */
      .arx-tooltip { pointer-events: none; }
      .arx-tooltip-wrapper:hover .arx-tooltip { opacity: 1 !important; }

      /* Round 3: Rating */
      .arx-rating span:hover ~ span { color: #ddd !important; }

      /* Round 3: Gallery */
      .arx-gallery img { transition: transform 0.15s ease; }

      /* Round 3: Pagination */
      .arx-page-btn:hover:not(:disabled) { background: #f0f0f0 !important; }
      .arx-page-btn:disabled { opacity: 0.5; cursor: default; }

      /* Round 3: Dropdown */
      .arx-dropdown-menu { animation: fadeIn 0.15s ease; }

      /* Round 3: Virtual list */
      .arx-virtuallist { will-change: transform; }

      /* Round 3: Rich text */
      .arx-richtext h1 { font-size: 2em; font-weight: bold; margin: 0.5em 0; }
      .arx-richtext h2 { font-size: 1.5em; font-weight: bold; margin: 0.4em 0; }
      .arx-richtext h3 { font-size: 1.25em; font-weight: bold; margin: 0.3em 0; }
      .arx-richtext code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
      .arx-richtext a { color: #1976d2; text-decoration: underline; }
      .arx-richtext ul { padding-left: 20px; }
      .arx-richtext hr { border: none; border-top: 1px solid #e0e0e0; margin: 1em 0; }
      .arx-theme-dark .arx-richtext code { background: #2d2d4e; }

      /* Round 3: Color picker */
      .arx-colorpicker input[type="color"] { -webkit-appearance: none; border: 2px solid #ddd; border-radius: 8px; }
      .arx-colorpicker input[type="color"]::-webkit-color-swatch-wrapper { padding: 2px; }
      .arx-colorpicker input[type="color"]::-webkit-color-swatch { border: none; border-radius: 4px; }

      /* Round 3: Offline indicator */
      .arx-offline-banner { background: #e74c3c; color: #fff; text-align: center; padding: 8px; font-size: 13px; }

      /* Round 3: Breadcrumb dark mode */
      .arx-theme-dark .arx-breadcrumb-sep { color: #666 !important; }
      .arx-theme-dark .arx-page-btn { background: #16213e !important; color: #e0e0e0; border-color: #333 !important; }
      .arx-theme-dark .arx-dropdown-menu { background: #16213e !important; border-color: #333 !important; }
      .arx-theme-dark .arx-dropdown-trigger { background: #16213e !important; color: #e0e0e0; border-color: #333 !important; }
      .arx-theme-dark .arx-lightbox-overlay { background: rgba(0,0,0,.95); }

      /* Round 4: Sortable list */
      .arx-sortable-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,.12); }
      .arx-sortable-item:active { cursor: grabbing; }

      /* Round 4: Command palette */
      .arx-cmdpalette { animation: scaleIn 0.15s ease; }

      /* Round 4: Data table */
      .arx-datatable th:hover { background: #eee !important; }
      .arx-theme-dark .arx-datatable { border-color: #333; }
      .arx-theme-dark .arx-datatable th { background: #1e2a3a !important; border-color: #333; color: #ccc; }
      .arx-theme-dark .arx-datatable tr { border-color: #333; }
      .arx-theme-dark .arx-datatable tr:hover { background: #1e2a3a !important; }

      /* Round 4: Tree view */
      .arx-theme-dark .arx-treeview div:hover { background: rgba(255,255,255,.05) !important; }

      /* Round 4: Calendar */
      .arx-theme-dark .arx-calendar { border-color: #333; }
      .arx-theme-dark .arx-calendar div[style*="background:#f8f9fa"] { background: #1e2a3a !important; }

      /* Round 4: Chat bubble */
      .arx-chatbubble { animation: fadeIn 0.2s ease; }

      /* Round 4: Code editor */
      .arx-codeeditor code { display: block; }
      .arx-theme-dark .arx-codeeditor { border-color: #333; }

      /* Round 4: Signature pad */
      .arx-theme-dark .arx-signaturepad { border-color: #333; }
      .arx-theme-dark .arx-signaturepad canvas { background: #16213e; }
      .arx-theme-dark .arx-signaturepad button { background: #1e2a3a !important; color: #ccc; border-color: #333 !important; }

      /* Round 4: OTP input */
      .arx-theme-dark .arx-otpinput input { background: #16213e; color: #e0e0e0; border-color: #444; }

      /* Round 4: File upload */
      .arx-fileupload:hover { border-color: #1976d2; background: #f0f7ff; }
      .arx-theme-dark .arx-fileupload { border-color: #444; color: #ccc; }
      .arx-theme-dark .arx-fileupload:hover { background: rgba(25,118,210,0.1); border-color: #1976d2; }

      /* Round 4: Kanban */
      .arx-theme-dark .arx-kanban-col { background: #16213e !important; }
      .arx-theme-dark .arx-kanban-col div[style*="background:#fff"] { background: #1e2a3a !important; color: #e0e0e0; }

      /* Round 4: Circular progress */
      .arx-theme-dark .arx-circularprogress circle[stroke="#e0e0e0"] { stroke: #333; }

      /* Round 4: Audio/Video player */
      .arx-theme-dark .arx-audioplayer { background: #16213e !important; border-color: #333; }

      /* Round 4: Phone input */
      .arx-theme-dark .arx-phoneinput { border-color: #333; }
      .arx-theme-dark .arx-phoneinput select { background: #1e2a3a; color: #ccc; }
      .arx-theme-dark .arx-phoneinput input { background: #16213e; color: #e0e0e0; }

      /* Round 4: Diff viewer */
      .arx-theme-dark .arx-diffviewer { border-color: #333; }
      .arx-theme-dark .arx-diffviewer span[style*="background:#f8f9fa"] { background: #1e2a3a !important; }

      /* Round 4: Marquee animation */
      @keyframes arx-marquee { from { transform: translateX(100%); } to { transform: translateX(-100%); } }

      /* Round 4: Typewriter cursor blink */
      .arx-typewriter { animation: arx-blink 0.7s step-end infinite; }
      @keyframes arx-blink { 50% { border-color: transparent; } }

      /* Liquid-Glass-PRO integration hints */
      .lg.arx-card { border-radius: 22px; }
      .lg.arx-button, .lg.arx-btn { border-radius: 999px; }
      .lg.arx-modal { border-radius: 22px; backdrop-filter: none; }
      .lg.arx-bottomsheet { border-radius: 22px 22px 0 0; }
      .lg.arx-chip { border-radius: 999px; }
      .lg.arx-toast { border-radius: 16px; }
      .lg.arx-accordion { border-radius: 16px; overflow: hidden; }
      .lg.arx-dropdown-menu { border-radius: 16px; }
      .lg.arx-cmdpalette { border-radius: 22px; }

      /* Round 4: Swipe cards */
      .arx-swipecard-item:active { cursor: grabbing; }

      /* Round 5: Chart */
      .arx-chart canvas { border-radius: 8px; }

      /* Round 5: Heatmap */
      .arx-heatmap { border-radius: 8px; overflow: hidden; }

      /* Round 5: Org Chart */
      .arx-orgchart { padding: 16px; }
      .arx-theme-dark .arx-orgchart div[style*="border:2px solid"] { background: #16213e !important; color: #e0e0e0; border-color: #4f8ef7 !important; }

      /* Round 5: Funnel */
      .arx-funnel { padding: 8px; }

      /* Round 5: Split Pane */
      .arx-splitpane > div:first-child, .arx-splitpane > div:last-child { overflow: auto; }
      .arx-theme-dark .arx-splitpane > div:nth-child(2) { background: #333 !important; }

      /* Round 5: Drawer */
      .arx-theme-dark .arx-drawer { background: #1a1a2e !important; color: #e0e0e0; }

      /* Round 5: Bottom Nav */
      .arx-theme-dark .arx-bottomnav { background: #16213e !important; box-shadow: 0 -2px 8px rgba(0,0,0,.3); }
      .arx-theme-dark .arx-bottomnav button { color: #888 !important; }

      /* Round 5: FAB */
      .arx-fab-main:hover { transform: scale(1.1); }
      .arx-fab-main:active { transform: scale(0.95); }

      /* Round 5: App Bar */
      .arx-theme-dark .arx-appbar { background: #16213e !important; }

      /* Round 5: Terminal */
      .arx-theme-dark .arx-terminal { border: 1px solid #333; }

      /* Round 5: Autocomplete */
      .arx-autocomplete input:focus { border-color: #1976d2; box-shadow: 0 0 0 2px rgba(25,118,210,0.15); }
      .arx-theme-dark .arx-autocomplete input { background: #16213e; color: #e0e0e0; border-color: #444; }
      .arx-theme-dark .arx-autocomplete div[style*="background:#fff"] { background: #16213e !important; border-color: #333; }

      /* Round 5: Tag Input */
      .arx-taginput:focus-within { border-color: #1976d2; box-shadow: 0 0 0 2px rgba(25,118,210,0.15); }
      .arx-theme-dark .arx-taginput { background: #16213e; border-color: #444; color: #e0e0e0; }
      .arx-theme-dark .arx-taginput input { color: #e0e0e0; }
      .arx-theme-dark .arx-tag-chip { background: #2d3a5e !important; color: #90caf9 !important; }

      /* Round 5: WYSIWYG */
      .arx-theme-dark .arx-wysiwyg { border-color: #333; }
      .arx-theme-dark .arx-wysiwyg div[contenteditable] { background: #16213e; color: #e0e0e0; }
      .arx-theme-dark .arx-wysiwyg div[style*="background:#f8f9fa"] { background: #1e2a3a !important; }
      .arx-theme-dark .arx-wysiwyg button { background: #16213e !important; color: #ccc; border-color: #444 !important; }

      /* Round 5: Dual Range */
      .arx-theme-dark .arx-dualrange div[style*="background:#ddd"] { background: #444 !important; }

      /* Round 5: Credit Card */
      .arx-theme-dark .arx-creditcard input { background: #16213e; color: #e0e0e0; border-color: #444; }

      /* Round 5: Emoji Picker */
      .arx-theme-dark .arx-emojipicker { background: #16213e !important; border-color: #333; }
      .arx-theme-dark .arx-emojipicker button:hover { background: rgba(255,255,255,.1) !important; }

      /* Round 5: Mention */
      .arx-theme-dark .arx-mention input { background: #16213e; color: #e0e0e0; border-color: #444; }
      .arx-theme-dark .arx-mention div[style*="background:#fff"] { background: #16213e !important; border-color: #333; }

      /* Round 5: Reactions */
      .arx-theme-dark .arx-reactions button { background: #16213e !important; color: #e0e0e0; border-color: #444 !important; }
      .arx-reactions button:active { transform: scale(1.2); }

      /* Round 5: Presence */
      .arx-presence span:first-child { box-shadow: 0 0 0 2px #fff; }
      .arx-theme-dark .arx-presence span:first-child { box-shadow: 0 0 0 2px #1a1a2e; }

      /* Round 5: Thread */
      .arx-theme-dark .arx-thread div[style*="border-left:2px solid #e0e0e0"] { border-color: #333 !important; }
      .arx-theme-dark .arx-thread span[style*="background:#e3f2fd"] { background: #2d3a5e !important; }

      .arx-theme-light {
        background: #ffffff;
        color: #1a1a1a;
      }
    `;
    document.head.appendChild(style);
  }

  /** Inject a @style block with selectors scoped to this instance. */
  private _injectScopedStyle(node: StyleNode): void {
    const style = document.createElement('style');
    style.id = `arx-scoped-${this._instanceId}-${this._scopedStyles.length}`;
    // Prefix every CSS rule selector with the instance scope class
    const scopePrefix = `.${this._instanceId}`;
    const scoped = node.css.replace(
      /([^{}@/]+?)(\{)/g,
      (_match: string, selectors: string, brace: string) => {
        const prefixed = selectors
          .split(',')
          .map((s: string) => `${scopePrefix} ${s.trim()}`)
          .join(', ');
        return `${prefixed} ${brace}`;
      },
    );
    style.textContent = scoped;
    document.head.appendChild(style);
    this._scopedStyles.push(style);
  }

  private _literalVal(node: ValueNode): unknown {
    switch (node.kind) {
      case 'string': return node.v;
      case 'number': return node.v;
      case 'color':  return node.v;
      case 'ident':  return node.v;
      default:       return null;
    }
  }

  /**
   * Execute a list of actions with full runtime context
   * (used by @onMount / @onUnmount lifecycle hooks).
   */
  private _runActions(actions: Action[]): void {
    const state = this._state!;
    const rt    = this._rt();

    for (const action of actions) {
      if (action.kind === 'assign') {
        const cur = (state.get(action.var) as number) ?? 0;
        const val = evalExpr(action.val, state);
        if      (action.op === '+=') state.set(action.var, cur + (val as number));
        else if (action.op === '-=') state.set(action.var, cur - (val as number));
        else                         state.set(action.var, val);
      }

      if (action.kind === 'call') {
        const rArgs = action.args.map(a =>
          'key' in a
            ? { key: (a as { key: string; val: ValueNode }).key,
                val: evalExpr((a as { key: string; val: ValueNode }).val, state) }
            : evalExpr(a as ValueNode, state)
        );

        if      (action.fn === 'navigate') {
          rt.navigate(String(rArgs[0]), typeof rArgs[1] === 'object' ? rArgs[1] as Record<string, unknown> : {});
        }
        else if (action.fn === 'back')  rt.back();
        else if (action.fn === 'fetch') {
          const url    = String(rArgs[0] ?? '');
          const into   = action.into;
          // Auto-manage loading/error state vars: ~{into}Loading, ~{into}Error
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
              .catch((e: unknown) => {
                state.set(`${into}Error`, String(e));
                state.set(`${into}Loading`, false);
                this._error('fetch', String(e));
              });
          }
        }
        else if (action.fn === 'toast') {
          const msg      = String(rArgs[0] ?? '');
          const toastType = (rArgs[1] ? String(rArgs[1]) : 'info') as ToastType;
          const dur      = typeof rArgs[2] === 'number' ? rArgs[2] : 3000;
          showToast(msg, toastType, dur);
        }
        else if (action.fn === 'send') {
          const pl: Record<string, unknown> = {};
          for (const a of rArgs) {
            if (a && typeof a === 'object' && 'key' in a) {
              pl[(a as { key: string; val: unknown }).key] = (a as { key: string; val: unknown }).val;
            }
          }
          rt.send(pl);
        }
        else if (action.fn === 'copy') {
          navigator.clipboard?.writeText(String(rArgs[0] ?? '')).catch(() => {});
        }
        else if (action.fn === 'share') {
          const d: Record<string, string> = {};
          if (rArgs[0]) d['title'] = String(rArgs[0]);
          if (rArgs[1]) d['text']  = String(rArgs[1]);
          if (rArgs[2]) d['url']   = String(rArgs[2]);
          navigator.share?.(d).catch(() => {});
        }
        else if (action.fn === 'haptic' || action.fn === 'vibrate') {
          navigator.vibrate?.(typeof rArgs[0] === 'number' ? rArgs[0] : 50);
        }
        else if (action.fn === 'toggle') {
          const vn = action.args[0];
          const varKey = vn && !('key' in vn) && (vn as import('../ast/values.js').ValueNode).kind === 'reactive'
            ? (vn as Extract<import('../ast/values.js').ValueNode, { kind: 'reactive' }>).v : null;
          if (varKey) state.set(varKey, !state.get(varKey));
        }
        else if (action.fn === 'toggleTheme') {
          this.toggleTheme();
        }
        else if (action.fn === 'push') {
          const vn = action.args[0];
          const arrKey = vn && !('key' in vn) && (vn as import('../ast/values.js').ValueNode).kind === 'reactive'
            ? (vn as Extract<import('../ast/values.js').ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            if (Array.isArray(arr)) state.set(arrKey, [...arr, rArgs[1]]);
          }
        }
        else if (action.fn === 'pop') {
          const vn = action.args[0];
          const arrKey = vn && !('key' in vn) && (vn as import('../ast/values.js').ValueNode).kind === 'reactive'
            ? (vn as Extract<import('../ast/values.js').ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            if (Array.isArray(arr)) state.set(arrKey, arr.slice(0, -1));
          }
        }
        else if (action.fn === 'remove') {
          const vn = action.args[0];
          const arrKey = vn && !('key' in vn) && (vn as import('../ast/values.js').ValueNode).kind === 'reactive'
            ? (vn as Extract<import('../ast/values.js').ValueNode, { kind: 'reactive' }>).v : null;
          if (arrKey) {
            const arr = state.get(arrKey);
            const idx = typeof rArgs[1] === 'number' ? rArgs[1] : -1;
            if (Array.isArray(arr) && idx >= 0) { const c = [...arr]; c.splice(idx, 1); state.set(arrKey, c); }
          }
        }
        else if (action.fn === 'notify') {
          const title = String(rArgs[0] ?? 'Notification');
          const body = rArgs[1] ? String(rArgs[1]) : undefined;
          if ('Notification' in globalThis) {
            if (Notification.permission === 'granted') new Notification(title, { body });
            else if (Notification.permission !== 'denied') Notification.requestPermission().then(p => { if (p === 'granted') new Notification(title, { body }); });
          }
        }
        else if (action.fn === 'setLocale') {
          this.setLocale(String(rArgs[0] ?? 'en'));
        }
        else if (action.fn === 'log' || action.fn === 'debug') {
          console.log('[Architex]', ...rArgs);
        }
        else if (action.fn === 'setGlassVariant' || action.fn === 'lgvariant') {
          const setVariant = (globalThis as unknown as Record<string, unknown>)['setGlassVariant'] as ((v: string) => void) | undefined;
          setVariant?.(String(rArgs[0] ?? 'clear'));
        }
        else if (action.fn === 'setGlassType' || action.fn === 'lgtype') {
          const setType = (globalThis as unknown as Record<string, unknown>)['setGlassType'] as ((t: string) => void) | undefined;
          setType?.(String(rArgs[0] ?? 'BK7'));
        }
        else if (action.fn === 'refreshGlass') {
          const refresh = (globalThis as unknown as Record<string, unknown>)['refreshBackground'] as (() => void) | undefined;
          refresh?.();
        }
        else if (action.fn === 'undo') { this.undo(); }
        else if (action.fn === 'redo') { this.redo(); }
        else if (action.fn === 'checkpoint') { this.checkpoint(); }
        else if (action.fn === 'postWorker') {
          const idx = typeof rArgs[0] === 'number' ? rArgs[0] : 0;
          this.postToWorker(idx, rArgs[1]);
        }
      }
    }
  }
}

// ── IndexedDB helpers ────────────────────────────────────────────────────────

function _openArxDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('architex_store', 1);
    req.onupgradeneeded = () => { req.result.createObjectStore('kv'); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function _idbGet(db: IDBDatabase, key: string): Promise<unknown> {
  return new Promise((resolve) => {
    const tx = db.transaction('kv', 'readonly');
    const req = tx.objectStore('kv').get(key);
    req.onsuccess = () => resolve(req.result as unknown);
    req.onerror = () => resolve(undefined);
  });
}

function _idbSet(db: IDBDatabase, key: string, val: unknown): void {
  const tx = db.transaction('kv', 'readwrite');
  tx.objectStore('kv').put(val, key);
}

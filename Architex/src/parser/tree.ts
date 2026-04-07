/** Build the AST tree from a flat list of annotated lines. */

import { T, Token }      from '../lexer/tokens.js';
import { tokeniseLine }  from '../lexer/tokeniser.js';
import type { Line }     from '../lexer/scanner.js';
import type { Node, ScreenNode, VarDeclNode, ComputedNode,
              ComponentNode, ListNode, ForNode, HandlerNode,
              IfNode, IfBranch, WatchNode, LifecycleNode,
              ComponentDefNode, ThemeNode, ImportNode,
              SlotNode, StyleNode, HotkeyNode, TimerNode,
              WsNode, SseNode, RouteNode, DebugNode,
              CatchNode, OfflineNode, I18nNode, A11yNode,
              LiquidGlassNode, AnimationNode, TransitionNode,
              WorkerNode, PermissionNode, FsmNode, VoiceNode,
              BiometricNode, CronNode, SyncNode } from '../ast/nodes.js';
import type { Span }     from '../ast/span.js';
import { TokStream }     from './stream.js';
import { parseValue }    from './values.js';
import { parseMod, parseModifiers } from './modifiers.js';
import { parseAction }   from './actions.js';

/** A parse error with line number and description. */
export interface ParseError {
  message: string;
  line:    number;
}

export function buildTree(lines: Line[]): { nodes: Node[]; errors: ParseError[] } {
  let cursor = 0;
  const errors: ParseError[] = [];

  function parseBlock(baseIndent: number): Node[] {
    const nodes: Node[] = [];
    while (cursor < lines.length && (lines[cursor]?.indent ?? 0) > baseIndent) {
      const node = parseLine(lines[cursor]?.indent ?? 0);
      if (node) nodes.push(node);
    }
    return nodes;
  }

  function parseLine(currentIndent: number): Node | null {
    if (cursor >= lines.length) return null;
    const line = lines[cursor++]!;
    const span: Span = { line: line.lineNum };
    const ts = new TokStream(tokeniseLine(line.text));

    // ── @keyword dispatch ────────────────────────────────────────────────────
    if (ts.peek()?.t === T.AtKw) {
      const kw = (ts.eat() as Extract<Token, { t: T.AtKw }>).v;

      // @screen Name(params…)
      if (kw === 'screen') {
        const name = ts.peek()?.t === T.Ident
          ? (ts.eat() as Extract<Token, { t: T.Ident }>).v
          : 'Main';
        const params: string[] = [];
        if (ts.peek()?.t === T.LParen) {
          ts.eat();
          while (!ts.atEnd() && ts.peek()?.t !== T.RParen) {
            if (ts.peek()?.t === T.Ident) params.push((ts.eat() as Extract<Token, { t: T.Ident }>).v);
            if (ts.peek()?.t === T.Comma) ts.eat();
          }
          ts.eat();
        }
        return { kind: 'screen', name, params, body: parseBlock(currentIndent), span } satisfies ScreenNode;
      }

      // @component Name(param1, param2)
      if (kw === 'component') {
        const name = ts.peek()?.t === T.Ident
          ? (ts.eat() as Extract<Token, { t: T.Ident }>).v
          : 'Unknown';
        const params: string[] = [];
        if (ts.peek()?.t === T.LParen) {
          ts.eat();
          while (!ts.atEnd() && ts.peek()?.t !== T.RParen) {
            if (ts.peek()?.t === T.Ident) params.push((ts.eat() as Extract<Token, { t: T.Ident }>).v);
            if (ts.peek()?.t === T.Comma) ts.eat();
          }
          ts.eat(); // )
        }
        return { kind: 'compDef', name, params, body: parseBlock(currentIndent), span } satisfies ComponentDefNode;
      }

      // @if ~condition
      if (kw === 'if') {
        const cond = parseValue(ts);
        if (!cond) {
          errors.push({ message: '@if requires a condition expression', line: span.line });
          parseBlock(currentIndent);
          return null;
        }
        const branches: IfBranch[] = [{ condition: cond, body: parseBlock(currentIndent) }];
        const else_: Node[] = [];
        while (cursor < lines.length && (lines[cursor]?.indent ?? 0) === currentIndent) {
          const peekLine = lines[cursor]!;
          const pts = new TokStream(tokeniseLine(peekLine.text));
          if (pts.peek()?.t !== T.AtKw) break;
          const pkw = (pts.peek() as Extract<Token, { t: T.AtKw }>).v;
          if (pkw === 'elseif') {
            cursor++;
            pts.eat();
            const c = parseValue(pts);
            if (c) branches.push({ condition: c, body: parseBlock(currentIndent) });
            else   errors.push({ message: '@elseif requires a condition', line: peekLine.lineNum });
          } else if (pkw === 'else') {
            cursor++;
            else_.push(...parseBlock(currentIndent));
            break;
          } else break;
        }
        return { kind: 'if', branches, else_, span } satisfies IfNode;
      }

      // @for item, index in ~source
      if (kw === 'for') {
        const itemName = ts.peek()?.t === T.Ident
          ? (ts.eat() as Extract<Token, { t: T.Ident }>).v
          : 'item';
        let indexName: string | null = null;
        if (ts.peek()?.t === T.Comma) {
          ts.eat(); // ,
          if (ts.peek()?.t === T.Ident) {
            indexName = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
          }
        }
        // expect 'in'
        if (ts.peek()?.t === T.Ident && (ts.peek() as Extract<Token, { t: T.Ident }>).v === 'in') {
          ts.eat();
        }
        const source = parseValue(ts);
        if (source) return { kind: 'for', itemName, indexName, source, body: parseBlock(currentIndent), span } satisfies ForNode;
        errors.push({ message: `@for requires a source expression`, line: span.line });
        return null;
      }

      // @theme — design tokens
      if (kw === 'theme') {
        const vars: { name: string; expr: import('../ast/values.js').ValueNode }[] = [];
        const body = parseBlock(currentIndent);
        for (const child of body) {
          if (child.kind === 'varDecl') {
            vars.push({ name: child.name, expr: child.expr });
          }
        }
        return { kind: 'theme', vars, span } satisfies ThemeNode;
      }

      // @import "./path.arx"
      if (kw === 'import') {
        const pathTok = ts.peek();
        if (pathTok?.t === T.String) {
          ts.eat();
          return { kind: 'import', path: pathTok.v, span } satisfies ImportNode;
        }
        errors.push({ message: '@import requires a string path', line: span.line });
        return null;
      }

      // @slot [name] — component composition slot
      if (kw === 'slot') {
        let slotName = 'default';
        if (ts.peek()?.t === T.Ident) {
          slotName = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
        }
        return { kind: 'slot', name: slotName, span } satisfies SlotNode;
      }

      // @style — scoped CSS injection block
      if (kw === 'style') {
        const cssLines: string[] = [];
        while (cursor < lines.length && (lines[cursor]?.indent ?? 0) > currentIndent) {
          cssLines.push(lines[cursor]!.text);
          cursor++;
        }
        return { kind: 'style', css: cssLines.join('\n'), span } satisfies StyleNode;
      }

      // @watch ~key
      if (kw === 'watch') {
        if (ts.peek()?.t !== T.Reactive) {
          errors.push({ message: '@watch requires a reactive target (~var)', line: span.line });
          parseBlock(currentIndent);
          return null;
        }
        const target = (ts.eat() as Extract<Token, { t: T.Reactive }>).v;
        const actions = [];
        if (ts.peek()?.t === T.Arrow) { ts.eat(); const a = parseAction(ts); if (a) actions.push(a); }
        const body = parseBlock(currentIndent);
        for (const child of body) { if (child.kind === 'handler') actions.push(...child.actions); }
        return { kind: 'watch', target, actions, span } satisfies WatchNode;
      }

      // @onMount / @onUnmount lifecycle hooks (P3 #23)
      if (kw === 'onMount' || kw === 'onmount' || kw === 'onUnmount' || kw === 'onunmount') {
        const hook: 'mount' | 'unmount' =
          kw.toLowerCase() === 'onmount' ? 'mount' : 'unmount';
        const actions = [];
        // inline: @onMount => fetch("url") ~data
        if (ts.peek()?.t === T.Arrow) { ts.eat(); const a = parseAction(ts); if (a) actions.push(a); }
        // block form
        const body = parseBlock(currentIndent);
        for (const child of body) { if (child.kind === 'handler') actions.push(...child.actions); }
        return { kind: 'lifecycle', hook, actions, span } satisfies LifecycleNode;
      }

      // @hotkey "ctrl+k" => action
      if (kw === 'hotkey') {
        const keysTok = ts.peek();
        let keys = '';
        if (keysTok?.t === T.String) { ts.eat(); keys = keysTok.v; }
        else if (keysTok?.t === T.Ident) { ts.eat(); keys = (keysTok as Extract<Token, { t: T.Ident }>).v; }
        else { errors.push({ message: '@hotkey requires a key combo string', line: span.line }); return null; }
        const actions: import('../ast/actions.js').Action[] = [];
        if (ts.peek()?.t === T.Arrow) { ts.eat(); const a = parseAction(ts); if (a) actions.push(a); }
        const body = parseBlock(currentIndent);
        for (const child of body) { if (child.kind === 'handler') actions.push(...child.actions); }
        return { kind: 'hotkey', keys, actions, span } satisfies HotkeyNode;
      }

      // @timer 5000 => action
      if (kw === 'timer') {
        const intervalTok = ts.peek();
        let interval = 1000;
        if (intervalTok?.t === T.Number) { ts.eat(); interval = intervalTok.v; }
        const actions: import('../ast/actions.js').Action[] = [];
        if (ts.peek()?.t === T.Arrow) { ts.eat(); const a = parseAction(ts); if (a) actions.push(a); }
        const body = parseBlock(currentIndent);
        for (const child of body) { if (child.kind === 'handler') actions.push(...child.actions); }
        return { kind: 'timer', interval, actions, span } satisfies TimerNode;
      }

      // @ws "url" ~target
      if (kw === 'ws' || kw === 'websocket') {
        const urlTok = ts.peek();
        let url = '';
        if (urlTok?.t === T.String) { ts.eat(); url = urlTok.v; }
        let target: string | null = null;
        if (ts.peek()?.t === T.Arrow) { ts.eat(); }
        if (ts.peek()?.t === T.Reactive) { target = (ts.eat() as Extract<Token, { t: T.Reactive }>).v; }
        const actions: import('../ast/actions.js').Action[] = [];
        const body = parseBlock(currentIndent);
        for (const child of body) { if (child.kind === 'handler') actions.push(...child.actions); }
        return { kind: 'ws', url, target, actions, span } satisfies WsNode;
      }

      // @sse "url" ~target
      if (kw === 'sse') {
        const urlTok = ts.peek();
        let url = '';
        if (urlTok?.t === T.String) { ts.eat(); url = urlTok.v; }
        let target: string | null = null;
        if (ts.peek()?.t === T.Arrow) { ts.eat(); }
        if (ts.peek()?.t === T.Reactive) { target = (ts.eat() as Extract<Token, { t: T.Reactive }>).v; }
        parseBlock(currentIndent); // consume children
        return { kind: 'sse', url, target, span } satisfies SseNode;
      }

      // @route "/path" ScreenName
      if (kw === 'route') {
        const pathTok = ts.peek();
        let path = '/';
        if (pathTok?.t === T.String) { ts.eat(); path = pathTok.v; }
        let screen = '';
        if (ts.peek()?.t === T.Arrow) ts.eat();
        if (ts.peek()?.t === T.Ident) { screen = (ts.eat() as Extract<Token, { t: T.Ident }>).v; }
        return { kind: 'route', path, screen, span } satisfies RouteNode;
      }

      // @debug ~expr
      if (kw === 'debug') {
        const expr = parseValue(ts);
        return { kind: 'debug', expr, span } satisfies DebugNode;
      }

      // @catch [fallback]
      if (kw === 'catch') {
        let fallback: string | null = null;
        if (ts.peek()?.t === T.String) { fallback = (ts.eat() as Extract<Token, { t: T.String }>).v; }
        else if (ts.peek()?.t === T.Ident) { fallback = (ts.eat() as Extract<Token, { t: T.Ident }>).v; }
        return { kind: 'catch', fallback, body: parseBlock(currentIndent), span } satisfies CatchNode;
      }

      // @offline
      if (kw === 'offline') {
        return { kind: 'offline', body: parseBlock(currentIndent), span } satisfies OfflineNode;
      }

      // @i18n locale "path"
      if (kw === 'i18n') {
        let locale = 'en';
        if (ts.peek()?.t === T.Ident) { locale = (ts.eat() as Extract<Token, { t: T.Ident }>).v; }
        let i18nPath: string | null = null;
        if (ts.peek()?.t === T.String) { i18nPath = (ts.eat() as Extract<Token, { t: T.String }>).v; }
        return { kind: 'i18n', locale, path: i18nPath, span } satisfies I18nNode;
      }

      // @a11y — accessibility block
      if (kw === 'a11y') {
        return { kind: 'a11y', body: parseBlock(currentIndent), span } satisfies A11yNode;
      }

      // @liquidglass — Liquid-Glass-PRO global init
      if (kw === 'liquidglass' || kw === 'lg') {
        const config: Record<string, unknown> = {};
        // Parse inline key-value args: @liquidglass variant "obsidian" type "SF11"
        while (!ts.atEnd()) {
          if (ts.peek()?.t === T.Ident) {
            const key = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
            if (ts.peek()?.t === T.String) {
              config[key] = (ts.eat() as Extract<Token, { t: T.String }>).v;
            } else if (ts.peek()?.t === T.Number) {
              config[key] = (ts.eat() as Extract<Token, { t: T.Number }>).v;
            } else if (ts.peek()?.t === T.Ident) {
              config[key] = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
            } else {
              config[key] = true;
            }
          } else break;
        }
        // Block form: children are key = value pairs
        const body = parseBlock(currentIndent);
        for (const child of body) {
          if (child.kind === 'varDecl') {
            config[child.name] = child.expr.kind === 'string' ? child.expr.v
              : child.expr.kind === 'number' ? child.expr.v
              : child.expr.kind === 'ident' ? child.expr.v
              : true;
          }
        }
        return { kind: 'liquidglass', config, span } satisfies LiquidGlassNode;
      }

      // @animation name
      if (kw === 'animation' || kw === 'anim') {
        let name = 'unnamed';
        if (ts.peek()?.t === T.Ident) name = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
        else if (ts.peek()?.t === T.String) name = (ts.eat() as Extract<Token, { t: T.String }>).v;
        return { kind: 'animation', name, body: parseBlock(currentIndent), span } satisfies AnimationNode;
      }

      // @transition
      if (kw === 'transition') {
        const config: Record<string, unknown> = {};
        while (!ts.atEnd() && ts.peek()?.t === T.Ident) {
          const k = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
          if (ts.peek()?.t === T.String) config[k] = (ts.eat() as Extract<Token, { t: T.String }>).v;
          else if (ts.peek()?.t === T.Number) config[k] = (ts.eat() as Extract<Token, { t: T.Number }>).v;
          else config[k] = true;
        }
        parseBlock(currentIndent);
        return { kind: 'transition', config, span } satisfies TransitionNode;
      }

      // @worker "script.js" ~target
      if (kw === 'worker') {
        let src = '';
        if (ts.peek()?.t === T.String) src = (ts.eat() as Extract<Token, { t: T.String }>).v;
        let target: string | null = null;
        if (ts.peek()?.t === T.Arrow) ts.eat();
        if (ts.peek()?.t === T.Reactive) target = (ts.eat() as Extract<Token, { t: T.Reactive }>).v;
        return { kind: 'worker', src, target, span } satisfies WorkerNode;
      }

      // @permission camera|mic|notification
      if (kw === 'permission') {
        let permType = 'camera';
        if (ts.peek()?.t === T.Ident) permType = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
        else if (ts.peek()?.t === T.String) permType = (ts.eat() as Extract<Token, { t: T.String }>).v;
        return { kind: 'permission', type: permType, body: parseBlock(currentIndent), span } satisfies PermissionNode;
      }

      // @fsm name
      if (kw === 'fsm') {
        let name = 'machine';
        if (ts.peek()?.t === T.Ident) name = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
        return { kind: 'fsm', name, body: parseBlock(currentIndent), span } satisfies FsmNode;
      }

      // @voice — voice commands block
      if (kw === 'voice') {
        const commands: { phrase: string; actions: import('../ast/actions.js').Action[] }[] = [];
        const body = parseBlock(currentIndent);
        for (const child of body) {
          if (child.kind === 'handler' && child.actions.length > 0) {
            commands.push({ phrase: '', actions: child.actions });
          }
        }
        return { kind: 'voice', commands, span } satisfies VoiceNode;
      }

      // @biometric ~target
      if (kw === 'biometric') {
        let target: string | null = null;
        if (ts.peek()?.t === T.Arrow) ts.eat();
        if (ts.peek()?.t === T.Reactive) target = (ts.eat() as Extract<Token, { t: T.Reactive }>).v;
        return { kind: 'biometric', target, span } satisfies BiometricNode;
      }

      // @cron "pattern" => action
      if (kw === 'cron') {
        let pattern = '';
        if (ts.peek()?.t === T.String) pattern = (ts.eat() as Extract<Token, { t: T.String }>).v;
        else if (ts.peek()?.t === T.Number) pattern = String((ts.eat() as Extract<Token, { t: T.Number }>).v);
        const actions: import('../ast/actions.js').Action[] = [];
        if (ts.peek()?.t === T.Arrow) { ts.eat(); const a = parseAction(ts); if (a) actions.push(a); }
        const body = parseBlock(currentIndent);
        for (const child of body) { if (child.kind === 'handler') actions.push(...child.actions); }
        return { kind: 'cron', pattern, actions, span } satisfies CronNode;
      }

      // @sync ~var1 ~var2 — cross-tab sync
      if (kw === 'sync') {
        const vars: string[] = [];
        while (ts.peek()?.t === T.Reactive) {
          vars.push((ts.eat() as Extract<Token, { t: T.Reactive }>).v);
        }
        return { kind: 'sync', vars, span } satisfies SyncNode;
      }

      // Stray @elseif / @else
      if (kw === 'elseif' || kw === 'else') {
        errors.push({ message: `Unexpected @${kw} without a preceding @if`, line: span.line });
        parseBlock(currentIndent);
        return null;
      }

      // Unknown @keyword
      errors.push({ message: `Unknown keyword "@${kw}"`, line: span.line });
      return null;
    }

    // ── ~var = expr  /  ~var := expr  /  ~var: type = expr ──────────────────
    if (ts.peek()?.t === T.Reactive) {
      const varName = (ts.eat() as Extract<Token, { t: T.Reactive }>).v;

      // Optional type annotation: ~var: type
      let typeAnnotation: string | undefined;
      if (ts.peek()?.t === T.Colon) {
        ts.eat(); // :
        if (ts.peek()?.t === T.Ident) {
          typeAnnotation = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
        }
      }

      if (ts.peek()?.t === T.Compute) {
        ts.eat();
        const expr = parseValue(ts);
        if (expr) return { kind: 'computed', name: varName, expr, span } satisfies ComputedNode;
        errors.push({ message: `Missing value in computed "~${varName} :="`, line: span.line });
        return null;
      }
      if (ts.peek()?.t === T.Assign) {
        ts.eat();
        const expr = parseValue(ts);
        if (expr) return { kind: 'varDecl', name: varName, expr, ...(typeAnnotation ? { type: typeAnnotation } : {}), span } satisfies VarDeclNode;
        errors.push({ message: `Missing value in "~${varName} ="`, line: span.line });
        return null;
      }
      // reactive token with no operator — skip but don't consume children
      return null;
    }

    // ── => action  ────────────────────────────────────────────────────────────
    if (ts.peek()?.t === T.Arrow) {
      ts.eat();
      const action = parseAction(ts);
      if (action) return { kind: 'handler', actions: [action], span } satisfies HandlerNode;
      errors.push({ message: 'Empty handler "=>"', line: span.line });
      return null;
    }

    // ── list itemName from ~source ────────────────────────────────────────────
    if (ts.peek()?.t === T.Ident && (ts.peek() as Extract<Token, { t: T.Ident }>).v === 'list') {
      ts.eat();
      const itemName = ts.peek()?.t === T.Ident
        ? (ts.eat() as Extract<Token, { t: T.Ident }>).v
        : 'item';
      if (ts.peek()?.t === T.Ident && (ts.peek() as Extract<Token, { t: T.Ident }>).v === 'from') {
        ts.eat();
        const source = parseValue(ts);
        if (source) return { kind: 'list', itemName, source, body: parseBlock(currentIndent), span };
        errors.push({ message: `Missing source in "list ${itemName} from"`, line: span.line });
        return null;
      }
      errors.push({ message: `Expected "from ~source" after "list ${itemName}"`, line: span.line });
      return null;
    }

    // ── component  name [args] [:: mods] [=> handler] ────────────────────────
    if (ts.peek()?.t !== T.Ident) {
      // Unknown token — skip this line only, do not consume children (Б5 fix)
      return null;
    }

    const name = (ts.eat() as Extract<Token, { t: T.Ident }>).v;
    const args  = collectArgs(ts);

    // Detect optional event name before => (e.g. onBlur, onChange, onFocus)
    // collectArgs may have consumed it as an ident arg — pop it if it starts with 'on'
    let inlineEvent: string | undefined;
    if (args.length > 0) {
      const last = args[args.length - 1];
      if (last && last.kind === 'ident' && /^on[A-Z]/.test(last.v)) {
        inlineEvent = last.v.slice(2).toLowerCase(); // 'onBlur' → 'blur'
        args.pop();
      }
    }

    const mods  = parseModifiers(ts);
    const handlers = collectHandlers(ts, mods, span);

    // Support multiple chained => action => action
    while (ts.peek()?.t === T.Arrow) {
      ts.eat();
      const a = parseAction(ts);
      if (a) handlers.push({ kind: 'handler', actions: [a], span, ...(inlineEvent ? { event: inlineEvent } : {}) });
      // Only first handler gets the inlineEvent; rest are default event
      inlineEvent = undefined;
    }

    const children: Node[] = [];
    for (const node of parseBlock(currentIndent)) {
      if (!node) continue;
      if (node.kind === 'handler') handlers.push(node);
      else children.push(node);
    }

    return { kind: 'component', name, args, mods, handlers, children, span } satisfies ComponentNode;
  }

  const nodes: Node[] = [];
  while (cursor < lines.length) {
    const node = parseLine(lines[cursor]?.indent ?? 0);
    if (node) nodes.push(node);
  }
  return { nodes, errors };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

import type { ValueNode }   from '../ast/values.js';
import type { Modifier }    from '../ast/modifiers.js';

function collectArgs(ts: TokStream): ValueNode[] {
  const args: ValueNode[] = [];
  while (!ts.atEnd() && ts.peek()?.t !== T.DColon && ts.peek()?.t !== T.Arrow) {
    const v = parseValue(ts);
    if (!v) break;
    args.push(v);
  }
  return args;
}

function collectHandlers(ts: TokStream, mods: Modifier[], span: Span): HandlerNode[] {
  const handlers: HandlerNode[] = [];
  while (ts.peek()?.t === T.DColon) {
    ts.eat();
    if (ts.peek()?.t === T.Arrow) {
      ts.eat();
      const a = parseAction(ts);
      if (a) handlers.push({ kind: 'handler', actions: [a], span });
    } else {
      while (!ts.atEnd() && ts.peek()?.t !== T.DColon && ts.peek()?.t !== T.Arrow) {
        const m = parseMod(ts);
        if (!m) break;
        mods.push(m);
      }
    }
  }
  return handlers;
}

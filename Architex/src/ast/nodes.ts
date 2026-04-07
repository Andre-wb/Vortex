/** All AST node types that form the component tree. */

import type { Span }     from './span.js';
import type { ValueNode } from './values.js';
import type { Modifier }  from './modifiers.js';
import type { Action }    from './actions.js';

export interface ScreenNode {
  kind:   'screen';
  name:   string;
  params: string[];
  body:   Node[];
  span:   Span;
}

export interface VarDeclNode {
  kind: 'varDecl';
  name: string;
  expr: ValueNode;
  type?: string;        // optional type annotation: ~count: number = 0
  span: Span;
}

export interface ComputedNode {
  kind: 'computed';
  name: string;
  expr: ValueNode;
  span: Span;
}

export interface ComponentNode {
  kind:     'component';
  name:     string;
  args:     ValueNode[];
  mods:     Modifier[];
  handlers: HandlerNode[];
  children: Node[];
  span:     Span;
}

export interface ListNode {
  kind:     'list';
  itemName: string;
  source:   ValueNode;
  body:     Node[];
  span:     Span;
}

/** @for item, index in ~source — loop with index variable */
export interface ForNode {
  kind:      'for';
  itemName:  string;
  indexName:  string | null;   // null if no index variable
  source:    ValueNode;
  body:      Node[];
  span:      Span;
}

/** @theme — design tokens block */
export interface ThemeNode {
  kind:   'theme';
  vars:   { name: string; expr: ValueNode }[];
  span:   Span;
}

/** @import "./path.arx" — module import */
export interface ImportNode {
  kind: 'import';
  path: string;
  span: Span;
}

export interface HandlerNode {
  kind:    'handler';
  actions: Action[];        // БЫЛО: action: Action
  event?:  string;          // 'click' | 'blur' | 'focus' | 'change' | 'input' | 'mouseenter' | 'mouseleave' | undefined
  span:    Span;
}

/** @if ~cond … @elseif … @else */
export interface IfBranch {
  condition: ValueNode;
  body:      Node[];
}

export interface IfNode {
  kind:     'if';
  branches: IfBranch[];
  else_:    Node[];
  span:     Span;
}

/** @watch ~key (P2 #17) */
export interface WatchNode {
  kind:    'watch';
  target:  string;
  actions: Action[];
  span:    Span;
}

/** @onMount / @onUnmount lifecycle hooks (P3 #23) */
export interface LifecycleNode {
  kind:    'lifecycle';
  hook:    'mount' | 'unmount';
  actions: Action[];
  span:    Span;
}

/** @component Name(param1, param2) — user-defined reusable component */
export interface ComponentDefNode {
  kind:   'compDef';
  name:   string;
  params: string[];
  body:   Node[];
  span:   Span;
}

/** @slot — marks where children should be inserted in a component */
export interface SlotNode {
  kind: 'slot';
  name: string;  // 'default' or named
  span: Span;
}

/** @style — scoped CSS injection block */
export interface StyleNode {
  kind: 'style';
  css:  string;  // raw CSS content
  span: Span;
}

/** @hotkey "ctrl+k" => action — keyboard shortcut */
export interface HotkeyNode {
  kind:    'hotkey';
  keys:    string;
  actions: Action[];
  span:    Span;
}

/** @timer 5000 => action — repeating interval */
export interface TimerNode {
  kind:     'timer';
  interval: number;
  actions:  Action[];
  span:     Span;
}

/** @ws "url" => ~target — WebSocket connection */
export interface WsNode {
  kind: 'ws';
  url: string;
  target: string | null;
  actions: Action[];
  span: Span;
}

/** @sse "url" => ~target — Server-Sent Events */
export interface SseNode {
  kind: 'sse';
  url: string;
  target: string | null;
  span: Span;
}

/** @route "/path" => ScreenName — URL deep link routing */
export interface RouteNode {
  kind: 'route';
  path: string;
  screen: string;
  span: Span;
}

/** @debug — debug logging block */
export interface DebugNode {
  kind: 'debug';
  expr: ValueNode | null;
  span: Span;
}

/** @catch — error boundary wrapping child nodes */
export interface CatchNode {
  kind: 'catch';
  fallback: string | null;  // fallback screen or text
  body: Node[];
  span: Span;
}

/** @offline — block rendered when offline */
export interface OfflineNode {
  kind: 'offline';
  body: Node[];
  span: Span;
}

/** @i18n locale "path" — internationalization config */
export interface I18nNode {
  kind: 'i18n';
  locale: string;
  path: string | null;
  span: Span;
}

/** @a11y — accessibility auto-enhancement block */
export interface A11yNode {
  kind: 'a11y';
  body: Node[];
  span: Span;
}

/** @liquidglass — global Liquid-Glass-PRO initialization config */
export interface LiquidGlassNode {
  kind:    'liquidglass';
  config:  Record<string, unknown>;
  span:    Span;
}

/** @animation name — keyframe animation definition */
export interface AnimationNode {
  kind: 'animation';
  name: string;
  body: Node[];
  span: Span;
}

/** @transition — shared element transition config */
export interface TransitionNode {
  kind: 'transition';
  config: Record<string, unknown>;
  span: Span;
}

/** @worker "script.js" — Web Worker offload */
export interface WorkerNode {
  kind: 'worker';
  src: string;
  target: string | null;
  span: Span;
}

/** @permission camera|mic|notification — permission request flow */
export interface PermissionNode {
  kind: 'permission';
  type: string;
  body: Node[];
  span: Span;
}

/** @fsm name — finite state machine */
export interface FsmNode {
  kind: 'fsm';
  name: string;
  body: Node[];
  span: Span;
}

/** @voice "command" => action — voice command */
export interface VoiceNode {
  kind: 'voice';
  commands: { phrase: string; actions: Action[] }[];
  span: Span;
}

/** @biometric — WebAuthn biometric auth */
export interface BiometricNode {
  kind: 'biometric';
  target: string | null;
  span: Span;
}

/** @cron "pattern" => action — scheduled task */
export interface CronNode {
  kind: 'cron';
  pattern: string;
  actions: Action[];
  span: Span;
}

/** @sync ~var — BroadcastChannel cross-tab sync */
export interface SyncNode {
  kind: 'sync';
  vars: string[];
  span: Span;
}

export type Node =
  | ScreenNode
  | VarDeclNode
  | ComputedNode
  | ComponentNode
  | ListNode
  | ForNode
  | HandlerNode
  | IfNode
  | WatchNode
  | LifecycleNode
  | ComponentDefNode
  | ThemeNode
  | ImportNode
  | SlotNode
  | StyleNode
  | HotkeyNode
  | TimerNode
  | WsNode
  | SseNode
  | RouteNode
  | DebugNode
  | CatchNode
  | OfflineNode
  | I18nNode
  | A11yNode
  | LiquidGlassNode
  | AnimationNode
  | TransitionNode
  | WorkerNode
  | PermissionNode
  | FsmNode
  | VoiceNode
  | BiometricNode
  | CronNode
  | SyncNode;

export type GlobalNode = VarDeclNode | ComputedNode;

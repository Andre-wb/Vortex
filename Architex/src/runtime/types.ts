/** ArchiRuntime constructor options. */

import type { StateAPI } from '../reactive/types.js';

/** Structured error reported by the runtime. */
export interface ArchiError {
  kind:     string;   // 'parse' | 'navigate' | 'fetch' | 'render'
  message:  string;
  line?:    number;   // for parse errors
}

export interface ArchiOptions {
  container: HTMLElement;
  send?:     (payload: Record<string, unknown>) => void;
  fetch?:    (url: string, state: StateAPI) => void;
  onError?:  (err: ArchiError) => void;
  /** Resolver for @import paths — returns source text for the given path. */
  resolve?:  (path: string) => Promise<string>;
  [key: string]: unknown;
}

/** Reactive state public interface and helper types. */

export type Subscriber<T = unknown> = (value: T, key: string) => void;
export type Unsubscribe             = () => void;

export interface StateAPI {
  get(key: string): unknown;
  set(key: string, val: unknown): void;
  update(key: string, fn: (current: unknown) => unknown): void;
  subscribe(key: string, fn: Subscriber): Unsubscribe;
  /** P2 #17 — alias for subscribe, expresses intent to run a side-effect */
  watch(key: string, fn: Subscriber): Unsubscribe;
  computed(key: string, expr: (state: StateAPI) => unknown, deps?: string[]): void;
  batch(fn: () => void): void;
  snapshot(): Record<string, unknown>;
  reset(data: Record<string, unknown>): void;
}

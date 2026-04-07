/** Renderer runtime hooks and context types. */

export interface RuntimeHooks {
  /** Navigate to a named screen, optionally passing params into RenderCtx. */
  navigate(screen: string, params?: Record<string, unknown>): void;
  /** Go back to the previous screen in the history stack (P3 #21). */
  back(): void;
  send(payload: Record<string, unknown>): void;
  fetch(url: string): unknown;
  getCompDef?(name: string): unknown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: ((...args: any[]) => any) | undefined;
}

/** Variables injected by list context or screen navigate() params. */
export type RenderCtx = Record<string, unknown>;

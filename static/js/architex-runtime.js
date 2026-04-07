/**
 * Architex browser runtime stub.
 * The real implementation lives in Architex/src/ (TypeScript).
 * After `npm run build` in Architex/, copy dist/index.js here
 * or import directly from the dist folder.
 *
 * Quick usage (dev, no build step):
 *   <script type="module">
 *     import { ArchiRuntime } from '/static/js/architex-runtime.js';
 *     new ArchiRuntime(src, { container, send }).start();
 *   </script>
 */

// Re-export from the compiled TypeScript dist.
// Adjust the path after running `npm run build` inside Architex/.
export * from '../../Architex/dist/index.js';

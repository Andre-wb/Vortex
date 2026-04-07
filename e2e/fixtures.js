// @ts-check
/**
 * Worker-scoped request context shared across all tests.
 *
 * Playwright forbids changing the scope of the built-in `request` fixture, so
 * we keep it test-scoped but make every test return the *same* underlying
 * APIRequestContext by delegating to a worker-scoped intermediate fixture.
 * This means cookies (auth + CSRF) set during beforeAll persist into all
 * subsequent test() callbacks without any changes to the test files themselves.
 */
const { test: base, expect } = require('@playwright/test');

exports.test = base.extend({
    // Per-test fresh (unauthenticated) request context.
    // Use this fixture — as `{ freshRequest }` — in tests that explicitly need
    // to verify unauthenticated behaviour.  Unlike `request`, it is test-scoped
    // and starts with an empty cookie jar every time.
    freshRequest: async ({ playwright }, use, testInfo) => {
        const baseURL =
            testInfo.project.use.baseURL ||
            process.env.VORTEX_URL ||
            `http://localhost:${process.env.E2E_PORT || '19000'}`;
        const context = await playwright.request.newContext({ baseURL });
        await use(context);
        await context.dispose();
    },

    // One APIRequestContext per worker, shared by all tests and hooks.
    _sharedApiContext: [
        async ({ playwright }, use, workerInfo) => {
            const baseURL =
                workerInfo.project.use.baseURL ||
                process.env.VORTEX_URL ||
                `http://localhost:${process.env.E2E_PORT || '19000'}`;
            const context = await playwright.request.newContext({ baseURL });
            await use(context);
            await context.dispose();
        },
        { scope: 'worker' },
    ],

    // Override the built-in test-scoped `request` to proxy the shared context.
    // Scope stays 'test' (Playwright enforces this), but every test receives
    // the same underlying object — so the cookie jar is shared across the suite.
    request: [
        async ({ _sharedApiContext }, use) => {
            await use(_sharedApiContext);
        },
        { override: true },
    ],
});

exports.expect = expect;

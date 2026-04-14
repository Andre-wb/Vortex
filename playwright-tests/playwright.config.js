// @ts-check
const path = require('path');
const { defineConfig, devices } = require('@playwright/test');

// Dedicated port for e2e tests — avoids conflicts with the dev server (8000)
const E2E_PORT = parseInt(process.env.E2E_PORT || '19000', 10);
const BASE_URL = process.env.VORTEX_URL || `http://localhost:${E2E_PORT}`;

/**
 * Playwright configuration for Vortex E2E tests.
 *
 * Usage:
 *   node_modules/.bin/playwright install
 *   node_modules/.bin/playwright test
 *   node_modules/.bin/playwright test --headed
 *   node_modules/.bin/playwright test --project=chromium
 *
 *   # Point at an already-running server instead:
 *   VORTEX_URL=http://localhost:8000 npm run test:e2e
 */
module.exports = defineConfig({
    testDir: './tests',
    timeout: 60_000,
    expect: { timeout: 10_000 },
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 1,
    workers: process.env.CI ? 4 : 30,
    reporter: process.env.CI ? 'github' : 'html',

    use: {
        baseURL: BASE_URL,
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
    },

    projects: [
        // ── Chromium-based ───────────────────────────────────────────────────
        { name: 'google-chrome',  use: { ...devices['Desktop Chrome'],  channel: 'chrome' } },
        { name: 'microsoft-edge', use: { ...devices['Desktop Chrome'],  channel: 'chrome',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        }},
        { name: 'opera',          use: { ...devices['Desktop Chrome'],  channel: 'chrome',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
        }},
        { name: 'yandex',         use: { ...devices['Desktop Chrome'],  channel: 'chrome',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 YaBrowser/24.7.0 Safari/537.36',
        }},

        // ── Privacy-focused (Chromium-based) ────────────────────────────────
        { name: 'brave',           use: { ...devices['Desktop Chrome'],  channel: 'chrome',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/126',
        }},
        { name: 'atom',            use: { ...devices['Desktop Chrome'],  channel: 'chrome',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Atom/28.0.0',
        }},

        // ── Other engines ────────────────────────────────────────────────────
        { name: 'mozilla-firefox', use: { ...devices['Desktop Firefox'] } },
        { name: 'tor-browser',     use: { ...devices['Desktop Firefox'],
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0',
        }},
        { name: 'apple-safari',   use: { ...devices['Desktop Safari'] } },

        // ── Mobile ───────────────────────────────────────────────────────────
        { name: 'mobile-ios',     use: { ...devices['iPhone 14'] } },
        { name: 'mobile-android', use: { ...devices['Pixel 7'] } },
    ],

    webServer: process.env.VORTEX_URL ? undefined : {
        command: `python -m uvicorn app.main:app --host 0.0.0.0 --port ${E2E_PORT} --no-access-log`,
        cwd: path.join(__dirname, '..'),
        url: `${BASE_URL}/health`,
        reuseExistingServer: true,
        timeout: 60_000,
        env: { ...process.env, TESTING: 'true', REGISTRATION_MODE: 'open' },
    },
});

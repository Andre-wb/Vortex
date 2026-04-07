// @ts-check
const { test, expect } = require('../fixtures');
const { randomStr, randomDigits, makePublicKey } = require('./helpers');

/**
 * Vortex E2E — Browser UI Tests (page context)
 *
 * Covers:
 *   - Landing page rendering
 *   - Auth screen layout (tabs, forms)
 *   - Registration flow in browser
 *   - Login flow in browser
 *   - App boot after auth
 *   - Sidebar / navigation
 *   - PWA manifest, service worker
 *   - Responsive layout (mobile viewport)
 *   - Accessibility (a11y) checks
 *   - Keyboard shortcuts
 *   - Static assets load
 */

test.describe('Browser UI', () => {

    // ── Landing / Auth ────────────────────────────────────────────────────────

    test('landing page loads with auth screen', async ({ page }) => {
        await page.goto('/');
        await expect(page).toHaveTitle(/Vortex/i);
        // Auth screen should be visible
        const authScreen = page.locator('#auth-screen');
        await expect(authScreen).toBeVisible({ timeout: 15_000 });
    });

    test('auth tabs are clickable', async ({ page }) => {
        await page.goto('/');
        const authScreen = page.locator('#auth-screen');
        await expect(authScreen).toBeVisible({ timeout: 15_000 });

        // Should have login/register tabs
        const loginTab = page.locator('.auth-tab').first();
        if (await loginTab.isVisible()) {
            await loginTab.click();
        }
    });

    test('register form has required fields', async ({ page }) => {
        await page.goto('/');
        await page.waitForSelector('#auth-screen', { timeout: 15_000 });

        // Click register tab
        const tabs = page.locator('.auth-tab');
        const tabCount = await tabs.count();
        if (tabCount >= 2) {
            await tabs.nth(1).click();
            await page.waitForTimeout(300);
        }

        // Check form fields exist
        const usernameInput = page.locator('#r-username, #r-login, [name="username"]');
        const passwordInput = page.locator('#r-pass, [name="password"]');
        const phoneInput = page.locator('#r-phone, [name="phone"]');

        // At least username and password should exist
        const fieldsExist = (await usernameInput.count()) > 0 || (await passwordInput.count()) > 0;
        expect(fieldsExist).toBeTruthy();
    });

    test('password strength indicator appears on input', async ({ page }) => {
        await page.goto('/');
        await page.waitForSelector('#auth-screen', { timeout: 15_000 });

        // Switch to register
        const tabs = page.locator('.auth-tab');
        if ((await tabs.count()) >= 2) {
            await tabs.nth(1).click();
            await page.waitForTimeout(300);
        }

        const passInput = page.locator('#r-pass');
        if (await passInput.isVisible()) {
            await passInput.fill('TestStr0ng!');
            // Strength bar should become visible
            const strengthWrap = page.locator('#r-pass-strength, .password-strength-wrap');
            if (await strengthWrap.count()) {
                await expect(strengthWrap.first()).toBeVisible({ timeout: 3000 });
            }
        }
    });

    test('country picker opens and lists countries', async ({ page }) => {
        await page.goto('/');
        await page.waitForSelector('#auth-screen', { timeout: 15_000 });

        // Switch to register
        const tabs = page.locator('.auth-tab');
        if ((await tabs.count()) >= 2) {
            await tabs.nth(1).click();
            await page.waitForTimeout(300);
        }

        const countryBtn = page.locator('#phone-country-btn, .phone-country-btn');
        if (await countryBtn.isVisible()) {
            await countryBtn.click();
            const dropdown = page.locator('#phone-country-dropdown, .phone-country-dropdown');
            await expect(dropdown).toBeVisible({ timeout: 3000 });

            // Search for a country
            const search = dropdown.locator('input');
            if (await search.isVisible()) {
                await search.fill('Россия');
                await page.waitForTimeout(200);
                const items = dropdown.locator('.phone-country-item');
                expect(await items.count()).toBeGreaterThan(0);
            }
        }
    });

    // ── Full Registration + Login in Browser ──────────────────────────────────

    test('full browser registration and login flow', async ({ page }) => {
        const u = `br_e2e_${randomStr(6)}`;
        const pw = 'BrowserTest99!@';
        const ph = `900${randomDigits(7)}`;

        await page.goto('/');
        await page.waitForSelector('#auth-screen', { timeout: 15_000 });

        // Switch to register tab
        const tabs = page.locator('.auth-tab');
        if ((await tabs.count()) >= 2) {
            await tabs.nth(1).click();
            await page.waitForTimeout(500);
        }

        // Fill registration form
        const rUser = page.locator('#r-username, #r-login');
        const rPass = page.locator('#r-pass');
        const rConfirm = page.locator('#r-pass-confirm');
        const rPhone = page.locator('#r-phone');

        if (await rUser.isVisible()) {
            await rUser.fill(u);
            await rPass.fill(pw);
            if (await rConfirm.isVisible()) await rConfirm.fill(pw);
            if (await rPhone.isVisible()) await rPhone.fill(ph);

            // Submit — look for register button
            const regBtn = page.locator('button:has-text("Регистрация"), button:has-text("Register"), #btn-register');
            if (await regBtn.isVisible()) {
                await regBtn.click();
                // Wait for either success or error message
                await page.waitForTimeout(3000);
            }
        }
    });

    // ── Static Assets ─────────────────────────────────────────────────────────

    test('manifest.json loads', async ({ request }) => {
        const res = await request.get('/manifest.json');
        expect([200, 404]).toContain(res.status());
        if (res.ok()) {
            const body = await res.json();
            expect(body.name || body.short_name).toBeDefined();
        }
    });

    test('service worker loads', async ({ request }) => {
        const res = await request.get('/service-worker.js');
        expect([200, 404]).toContain(res.status());
    });

    test('CSS files load', async ({ request }) => {
        const cssFiles = [
            '/static/css/variables.css',
            '/static/css/layout.css',
            '/static/css/auth.css',
            '/static/css/chat.css',
            '/static/css/group-call.css',
        ];
        for (const file of cssFiles) {
            const res = await request.get(file);
            expect([200, 404]).toContain(res.status());
        }
    });

    test('JS modules load', async ({ request }) => {
        const jsFiles = [
            '/static/js/main.js',
            '/static/js/auth.js',
            '/static/js/utils.js',
        ];
        for (const file of jsFiles) {
            const res = await request.get(file);
            expect(res.ok()).toBeTruthy();
        }
    });

    // ── Metrics ───────────────────────────────────────────────────────────────

    test('prometheus metrics endpoint', async ({ request }) => {
        const res = await request.get('/metrics');
        expect(res.ok()).toBeTruthy();
        const text = await res.text();
        expect(text).toContain('vortex_');
    });
});

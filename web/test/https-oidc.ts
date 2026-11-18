import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { required } from './required.ts';

// Actual app -> independent login tab -> IdP -> SPA callback -> original
// access issuance. Chromium enforces TLS, CSP, cookies and cross-site navigation.
const origin = required(process.argv[2]);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/);
const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    if (process.argv[3] && !['blocked', 'named'].includes(process.argv[3])) {
        const login = await context.newPage();
        await login.setViewportSize({ width: 390, height: 844 });
        await login.emulateMedia({ colorScheme: 'dark' });
        await login.goto(process.argv[3]);
        await login.getByRole('heading', { name: 'Confirm your SSH login' }).waitFor();
        assert.equal(await login.title(), 'Fixture sign-in');
        assert.deepEqual(
            await login.evaluate(
                () => (window as Window & { oidcCustomEvents?: string[] }).oidcCustomEvents,
            ),
            ['configure', 'ready'],
        );
        assert.equal(await login.locator('#custom-login-body').textContent(), 'Operator content');
        assert.equal(
            await login
                .locator('.bifroest-login-card')
                .evaluate((card) =>
                    getComputedStyle(card).getPropertyValue('--login-custom-check').trim(),
                ),
            'applied',
        );
        const choices = login.getByRole('button', { name: /^Code /u });
        assert.equal(await choices.count(), 3);
        const labels = await choices.allTextContents();
        assert(labels.includes(required(process.argv[4])));
        await login.waitForFunction(() => document.documentElement.dataset.colorScheme === 'dark');
        const mobile = await login.locator('section').boundingBox();
        assert(mobile && mobile.width === 390 && mobile.height >= 844);
        assert(await login.locator('.bifroest-login-brand-inside').isVisible());
        assert(!(await login.locator('.bifroest-login-brand-outside').isVisible()));
        assert.equal(await login.getByText('verified-subject', { exact: true }).count(), 0);
        const decline = login.getByRole('button', { name: 'Decline login', exact: true });
        const declineBox = await decline.boundingBox();
        const choiceBox = await login.locator('.bifroest-login-choices').boundingBox();
        assert(declineBox && choiceBox && Math.abs(declineBox.width - choiceBox.width) < 1);
        assert(
            await decline.evaluate((button) => getComputedStyle(button).borderTopStyle !== 'none'),
        );
        await login.reload();
        await login.getByRole('heading', { name: 'Confirm your SSH login' }).waitFor();
        assert.deepEqual(
            await choices.allTextContents(),
            labels,
            'approval resumes without another IdP login',
        );
        await login.setViewportSize({ width: 760, height: 360 });
        await login.locator('.bifroest-login-brand-inside').waitFor({ state: 'visible' });
        const landscape = await login.locator('section').boundingBox();
        assert(landscape && landscape.width === 760);
        await login.setViewportSize({ width: 1200, height: 900 });
        await login.emulateMedia({ colorScheme: 'light' });
        await login.waitForFunction(() => document.documentElement.dataset.colorScheme === 'light');
        const desktop = await login.locator('section').boundingBox();
        assert(
            desktop &&
                desktop.width === 440 &&
                Math.abs(desktop.x - 380) < 2 &&
                desktop.height < 900,
        );
        assert(await login.locator('.bifroest-login-brand-outside').isVisible());
        assert(!(await login.locator('.bifroest-login-brand-inside').isVisible()));
        assert(
            !(await login
                .locator('section')
                .evaluate((card) =>
                    card.contains(document.querySelector('.bifroest-login-brand-outside')),
                )),
        );
        await login
            .getByRole('button', { name: `Code ${required(process.argv[4])}`, exact: true })
            .click();
        await login.getByRole('heading', { name: 'Login successful' }).waitFor();
        assert.equal(login.isClosed(), false, 'SSH retains its final outcome in the browser');
        process.stdout.write(
            'PASS: real OIDC redirect, SSH code choices, resume, responsive layout and system theme\n',
        );
    } else {
        const initial = await context.newPage();
        const named = process.argv[3] === 'named';
        if (named) {
            await initial.addInitScript(() => {
                localStorage.setItem('bifroest-ui-v1:username:Work', 'route-user');
            });
        }
        const popupBlocked = process.argv[3] === 'blocked';
        if (popupBlocked) {
            await initial.addInitScript(() => {
                Object.defineProperty(window, 'open', { value: () => null });
            });
        }
        const loginRequests: string[] = [];
        const outcomes: string[] = [];
        let approved = false;
        context.on('page', (page) => {
            if (page === initial) {
                return;
            }
            page.on('request', (request) => {
                const url = new URL(request.url());
                if (url.origin === origin) {
                    loginRequests.push(url.pathname);
                }
            });
            page.on('response', async (response) => {
                if (new URL(response.url()).pathname === '/api/v1/oidc/status') {
                    try {
                        outcomes.push(((await response.json()) as { status: string }).status);
                    } catch {
                        /* Tab may close after reading the response. */
                    }
                }
            });
            page.on('request', (request) => {
                if (new URL(request.url()).pathname === '/api/v1/oidc/approve') {
                    approved = true;
                }
            });
        });
        const discovery: string[] = [];
        initial.on('request', (request) => {
            if (new URL(request.url()).pathname === '/api/v1/discovery') {
                assert.equal(request.method(), 'POST');
                assert.equal(request.postDataJSON()?.slug, 'Work');
                discovery.push(new URL(request.url()).pathname);
            }
        });
        const missing = await initial.goto(`${origin}/df`);
        assert(missing && missing.status() === 404);
        assert.equal(
            (await missing.body()).byteLength,
            0,
            'unknown entries are empty server 404s, not an application error screen',
        );
        await initial.goto(`${origin}/#Work`);
        if (named) {
            const dialog = initial.getByRole('dialog', { name: 'Sign in', exact: true });
            const user = dialog.getByLabel('User name', { exact: true });
            await initial.waitForURL((url) => url.hash === '#route-user@Work');
            assert.equal(await user.inputValue(), 'route-user');
            await user.fill('');
            await dialog.locator('button[type="submit"]').click();
            await dialog
                .getByText('Enter a user name before signing in.', { exact: true })
                .waitFor();
            assert.equal(await user.getAttribute('aria-invalid'), 'true');
            await user.fill('route-user');
            assert.equal(await user.getAttribute('aria-invalid'), 'false');
            await dialog
                .getByRole('checkbox', { name: 'Remember this browser', exact: true })
                .check();
        }
        // Force the waiting tab to finish loading before its ticket arrives:
        // same-document hash navigation must start the flow as well.
        await initial.route('**/api/v1/login/oidc', async (route) => {
            await new Promise((resolve) => setTimeout(resolve, 1000));
            await route.continue();
        });
        await initial.evaluate(() => {
            Object.assign(window, { oidcOriginalDocument: true });
        });
        const popupEvent = initial.waitForEvent('popup');
        await initial.locator('form button[type="submit"]').click();
        if (popupBlocked) {
            await initial.getByRole('link', { name: 'Open identity-provider login' }).click();
        }
        const popup = await popupEvent;
        await popup.waitForEvent('close', { timeout: 15_000 });
        assert.equal(initial.isClosed(), false);
        assert.equal(
            await initial.evaluate(
                () => (window as Window & { oidcOriginalDocument?: boolean }).oidcOriginalDocument,
            ),
            true,
            'the original app document is not replaced by the IdP',
        );
        assert.equal(approved, false, 'WebUI login has no SSH code selection');
        assert(loginRequests.includes('/api/v1/oidc/start'));
        assert(loginRequests.includes('/login/callback'));
        assert(loginRequests.includes('/api/v1/oidc/callback'));
        assert(loginRequests.includes('/api/v1/oidc/status'));
        assert(discovery.every((path) => path.startsWith('/api/v1/discovery')));
        assert(
            loginRequests.every(
                (path) => !path.includes('/_bifroest/') && !path.startsWith('/api/v1/discovery'),
            ),
        );
        assert(
            loginRequests
                .filter((path) => path.endsWith('.js'))
                .every(
                    (path) =>
                        path.startsWith('/assets/') &&
                        !/(?:index|xterm|browser-protocol|AdminDataGrid|ArtifactPanel|ManagementPanel|wasm-key)-/u.test(
                            path,
                        ),
                ),
        );
        // Closing the tab is itself performed only after the SPA reads accepted.
        assert(outcomes.every((status) => ['authorizing', 'accepted'].includes(status)));
        if (named) {
            await initial.waitForURL((url) =>
                /^#route-user@Work\/[1-9A-HJ-NP-Za-km-z]{16,22}$/u.test(url.hash),
            );
            await initial.getByRole('button', { name: 'New connection', exact: true }).click();
            const dialog = initial.getByRole('dialog', { name: 'Sign in', exact: true });
            await dialog.getByRole('radio', { name: 'Saved', exact: true }).waitFor();
            await dialog.locator('[role="radio"][value="oidc:named"]').click();
            await initial.waitForURL((url) => url.hash === '#route-user@Work');
            assert.equal(
                await dialog.getByLabel('User name', { exact: true }).inputValue(),
                'route-user',
            );
            await dialog.getByRole('button', { name: 'Close', exact: true }).click();
            await initial.waitForURL((url) =>
                /^#route-user@Work\/[1-9A-HJ-NP-Za-km-z]{16,22}$/u.test(url.hash),
            );
            // A resumed grant must also retain the server-bound requesting user.
            await initial.getByRole('button', { name: 'New connection', exact: true }).click();
            await dialog.getByRole('radio', { name: 'Saved', exact: true }).waitFor();
            await dialog.locator('button[type="submit"]').click();
            await initial.waitForURL((url) =>
                /^#route-user@Work\/[1-9A-HJ-NP-Za-km-z]{16,22}$/u.test(url.hash),
            );
        }
        process.stdout.write(
            'PASS: real OIDC redirect, automatic popup, lean assets and final accepted outcome\n',
        );
    }
} finally {
    await browser.close();
}

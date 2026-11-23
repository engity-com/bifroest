import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { required } from './required.ts';

// Actual app -> independent login tab -> IdP -> SPA callback -> original
// access issuance. Chromium enforces TLS, CSP, cookies and cross-site navigation.
const origin = required(process.argv[2]);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/);
const prefix = process.env.BIFROEST_TEST_HTTP_PREFIX ?? '';
const base = origin + prefix;
const publicPath = (path: string) => prefix + path;
const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    context.setDefaultTimeout(10_000);
    if (prefix !== '') {
        await context.route(`${base}/api/v1/remember/resume`, async (route) => {
            const status = await route
                .request()
                .frame()
                .evaluate(async (body: unknown) => {
                    const response = await fetch('/other-bifroest/api/v1/remember/resume', {
                        method: 'POST',
                        credentials: 'omit',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                    });
                    return response.status;
                }, route.request().postDataJSON());
            assert.equal(status, 401, 'saved registrations are bound to their mount');
            await route.continue();
        });
        await context.route(`${base}/api/v1/oidc/callback`, async (route) => {
            // Real cookies and callback data must not authorize a different
            // mount, nor consume the original transaction on rejection.
            const cookies = (await context.cookies(origin)).filter((cookie) =>
                cookie.name.startsWith('__Host-bifroest-'),
            );
            assert(cookies.length > 0);
            assert(
                cookies.every(
                    (cookie) =>
                        cookie.secure &&
                        cookie.httpOnly &&
                        cookie.path === '/' &&
                        cookie.sameSite === 'Lax',
                ),
            );
            const status = await route
                .request()
                .frame()
                .evaluate(async (body: unknown) => {
                    const response = await fetch('/other-bifroest/api/v1/oidc/callback', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                    });
                    return response.status;
                }, route.request().postDataJSON());
            assert.equal(status, 401);
            await route.continue();
        });
    }
    if (process.argv[3] === 'forwarded') {
        // A real independent profile must not attach its IdP identity to an
        // attacker's attempt, even though the attacker knows the whole ticket.
        const initiatingPage = await context.newPage();
        await initiatingPage.goto(`${base}/#Work`);
        const post = (action: string, fields: Record<string, string>, token?: string) =>
            initiatingPage.evaluate(
                async ({ action, fields, token, prefix }) => {
                    const response = await fetch(`${prefix}/api/v1/${action}`, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { Authorization: `Bearer ${token}` } : {}),
                        },
                        body: JSON.stringify(fields),
                    });
                    const body: unknown = response.status === 204 ? null : await response.json();
                    return { status: response.status, body };
                },
                { action, fields, token, prefix },
            );
        const started = await post('login/oidc', { slug: 'Work', user: '' });
        assert.equal(started.status, 202);
        const pending = started.body as { attemptToken: string };
        assert.match(pending.attemptToken, /^bwl1\.[A-Za-z0-9_-]{43}$/u);
        let step: { sequence: string; message: string } | undefined;
        for (let poll = 0; poll < 20 && !step; poll++) {
            const response = await post('login/poll', { slug: 'Work' }, pending.attemptToken);
            assert.equal(response.status, 200);
            step = (response.body as { step?: typeof step }).step;
            if (!step) {
                await initiatingPage.waitForTimeout(250);
            }
        }
        assert(step);
        const link = required(/https:\/\/\S+/u.exec(step.message)?.[0]);
        const reply = await post(
            'login/reply',
            { slug: 'Work', sequence: step.sequence },
            pending.attemptToken,
        );
        assert.equal(reply.status, 202);
        const binding = (await context.cookies(origin)).filter((cookie) =>
            cookie.name.startsWith('__Host-bifroest-oidc-init-'),
        );
        assert.equal(binding.length, 1);
        assert(required(binding[0]).secure && required(binding[0]).httpOnly);
        assert.equal(await initiatingPage.evaluate(() => document.cookie), '');
        const victim = await browser.newContext({ ignoreHTTPSErrors: true });
        try {
            const page = await victim.newPage();
            const decision = page.waitForResponse(
                (response) => new URL(response.url()).pathname === publicPath('/api/v1/oidc/start'),
            );
            await page.goto(link);
            assert.equal((await decision).status(), 401);
            assert.deepEqual(await victim.cookies(origin), []);
            assert.equal(await page.evaluate(() => document.cookie), '');
            const claim = await post('login/poll', { slug: 'Work' }, pending.attemptToken);
            assert.equal(claim.status, 200);
            const result = claim.body as { status: string; accessToken?: string };
            assert.equal(result.status, 'pending');
            assert.equal(result.accessToken, undefined);
        } finally {
            await victim.close();
            const cancelled = await post('login/cancel', { slug: 'Work' }, pending.attemptToken);
            assert.equal(cancelled.status, 204);
        }
        process.stdout.write(
            'PASS: real OIDC redirect rejects a forwarded WebUI ticket in another profile\n',
        );
    } else if (process.argv[3] && !['blocked', 'named'].includes(process.argv[3])) {
        const login = await context.newPage();
        await login.setViewportSize({ width: 390, height: 844 });
        await login.emulateMedia({ colorScheme: 'dark' });
        // Follow the user's own SSH link from an independent webmail origin.
        // Chromium supplies the real cross-site navigation headers; no IdP or
        // authentication request is intercepted or replayed.
        const link = new URL(process.argv[3]);
        assert.equal(link.origin, origin);
        assert.equal(link.pathname, publicPath('/login/'));
        assert.match(link.hash, /^#start\/[A-Za-z0-9_-]{43}$/u);
        const mail = 'https://mail.example.net/owned-ssh-link';
        await login.route(mail, (route) =>
            route.fulfill({
                contentType: 'text/html',
                body: '<!doctype html><a href="#">Open my SSH login</a>',
            }),
        );
        await login.goto(mail);
        const ownedLink = login.getByRole('link', { name: 'Open my SSH login', exact: true });
        await ownedLink.evaluate((element, href) => element.setAttribute('href', href), link.href);
        const navigation = login.waitForResponse(
            (response) =>
                response.request().isNavigationRequest() && response.url() === `${base}/login/`,
        );
        await ownedLink.click();
        const loginDocument = await navigation;
        assert.equal(loginDocument.status(), 200);
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
            await initial.addInitScript((prefix) => {
                const key = 'bifroest-ui-v1:username:Work';
                localStorage.setItem(
                    prefix === '' ? key : `bifroest-path-${encodeURIComponent(prefix)}:${key}`,
                    'route-user',
                );
            }, prefix);
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
                    if (prefix !== '' && url.pathname === '/other-bifroest/api/v1/oidc/callback') {
                        // This one request is the explicit negative mount test.
                        return;
                    }
                    assert(url.pathname.startsWith(`${prefix}/`));
                    loginRequests.push(url.pathname.slice(prefix.length));
                }
            });
            page.on('response', async (response) => {
                if (new URL(response.url()).pathname === publicPath('/api/v1/oidc/status')) {
                    try {
                        outcomes.push(((await response.json()) as { status: string }).status);
                    } catch {
                        /* Tab may close after reading the response. */
                    }
                }
            });
            page.on('request', (request) => {
                if (new URL(request.url()).pathname === publicPath('/api/v1/oidc/approve')) {
                    approved = true;
                }
            });
        });
        const discovery: string[] = [];
        initial.on('request', (request) => {
            if (new URL(request.url()).pathname === publicPath('/api/v1/discovery')) {
                assert.equal(request.method(), 'POST');
                assert.equal(request.postDataJSON()?.slug, 'Work');
                discovery.push(new URL(request.url()).pathname.slice(prefix.length));
            }
        });
        const missing = await initial.goto(`${base}/df`);
        assert(missing && missing.status() === 404);
        assert.equal(
            (await missing.body()).byteLength,
            0,
            'unknown entries are empty server 404s, not an application error screen',
        );
        await initial.goto(`${base}/#Work`);
        if (prefix !== '') {
            // Exercise the real module worker, Go runtime and public WASM
            // under the mount, not only the OIDC document's JavaScript graph.
            assert.equal(
                await initial.evaluate(async () => {
                    const mount = document
                        .querySelector('meta[name="bifroest-path-prefix"]')
                        ?.getAttribute('content');
                    if (!mount) {
                        return false;
                    }
                    const response = await fetch(`${mount}/assets/browser-key.wasm`, {
                        credentials: 'omit',
                        mode: 'same-origin',
                        redirect: 'error',
                    });
                    if (
                        response.status !== 200 ||
                        response.headers.get('Content-Type') !== 'application/wasm'
                    ) {
                        return false;
                    }
                    const wasm = await response.arrayBuffer();
                    const worker = new Worker(`${mount}/assets/browser-key-worker.js`, {
                        type: 'module',
                    });
                    return await new Promise<boolean>((resolve) => {
                        const finish = (ready: boolean) => {
                            clearTimeout(timer);
                            worker.terminate();
                            resolve(ready);
                        };
                        const timer = setTimeout(() => finish(false), 5000);
                        worker.onerror = () => finish(false);
                        worker.onmessage = (event: MessageEvent<unknown>) =>
                            finish(
                                event.data !== null &&
                                    typeof event.data === 'object' &&
                                    'kind' in event.data &&
                                    event.data.kind === 'ready',
                            );
                        worker.postMessage({ kind: 'boot', wasm }, [wasm]);
                    });
                }),
                true,
            );
        }
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
            const resumeStatuses: { action: string; status: number }[] = [];
            initial.on('response', (response) => {
                const path = new URL(response.url()).pathname;
                for (const action of ['resume', 'prove']) {
                    if (path === publicPath(`/api/v1/remember/${action}`)) {
                        resumeStatuses.push({ action, status: response.status() });
                    }
                }
            });
            await dialog.locator('button[type="submit"]').click();
            await initial
                .waitForURL((url) =>
                    /^#route-user@Work\/[1-9A-HJ-NP-Za-km-z]{16,22}$/u.test(url.hash),
                )
                .catch(() => {
                    throw new Error(
                        `Saved resume did not finish: ${JSON.stringify(resumeStatuses)}`,
                    );
                });
        }
        process.stdout.write(
            'PASS: real OIDC redirect, automatic popup, lean assets and final accepted outcome\n',
        );
    }
} finally {
    await browser.close();
}

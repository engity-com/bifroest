import assert from 'node:assert/strict';
import type { Request } from 'playwright';
import type { LoginRequest, Page } from './fixture-types.ts';
import { required } from './required.ts';
import { activeAccess, assertUiPreferences, loginLayout } from './workspace-ui.ts';

export async function exerciseLoginOptions(page: Page) {
    const logins: LoginRequest[] = [];
    let sockets = 0;
    let documents = 0;
    let anonymousRememberRequests = 0;
    page.on('websocket', () => sockets++);
    page.on('request', (request) => {
        if (request.resourceType() === 'document') {
            documents++;
        }
        const url = new URL(request.url());
        if (request.method() === 'POST' && url.pathname.includes('/remember/')) {
            if (JSON.parse(required(request.postData())).slug === 'Public') {
                anonymousRememberRequests++;
            }
        }
        if (
            request.method() === 'POST' &&
            /\/login\/(password|interactive|public-key)$/u.test(url.pathname)
        ) {
            const body = JSON.parse(required(request.postData()));
            logins.push({
                method: url.pathname.split('/').at(-1),
                slug: body.slug,
                user: body.user,
            });
        }
        if (url.pathname === '/api/v1/discovery') {
            assert.equal(request.method(), 'POST');
            assert.equal(request.headers().authorization === undefined, true);
            assert.equal(request.headers().cookie === undefined, true);
            assert.equal(url.search === '', true);
        }
    });
    await page.evaluate(() => {
        window.routeWorkspaceSentinel = 'same-document';
    });
    const dialog = () => page.getByRole('dialog', { name: 'Sign in', exact: true });
    const noPassword = async () =>
        assert.equal(await dialog().getByLabel('Password', { exact: true }).count(), 0);
    async function chooseSlug(slug: string) {
        await dialog().getByLabel('Slug', { exact: true }).click();
        await page.getByRole('option', { name: slug || '/', exact: true }).click();
        await page.waitForURL(
            (url) =>
                url.pathname === '/' &&
                url.search === '' &&
                ((url.hash.slice(1).split('/')[0] ?? '').split('@').at(-1) ===
                    encodeURIComponent(slug) ||
                    (slug === '' && url.hash === '')),
        );
        await page.waitForFunction(
            (slug) =>
                document
                    .querySelector('.login-dialog [data-login-ready="true"]')
                    ?.getAttribute('data-login-scope') === slug,
            slug,
        );
        assert.equal(await page.evaluate(() => window.routeWorkspaceSentinel), 'same-document');
    }
    async function input(text: string) {
        await page
            .locator('[data-connection-active="true"] [data-terminal-phase="connected"]')
            .waitFor();
        await page.locator('[data-terminal-active="true"] textarea').focus();
        await page.keyboard.type(`${text}\n`);
        await page.waitForFunction(
            (text) =>
                document
                    .querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
                    ?.textContent?.includes(`STDIN:${text}`),
            text,
        );
    }

    assert.equal(new URL(page.url()).pathname, '/');
    assert.equal(new URL(page.url()).hash, '#Mixed');
    await dialog().getByLabel('Password', { exact: true }).fill('discard-on-routing');
    await dialog().getByLabel('Login method', { exact: true }).click();
    await page
        .getByRole('option', {
            name: 'Interactive / device login · Without user name',
            exact: true,
        })
        .click();
    assert.equal(await dialog().getByLabel('User name', { exact: true }).count(), 0);
    await noPassword();
    assert.equal(logins.length, 0);

    await chooseSlug('Keys');
    await loginLayout(page, ['SSH key login']);
    assert.equal(await dialog().getByRole('radio').count(), 1);
    await dialog().getByRole('radio', { name: 'SSH key login', exact: true }).waitFor();
    await noPassword();
    assert.equal(
        await dialog()
            .getByRole('radio', { name: 'Interactive / device login', exact: true })
            .count(),
        0,
    );
    await page.locator('#key-private').setInputFiles({
        name: 'local-only.pem',
        mimeType: 'text/plain',
        buffer: Buffer.from('not submitted'),
    });

    await chooseSlug('Certificates');
    assert.equal(
        await page
            .locator('#key-private')
            .evaluate((input: HTMLInputElement) => input.files?.length),
        0,
    );
    assert.equal(
        await dialog()
            .getByLabel('SSH user certificate (required)', { exact: true })
            .getAttribute('required'),
        '',
    );
    await noPassword();

    await chooseSlug('Empty');
    await dialog()
        .getByText('No sign-in method is available for this access link.', { exact: true })
        .waitFor();
    assert.equal(await dialog().locator('form').count(), 0);

    assert.equal(logins.length, 0, 'routing must not attempt authentication');
    assert.equal(sockets, 0, 'routing must not start an execution');
    await page.goBack();
    await page.waitForURL((url) => url.pathname === '/' && url.hash === '#Certificates');
    await dialog().getByLabel('SSH user certificate (required)', { exact: true }).waitFor();
    await page.goForward();
    await page.waitForURL((url) => url.pathname === '/' && url.hash === '#Empty');
    await dialog()
        .getByText('No sign-in method is available for this access link.', { exact: true })
        .waitFor();

    await page.setViewportSize({ width: 390, height: 844 });
    await chooseSlug('Work');
    assert.equal(await dialog().getByRole('radio').count(), 2);
    await dialog().getByLabel('User name', { exact: true }).fill('alice');
    assert.equal(
        await dialog().getByLabel('Password', { exact: true }).inputValue(),
        '',
        'route changes cannot replay previous credentials',
    );
    await dialog().getByLabel('Password', { exact: true }).fill('correct');
    await dialog().getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, 'alice');
    await page.locator('[data-terminal-phase="connected"]').waitFor();
    await input('before-route-change');

    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await chooseSlug('Mixed');
    await dialog().getByLabel('Login method', { exact: true }).click();
    await page
        .getByRole('option', {
            name: 'Interactive / device login · Without user name',
            exact: true,
        })
        .click();
    assert.equal(await dialog().getByLabel('User name', { exact: true }).count(), 0);
    await dialog().getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.evaluate(() => {
        history.back();
    });
    await dialog()
        .getByText('Complete or resolve the current operation before changing the Slug.', {
            exact: true,
        })
        .waitFor();
    assert.equal(
        new URL(page.url()).hash,
        '#Mixed',
        'an in-flight login retains its original route',
    );
    const device = dialog().getByRole('group', { name: 'Device sign-in', exact: true });
    await device.getByText('test-code', { exact: true }).waitFor();
    assert.equal(await page.locator('[data-auth-terminal-active="true"]').count(), 0);
    const popup = page.waitForEvent('popup');
    await device.getByRole('link', { name: 'Open verification page', exact: true }).click();
    const verification = await popup;
    await verification.close();
    await page.bringToFront();
    await activeAccess(page, 'verified-subject');
    // Wait for the login dialog's exit transition before checking for a
    // mistakenly deferred warning modal.
    await dialog().waitFor({ state: 'hidden' });
    assert.deepEqual(
        await page.getByRole('dialog').allTextContents(),
        [],
        'an inline login warning must not turn into another modal after successful authentication',
    );
    assert.deepEqual(logins, [
        { method: 'password', slug: 'Work', user: 'alice' },
        { method: 'interactive', slug: 'Mixed', user: '' },
    ]);
    await page.getByRole('tab', { name: 'Terminal 1 alice', exact: true }).click();
    await activeAccess(page, 'alice');
    assert.equal(new URL(page.url()).pathname, '/');
    assert.equal(
        decodeURIComponent(
            (new URL(page.url()).hash.slice(1).split('/')[0] ?? '').split('@').at(-1) ?? '',
        ),
        'Work',
    );
    await input('still-the-original-execution');
    assert.equal(sockets, 2);

    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await chooseSlug('Public');
    await noPassword();
    assert.equal(await dialog().getByLabel('User name', { exact: true }).count(), 0);
    assert.equal(sockets, 2);
    assert.equal(
        await dialog()
            .getByRole('checkbox', { name: 'Remember this browser', exact: true })
            .count(),
        0,
        'anonymous authorization cannot offer RememberMe',
    );
    await dialog()
        .getByRole('button', { name: 'Continue without credentials', exact: true })
        .click();
    await activeAccess(page, 'anonymous');
    await input('anonymous-execution-started');
    assert.equal(sockets, 3);
    assert.deepEqual(logins[2], { method: 'password', slug: 'Public', user: '' });
    await page.getByRole('tab', { name: 'Terminal 1 alice', exact: true }).click();
    await activeAccess(page, 'alice');
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await chooseSlug('Public');
    assert.equal(await dialog().getByRole('radio', { name: 'Saved', exact: true }).count(), 0);
    assert.equal(
        await dialog().getByRole('button', { name: 'Saved access options', exact: true }).count(),
        0,
    );
    assert.equal(anonymousRememberRequests, 0, 'anonymous login cannot register saved access');
    await dialog().getByRole('button', { name: 'Close', exact: true }).click();
    await activeAccess(page, 'alice');
    await input('anonymous-access-does-not-affect-alice');
    assert.equal(sockets, 3);
    assert.equal(documents, 0, 'Slug navigation must not reload the workspace');
    const view = await page.evaluate(() => history.state?.usr);
    assert.deepEqual(Object.keys(view).sort(), ['generation', 'view']);
    assert.equal(typeof view.generation, 'string');
    assert.equal(view.view, 1);
    assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
    );
    await assertUiPreferences(page);
}

export async function exerciseSlugInput(page: Page) {
    const hidden = 'x7Vq2Ha9Rm4Dz8Kp6Nw3Yt5Bc1Fs0LjE';
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    const slug = dialog.getByRole('combobox', { name: 'Slug', exact: true });
    const requests: { path: string; body: Record<string, string> | null }[] = [];
    page.on('request', (request) => {
        const url = new URL(request.url());
        assert(!url.pathname.includes(hidden));
        assert(!url.search.includes(hidden));
        assert(!url.pathname.includes('notexistent'));
        if (url.pathname.startsWith('/api/')) {
            requests.push({ path: url.pathname, body: request.postDataJSON() });
        }
    });
    await slug.waitFor();
    assert.equal(await slug.inputValue(), 'notexistent');
    assert.equal(await slug.getAttribute('aria-invalid'), 'true');
    await dialog.getByText('Invalid Slug.', { exact: true }).waitFor();
    assert.equal(await dialog.getByRole('alert').count(), 0);
    assert.equal(await dialog.locator('form').count(), 0);
    await slug.click();
    await page.getByRole('option', { name: 'Work', exact: true }).waitFor();
    assert.equal(await page.getByRole('option', { name: hidden, exact: true }).count(), 0);
    await page.keyboard.press('Escape');
    await slug.fill(hidden);
    await slug.press('Enter');
    const user = dialog.getByLabel('User name', { exact: true });
    await user.waitFor();
    assert.equal(new URL(page.url()).hash, `#${hidden}`);
    assert.equal(await slug.getAttribute('aria-invalid'), 'false');
    const reads = requests.length;
    await dialog.getByLabel('Password', { exact: true }).fill('keep-local');
    const history = await page.evaluate(() => window.history.length);
    await user.fill('alice@example.org');
    await page.waitForURL((url) => url.hash === `#alice%40example.org@${hidden}`);
    assert.equal(await dialog.getByLabel('Password', { exact: true }).inputValue(), 'keep-local');
    assert.equal(requests.length, reads, 'username edits never rediscover or authenticate');
    assert.equal(await page.evaluate(() => window.history.length), history);
    await page.reload();
    await user.waitFor();
    assert.equal(await user.inputValue(), 'alice@example.org');
    assert.equal(await dialog.getByLabel('Password', { exact: true }).inputValue(), '');
    await slug.fill('notexistent');
    await slug.press('Enter');
    await dialog.getByText('Invalid Slug.', { exact: true }).waitFor();
    assert.equal(await dialog.getByRole('alert').count(), 0);
    assert.equal(await dialog.locator('form').count(), 0);
    assert(requests.every((request) => request.path === '/api/v1/discovery'));
    assert(requests.some((request) => request.body?.slug === hidden));
}

export async function exerciseRootAccess(page: Page) {
    let authentications = 0;
    page.on('request', (request) => {
        if (
            request.method() === 'POST' &&
            new URL(request.url()).pathname !== '/api/v1/discovery'
        ) {
            authentications++;
        }
    });
    assert.equal(new URL(page.url()).pathname, '/');
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    const select = dialog.getByLabel('Slug', { exact: true });
    assert.equal(await select.inputValue(), '/');
    await select.click();
    await page.getByRole('option', { name: '/', exact: true }).waitFor();
    await page.keyboard.press('Escape');
    await dialog.locator('form').waitFor();
    assert.equal(authentications, 0, 'root discovery never signs in automatically');
}

export async function exerciseRootDirectory(page: Page) {
    let authentications = 0;
    let sockets = 0;
    let documents = 0;
    page.on('request', (request) => {
        if (
            request.method() === 'POST' &&
            new URL(request.url()).pathname !== '/api/v1/discovery'
        ) {
            authentications++;
        }
        if (request.resourceType() === 'document') {
            documents++;
        }
    });
    page.on('websocket', () => sockets++);
    assert.equal(new URL(page.url()).pathname, '/');
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await dialog.getByText('Choose a published Slug to sign in.', { exact: true }).waitFor();
    assert.equal(await dialog.locator('form').count(), 0);
    const select = dialog.getByLabel('Slug', { exact: true });
    assert.equal(await select.inputValue(), '/');
    await select.click();
    assert.equal(await page.getByRole('option', { name: '/', exact: true }).count(), 0);
    await page.getByRole('option', { name: 'Work', exact: true }).click();
    await page.waitForURL((url) => url.pathname === '/' && url.hash === '#Work');
    await dialog.getByLabel('User name', { exact: true }).waitFor();
    await dialog.getByLabel('Password', { exact: true }).waitFor();
    assert.equal(authentications, 0, 'choosing a published link only loads sign-in metadata');
    assert.equal(sockets, 0);
    assert.equal(
        documents,
        0,
        'the root directory uses the same live router, not a document reload',
    );
}

export function observeSingleRootDirectory(page: {
    on(event: 'request', listener: (request: Request) => void): unknown;
    on(event: 'websocket', listener: () => void): unknown;
}) {
    const state = { metadata: [] as string[], posts: 0, documents: 0, sockets: 0 };
    page.on('request', (request) => {
        if (
            request.method() === 'POST' &&
            new URL(request.url()).pathname !== '/api/v1/discovery'
        ) {
            state.posts++;
        }
        if (request.resourceType() === 'document') {
            state.documents++;
        }
        if (request.headers().accept === 'application/json') {
            assert.equal(request.headers().authorization === undefined, true);
            assert.equal(request.headers().cookie === undefined, true);
            assert.equal(new URL(request.url()).search === '', true);
            state.metadata.push(new URL(request.url()).pathname);
        }
    });
    page.on('websocket', () => state.sockets++);
    return state;
}

export async function exerciseSingleRootDirectory(
    page: Page,
    state: ReturnType<typeof observeSingleRootDirectory>,
) {
    await page.waitForURL((url) => url.pathname === '/' && url.hash === '#foo');
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await dialog.getByLabel('User name', { exact: true }).waitFor();
    await dialog.getByLabel('Password', { exact: true }).waitFor();
    assert.equal(await dialog.getByLabel('Slug', { exact: true }).inputValue(), 'foo');
    assert.deepEqual(state.metadata, ['/api/v1/discovery', '/api/v1/discovery']);
    assert.equal(
        state.posts,
        0,
        'choosing the only published access must not authenticate or resume a grant',
    );
    assert.equal(state.sockets, 0);
    assert.equal(state.documents, 1, 'the automatic selection must not reload the document');
    const history = await page.evaluate(() => ({
        initial: window.singleRootInitialHistoryLength,
        current: window.history.length,
        entries: window.singleRootHistoryEvents,
    }));
    assert.equal(
        history.current,
        history.initial,
        'automatic choice replaces, never pushes a root redirect loop',
    );
    assert.deepEqual(
        history.entries.filter((entry) => entry.path === '/#foo').map((entry) => entry.method),
        ['replaceState'],
    );
    await page.reload();
    await dialog.getByLabel('User name', { exact: true }).waitFor();
    assert.equal(new URL(page.url()).pathname, '/');
    assert.equal(new URL(page.url()).hash, '#foo');
    assert.equal(await dialog.getByLabel('Slug', { exact: true }).inputValue(), 'foo');
    assert.deepEqual(state.metadata, [
        '/api/v1/discovery',
        '/api/v1/discovery',
        '/api/v1/discovery',
    ]);
    assert.equal(state.posts, 0);
    assert.equal(state.sockets, 0);
    assert.equal(state.documents, 2);
}

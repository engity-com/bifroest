import assert from 'node:assert/strict';
import {
  activeAccess,
  answerAuthentication,
  assertUiPreferences,
  loginLayout,
  notification,
} from './workspace-ui.mjs';

export async function exerciseLoginOptions(page) {
  const logins = [];
  let sockets = 0;
  let documents = 0;
  page.on('websocket', () => sockets++);
  page.on('request', (request) => {
    if (request.resourceType() === 'document') {
      documents++;
    }
    const url = new URL(request.url());
    if (
      request.method() === 'POST' &&
      /\/login\/(password|interactive|public-key)$/u.test(url.pathname)
    ) {
      const body = JSON.parse(request.postData());
      logins.push({ method: url.pathname.split('/').at(-1), slug: body.slug, user: body.user });
    }
    if (request.method() === 'GET' && request.headers().accept === 'application/json') {
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
  async function chooseSlug(slug) {
    await dialog().getByLabel('Slug', { exact: true }).click();
    await page.getByRole('option', { name: slug || '/', exact: true }).click();
    await page.waitForURL(
      (url) =>
        url.pathname === '/' &&
        url.search === '' &&
        (url.hash === `#${encodeURIComponent(slug)}` || (slug === '' && url.hash === '')),
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
  async function input(text) {
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
    .getByRole('option', { name: 'Interactive / device login · Without user name', exact: true })
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
    await dialog().getByRole('radio', { name: 'Interactive / device login', exact: true }).count(),
    0,
  );
  await page.locator('#key-private').setInputFiles({
    name: 'local-only.pem',
    mimeType: 'text/plain',
    buffer: Buffer.from('not submitted'),
  });

  await chooseSlug('Certificates');
  assert.equal(await page.locator('#key-private').evaluate((input) => input.files.length), 0);
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
    .getByRole('option', { name: 'Interactive / device login · Without user name', exact: true })
    .click();
  assert.equal(await dialog().getByLabel('User name', { exact: true }).count(), 0);
  await dialog().getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.evaluate(() => {
    history.back();
  });
  await notification(page, 'Complete or resolve the current operation before changing the Slug.');
  assert.equal(new URL(page.url()).hash, '#Mixed', 'an in-flight login retains its original route');
  await answerAuthentication(page, '', { kind: 'info', text: 'test-code' });
  await activeAccess(page, 'verified-subject');
  assert.deepEqual(logins, [
    { method: 'password', slug: 'Work', user: 'alice' },
    { method: 'interactive', slug: 'Mixed', user: '' },
  ]);
  await page.getByRole('tab', { name: 'Terminal 1 alice', exact: true }).click();
  await activeAccess(page, 'alice');
  assert.equal(new URL(page.url()).pathname, '/');
  assert.equal(decodeURIComponent(new URL(page.url()).hash.slice(1).split('/')[0]), 'Work');
  await input('still-the-original-execution');
  assert.equal(sockets, 2);

  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await chooseSlug('Public');
  await noPassword();
  assert.equal(await dialog().getByLabel('User name', { exact: true }).count(), 0);
  assert.equal(sockets, 2);
  await dialog().getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  await dialog().getByRole('button', { name: 'Continue without credentials', exact: true }).click();
  await activeAccess(page, 'anonymous');
  await input('anonymous-execution-started');
  assert.equal(sockets, 3);
  assert.deepEqual(logins[2], { method: 'password', slug: 'Public', user: '' });
  await page.getByRole('tab', { name: 'Terminal 1 alice', exact: true }).click();
  await activeAccess(page, 'alice');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await chooseSlug('Public');
  await dialog().getByRole('button', { name: 'Saved access options', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Forget saved browser access', exact: true }).click();
  const revoke = page.getByRole('dialog', { name: 'Revoke saved browser access?', exact: true });
  await revoke.getByText(`${new URL(page.url()).origin}/Public`, { exact: true }).waitFor();
  await revoke.getByRole('button', { name: 'Revoke browser permission', exact: true }).click();
  await dialog().getByText('Browser permission revoked.', { exact: true }).waitFor();
  await dialog().getByRole('button', { name: 'Close', exact: true }).click();
  await activeAccess(page, 'alice');
  await input('another-slug-revocation-does-not-affect-alice');
  assert.equal(sockets, 3);
  assert.equal(documents, 0, 'Slug navigation must not reload the workspace');
  const view = await page.evaluate(() => history.state?.usr);
  assert.deepEqual(Object.keys(view).sort(), ['generation', 'view']);
  assert.equal(typeof view.generation, 'string');
  assert.equal(view.view, 1);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await assertUiPreferences(page);
}

export async function exerciseRootAccess(page) {
  let authentications = 0;
  page.on('request', (request) => {
    if (request.method() === 'POST') {
      authentications++;
    }
  });
  assert.equal(new URL(page.url()).pathname, '/');
  const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
  const select = dialog.getByLabel('Slug', { exact: true });
  assert.equal(await select.textContent(), '/');
  await select.click();
  await page.getByRole('option', { name: '/', exact: true }).waitFor();
  await page.keyboard.press('Escape');
  await dialog.locator('form').waitFor();
  assert.equal(authentications, 0, 'root discovery never signs in automatically');
}

export async function exerciseRootDirectory(page) {
  let authentications = 0;
  let sockets = 0;
  let documents = 0;
  page.on('request', (request) => {
    if (request.method() === 'POST') {
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
  assert.equal((await select.textContent()).replaceAll('\u200b', ''), '');
  await select.click();
  assert.equal(await page.getByRole('option', { name: '/', exact: true }).count(), 0);
  await page.getByRole('option', { name: 'Work', exact: true }).click();
  await page.waitForURL((url) => url.pathname === '/' && url.hash === '#Work');
  await dialog.getByLabel('User name', { exact: true }).waitFor();
  await dialog.getByLabel('Password', { exact: true }).waitFor();
  assert.equal(authentications, 0, 'choosing a published link only loads sign-in metadata');
  assert.equal(sockets, 0);
  assert.equal(documents, 0, 'the root directory uses the same live router, not a document reload');
}

export function observeSingleRootDirectory(page) {
  const state = { metadata: [], posts: 0, documents: 0, sockets: 0 };
  page.on('request', (request) => {
    if (request.method() === 'POST') {
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

export async function exerciseSingleRootDirectory(page, state) {
  await page.waitForURL((url) => url.pathname === '/' && url.hash === '#foo');
  const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
  await dialog.getByLabel('User name', { exact: true }).waitFor();
  await dialog.getByLabel('Password', { exact: true }).waitFor();
  assert.equal(await dialog.getByLabel('Slug', { exact: true }).count(), 0);
  assert.deepEqual(state.metadata, ['/', '/foo']);
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
  assert.equal(await dialog.getByLabel('Slug', { exact: true }).count(), 0);
  assert.deepEqual(state.metadata, ['/', '/foo', '/foo']);
  assert.equal(state.posts, 0);
  assert.equal(state.sockets, 0);
  assert.equal(state.documents, 2);
}

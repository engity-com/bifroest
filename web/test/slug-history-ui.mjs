import assert from 'node:assert/strict';
import { activeAccess, assertUiPreferences, duplicateTab } from './workspace-ui.mjs';

// Real Go UI mode: the holding Work fixture must also accept /bla-bla as an
// included (unpublished) alias of that same flow. Never intercept discovery/auth.
export async function exerciseSlugHistory(page, login) {
  await page.evaluate(() => {
    window.slugHistoryEvents = [];
    for (const method of ['pushState', 'replaceState']) {
      const original = history[method].bind(history);
      history[method] = (state, unused, url) => {
        original(state, unused, url);
        window.slugHistoryEvents.push({
          method,
          path: location.pathname + location.hash,
          view: state?.usr?.view ?? null,
        });
      };
    }
    addEventListener('popstate', () =>
      window.slugHistoryEvents.push({
        method: 'pop',
        path: location.pathname + location.hash,
        view: history.state?.usr?.view ?? null,
      }),
    );
  });
  const requests = [];
  let sockets = 0;
  let documents = 0;
  page.on('websocket', () => sockets++);
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (request.resourceType() === 'document') {
      documents++;
    }
    if (request.method() === 'POST' || request.headers().accept === 'application/json') {
      requests.push({ path, method: request.method() });
    }
  });
  const dialog = () => page.getByRole('dialog', { name: 'Sign in', exact: true });
  const tab = (id, user) => page.getByRole('tab', { name: `Terminal ${id} ${user}`, exact: true });
  async function selected(id, slug) {
    try {
      await page.waitForURL(
        (url) =>
          url.pathname === '/' &&
          url.search === '' &&
          new RegExp(`^#${encodeURIComponent(slug)}/[1-9A-HJ-NP-Za-km-z]{16,22}$`, 'u').test(
            url.hash,
          ),
      );
    } catch (error) {
      throw new Error(
        JSON.stringify(
          await page.evaluate(() => ({
            path: location.pathname + location.hash,
            events: window.slugHistoryEvents,
          })),
        ),
        { cause: error },
      );
    }
    await page.locator(`#terminal-pane-${id}[data-connection-active="true"]`).waitFor();
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
  await page.waitForURL((url) => url.pathname === '/' && url.hash === '#bla-bla');
  await login(page, false);
  await selected(1, 'bla-bla');
  await input('original-alias-execution');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await dialog().getByLabel('Slug', { exact: true }).click();
  await page.getByRole('option', { name: 'Work', exact: true }).click();
  await page.waitForFunction(
    () =>
      document
        .querySelector('.login-dialog [data-login-ready="true"]')
        ?.getAttribute('data-login-scope') === 'Work',
  );
  await login(page, false, 'bob');
  await selected(2, 'Work');
  const workHash = new URL(page.url()).hash;
  await input('published-slug-execution');
  const beforeSwitch = requests.length;
  const beforeSwitchHistory = await page.evaluate(() => history.length);
  await tab(1, 'alice').click();
  await selected(1, 'bla-bla');
  const aliasHash = new URL(page.url()).hash;
  await input('alias-survives-tab-switch');
  assert.equal(
    await page.evaluate(() => history.length),
    beforeSwitchHistory + 1,
    'a pointer activation must create exactly one history entry, not one for focus and another for click',
  );
  await page.goBack();
  await selected(2, 'Work');
  await page.goForward();
  await selected(1, 'bla-bla');
  assert.equal(
    requests.length,
    beforeSwitch,
    'tab/POP navigation has no discovery/auth/resume requests',
  );
  assert.equal(sockets, 2, 'existing executions are never reconnected by routing');
  // Exercise actual native hashchange/POP entries, not only router-generated
  // history. Browsers need not attach a distinct React Router state key.
  await page.evaluate((hash) => {
    location.hash = hash;
  }, workHash);
  await selected(2, 'Work');
  await page.evaluate((hash) => {
    location.hash = hash;
  }, aliasHash);
  await selected(1, 'bla-bla');
  assert.equal(requests.length, beforeSwitch);
  assert.equal(sockets, 2);
  assert.equal(documents, 0);
  await duplicateTab(page);
  await selected(3, 'bla-bla');
  await input('duplicate-keeps-entry-alias');
  await page.goBack();
  await selected(1, 'bla-bla');
  await page.goForward();
  await selected(3, 'bla-bla');
  assert.equal(requests.length, beforeSwitch);
  assert.equal(sockets, 3);
  const state = await page.evaluate(() => history.state.usr);
  assert.deepEqual(Object.keys(state).sort(), ['generation', 'view']);
  assert.equal(typeof state.generation, 'string');
  assert.equal(state.view, 3);
  await tab(1, 'alice').click();
  await selected(1, 'bla-bla');
  const beforeCloseHistory = await page.evaluate(() => history.length);
  await tab(3, 'alice').getByRole('button', { name: 'Close terminal 3', exact: true }).click();
  const closing = page.getByRole('dialog', { name: 'Close this terminal?', exact: true });
  await closing.waitFor();
  assert.equal(
    await page.evaluate(() => history.state.usr.view),
    1,
    'opening a background-tab close dialog must not activate that tab through focus',
  );
  assert.equal(await page.evaluate(() => history.length), beforeCloseHistory);
  await closing.getByRole('button', { name: 'Close terminal', exact: true }).click();
  await tab(3, 'alice').waitFor({ state: 'detached' });
  await page.goBack();
  await dialog().waitFor();
  assert.equal(new URL(page.url()).pathname, '/');
  assert.equal(new URL(page.url()).hash, '#bla-bla/-');
  assert.equal(sockets, 3, 'a closed history view becomes a login, never a restored execution');
  await dialog().getByRole('button', { name: 'Close', exact: true }).click();
  await activeAccess(page, 'alice');
  await selected(1, 'bla-bla');
  await input('still-the-initial-alias-execution');
  assert.equal(documents, 0);
  const authRequests = () => requests.filter((request) => request.method === 'POST').length;
  const beforeReload = authRequests();
  await page.reload();
  await dialog().getByLabel('User name', { exact: true }).waitFor();
  assert.equal(new URL(page.url()).pathname, '/');
  assert.equal(new URL(page.url()).hash, '#bla-bla/-');
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(
    authRequests(),
    beforeReload,
    'reload does not resume or reattach even with old history state',
  );
  assert.equal(sockets, 3);
  assert.equal(documents, 1);
  await assertUiPreferences(page);
}

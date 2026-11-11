import assert from 'node:assert/strict';
import { managementWire } from './management-wire.mjs';
import { expectTerminalExit, observeTerminalResults } from './terminal-results.mjs';
import {
  answerAuthentication,
  assertUiPreferences,
  captureLayout,
  chooseLoginMethod,
  duplicateTab,
  exactArtifactSelection,
  logoutAccess,
  settledLogin,
  terminalAction,
  workspace,
} from './workspace-ui.mjs';

export async function exerciseConnections(page, login) {
  const wire = managementWire(page);
  const terminals = observeTerminalResults(page);
  const documentOrigin = new URL(page.url()).origin;
  let documentReloads = 0;
  page.on('request', (request) => {
    if (request.resourceType() === 'document') {
      documentReloads++;
    }
  });
  const requests = [];
  const managementReads = [];
  let resumes = 0;
  let sockets = 0;
  let managementSockets = 0;
  page.on('websocket', (socket) => {
    if (new URL(socket.url()).pathname.endsWith('/management/channel')) {
      managementSockets++;
    } else {
      sockets++;
    }
  });
  wire.on('request', (request) => {
    const body = JSON.parse(request.postData());
    managementReads.push({
      path: new URL(request.url()).pathname.split('/management/')[1],
      slug: request.slug(),
      long: body.long,
    });
  });
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (path.endsWith('/remember/resume')) {
      resumes++;
    }
    if (request.method() === 'POST' && /\/login\/(?:password|interactive)$/u.test(path)) {
      const body = JSON.parse(request.postData());
      requests.push({ slug: body.slug, user: body.user, method: path.split('/').at(-1) });
    }
  });
  const tab = (id, user, kind = 'Terminal') =>
    page.getByRole('tab', { name: `${kind} ${id} ${user}`, exact: true });
  const active = (text) =>
    page.waitForFunction(
      (text) =>
        document
          .querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
          ?.textContent?.includes(text),
      text,
    );
  const auditlogInput = () =>
    page
      .getByRole('dialog', { name: 'Open by ID', exact: true })
      .getByRole('textbox', { name: /^Recording ID/u });
  const select = async (id, user, kind) => {
    await tab(id, user, kind).click();
    // The same principal can own several flows/views. Selection is controlled
    // by the committed route, not the preceding access snapshot or metadata.
    await page.waitForFunction(
      ({ id, user }) => {
        const pane = document.getElementById(`terminal-pane-${id}`);
        return (
          document.getElementById(`terminal-tab-${id}`)?.getAttribute('aria-selected') === 'true' &&
          pane?.getAttribute('data-connection-active') === 'true' &&
          pane.getAttribute('data-connection-principal') === user &&
          location.pathname === '/' &&
          location.search === '' &&
          decodeURIComponent(location.hash.slice(1).split('/')[0]) ===
            pane.getAttribute('data-connection-scope') &&
          history.state?.usr?.view === id
        );
      },
      { id, user },
    );
  };
  async function newConnection(slug) {
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await dialog.getByLabel('Slug', { exact: true }).click();
    const metadata = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === `/${slug}` &&
        response.request().headers().accept === 'application/json',
    );
    await page.getByRole('option', { name: slug, exact: true }).click();
    const response = await metadata;
    assert.equal(response.request().headers().authorization, undefined);
    assert.equal(response.request().headers().cookie, undefined);
    await page.waitForFunction(
      (slug) =>
        document
          .querySelector('.login-dialog [data-login-ready="true"]')
          ?.getAttribute('data-login-scope') === slug &&
        document.querySelector('.login-dialog [role="combobox"]')?.textContent === slug,
      slug,
    );
    assert.equal(
      page.url(),
      `${documentOrigin}/#${encodeURIComponent(slug)}`,
      'the selected Slug must be reflected in the URL',
    );
    assert.equal(documentReloads, 0, 'Slug routing must preserve the live document');
  }
  await login(page, false);
  await active('EXECUTION_START:1');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
  await chooseLoginMethod(page, 'Interactive / device login');
  await dialog.getByLabel('User name', { exact: true }).fill('bob');
  await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
  await answerAuthentication(page, 'correct', { kind: 'prompt', echo: false });
  await settledLogin(page, 'bob', true);
  await active('EXECUTION_START:2');
  await select(1, 'alice');
  await duplicateTab(page);
  await active('EXECUTION_START:3');
  assert.equal(
    await tab(3, 'alice').getAttribute('aria-selected'),
    'true',
    'another terminal must use the active Alice access, not the last Bob login',
  );
  await newConnection('Other');
  await chooseLoginMethod(page, 'Password login');
  await login(page, false, 'bob');
  await active('EXECUTION_START:4');
  await duplicateTab(page);
  await active('EXECUTION_START:5');
  await terminalAction(page, 'Request INT signal');
  await active('SIGNAL:INT');
  await newConnection('Manage');
  const initialVersion = wire.waitForResponse((response) =>
    response.url().endsWith('/management/version/show'),
  );
  const initialFlows = wire.waitForResponse((response) =>
    response.url().endsWith('/management/flows/list'),
  );
  await login(page, false);
  const manager = tab(6, 'alice', 'Management');
  const managerPanel = page.getByRole('tabpanel', { name: 'Management 6 alice', exact: true });
  await manager.waitFor();
  assert.equal(
    await page
      .getByRole('tablist', { name: 'Connections and terminals', exact: true })
      .getByRole('tab')
      .count(),
    6,
  );
  assert.equal(
    sockets,
    5,
    'management login does not open a terminal or reconnect existing shells',
  );
  assert.equal((await initialFlows).status(), 200);
  assert.equal(
    managementSockets,
    1,
    'management gets only its own admitted channel, not a terminal',
  );
  await managerPanel
    .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  await workspace(page, 'Sessions');
  await managerPanel.getByRole('grid', { name: 'Live session metadata', exact: true }).waitFor();
  const fullVersion = wire.waitForResponse(
    (response) =>
      response.url().endsWith('/management/version/show') &&
      JSON.parse(response.request().postData()).long === 'true',
  );
  await workspace(page, 'Version');
  assert.equal((await initialVersion).status(), 200);
  assert.equal((await fullVersion).status(), 200);
  const version = managerPanel.getByRole('region', { name: 'Server version', exact: true });
  await version.waitFor();
  assert(
    (await manager.textContent()).includes('Version'),
    'management labels follow the selected primary page',
  );
  await version.getByRole('region', { name: 'Build information', exact: true }).waitFor();
  assert.deepEqual(
    managementReads,
    [
      { path: 'flows/list', slug: 'Manage', long: undefined },
      { path: 'sessions/list', slug: 'Manage', long: undefined },
      { path: 'version/show', slug: 'Manage', long: 'false' },
      { path: 'version/show', slug: 'Manage', long: 'true' },
    ],
    'Overview and Version read only their own metadata on the admitted grant',
  );
  const refresh = wire.waitForResponse((response) =>
    response.url().endsWith('/management/version/show'),
  );
  await managerPanel.getByRole('button', { name: 'Refresh server version', exact: true }).click();
  assert.equal((await refresh).status(), 200);
  await version.getByRole('region', { name: 'Build information', exact: true }).waitFor();
  assert.equal(managementReads.length, 5);
  assert.deepEqual(
    managementReads[4],
    { path: 'version/show', slug: 'Manage', long: 'true' },
    'only the explicit refresh rereads the structured build version',
  );
  const retainedVersion = await version.elementHandle();
  await select(1, 'alice');
  await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
  await page.keyboard.type('still-owned-by-alice');
  await page.keyboard.press('Enter');
  await active('STDIN:still-owned-by-alice');
  const applicationTitle = await page.title();
  await page.keyboard.type('title-live');
  await page.keyboard.press('Enter');
  await active('TITLE_REPORTED');
  await tab(1, 'alice').getByText('mc [alice@fixture]', { exact: true }).waitFor();
  assert.equal(
    await page.title(),
    applicationTitle,
    'a live shell title changes only its own connection tab',
  );
  await select(6, 'alice', 'Management');
  assert.equal(
    await version.count(),
    1,
    'reactivating the same management view must retain its loaded server version',
  );
  await version.waitFor();
  assert.equal(
    await retainedVersion.evaluate((node) => node.isConnected),
    true,
    'selecting a terminal must not remount the management result',
  );
  assert.equal(
    managementReads.length,
    5,
    'returning to an initialized management view must not reread',
  );
  await exactArtifactSelection(page);
  await captureLayout(page, 'connections-artifact-selection');
  await auditlogInput().fill('00000000-0000-4000-8000-000000000077');
  await select(4, 'bob');
  const closedHint = page
    .locator('.MuiTooltip-popper')
    .filter({ hasText: 'bob · Other · Terminal 4 · connected' });
  await tab(4, 'bob').locator('span.MuiBox-root').first().hover();
  await closedHint.waitFor({ state: 'visible' });
  await page.mouse.move(5, 700);
  await page
    .locator('.MuiTooltip-popperClose')
    .filter({ hasText: 'bob · Other · Terminal 4 · connected' })
    .waitFor({ state: 'attached' });
  assert.equal(
    await closedHint.isVisible(),
    false,
    'a closed tooltip must not leave a layout box during its exit transition',
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await captureLayout(page, 'connections-tooltip-exit-mobile');
  await page.waitForFunction(() => {
    const tab = document.querySelector(
      '[aria-label="Connections and terminals"] [role="tab"][aria-selected="true"]',
    );
    const list = document.querySelector('.terminal-tab-list');
    if (!tab || !list) {
      return false;
    }
    const a = tab.getBoundingClientRect();
    const b = list.getBoundingClientRect();
    return (
      a.left >= b.left - 1 &&
      a.right <= b.right + 1 &&
      document.documentElement.scrollWidth <= innerWidth
    );
  });
  await captureLayout(page, 'connections-mobile');
  await page.setViewportSize({ width: 1280, height: 800 });
  await select(6, 'alice', 'Management');
  await exactArtifactSelection(page);
  assert.equal(
    await auditlogInput().inputValue(),
    '00000000-0000-4000-8000-000000000077',
    'switching tabs must retain this access-owned artifact workflow',
  );
  const restoredRecordings = managerPanel.getByRole('grid', {
    name: 'Recordings · default',
    exact: true,
  });
  const restoredStarted = restoredRecordings.getByRole('columnheader', { name: /^Started/u });
  await restoredStarted.waitFor();
  await page.waitForFunction(
    (node) => node.getBoundingClientRect().width >= 190,
    await restoredStarted.elementHandle(),
  );
  const restoredBounds = await restoredStarted.boundingBox();
  assert(
    restoredBounds && restoredBounds.width >= 190,
    'restoring an owned hidden grid must restore its actual metadata column geometry',
  );
  await captureLayout(page, 'connections-management');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await chooseLoginMethod(page, 'Password login');
  await dialog.getByLabel('User name', { exact: true }).fill('bob');
  await dialog.getByLabel('Password', { exact: true }).fill('wrong');
  await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dialog.getByText('Access was denied.', { exact: false }).waitFor();
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  await exactArtifactSelection(page);
  assert.equal(
    await auditlogInput().inputValue(),
    '00000000-0000-4000-8000-000000000077',
    'a rejected additional login must not retire another management context',
  );
  await logoutAccess(page);
  await manager.waitFor({ state: 'detached' });
  assert.equal(
    await page
      .getByRole('tablist', { name: 'Connections and terminals', exact: true })
      .getByRole('tab')
      .count(),
    5,
    'management logout must leave all unrelated terminal grants and tabs intact',
  );
  await logoutAccess(page);
  await tab(5, 'bob').waitFor({ state: 'detached' });
  assert.equal(
    await page
      .getByRole('tablist', { name: 'Connections and terminals', exact: true })
      .getByRole('tab')
      .count(),
    3,
    'logout removes both Other views sharing that access, not Work/bob or Work/alice',
  );
  await select(2, 'bob');
  await logoutAccess(page);
  await tab(2, 'bob').waitFor({ state: 'detached' });
  assert.equal(
    await page
      .getByRole('tablist', { name: 'Connections and terminals', exact: true })
      .getByRole('tab')
      .count(),
    2,
  );
  await select(1, 'alice');
  await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
  await page.keyboard.type('alive-after-unrelated-logouts');
  await page.keyboard.press('Enter');
  await active('STDIN:alive-after-unrelated-logouts');
  await logoutAccess(page);
  await page.locator('[data-connection-active="true"]').waitFor({ state: 'detached' });
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(new URL(page.url()).origin, documentOrigin);
  assert.equal(documentReloads, 0);
  assert.equal(sockets, 5);
  assert.equal(managementSockets, 1);
  assert.deepEqual(
    requests.filter((r) => r.user === 'bob' && r.method === 'interactive'),
    [{ slug: 'Work', user: 'bob', method: 'interactive' }],
  );
  assert(requests.some((r) => r.slug === 'Other' && r.user === 'bob'));
  assert(requests.some((r) => r.slug === 'Manage' && r.user === 'alice'));
  assert.deepEqual(
    requests,
    [
      { slug: 'Work', user: 'alice', method: 'password' },
      { slug: 'Work', user: 'bob', method: 'interactive' },
      { slug: 'Other', user: 'bob', method: 'password' },
      { slug: 'Manage', user: 'alice', method: 'password' },
      { slug: 'Manage', user: 'bob', method: 'password' },
    ],
    'metadata reads, tab activation and refresh cannot authenticate or execute again',
  );
  assert.equal(resumes, 0);
  // A deliberately new, successful execution after all targeted logouts must
  // close its last tab without resurrecting any retired grant or execution.
  await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor();
  await login(page, false, 'alice');
  await active('EXECUTION_START:6');
  const pane = page.locator('[data-terminal-active="true"]');
  const paneId = await pane.getAttribute('id');
  const result = terminals.latest();
  await pane.locator('.xterm-helper-textarea').focus();
  await page.keyboard.type('exit-zero');
  await page.keyboard.press('Enter');
  await expectTerminalExit(page, result, 0, paneId);
  await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor();
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(sockets, 6);
  assert.equal(managementSockets, 1);
  assert.equal(requests.length, 6);
  assert.deepEqual(requests.at(-1), { slug: 'Work', user: 'alice', method: 'password' });
  assert.equal(resumes, 0);
  await assertUiPreferences(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

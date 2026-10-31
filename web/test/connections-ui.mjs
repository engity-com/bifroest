import assert from 'node:assert/strict';
import {
  activeAccess,
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
  const documentURL = page.url();
  const requests = [];
  let sockets = 0;
  page.on('websocket', () => sockets++);
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
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
          .querySelector('[data-terminal-active="true"] .xterm-rows')
          ?.textContent?.includes(text),
      text,
    );
  const auditlogInput = () =>
    page
      .locator('[role="tabpanel"]:not([hidden])')
      .getByRole('textbox', { name: /^Artifact auditlog/u });
  const select = async (id, user, kind) => {
    await tab(id, user, kind).click();
    await activeAccess(page, user);
  };
  async function newConnection(slug) {
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await dialog.getByLabel('Access link / flow', { exact: true }).click();
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
      (slug) => document.querySelector('.login-dialog [role="combobox"]')?.textContent === slug,
      slug,
    );
    assert.equal(page.url(), documentURL, 'selecting a flow must not navigate/reload the document');
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
  await login(page, false);
  const manager = tab(6, 'alice', 'Management');
  await manager.waitFor();
  assert.equal(await page.getByRole('tab').count(), 6);
  assert.equal(
    sockets,
    5,
    'management login does not open a terminal or reconnect existing shells',
  );
  await workspace(page, 'Server');
  await page.getByRole('button', { name: 'Load server version', exact: true }).click();
  const version = page.getByRole('region', { name: 'Server version', exact: true });
  await version.waitFor();
  await select(1, 'alice');
  await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
  await page.keyboard.type('still-owned-by-alice');
  await page.keyboard.press('Enter');
  await active('STDIN:still-owned-by-alice');
  await select(6, 'alice', 'Management');
  await version.waitFor();
  await exactArtifactSelection(page);
  await captureLayout(page, 'connections-artifact-selection');
  await auditlogInput().fill('local-review-selection');
  await select(4, 'bob');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => {
    const tab = document.querySelector('[role="tab"][aria-selected="true"]');
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
  assert.equal(
    await auditlogInput().inputValue(),
    'local-review-selection',
    'switching tabs must retain this access-owned artifact workflow',
  );
  await captureLayout(page, 'connections-management');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await chooseLoginMethod(page, 'Password login');
  await dialog.getByLabel('User name', { exact: true }).fill('bob');
  await dialog.getByLabel('Password', { exact: true }).fill('wrong');
  await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dialog.getByText('Access was denied.', { exact: false }).waitFor();
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  assert.equal(
    await auditlogInput().inputValue(),
    'local-review-selection',
    'a rejected additional login must not retire another management context',
  );
  await logoutAccess(page);
  await manager.waitFor({ state: 'detached' });
  assert.equal(
    await page.getByRole('tab').count(),
    5,
    'management logout must leave all unrelated terminal grants and tabs intact',
  );
  await logoutAccess(page);
  await tab(5, 'bob').waitFor({ state: 'detached' });
  assert.equal(
    await page.getByRole('tab').count(),
    3,
    'logout removes both Other views sharing that access, not Work/bob or Work/alice',
  );
  await select(2, 'bob');
  await logoutAccess(page);
  await tab(2, 'bob').waitFor({ state: 'detached' });
  assert.equal(await page.getByRole('tab').count(), 2);
  await select(1, 'alice');
  await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
  await page.keyboard.type('alive-after-unrelated-logouts');
  await page.keyboard.press('Enter');
  await active('STDIN:alive-after-unrelated-logouts');
  await logoutAccess(page);
  await page.locator('[data-connection-active="true"]').waitFor({ state: 'detached' });
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(page.url(), documentURL);
  assert.equal(sockets, 5);
  assert.deepEqual(
    requests.filter((r) => r.user === 'bob' && r.method === 'interactive'),
    [{ slug: 'Work', user: 'bob', method: 'interactive' }],
  );
  assert(requests.some((r) => r.slug === 'Other' && r.user === 'bob'));
  assert(requests.some((r) => r.slug === 'Manage' && r.user === 'alice'));
  await assertUiPreferences(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

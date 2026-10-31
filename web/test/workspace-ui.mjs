import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

// Storage is allowed only for the explicitly requested, non-auth UI prefs.
// Reject any token/password/selector payload rather than dropping the old
// no-local-login assertion just because username/theme persistence was added.
export async function assertUiPreferences(page, usernames = ['alice', 'bob', 'e2e']) {
  const state = await page.evaluate(() => ({
    session: sessionStorage.length,
    values: Object.fromEntries(
      Object.keys(localStorage).map((key) => [key, localStorage.getItem(key)]),
    ),
  }));
  assert.equal(state.session, 0, 'sessionStorage must not retain login data');
  for (const [key, value] of Object.entries(state.values)) {
    if (key === 'bifroest-ui-v1:theme') {
      assert(['auto', 'light', 'dark'].includes(value));
    } else {
      assert(
        key.startsWith('bifroest-ui-v1:username:'),
        'only UI preference keys may be persisted',
      );
      const slug = decodeURIComponent(key.slice('bifroest-ui-v1:username:'.length));
      assert(/^(?:[A-Za-z0-9]{1,64}(?:\/[A-Za-z0-9]{1,64})?)?$/u.test(slug));
      assert(
        usernames.includes(value),
        'only original fixture usernames, never credentials/principals/tokens, may be persisted',
      );
    }
  }
}

export async function settledLogin(page, user, holding = false) {
  await page.waitForFunction(
    (user) =>
      document
        .querySelector('[data-connection-active="true"]')
        ?.getAttribute('data-connection-principal') === user ||
      document.querySelector('.access-notice')?.getAttribute('data-access-principal') === user,
    user,
  );
  await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden' });
  await page
    .getByRole('dialog', { name: 'Authentication step', exact: true })
    .waitFor({ state: 'hidden' });
  if (!holding && (await page.locator('[data-terminal-active="true"]').count())) {
    await page.locator('[data-terminal-phase="exited"]').waitFor();
  }
}

export async function activeAccess(page, user) {
  await page.waitForFunction(
    (user) =>
      document
        .querySelector('[data-connection-active="true"]')
        ?.getAttribute('data-connection-principal') === user,
    user,
  );
}

export async function activeAccessCount(page, user) {
  return page.evaluate(
    (user) =>
      [...document.querySelectorAll('[data-connection-active="true"]')].filter(
        (node) => node.getAttribute('data-connection-principal') === user,
      ).length,
    user,
  );
}

export async function chooseLoginMethod(page, name) {
  const input = page.getByRole('radio', { name, exact: true });
  await input.click();
  assert.equal(await input.isChecked(), true);
}

export async function assertAccessActionsBlocked(page) {
  assert.equal(
    await page
      .getByRole('button', { name: 'New connection', exact: true, includeHidden: true })
      .isEnabled(),
    false,
  );
  assert.equal(
    await page
      .getByRole('button', { name: 'Connection options', exact: true, includeHidden: true })
      .isEnabled(),
    false,
  );
  for (const tab of await page
    .getByRole('tablist', { includeHidden: true })
    .getByRole('tab', { includeHidden: true })
    .all()) {
    assert.equal(await tab.isEnabled(), false);
  }
  await page
    .getByRole('tablist', { includeHidden: true })
    .getByRole('tab', { selected: true, includeHidden: true })
    .dispatchEvent('contextmenu');
  assert.equal(await page.getByRole('menuitem', { name: 'Log out', exact: true }).count(), 0);
  assert.equal(await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).count(), 0);
}

export async function tabMenu(page) {
  await page
    .getByRole('tablist', { name: 'Connections and terminals', exact: true })
    .getByRole('tab', { selected: true })
    .click({ button: 'right' });
}

export async function duplicateTab(page) {
  await tabMenu(page);
  await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).click();
}

export async function terminalAction(page, name) {
  await tabMenu(page);
  await page.getByRole('menuitem', { name, exact: true }).click();
}

export async function authenticationConsole(page, { text, kind, echo } = {}) {
  const console = page.locator(
    '[data-auth-terminal-active="true"] .authentication-surface[data-auth-ready="true"]',
  );
  await console.waitFor();
  if (text !== undefined) {
    await page.waitForFunction(
      (text) =>
        document
          .querySelector('[data-auth-terminal-active="true"] .xterm-rows')
          ?.textContent?.includes(text),
      text,
    );
  }
  if (kind !== undefined) {
    assert.equal(await console.getAttribute('data-auth-kind'), kind);
  }
  if (echo !== undefined) {
    assert.equal(await console.getAttribute('data-auth-echo'), String(echo));
  }
  assert.equal(
    await page.getByRole('dialog', { name: 'Authentication step', exact: true }).count(),
    0,
  );
  return console;
}

export async function answerAuthentication(page, answer = '', options = {}) {
  const console = await authenticationConsole(page, options);
  await console.locator('textarea').focus();
  if (answer) {
    await page.keyboard.type(answer);
  }
  await page.keyboard.press('Enter');
}

export async function logoutAccess(page) {
  const recovery = page.getByRole('dialog', { name: 'Notification details', exact: true });
  if (await recovery.getByRole('button', { name: 'Log out', exact: true }).count()) {
    await recovery.getByRole('button', { name: 'Log out', exact: true }).click();
  } else {
    await tabMenu(page);
    await page.getByRole('menuitem', { name: 'Log out', exact: true }).click();
  }
}

export async function notification(page, text) {
  const dialog = page.getByRole('dialog', { name: 'Notification details', exact: true });
  if (!(await dialog.isVisible())) {
    await page.getByRole('button', { name: 'Notification details', exact: true }).click();
  }
  await dialog.getByText(text, { exact: false }).waitFor();
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
}

export async function reauthenticate(page) {
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
}

export async function changeTheme(page, name) {
  const login = page.getByRole('dialog', { name: 'Sign in', exact: true });
  const reopen = await login.isVisible();
  if (reopen) {
    await login.getByRole('button', { name: 'Close', exact: true }).click();
    await login.waitFor({ state: 'hidden' });
  }
  const notice = page.getByRole('dialog', { name: 'Notification details', exact: true });
  if (await notice.isVisible()) {
    await notice.getByRole('button', { name: 'Close', exact: true }).click();
    await notice.waitFor({ state: 'hidden' });
  }
  try {
    await page.getByRole('button', { name: 'Application menu', exact: true }).click();
  } catch (error) {
    const dialogs = await page.locator('[role="dialog"]').evaluateAll((nodes) =>
      nodes.map((node) => ({
        title: document.getElementById(node.getAttribute('aria-labelledby'))?.textContent,
        visible: node.getBoundingClientRect().height > 0,
        hidden: node.closest('[aria-hidden="true"]') !== null,
      })),
    );
    throw new Error(
      JSON.stringify({
        stage: 'appearance-owner',
        dialogs,
        rootHidden: await page.locator('#root').getAttribute('aria-hidden'),
      }),
      { cause: error },
    );
  }
  await page.getByRole('menuitem', { name: 'Appearance', exact: true }).click();
  const account = page.getByRole('dialog', { name: 'Appearance', exact: true });
  await account.getByText(name, { exact: true }).click();
  await account.getByRole('button', { name: 'Close', exact: true }).click();
  await account.waitFor({ state: 'hidden' });
  if (reopen) {
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
  }
}

export async function captureLayout(page, name) {
  const dimensions = await page.evaluate(() => ({
    width: innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  assert(
    dimensions.content <= dimensions.width,
    `${name}: page overflows (${dimensions.content}/${dimensions.width})`,
  );
  const directory = process.env.BIFROEST_TEST_UI_REVIEW_DIRECTORY;
  if (directory) {
    const scroll = await page.evaluate(() => ({ x: scrollX, y: scrollY }));
    await mkdir(directory, { recursive: true });
    await page.screenshot({
      path: join(directory, `${name}.png`),
      fullPage: true,
      animations: 'disabled',
    });
    if (
      name === 'sessions-initial' ||
      name === 'terminal-desktop' ||
      name.endsWith('-verification')
    ) {
      await changeTheme(page, 'Dark');
      await page.locator('html[data-color-scheme="dark"]').waitFor();
      await page.screenshot({
        path: join(directory, `${name}-dark.png`),
        fullPage: true,
        animations: 'disabled',
      });
      await changeTheme(page, 'Auto');
    }
    await page.evaluate(({ x, y }) => window.scrollTo(x, y), scroll);
  }
}

export async function loginLayout(page) {
  const viewport = page.viewportSize();
  for (const width of [1280, 390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    for (const name of ['Password login', 'Interactive / device login', 'SSH key login']) {
      const label = await page
        .getByRole('radio', { name, exact: true })
        .locator('..')
        .boundingBox();
      assert(
        label && label.x >= 0 && label.x + label.width <= width,
        `${name} must remain visible at ${width}px`,
      );
    }
    await captureLayout(page, `login-${width}`);
  }
  const keyMethod = page.getByRole('radio', { name: 'SSH key login', exact: true });
  await chooseLoginMethod(page, 'SSH key login');
  await page.getByLabel('Private key file (local only)', { exact: true }).waitFor();
  await captureLayout(page, 'login-key-320');
  await keyMethod.press('ArrowLeft');
  assert.equal(
    await page.getByRole('radio', { name: 'Interactive / device login', exact: true }).isChecked(),
    true,
    'login methods must also be reachable with the keyboard',
  );
  await chooseLoginMethod(page, 'Password login');
  await page.setViewportSize(viewport);
}

export async function sessionLayout(page, id) {
  const viewport = page.viewportSize();
  await captureLayout(page, 'sessions-desktop');
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    const cards = page.getByRole('region', { name: 'Live session metadata', exact: true });
    await cards.getByText(id, { exact: true }).waitFor();
    await cards
      .locator('article')
      .filter({ hasText: id })
      .getByRole('button', { name: `Session details ${id}`, exact: true })
      .click();
    await page.getByRole('region', { name: 'Session details', exact: true }).waitFor();
    assert.equal(
      await page.getByRole('table', { name: 'Live session metadata', exact: true }).count(),
      0,
      'mobile sessions must use cards, not a clipped table',
    );
    await captureLayout(page, `sessions-${width}`);
  }
  await page.setViewportSize(viewport);
}

export async function workspace(page, name) {
  const button = page
    .getByRole('navigation', { name: 'Workspace', exact: true })
    .getByRole('button', { name, exact: true });
  await button.click();
  assert.equal(await button.getAttribute('aria-current'), 'page');
}

export async function exactArtifactSelection(page) {
  await workspace(page, 'Recordings & audit');
  const selection = page.locator('[role="tabpanel"]:not([hidden]) .artifact-selection');
  if (!(await selection.evaluate((node) => node.open))) {
    await selection.locator(':scope > summary').click();
  }
  const summary = selection.getByText('Enter an exact auditlog / recording ID', { exact: true });
  if (!(await summary.locator('..').evaluate((node) => node.open))) {
    await summary.click();
  }
}

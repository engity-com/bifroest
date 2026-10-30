import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

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
  await input.locator('..').locator('label').click();
  assert.equal(await input.isChecked(), true);
}

export async function assertAccessActionsBlocked(page) {
  assert.equal(
    await page.getByRole('button', { name: 'New connection', exact: true }).isEnabled(),
    false,
  );
  assert.equal(
    await page.getByRole('button', { name: 'Connection options', exact: true }).isEnabled(),
    false,
  );
  for (const tab of await page.getByRole('tablist').getByRole('tab').all()) {
    assert.equal(await tab.isEnabled(), false);
  }
  await page
    .getByRole('tablist')
    .getByRole('tab', { selected: true })
    .locator('..')
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
  await page.getByRole('menuitem', { name: 'Special commands', exact: true }).hover();
  await page.getByRole('menuitem', { name, exact: true }).click();
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
  await page.getByRole('button', { name: 'Application menu', exact: true }).click();
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
      await page.locator('html[data-mantine-color-scheme="dark"]').waitFor();
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

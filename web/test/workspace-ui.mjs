import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

export async function settledLogin(page, user, holding = false) {
  await page.getByRole('heading', { name: `Signed in as ${user}`, exact: true }).waitFor();
  await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden' });
  if (await page.getByRole('button', { name: 'New terminal', exact: true }).count()) {
    await page.waitForFunction(
      () =>
        document.querySelector('[data-terminal-active="true"]') !== null ||
        document.body.textContent.includes(
          'RememberMe setup may have created a server permission.',
        ),
    );
    if (!holding && (await page.locator('[data-terminal-active="true"]').count())) {
      await page.locator('[data-terminal-phase="exited"]').waitFor();
    }
  }
}

export async function reauthenticate(page) {
  await page.getByRole('button', { name: 'Account', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Account', exact: true })
    .getByRole('button', { name: 'Sign in again', exact: true })
    .click();
}

export async function changeTheme(page, name) {
  const login = page.getByRole('dialog', { name: 'Sign in', exact: true });
  if (await login.count()) {
    await login.getByText(name, { exact: true }).click();
    return;
  }
  await page.getByRole('button', { name: 'Appearance', exact: true }).click();
  const account = page.getByRole('dialog', { name: 'Account', exact: true });
  await account.getByText(name, { exact: true }).click();
  await account.getByRole('button', { name: 'Close', exact: true }).click();
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
      const label = await page.getByText(name, { exact: true }).boundingBox();
      assert(
        label && label.x >= 0 && label.x + label.width <= width,
        `${name} must remain visible at ${width}px`,
      );
    }
    await captureLayout(page, `login-${width}`);
  }
  const keyMethod = page.getByRole('radio', { name: 'SSH key login', exact: true });
  await keyMethod.check();
  await page.getByLabel('Private key file (local only)', { exact: true }).waitFor();
  await captureLayout(page, 'login-key-320');
  await keyMethod.press('ArrowLeft');
  assert.equal(
    await page.getByRole('radio', { name: 'Interactive / device login', exact: true }).isChecked(),
    true,
    'login methods must also be reachable with the keyboard',
  );
  await page.getByRole('radio', { name: 'Password login', exact: true }).check();
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
  const selection = page.locator('.artifact-selection');
  if (!(await selection.evaluate((node) => node.open))) {
    await selection.locator(':scope > summary').click();
  }
  const summary = page.getByText('Enter an exact auditlog / recording ID', { exact: true });
  if (!(await summary.locator('..').evaluate((node) => node.open))) {
    await summary.click();
  }
}

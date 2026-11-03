import assert from 'node:assert/strict';
import { assertUiPreferences, duplicateTab, tabMenu } from './workspace-ui.mjs';

export async function exerciseTerminalTabs(page, login, logout) {
  let sockets = 0;
  page.on('websocket', () => {
    sockets++;
  });
  let entered;
  const held = new Promise((resolve) => {
    entered = resolve;
  });
  await page.route('**/xterm-*.js', async (route) => {
    entered(route);
  });
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByLabel('Password', { exact: true }).fill('correct');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const route = await held;
  await page.getByRole('tab', { name: 'Terminal 1 alice', exact: true }).waitFor();
  const canceledID = 1;
  await logout(page);
  const delivered = page.waitForResponse((response) => response.url() === route.request().url());
  await route.continue();
  await (await delivered).finished();
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    sockets,
    0,
    'a canceled renderer initialization cannot dispatch its old authorization later',
  );
  assert.equal(await page.locator('.xterm').count(), 0);
  await page.unroute('**/xterm-*.js');
  await login(page, false);
  const firstID = Number(
    (await page.getByRole('tab', { selected: true }).getAttribute('id')).slice(
      'terminal-tab-'.length,
    ),
  );
  assert.equal(firstID, canceledID + 1, 'retired history view IDs must never be reused');
  const selected = async (id) =>
    page.waitForFunction((id) => {
      const panel = document.getElementById(`terminal-pane-${id}`);
      return (
        history.state?.usr?.view === id &&
        document.getElementById(`terminal-tab-${id}`)?.getAttribute('aria-selected') === 'true' &&
        panel?.getAttribute('data-terminal-active') === 'true' &&
        panel.querySelector('[data-terminal-phase="exited"]') !== null
      );
    }, id);
  await selected(firstID);
  assert.equal(sockets, 1);
  for (let number = 2; number <= 8; number++) {
    const id = firstID + number - 1;
    await duplicateTab(page);
    await page.getByRole('tab', { name: `Terminal ${id} alice`, exact: true }).waitFor();
    await selected(id);
  }
  assert.equal(sockets, 8, 'each deliberate new tab owns exactly one new shell');
  await tabMenu(page);
  assert.equal(
    await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).isEnabled(),
    false,
    'local tab resources are bounded independently of server quotas',
  );
  await page.keyboard.press('Escape');
  const first = page.getByRole('tab', { name: `Terminal ${firstID} alice`, exact: true });
  await page
    .getByRole('tab', { name: `Terminal ${firstID + 7} alice`, exact: true })
    .evaluate((node) => {
      node.focus();
      node.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Home', bubbles: true, cancelable: true }),
      );
    });
  await selected(firstID);
  // Activate while returning keyboard focus to the bar in the same event turn.
  // A queued terminal-focus frame must respect that newer focus owner.
  await first.evaluate((node) => {
    node.click();
    node.focus();
  });
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    await first.evaluate((node) => node === document.activeElement),
    true,
    'a queued pane activation cannot steal newer tab-bar focus',
  );
  await first.focus();
  await first.press('ArrowRight');
  await selected(firstID + 1);
  assert.equal(
    await page
      .getByRole('tab', { name: `Terminal ${firstID + 1} alice`, exact: true })
      .getAttribute('aria-selected'),
    'true',
  );
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    await page
      .getByRole('tab', { name: `Terminal ${firstID + 1} alice`, exact: true })
      .evaluate((node) => node === document.activeElement),
    true,
    'tab keyboard navigation keeps focus in the bar',
  );
  assert.equal(sockets, 8, 'keyboard navigation cannot reconnect a tab');
  await page.getByRole('button', { name: `Close terminal ${firstID}`, exact: true }).click();
  await duplicateTab(page);
  await page.getByRole('tab', { name: `Terminal ${firstID + 8} alice`, exact: true }).waitFor();
  await selected(firstID + 8);
  assert.equal(sockets, 9);
  await logout(page);
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

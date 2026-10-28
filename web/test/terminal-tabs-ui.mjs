import assert from 'node:assert/strict';

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
  assert.equal(sockets, 1);
  for (let number = 2; number <= 8; number++) {
    await page.getByRole('button', { name: 'New terminal', exact: true }).click();
    await page.getByRole('tab', { name: `Terminal ${number} alice`, exact: true }).waitFor();
    await page.locator('[data-terminal-phase="exited"]').waitFor();
  }
  assert.equal(sockets, 8, 'each deliberate new tab owns exactly one new shell');
  assert.equal(
    await page.getByRole('button', { name: 'New terminal', exact: true }).isEnabled(),
    false,
    'local tab resources are bounded independently of server quotas',
  );
  const first = page.getByRole('tab', { name: 'Terminal 1 alice', exact: true });
  await page.getByRole('tab', { name: 'Terminal 8 alice', exact: true }).evaluate((node) => {
    node.focus();
    node.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Home', bubbles: true, cancelable: true }),
    );
  });
  await page.waitForFunction(
    () => document.getElementById('terminal-tab-1')?.getAttribute('aria-selected') === 'true',
  );
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
  await page.waitForFunction(
    () => document.getElementById('terminal-tab-2')?.getAttribute('aria-selected') === 'true',
  );
  assert.equal(
    await page
      .getByRole('tab', { name: 'Terminal 2 alice', exact: true })
      .getAttribute('aria-selected'),
    'true',
  );
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    await page
      .getByRole('tab', { name: 'Terminal 2 alice', exact: true })
      .evaluate((node) => node === document.activeElement),
    true,
    'tab keyboard navigation keeps focus in the bar',
  );
  assert.equal(sockets, 8, 'keyboard navigation cannot reconnect a tab');
  await page.getByRole('button', { name: 'Close terminal 1', exact: true }).click();
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await page.getByRole('tab', { name: 'Terminal 9 alice', exact: true }).waitFor();
  await page.locator('[data-terminal-phase="exited"]').waitFor();
  assert.equal(sockets, 9);
  await logout(page);
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

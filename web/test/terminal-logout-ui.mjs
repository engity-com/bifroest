import assert from 'node:assert/strict';

export async function exerciseLostTerminalLogout(page, login) {
  let sockets = 0;
  let logouts = 0;
  page.on('websocket', () => {
    sockets++;
  });
  page.on('request', (request) => {
    if (request.url().endsWith('/api/v1/logout')) {
      logouts++;
    }
  });
  await login(page, false);
  await page.waitForFunction(() =>
    document
      .querySelector('[data-terminal-active="true"] .xterm-rows')
      ?.textContent?.includes('EXECUTION_START:1'),
  );
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  const notice = page.getByRole('dialog', { name: 'Notification details', exact: true });
  await notice.getByText('Logout could not be confirmed.', { exact: false }).waitFor();
  await page
    .getByRole('heading', { name: 'Local access blocked for alice', exact: true })
    .waitFor();
  await page.locator('[data-terminal-phase="interrupted"]').waitFor();
  assert.equal(logouts, 1);
  assert.equal(sockets, 1);
  assert.equal(await page.getByText('Logout confirmed.', { exact: true }).count(), 0);
  await notice.getByRole('button', { name: 'Close', exact: true }).click();
  assert.equal(
    await page.getByRole('button', { name: 'New terminal', exact: true }).isEnabled(),
    false,
  );
  await page.getByRole('button', { name: 'Account', exact: true }).click();
  const account = page.getByRole('dialog', { name: 'Account', exact: true });
  assert.equal(
    await account.getByRole('button', { name: 'Sign in again', exact: true }).isEnabled(),
    false,
  );
  await account.getByRole('button', { name: 'Close', exact: true }).click();
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(logouts, 1, 'a lost logout response must not be replayed automatically');
  const denied = page.waitForResponse(
    (response) => response.url().endsWith('/api/v1/logout') && response.status() === 401,
  );
  await page.getByRole('button', { name: 'Retry logout', exact: true }).click();
  await denied;
  await notice.getByText('Logout could not be confirmed.', { exact: false }).waitFor();
  assert.equal(logouts, 2, 'only the explicit retry may dispatch another logout request');
  assert.equal(sockets, 1, 'a pruned regular grant cannot become a new permission or shell');
  assert.equal(
    await page.getByText('Logout confirmed.', { exact: true }).count(),
    0,
    'denial is not proof of server revocation',
  );
  assert.equal(
    await page.locator('[data-terminal-phase="exited"]').count(),
    0,
    'socket loss must not infer a successful process exit',
  );
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

import assert from 'node:assert/strict';
import { captureLayout } from './workspace-ui.mjs';

export async function exerciseTerminalExpiry(page, login, logout) {
  let sockets = 0;
  page.on('websocket', () => {
    sockets++;
  });
  const pane = () => page.locator('[data-terminal-active="true"]');
  const output = async (text) =>
    page.waitForFunction(
      (text) =>
        document
          .querySelector('[data-terminal-active="true"] .xterm-rows')
          ?.textContent?.includes(text),
      text,
      { timeout: 5000 },
    );
  const type = async (text) => {
    await pane().locator('.xterm-helper-textarea').focus();
    await page.keyboard.type(text);
    await page.keyboard.press('Enter');
    await output(`STDIN:${text}`);
  };
  await login(page, false);
  await output('EXECUTION_START:1');
  const expiry = await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/expire-current-access', {
      method: 'POST',
      credentials: 'omit',
      mode: 'same-origin',
    });
    if (!response.ok) {
      throw new Error('server grant expiry fixture failed');
    }
    return response.json();
  });
  assert(Number.isSafeInteger(expiry.advanceTo));
  // Date advances for the UI, not its socket/renderer timers or Go's wall clock.
  // The server-side permission has independently been expired above.
  await page.clock.setFixedTime(new Date(expiry.advanceTo));
  await type('old-shell-after-grant-expiry');
  assert.equal(sockets, 1, 'grant expiry does not reconnect an existing execution');
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  const signIn = page.getByRole('dialog', { name: 'Sign in', exact: true });
  await signIn.waitFor();
  assert.equal(sockets, 1, 'an expired grant must request authentication before another socket');
  await captureLayout(page, 'terminal-expiry-sign-in');
  await signIn.getByRole('button', { name: 'Close', exact: true }).click();
  await signIn.waitFor({ state: 'hidden' });
  await type('old-shell-after-expired-dialog-cancel');
  assert.equal(await page.getByRole('tab').count(), 1);
  assert.equal(sockets, 1);
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await signIn.waitFor();
  await page.clock.setFixedTime(new Date());
  await login(page, false);
  await output('EXECUTION_START:2');
  assert.equal(sockets, 2, 'a fresh confirmed login opens exactly one new shell');
  await page.getByRole('tab', { name: 'Terminal 1 alice', exact: true }).click();
  await type('old-shell-after-fresh-login');
  await logout(page);
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

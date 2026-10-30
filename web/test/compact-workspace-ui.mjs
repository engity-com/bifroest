import assert from 'node:assert/strict';
import {
  captureLayout,
  changeTheme,
  logoutAccess,
  notification,
  settledLogin,
  tabMenu,
  terminalAction,
} from './workspace-ui.mjs';

export async function exerciseCompactWorkspace(page) {
  let primaries = 0;
  let logouts = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/api/v1/login/password')) {
      primaries++;
    }
    if (request.url().endsWith('/api/v1/logout')) {
      logouts++;
    }
  });
  const viewport = page.viewportSize();
  const signIn = page.getByRole('dialog', { name: 'Sign in', exact: true });
  const pane = () => page.locator('[data-terminal-active="true"]');
  const output = (text) =>
    page.waitForFunction(
      (text) =>
        document
          .querySelector('[data-terminal-active="true"] .xterm-rows')
          ?.textContent?.includes(text),
      text,
    );
  async function type(text) {
    await pane().locator('.xterm-helper-textarea').focus();
    await page.keyboard.type(text);
    await page.keyboard.press('Enter');
  }
  async function password(remember = false) {
    await signIn.getByLabel('User name', { exact: true }).fill('alice');
    await signIn.getByLabel('Password', { exact: true }).fill('correct');
    if (remember) {
      await signIn.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
    }
    await signIn.getByRole('button', { name: 'Sign in', exact: true }).click();
    await settledLogin(page, 'alice', true);
  }
  async function compact(name) {
    await signIn.waitFor();
    const box = await signIn.boundingBox();
    assert(
      box && box.height < 580,
      'normal sign-in must fit in a compact dialog, not a page-length form',
    );
    assert.equal(
      await signIn.getByText('About this browser interface', { exact: true }).count(),
      0,
    );
    assert.equal(await signIn.getByRole('link').count(), 0);
    assert.equal(await signIn.getByText('Auto', { exact: true }).count(), 0);
    assert.equal(
      await signIn.getByText('This opens a new tab after sign-in.', { exact: false }).count(),
      0,
    );
    await captureLayout(page, name);
  }
  await compact('compact-login-light');
  await changeTheme(page, 'Dark');
  await compact('compact-login-dark');
  await page.setViewportSize({ width: 390, height: 844 });
  await compact('compact-login-mobile');
  await page.setViewportSize(viewport);
  await password();
  await output('EXECUTION_START:1');
  assert.equal(
    await page.locator('.application-brand,.application-status,.application-account').count(),
    0,
  );
  assert.equal(await page.getByText('Signed in as', { exact: false }).count(), 0);
  await type('mouse-on');
  await output('MOUSE_TRACKING_ON');
  await page.evaluate(() => {
    window.terminalContextEvents = [];
    document.addEventListener('contextmenu', (event) => {
      if (event.target.closest('.terminal-surface')) {
        window.terminalContextEvents.push(event.defaultPrevented);
      }
    });
  });
  await pane()
    .locator('.xterm-screen')
    .click({ button: 'right', position: { x: 40, y: 120 } });
  await page.keyboard.press('Enter');
  await output('RIGHT_BUTTON_EVENTS:2');
  assert.deepEqual(
    await page.evaluate(() => window.terminalContextEvents),
    [true],
    'cancel the browser menu without swallowing terminal right-button reporting',
  );
  assert.equal(await page.getByRole('menu').count(), 0);
  await tabMenu(page);
  await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).waitFor();
  await captureLayout(page, 'compact-tab-context-menu');
  await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).click();
  await output('EXECUTION_START:2');
  assert.equal(primaries, 1);
  await page.getByRole('button', { name: 'Connection options', exact: true }).click();
  await page.getByRole('menuitem', { name: /^Work · alice/u }).waitFor();
  await captureLayout(page, 'compact-plus-menu');
  await page.getByRole('menuitem', { name: /^Work · alice/u }).click();
  await output('EXECUTION_START:3');
  assert.equal(primaries, 1, 'the signed-in flow choice reuses only that selected access');
  await page
    .getByRole('button', { name: 'New connection', exact: true })
    .click({ button: 'right' });
  await page.getByRole('menuitem', { name: /^Work · alice/u }).waitFor();
  await page.keyboard.press('Escape');
  const selected = page.getByRole('tab', { selected: true });
  await selected.focus();
  await selected.press('Shift+F10');
  await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).waitFor();
  await page.keyboard.press('Escape');
  const bounds = await selected.boundingBox();
  const session = await page.context().newCDPSession(page);
  await session.send('Input.dispatchTouchEvent', {
    type: 'touchStart',
    touchPoints: [{ x: bounds.x + 20, y: bounds.y + 15 }],
  });
  await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).waitFor();
  await session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
  await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).waitFor();
  await page.keyboard.press('Escape');
  await session.detach();
  await terminalAction(page, 'Request INT signal');
  await output('SIGNAL:INT');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await compact('compact-new-login');
  assert.equal(await page.getByRole('tab').count(), 3);
  assert.equal(primaries, 1, 'plus itself must not reuse a grant or start another primary request');
  await password(true);
  await output('EXECUTION_START:4');
  await notification(page, 'RememberMe setup confirmed');
  assert.equal(primaries, 2);
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await signIn.getByRole('button', { name: 'Use saved access', exact: true }).waitFor();
  await compact('compact-saved-login');
  await signIn.getByRole('button', { name: 'Close', exact: true }).click();
  await signIn.waitFor({ state: 'hidden' });
  await logoutAccess(page);
  await page
    .getByRole('tab', { name: 'Terminal 4 alice', exact: true })
    .waitFor({ state: 'detached' });
  assert.equal(await page.getByRole('tab').count(), 3);
  assert.equal(logouts, 1);
  for (const number of [3, 2, 1]) {
    const tab = page.getByRole('tab', { name: `Terminal ${number} alice`, exact: true });
    await tab.click({ button: 'right' });
    await page.getByRole('menuitem', { name: 'Close', exact: true }).click();
    const close = page.getByRole('dialog', { name: 'Close this terminal?', exact: true });
    await close.getByRole('button', { name: 'Close terminal', exact: true }).click();
    await close.waitFor({ state: 'hidden' });
    await tab.waitFor({ state: 'detached' });
  }
  assert.equal(await page.getByRole('dialog').count(), 0);
  assert.equal(
    logouts,
    1,
    'closing all local tabs is not an implicit server logout or workload disposal',
  );
  await page.getByRole('button', { name: 'Connection options', exact: true }).click();
  assert.equal(await page.getByRole('menuitem', { name: /^Work · alice/u }).count(), 0);
  await page.keyboard.press('Escape');
  await captureLayout(page, 'compact-empty-window');
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { settledLogin } from './workspace-ui.mjs';

const frames = (page) =>
  page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
const terminal = (page, number, user) =>
  page.getByRole('tab', { name: `Terminal ${number} ${user}`, exact: true });
const activeOutput = (page, text) =>
  page.waitForFunction(
    (text) =>
      document
        .querySelector('[data-terminal-active="true"] .xterm-rows')
        ?.textContent?.includes(text),
    text,
  );

async function submitPassword(page, user, remember = false) {
  const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
  await dialog.getByLabel('User name', { exact: true }).fill(user);
  await dialog.getByLabel('Password', { exact: true }).fill('correct');
  if (remember) {
    await dialog.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  }
  await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
}

export async function exerciseConnectionRaces(page) {
  let sockets = 0;
  page.on('websocket', () => sockets++);
  await submitPassword(page, 'alice');
  await settledLogin(page, 'alice', true);
  await activeOutput(page, 'EXECUTION_START:1');
  let reached;
  const connected = new Promise((resolve) => {
    reached = resolve;
  });
  let held = false;
  await page.routeWebSocket('**/api/v1/terminal', (socket) => {
    const server = socket.connectToServer();
    if (held) {
      return;
    }
    held = true;
    let received = '';
    server.onMessage((message) => {
      // Delay this one real connection's ready/output only. Never record or
      // replace its opening bearer, and never replay it as another connection.
      received = (
        received + (typeof message === 'string' ? message : new TextDecoder().decode(message))
      ).slice(-8192);
      if (received.includes('EXECUTION_START:2')) {
        reached();
      }
    });
  });
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await submitPassword(page, 'bob');
  await terminal(page, 2, 'bob').waitFor();
  await connected;
  let release;
  const holding = new Promise((resolve) => {
    release = resolve;
  });
  let entered;
  const entering = new Promise((resolve) => {
    entered = resolve;
  });
  await page.route('**/Other', async (route) => {
    entered();
    await holding;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        scope: { origin: new URL(page.url()).origin, slug: 'Wrong' },
        requestUser: true,
      }),
    });
  });
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  const signIn = page.getByRole('dialog', { name: 'Sign in', exact: true });
  await signIn.getByLabel('Access link / flow', { exact: true }).click();
  await page.getByRole('option', { name: 'Other', exact: true }).click();
  await entering;
  await terminal(page, 2, 'bob').waitFor({ state: 'detached' });
  await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
  release();
  await signIn.getByText('The operation could not be confirmed.', { exact: false }).waitFor();
  await signIn.getByRole('button', { name: 'Close', exact: true }).click();
  await page.unroute('**/Other');
  assert.equal(await terminal(page, 1, 'alice').getAttribute('aria-selected'), 'true');
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await activeOutput(page, 'EXECUTION_START:3');
  assert.equal(await terminal(page, 3, 'alice').getAttribute('aria-selected'), 'true');
  await page.getByRole('button', { name: 'Terminal actions', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Request INT signal', exact: true }).click();
  await activeOutput(page, 'SIGNAL:INT');
  await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/interrupt-enrollment', {
      method: 'POST',
      credentials: 'omit',
    });
    if (response.status !== 204) {
      throw new Error('controlled enrollment fault was not armed');
    }
  });
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await submitPassword(page, 'bob', true);
  const notice = page.getByRole('dialog', { name: 'Notification details', exact: true });
  await notice
    .getByText('RememberMe setup may have created a server permission.', { exact: false })
    .waitFor();
  await notice.getByRole('button', { name: 'Close', exact: true }).click();
  assert.equal(sockets, 3);
  assert.equal(await page.getByRole('tab').count(), 2);
  assert.equal(
    await page.getByRole('button', { name: 'New connection', exact: true }).isEnabled(),
    false,
  );
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
  await frames(page);
  assert.equal(
    sockets,
    3,
    'logging out an unadmitted uncertain Bob candidate must not start another Alice execution',
  );
  assert.equal(await page.getByRole('tab').count(), 2);
  await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
  await page.keyboard.type('original-alice-still-running');
  await page.keyboard.press('Enter');
  await activeOutput(page, 'STDIN:original-alice-still-running');
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await signIn.waitFor();
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

export async function exerciseManagementOwner(page, fixture, login, logout, closeProbe = false) {
  const target = JSON.parse(readFileSync(fixture, 'utf8'));
  let commits = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/management/sessions/confirm')) {
      commits++;
    }
  });
  await login(page, false);
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await login(page, false, 'bob');
  await page.getByRole('button', { name: 'Load sessions', exact: true }).click();
  await page.getByRole('table', { name: 'Live session metadata', exact: true }).waitFor();
  const alice = page.getByRole('tab', { name: 'Management 1 alice', exact: true });
  const bob = page.getByRole('tab', { name: 'Management 2 bob', exact: true });
  const alicePanel = page.getByRole('tabpanel', { name: 'Management 1 alice', exact: true });
  await alice.click();
  await alicePanel.getByText('Action on a known session', { exact: true }).click();
  await page.getByRole('textbox', { name: /^Target flow/u }).fill(target.flow);
  await page.getByRole('textbox', { name: /^Target session ID/u }).fill(target.id);
  await page.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/preparation-entered', { credentials: 'omit' });
    if (response.status !== 204) {
      throw new Error('controlled preparation did not enter its barrier');
    }
  });
  if (closeProbe) {
    await page.getByRole('button', { name: 'Close management view 1', exact: true }).click();
    await page.getByRole('dialog', { name: 'Close this management view?', exact: true }).waitFor();
  } else {
    await bob.click();
  }
  await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/preparation-release', {
      method: 'POST',
      credentials: 'omit',
    });
    if (response.status !== 204) {
      throw new Error('controlled preparation did not leave its barrier');
    }
  });
  await frames(page);
  if (closeProbe) {
    const closing = page.getByRole('dialog', { name: 'Close this management view?', exact: true });
    assert.equal(
      await page.getByRole('dialog').count(),
      1,
      'late preparation must not overlay the older close dialog',
    );
    assert.equal(
      await page.getByRole('button', { name: 'Confirm session action', exact: true }).count(),
      0,
    );
    await closing.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
  } else {
    assert.equal(
      await page.getByRole('dialog').count(),
      0,
      'a late Alice preparation cannot open a portal over Bob',
    );
    await page.getByRole('heading', { name: 'Signed in as bob', exact: true }).waitFor();
  }
  assert.equal(commits, 0);
  await alice.click();
  assert.equal(
    await page.getByRole('dialog').count(),
    0,
    'the unused hidden confirmation is retired, not resurrected',
  );
  await page.getByRole('combobox', { name: 'Session action', exact: true }).click();
  await page.getByRole('option', { name: 'dispose', exact: true }).click();
  await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/interrupt-management-confirm', {
      method: 'POST',
      credentials: 'omit',
    });
    if (response.status !== 204) {
      throw new Error('controlled management fault was not armed');
    }
  });
  await page.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByText('Work · alice', { exact: true }).waitFor();
  await dialog
    .getByLabel('Type the exact flow/session ID shown above', { exact: true })
    .fill(`${target.flow}/${target.id}`);
  await dialog.getByRole('button', { name: 'Confirm session action', exact: true }).click();
  await page.getByText('The session action result is unknown.', { exact: false }).waitFor();
  assert.equal(await alice.getAttribute('aria-selected'), 'true');
  assert.equal(await bob.isEnabled(), false);
  assert.equal(
    await page.getByRole('button', { name: 'Close management view 1', exact: true }).isEnabled(),
    false,
  );
  assert.equal(
    await page.getByRole('dialog', { name: 'Close this management view?', exact: true }).count(),
    0,
    'no earlier close intent may survive into an unknown result',
  );
  assert.equal(
    await page.getByRole('button', { name: 'New connection', exact: true }).isEnabled(),
    false,
  );
  await page
    .getByRole('button', { name: 'Dismiss local warning (does not confirm result)', exact: true })
    .click();
  assert.equal(commits, 1);
  await logout(page);
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

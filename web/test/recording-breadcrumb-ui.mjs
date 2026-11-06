import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { managementWire } from './management-wire.mjs';
import { captureLayout, logoutAccess, notification, settledLogin } from './workspace-ui.mjs';

const origin = process.argv[2];
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
const browser = await chromium.launch({
  headless: true,
  args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addInitScript(() => {
    window.cspViolations = [];
    window.addEventListener('securitypolicyviolation', (event) =>
      window.cspViolations.push(event.violatedDirective),
    );
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.name));
  let terminalSockets = 0;
  page.on('websocket', (socket) => {
    if (new URL(socket.url()).pathname.endsWith('/terminal')) {
      terminalSockets++;
    }
  });
  const calls = [];
  managementWire(page).on('request', (request) => calls.push(new URL(request.url()).pathname));
  await page.goto(`${origin}/_bifroest/test/client.html`);
  const entry = await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/artifact-id', { credentials: 'omit' });
    if (response.status !== 200) {
      throw new Error('Fixture entry unavailable');
    }
    return response.json();
  });
  assert.match(entry.managementFlow, /^[A-Za-z0-9.-]+$/u);
  assert.match(entry.flow, /^[A-Za-z0-9.-]+$/u);
  assert.match(entry.id, /^[0-9a-f-]{36}$/u);
  const prefix = `/Work/${entry.managementFlow}/recordings/${entry.flow}`;
  assert.equal((await page.goto(origin + prefix)).status(), 200);
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByLabel('Password', { exact: true }).fill('correct');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await settledLogin(page, 'alice');
  const panel = page
    .locator('[data-connection-active="true"]')
    .getByRole('region', { name: 'Recordings', exact: true });
  const grid = panel.getByRole('grid', { name: 'Recordings · default', exact: true });
  const open = grid.getByRole('button', { name: `Open recording ${entry.id}`, exact: true });
  await open.waitFor();
  assert.equal(new URL(page.url()).search, '');
  assert.equal(calls.filter((path) => path.endsWith('/recordings/list')).length, 1);
  const retained = await grid.elementHandle();
  await open.click();
  const playback = panel.getByRole('region', { name: 'Recording playback', exact: true });
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  await playback.getByRole('button', { name: 'Play', exact: true }).click();
  await playback.locator('[data-playback-phase="ended"]').waitFor();
  assert(
    (await playback.locator('.xterm-accessibility-tree').textContent()).includes('PLAYBACK_ONLY'),
  );
  const before = calls.length;
  await page
    .getByRole('navigation', { name: 'Breadcrumb', exact: true })
    .getByRole('button', { name: entry.flow, exact: true })
    .click();
  await open.waitFor();
  assert.equal(new URL(page.url()).pathname, prefix);
  assert.equal(new URL(page.url()).search, '?auditlog=default');
  assert.equal(
    calls.length,
    before,
    'returning after real playback must not replay any metadata read or transfer',
  );
  assert.equal(calls.filter((path) => path.endsWith('/recordings/list')).length, 1);
  assert.equal(calls.filter((path) => path.endsWith('/artifacts/recording')).length, 1);
  assert.equal(await grid.evaluate((node, old) => node === old, retained), true);
  assert.equal(await playback.count(), 0);
  assert.equal(
    await panel.getByRole('button', { name: 'Continue verification', exact: true }).count(),
    0,
  );
  assert.equal(
    await panel.getByText('Catalog verification needs another read.', { exact: false }).count(),
    0,
  );
  assert.equal(terminalSockets, 0);
  await captureLayout(page, 'recording-flow-breadcrumb-retained');
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  await page.waitForFunction(() => document.querySelectorAll('[role="tab"]').length === 0);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await context.close();
  console.log(JSON.stringify({ success: true }));
} finally {
  await browser.close();
}

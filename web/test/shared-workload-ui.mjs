import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { activeAccess, chooseLoginMethod, logoutAccess, notification } from './workspace-ui.mjs';

// This drives the actual built UI against the owned Bifröst binary and real
// Docker/Kubernetes backend. No SSH self-dial or management CLI web action.
const [origin, keyFile, backend] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(keyFile);
assert(['docker', 'kubernetes'].includes(backend));
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
  const replies = [];
  const controls = [];
  const networkFailures = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('requestfailed', (request) =>
    networkFailures.push({
      path: new URL(request.url()).pathname,
      error: request.failure()?.errorText,
    }),
  );
  page.on('response', (response) => {
    const path = new URL(response.url()).pathname;
    if (path.includes('/api/') || response.status() >= 400) {
      replies.push({ path, status: response.status() });
    }
  });
  page.on('websocket', (socket) => {
    socket.on('framereceived', ({ payload }) => {
      if (typeof payload !== 'string') {
        return;
      }
      try {
        const body = JSON.parse(payload);
        controls.push({ type: body.type, code: body.code, status: body.status }); // Never inspect/send the opening bearer frame.
      } catch {
        controls.push({ type: 'malformed' });
      }
    });
  });
  page.on('request', (request) => {
    const body = request.postData() ?? '';
    assert(!body.includes('PRIVATE KEY'), 'local login keys must not enter HTTP');
    assert.equal(new URL(request.url()).search, '', 'no bearer may enter query strings');
  });
  const login = async () => {
    const response = await page.goto(`${origin}/Work`);
    assert.equal(response.status(), 200);
    assert(!response.headers()['content-security-policy'].includes('wasm-unsafe-eval'));
    try {
      await chooseLoginMethod(page, 'SSH key login');
    } catch (error) {
      throw new Error(
        JSON.stringify({
          stage: 'initial-login-view',
          errors,
          replies,
          networkFailures,
          headings: await page.getByRole('heading').allTextContents(),
          root: (await page.locator('#root').textContent())?.slice(0, 1024),
          csp: await page.evaluate(() => window.cspViolations),
        }),
        { cause: error },
      );
    }
    await page.getByLabel('User name', { exact: true }).fill('e2e');
    await page.getByLabel('Private key file (local only)', { exact: true }).setInputFiles(keyFile);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, 'e2e');
    await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden' });
    await page.locator('[data-terminal-phase="connected"]').waitFor();
    assert.equal(
      await page.getByRole('tab').count(),
      1,
      'a fresh login/reload starts one new shell, not a reattachment',
    );
  };
  const execute = async (marker, expectedExit, update) => {
    const command = `/bin/sh -c '/usr/local/bin/e2e-helper environment; printf "account="; /usr/bin/id -u; printf "pty=%s\\n" "$([ -t 0 ] && printf true || printf false)"; /bin/cat /home/e2e/bifroest-web-marker; ${update ? 'printf "web-owned\\n" > /home/e2e/bifroest-web-marker; ' : ''}printf "run=${marker}\\n"; exit ${expectedExit}'`;
    try {
      await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
      await page.keyboard.type(`exec ${command}`);
      await page.keyboard.press('Enter');
      await page.locator('[data-terminal-phase="exited"]').waitFor();
      assert.equal(
        await page
          .locator('[data-terminal-phase="exited"]')
          .getAttribute('data-terminal-exit-status'),
        String(expectedExit),
      );
      assert.equal(
        await page.locator('[data-terminal-phase="exited"]').textContent(),
        `Validated exit status: ${expectedExit}`,
      );
      await page.locator('.terminal-surface').scrollIntoViewIfNeeded();
      await page.waitForFunction(
        (marker) => document.querySelector('.xterm-rows')?.textContent?.includes(`run=${marker}`),
        marker,
      );
    } catch (error) {
      throw new Error(
        JSON.stringify({
          phase: await page.locator('[data-terminal-phase]').getAttribute('data-terminal-phase'),
          notice: await page.locator('[data-terminal-phase]').textContent(),
          output: await page.locator('.xterm-rows').textContent(),
          csp: await page.evaluate(() => window.cspViolations),
          errors,
          replies,
          controls,
        }),
        { cause: error },
      );
    }
    const text = await page.locator('.xterm-rows').textContent();
    assert(
      text.includes('pty=true'),
      `the actual shell must confirm a PTY: ${JSON.stringify(text)}`,
    );
    assert(
      text.includes(update ? 'ssh-owned' : 'web-owned'),
      'the browser must see the previous execution marker in the same workload',
    );
    const session = /session=([0-9a-f-]{36})/u.exec(text)?.[1];
    const connection = /connection=([0-9a-f-]{36})/u.exec(text)?.[1];
    const account = /account=([0-9]+)/u.exec(text)?.[1];
    assert(
      session && connection && account,
      'real workload output must contain separate session/connection/account IDs',
    );
    return { session, connection, account };
  };
  await login();
  const first = await execute('web-a', 7, true);
  // Reload destroys the tab's permission; explicitly log in and start anew.
  await login();
  const second = await execute('web-b', 0, false);
  assert.equal(first.session, second.session);
  assert.equal(first.account, second.account);
  assert.notEqual(first.connection, second.connection);
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  console.log(JSON.stringify({ executions: [first, second] }));
} finally {
  await browser.close();
}

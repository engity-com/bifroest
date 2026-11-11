import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { observePublicKeyWasm } from './public-wasm-diagnostics.mjs';
import { fixtureShellPromptPattern } from './shared-workload-prompt.mjs';
import { expectTerminalExit, observeTerminalResults } from './terminal-results.mjs';
import {
  activeAccess,
  assertUiPreferences,
  chooseLoginMethod,
  logoutAccess,
  notification,
} from './workspace-ui.mjs';

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
  let stage = 'navigation';
  const publicWasm = await observePublicKeyWasm(page, origin, () => stage);
  const terminals = observeTerminalResults(page);
  const errors = [];
  const replies = [];
  const controls = [];
  const networkFailures = [];
  const inputPrefixes = [];
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
    const index = inputPrefixes.push(Buffer.alloc(0)) - 1;
    socket.on('framesent', ({ payload }) => {
      if (typeof payload !== 'string') {
        inputPrefixes[index] = Buffer.concat([inputPrefixes[index], payload]).subarray(0, 32);
      }
    });
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
    stage = 'navigation';
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
    stage = 'primary-login';
    try {
      await page.getByLabel('User name', { exact: true }).fill('e2e');
      await page
        .getByLabel('Private key file (local only)', { exact: true })
        .setInputFiles(keyFile);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await activeAccess(page, 'e2e');
      stage = 'terminal-start';
      await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden' });
      await page.locator('[data-terminal-phase="connected"]').waitFor();
    } catch (error) {
      throw new Error(
        JSON.stringify({
          stage,
          backend,
          publicWasm: publicWasm.events,
          errors,
          replies,
          networkFailures,
          controls,
          notices: await page.getByRole('status').allTextContents(),
          csp: await page.evaluate(() => window.cspViolations),
        }),
        { cause: error },
      );
    }
    stage = 'fixture-shell-prompt';
    // Transport admission is not shell readiness. Wait for the pinned fixture's
    // actual ash prompt before sending any command; never retry that command.
    try {
      await page.waitForFunction(
        (pattern) =>
          new RegExp(pattern).test(
            document
              .querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
              ?.textContent?.trimEnd() ?? '',
          ),
        fixtureShellPromptPattern(backend),
      );
    } catch (error) {
      throw new Error(
        JSON.stringify({
          stage: 'fixture-shell-prompt',
          backend,
          phase: await page.locator('[data-terminal-phase]').getAttribute('data-terminal-phase'),
          output: (
            await page
              .locator('[data-terminal-active="true"] .xterm-accessibility-tree')
              .textContent()
          ).slice(0, 4096),
          sentInputPrefixes: inputPrefixes.map((prefix) => prefix.toString('utf8')),
          csp: await page.evaluate(() => window.cspViolations),
          errors,
          controls,
        }),
        { cause: error },
      );
    }
    assert.equal(
      await page.getByRole('tab').count(),
      1,
      'a fresh login/reload starts one new shell, not a reattachment',
    );
  };
  const execute = async (marker, expectedExit, update) => {
    const command = `/bin/sh -c '/usr/local/bin/e2e-helper environment; printf "account="; /usr/bin/id -u; printf "pty=%s\\n" "$([ -t 0 ] && printf true || printf false)"; /bin/cat /home/e2e/bifroest-web-marker; ${update ? 'printf "web-owned\\n" > /home/e2e/bifroest-web-marker; ' : ''}printf "run=${marker}\\n"; exit ${expectedExit}'`;
    const paneId = await page.locator('[data-terminal-active="true"]').getAttribute('id');
    const result = terminals.latest();
    let text;
    try {
      await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
      await page.keyboard.type(`exec ${command}`);
      await page.keyboard.press('Enter');
      const output = await expectTerminalExit(page, result, expectedExit, paneId);
      assert(output.split(/\r?\n/u).some((line) => line.trim() === `run=${marker}`));
      if (expectedExit === 0) {
        await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor();
        assert.equal(await page.getByRole('tab').count(), 0);
        text = output;
      } else {
        await page.locator('.terminal-surface').scrollIntoViewIfNeeded();
        await page.waitForFunction(
          (marker) =>
            [...document.querySelectorAll('.xterm-accessibility-tree > div')].some(
              (row) => row.textContent.trim() === `run=${marker}`,
            ),
          marker,
        );
        text = await page
          .locator('.xterm-accessibility-tree > div')
          .evaluateAll((rows) =>
            rows
              .map((row) => (row.textContent ?? '').replaceAll('\u00a0', ' ').trimEnd())
              .join('\n'),
          );
      }
    } catch (error) {
      throw new Error(
        JSON.stringify({
          terminal: await page.evaluate(() => {
            const pane = document.querySelector('[data-terminal-active="true"]');
            return {
              phase: pane
                ?.querySelector('[data-terminal-phase]')
                ?.getAttribute('data-terminal-phase'),
              exit: pane?.getAttribute('data-terminal-exit-status'),
            };
          }),
          serverExit: result?.status,
          output: result?.text(),
          csp: await page.evaluate(() => window.cspViolations),
          errors,
          replies,
          controls,
          sentInputPrefixes: inputPrefixes.map((prefix) => prefix.toString('utf8')),
        }),
        { cause: error },
      );
    }
    assert(
      text.includes('pty=true'),
      `the actual shell must confirm a PTY: ${JSON.stringify(text)}`,
    );
    assert(
      text.includes(update ? 'ssh-owned' : 'web-owned'),
      'the browser must see the previous execution marker in the same workload',
    );
    const session = /^session=([1-9A-HJ-NP-Za-km-z]{16,22})\r?$/mu.exec(text)?.[1];
    const connection = /^connection=([1-9A-HJ-NP-Za-km-z]{16,22})\r?$/mu.exec(text)?.[1];
    const account = /^account=([0-9]+)\r?$/mu.exec(text)?.[1];
    assert(
      session && connection && account,
      'real workload output must contain separate session/connection/account IDs',
    );
    assert.equal(connection, result.connection);
    return { session, connection, account };
  };
  await login();
  const first = await execute('web-a', 7, true);
  // Navigation destroys the tab's permission; explicitly log in and start anew.
  await login();
  const second = await execute('web-b', 7, false);
  // Keep logout coverage independent of successful last-tab autoclose.
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  assert.equal(await page.locator('.xterm').count(), 0);
  await login();
  const third = await execute('web-c', 0, false);
  for (const current of [second, third]) {
    assert.equal(first.session, current.session);
    assert.equal(first.account, current.account);
  }
  assert.equal(new Set([first, second, third].map((value) => value.connection)).size, 3);
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page, ['e2e']);
  await publicWasm.close();
  console.log(JSON.stringify({ executions: [first, second, third] }));
} finally {
  await browser.close();
}

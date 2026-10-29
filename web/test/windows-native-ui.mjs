import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright';

const [address, fixtureFile, keyFile] = process.argv.slice(2);
assert.equal(isIP(address), 4);
const fixture = JSON.parse(readFileSync(fixtureFile, 'utf8'));
assert.match(fixture.probe, /^[a-z]:\\[a-z0-9\\_.-]+$/iu);
const origin = 'https://app.example.org:8443';
const input = createInterface({ input: process.stdin });
const errors = [];
const failures = [];
const frames = [];
const resizes = new EventEmitter();
let sockets = 0;
let page;
const executions = [];
const controls = [];
const assetRequests = [];
const pendingRequests = new Map();
const keyDownloads = new Map();
const workerEvents = [];
let requestNumber = 0;
let workerNumber = 0;
let loginNumber = 0;
let stage = 'startup';
async function checkpoint(name) {
  const response = new Promise((resolve, reject) => {
    const closed = () => {
      input.off('line', received);
      reject(new Error('native parent closed the checkpoint channel'));
    };
    function received(line) {
      input.off('close', closed);
      resolve(line);
    }
    input.once('line', received);
    input.once('close', closed);
  });
  console.log(JSON.stringify({ checkpoint: name }));
  assert.deepEqual(JSON.parse(await response), { checkpoint: name, success: true });
}
const browser = await chromium.launch({
  headless: true,
  args: [`--host-resolver-rules=MAP app.example.org ${address}`, '--no-proxy-server'],
});
function parentClosed() {
  void browser.close().catch(() => {});
}
input.once('close', parentClosed);
try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 844 },
  });
  await context.addInitScript(() => {
    window.cspViolations = [];
    window.addEventListener('securitypolicyviolation', (event) =>
      window.cspViolations.push(event.violatedDirective),
    );
  });
  page = await context.newPage();
  // The key worker is retired immediately after signing. Complete the public
  // WASM request's browser-observation lifecycle before allowing the real login
  // start through, so retiring that worker cannot race DevTools' requestfinished
  // bookkeeping. No response is mocked or changed, and nothing is retried.
  await page.route('**/_bifroest/api/v1/login/public-key', async (route) => {
    let timer;
    try {
      controls.push({ type: 'key-asset-barrier', pending: keyDownloads.size, stage });
      await Promise.race([
        Promise.all([...keyDownloads.values()].map((download) => download.promise)),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('key asset lifecycle did not finish')), 5000);
        }),
      ]);
      await route.continue();
    } catch {
      failures.push({
        path: '/_bifroest/api/v1/login/public-key',
        failedStage: stage,
        error: 'key asset lifecycle barrier failed',
      });
      await route.abort().catch(() => undefined);
    } finally {
      clearTimeout(timer);
    }
  });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('requestfailed', (request) => {
    failures.push({
      ...pendingRequests.get(request),
      path: new URL(request.url()).pathname,
      failedStage: stage,
      error: request.failure()?.errorText,
    });
    keyDownloads.get(request)?.resolve();
    keyDownloads.delete(request);
    pendingRequests.delete(request);
  });
  page.on('requestfinished', (request) => {
    if (new URL(request.url()).pathname === '/_bifroest/files/browser-key.wasm') {
      assetRequests.push({ ...pendingRequests.get(request), finishedStage: stage });
    }
    keyDownloads.get(request)?.resolve();
    keyDownloads.delete(request);
    pendingRequests.delete(request);
  });
  page.on('worker', (worker) => {
    const number = ++workerNumber;
    const path = new URL(worker.url()).pathname;
    workerEvents.push({ number, path, type: 'started', stage });
    worker.on('close', () => workerEvents.push({ number, path, type: 'closed', stage }));
  });
  page.on('request', (request) => {
    pendingRequests.set(request, { request: ++requestNumber, startedStage: stage });
    if (new URL(request.url()).pathname === '/_bifroest/files/browser-key.wasm') {
      keyDownloads.set(request, Promise.withResolvers());
    }
    assert(
      !(request.postData() ?? '').includes('PRIVATE KEY'),
      'private login keys stay in the browser tab',
    );
    assert.equal(new URL(request.url()).search, '', 'permissions never enter query strings');
  });
  page.on('websocket', (socket) => {
    sockets++;
    const number = sockets;
    socket.on('framereceived', ({ payload }) => {
      if (typeof payload !== 'string') {
        return;
      }
      const message = JSON.parse(payload);
      if (['ready', 'error', 'exit'].includes(message.type)) {
        controls.push({
          socket: number,
          type: message.type,
          code: message.code,
          status: message.status,
          connectionId: message.connectionId,
        });
      }
    });
    socket.on('close', () => controls.push({ socket: number, type: 'closed' }));
    socket.on('framesent', ({ payload }) => {
      if (typeof payload !== 'string') {
        return;
      }
      const frame = JSON.parse(payload);
      if (frame.type === 'resize') {
        const size = { columns: frame.columns, rows: frame.rows };
        frames.push(size);
        resizes.emit('resize', size);
      }
      // Never retain/log the opening bearer frame.
    });
  });
  const pane = () => page.locator('[data-terminal-active="true"]');
  async function type(command) {
    await pane().locator('.xterm-helper-textarea').focus();
    await page.keyboard.type(command);
    await page.keyboard.press('Enter');
  }
  async function probe(marker, mode = 'browser-probe', args = '') {
    stage = marker;
    await type(
      `${fixture.probe} ${mode} ${args ? `${args} ` : ''}${marker}${marker === 'web-a' ? ' web-owned' : ''}`,
    );
    await page.waitForFunction((marker) => {
      const text =
        document.querySelector('[data-terminal-active="true"] .xterm-rows')?.textContent ?? '';
      const observed = [
        ...text.matchAll(/BIFROEST_NATIVE_PROBE=([A-Za-z0-9+/=]+);ENDPROBE/gu),
      ].some((match) => {
        try {
          return JSON.parse(atob(match[1])).marker === marker;
        } catch {
          return false;
        }
      });
      const phase = document
        .querySelector('.application-status [data-terminal-phase]')
        ?.getAttribute('data-terminal-phase');
      return observed || ['interrupted', 'disconnected', 'exited'].includes(phase);
    }, marker);
    const text = await pane().locator('.xterm-rows').textContent();
    const observations = [...text.matchAll(/BIFROEST_NATIVE_PROBE=([A-Za-z0-9+/=]+);ENDPROBE/gu)]
      .map((match) => JSON.parse(Buffer.from(match[1], 'base64').toString('utf8')))
      .filter((value) => value.marker === marker);
    assert.equal(observations.length, 1);
    const value = observations[0];
    assert.equal(value.sid, fixture.sid);
    assert.equal(value.user.toLowerCase(), fixture.user.toLowerCase());
    assert.equal(value.pty, true, 'the native child must have a real ConPTY console');
    assert(value.columns > 0 && value.rows > 0);
    assert.match(value.session, /^[0-9a-f-]{36}$/u);
    assert.match(value.connection, /^[0-9a-f-]{36}$/u);
    assert.match(value.execution, /^[0-9a-f-]{36}$/u);
    assert.equal(value.content, 'web-owned');
    return value;
  }
  async function login(navigate = true) {
    const number = ++loginNumber;
    stage = `login-${number}-begin`;
    if (navigate) {
      const response = await page.goto(`${origin}/Work`);
      assert.equal(response.status(), 200);
      assert(response.headers()['content-security-policy'].includes("frame-ancestors 'none'"));
      assert(!response.headers()['content-security-policy'].includes('wasm-unsafe-eval'));
    }
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await dialog.getByText('SSH key login', { exact: true }).click();
    await dialog.getByLabel('User name', { exact: true }).fill(fixture.user);
    await dialog
      .getByLabel('Private key file (local only)', { exact: true })
      .setInputFiles(keyFile);
    await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page
      .getByRole('heading', { name: `Signed in as ${fixture.user}`, exact: true })
      .waitFor();
    await dialog.waitFor({ state: 'hidden' });
    await page.locator('[data-terminal-phase="connected"]').waitFor();
    stage = `login-${number}-connected`;
    assert.equal(
      await page.getByRole('tab').count(),
      1,
      'confirmed login opens exactly one fresh shell',
    );
  }
  async function exit(status) {
    await type(`exit ${status}`);
    await page.locator('[data-terminal-phase="exited"]').waitFor();
    assert.equal(
      await page
        .locator('[data-terminal-phase="exited"]')
        .getAttribute('data-terminal-exit-status'),
      String(status),
    );
    assert.equal(
      await page.locator('[data-terminal-phase="exited"]').textContent(),
      `Validated exit status: ${status}`,
    );
  }
  await login();
  const a = await probe('web-a');
  executions.push({ ...a, exit: 7 });
  const changed = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      resizes.off('resize', observe);
      reject(new Error('the UI did not send a changed terminal size'));
    }, 5000);
    function observe(size) {
      if (size.columns === a.columns && size.rows === a.rows) {
        return;
      }
      clearTimeout(timer);
      resizes.off('resize', observe);
      resolve(size);
    }
    resizes.on('resize', observe);
  });
  await page.setViewportSize({ width: 960, height: 640 });
  const size = await changed;
  const resized = await probe('web-resized', 'browser-size', `${size.columns} ${size.rows}`);
  assert.equal(resized.connection, a.connection);
  assert.equal(resized.columns, size.columns);
  assert.equal(resized.rows, size.rows);
  assert(
    resized.columns !== a.columns || resized.rows !== a.rows,
    'native ConPTY dimensions must actually change',
  );
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await page.getByRole('tab', { name: `Terminal 2 ${fixture.user}`, exact: true }).waitFor();
  await page.waitForFunction(
    () => document.getElementById('terminal-tab-2')?.getAttribute('aria-selected') === 'true',
  );
  await page.locator('[data-terminal-phase="connected"]').waitFor();
  const b = await probe('web-b');
  executions.push({ ...b, exit: null });
  await page.getByRole('button', { name: 'Close terminal 2', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Close this terminal?', exact: true })
    .getByRole('button', { name: 'Close terminal', exact: true })
    .click();
  await page
    .getByRole('tab', { name: `Terminal 2 ${fixture.user}`, exact: true })
    .waitFor({ state: 'hidden' });
  const kept = await probe('web-after-close');
  assert.equal(kept.connection, a.connection);
  await checkpoint('after-close');
  await exit(7);
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await page.locator('[data-terminal-phase="connected"]').waitFor();
  executions.push({ ...(await probe('web-before-reload')), exit: null });
  await page.reload();
  await checkpoint('after-reload');
  await login(false);
  executions.push({ ...(await probe('web-after-reload')), exit: null });
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await page.getByText('Logout confirmed.', { exact: true }).waitFor();
  assert.equal(await page.locator('.xterm').count(), 0);
  await checkpoint('after-logout');
  await login(false);
  executions.push({ ...(await probe('web-fresh-login')), exit: 0 });
  await exit(0);
  assert.equal(
    sockets,
    5,
    'only five deliberately requested or confirmed-login shells are allowed',
  );
  assert.equal(new Set(executions.map((value) => value.connection)).size, 5);
  assert.equal(new Set(executions.map((value) => value.execution)).size, 5);
  assert.equal(new Set(executions.map((value) => value.session)).size, 1);
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await page.getByText('Logout confirmed.', { exact: true }).waitFor();
  assert.deepEqual(errors, []);
  assert.deepEqual(failures, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal((await context.cookies()).length, 0);
  console.log(JSON.stringify({ executions }));
} catch (error) {
  console.error(
    JSON.stringify({
      stage,
      errors,
      failures,
      sockets,
      status: await page
        ?.locator('.application-status')
        .textContent()
        .catch(() => null),
      output: (
        await page
          ?.locator('[data-terminal-active="true"] .xterm-rows')
          .textContent()
          .catch(() => null)
      )?.slice(-4096),
      sizes: frames,
      controls,
      assetRequests,
      workerEvents,
    }),
  );
  throw error;
} finally {
  input.off('close', parentClosed);
  input.close();
  await browser.close();
}

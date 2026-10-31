import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright';
import {
  answerAuthentication,
  assertUiPreferences,
  chooseLoginMethod,
  duplicateTab,
  logoutAccess,
  notification,
  settledLogin,
} from './workspace-ui.mjs';

const [address, fixtureFile, passwordFile] = process.argv.slice(2);
assert.equal(isIP(address), 4);
const fixture = JSON.parse(await readFile(fixtureFile, 'utf8'));
assert.equal(fixture.passwordResume, true);
assert.match(fixture.probe, /^[a-z]:\\[a-z0-9\\_.-]+$/iu);
const password = await readFile(passwordFile, 'utf8');
const origin = 'https://app.example.org:8443';
const input = createInterface({ input: process.stdin });
const executions = [];
const failures = [];
const responses = [];
const expectedDenials = new Set();
const requestIDs = new WeakMap();
let requestNumber = 0;
let stage = 'start';
let primaryLogins = 0;
let resumes = 0;
let denied = 0;
let groupDenied = 0;
let groupRejection;
let credentialLeak = false;
let context;
let page;
const profiles = [];

async function checkpoint(name) {
  const response = new Promise((resolve, reject) => {
    const closed = () => {
      input.off('line', received);
      reject(new Error('fixture controller closed'));
    };
    const received = (line) => {
      try {
        const value = JSON.parse(line);
        if (value.checkpoint !== name || value.success !== true) {
          throw new Error('unexpected controller reply');
        }
        input.off('close', closed);
        input.off('line', received);
        resolve();
      } catch {
        input.off('close', closed);
        input.off('line', received);
        reject(new Error('invalid controller reply'));
      }
    };
    input.once('close', closed);
    input.once('line', received);
  });
  console.log(JSON.stringify({ checkpoint: name }));
  await response;
}

async function open(profile) {
  context = await chromium.launchPersistentContext(profile, {
    headless: true,
    ignoreHTTPSErrors: true,
    args: [`--host-resolver-rules=MAP app.example.org ${address}`, '--no-proxy-server'],
  });
  await context.addInitScript(() => {
    window.cspViolations = [];
    window.addEventListener('securitypolicyviolation', (event) =>
      window.cspViolations.push(event.violatedDirective),
    );
  });
  const page = await context.newPage();
  page.on('pageerror', () => failures.push({ type: 'pageerror', stage }));
  page.on('request', (request) => {
    requestIDs.set(request, ++requestNumber);
    const path = new URL(request.url()).pathname;
    if (request.method() !== 'POST') {
      return;
    }
    if (path.endsWith('/login/password') || path.endsWith('/login/interactive')) {
      primaryLogins++;
    }
    if (path.endsWith('/remember/resume')) {
      resumes++;
    }
    const body = request.postData() ?? '';
    if (
      body.includes(password) &&
      !path.endsWith('/login/password') &&
      !path.endsWith('/login/reply')
    ) {
      credentialLeak = true;
    }
  });
  page.on('response', (response) => {
    if (response.status() < 400) {
      return;
    }
    const path = new URL(response.url()).pathname;
    const id = requestIDs.get(response.request());
    const observation = { type: 'response', path, status: response.status(), stage, id };
    responses.push(observation);
    // Deliberate native-policy denials are asserted individually, not a blanket
    // network-error filter. Their Http.post body cancellation can yield ABORTED.
    if (
      stage.startsWith('denied-') &&
      path.endsWith('/remember/prove') &&
      response.status() === 401
    ) {
      expectedDenials.add(id);
      denied++;
    } else {
      failures.push(observation);
    }
  });
  page.on('requestfailed', (request) =>
    failures.push({
      type: 'requestfailed',
      path: new URL(request.url()).pathname,
      error: request.failure()?.errorText,
      id: requestIDs.get(request),
      stage,
    }),
  );
  page.on('websocket', (socket) =>
    socket.on('framereceived', ({ payload }) => {
      if (typeof payload !== 'string') {
        return;
      }
      try {
        const message = JSON.parse(payload);
        if (
          stage.startsWith('stale-group-') &&
          message.type === 'error' &&
          message.code === 'connection-denied'
        ) {
          groupDenied++;
          groupRejection?.();
          groupRejection = undefined;
        }
      } catch {}
    }),
  );
  const response = await page.goto(`${origin}/Work`);
  assert.equal(response.status(), 200);
  assert(response.headers()['content-security-policy'].includes("frame-ancestors 'none'"));
  return page;
}

async function storedKeys(page) {
  const valid = await page.evaluate(async () => {
    const database = await new Promise((resolve, reject) => {
      const request = indexedDB.open('bifroest-browser-remember-v1');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('storage'));
    });
    try {
      const values = await new Promise((resolve, reject) => {
        const request = database
          .transaction('bindings', 'readonly')
          .objectStore('bindings')
          .getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error('storage'));
      });
      return (
        values.length === 1 &&
        values.every(
          (value) =>
            value.signing.privateKey instanceof CryptoKey &&
            value.signing.privateKey.extractable === false &&
            value.encryption instanceof CryptoKey &&
            value.encryption.extractable === false &&
            value.ciphertext instanceof ArrayBuffer &&
            !('password' in value),
        )
      );
    } finally {
      database.close();
    }
  });
  assert.equal(
    valid,
    true,
    'only independent non-exportable signing/encryption keys and encrypted selectors may persist',
  );
}

async function noStoredKeys(page) {
  const count = await page.evaluate(async () => {
    const database = await new Promise((resolve, reject) => {
      const request = indexedDB.open('bifroest-browser-remember-v1');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('storage'));
    });
    try {
      return await new Promise((resolve, reject) => {
        const request = database
          .transaction('bindings', 'readonly')
          .objectStore('bindings')
          .count();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error('storage'));
      });
    } finally {
      database.close();
    }
  });
  assert.equal(count, 0, 'confirmed logout must durably remove this owned browser registration');
}

async function connected(page) {
  await settledLogin(page, fixture.user, true);
  await page.locator('[data-terminal-phase="connected"]').waitFor();
  assert.equal(await page.getByRole('tab').count(), 1);
}

async function probeAndExit(page, marker, write = false) {
  const terminal = page.locator('[data-terminal-active="true"]');
  await terminal.locator('.xterm-helper-textarea').focus();
  await page.keyboard.type(
    `${fixture.probe} browser-probe ${marker}${write ? ' remember-owned' : ''}`,
  );
  await page.keyboard.press('Enter');
  await page.waitForFunction(
    (marker) =>
      [
        ...(
          document.querySelector('[data-terminal-active="true"] .xterm-rows')?.textContent ?? ''
        ).matchAll(/BIFROEST_NATIVE_PROBE=([A-Za-z0-9+/=]+);ENDPROBE/gu),
      ].some((match) => {
        try {
          return JSON.parse(atob(match[1])).marker === marker;
        } catch {
          return false;
        }
      }),
    marker,
  );
  const text = await terminal.locator('.xterm-rows').textContent();
  const values = [...text.matchAll(/BIFROEST_NATIVE_PROBE=([A-Za-z0-9+/=]+);ENDPROBE/gu)]
    .map((match) => JSON.parse(Buffer.from(match[1], 'base64').toString('utf8')))
    .filter((value) => value.marker === marker);
  assert.equal(values.length, 1);
  const value = values[0];
  assert.equal(value.sid, fixture.sid);
  assert.equal(value.user.toLowerCase(), fixture.user.toLowerCase());
  assert.equal(value.pty, true);
  assert.equal(value.content, 'remember-owned');
  executions.push(value);
  await terminal.locator('.xterm-helper-textarea').focus();
  await page.keyboard.type('exit 0');
  await page.keyboard.press('Enter');
  await page.locator('[data-terminal-phase="exited"]').waitFor();
  assert.equal(
    await page.locator('[data-terminal-phase="exited"]').getAttribute('data-terminal-exit-status'),
    '0',
  );
}

try {
  for (const method of ['password', 'interactive']) {
    const profile = await mkdtemp(join(tmpdir(), `bifroest-owned-${method}-`));
    profiles.push(profile);
    stage = `primary-${method}`;
    page = await open(profile);
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    if (method === 'interactive') {
      await chooseLoginMethod(page, 'Interactive / device login');
    }
    await dialog.getByLabel('User name', { exact: true }).fill(fixture.user);
    assert.equal(
      await dialog
        .getByRole('checkbox', { name: 'Remember this browser', exact: true })
        .isChecked(),
      false,
    );
    await dialog.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
    if (method === 'password') {
      await dialog.getByLabel('Password', { exact: true }).fill(password);
    }
    await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
    if (method === 'interactive') {
      await answerAuthentication(page, password, { kind: 'prompt', echo: false });
    }
    stage = `primary-${method}-connected`;
    await connected(page);
    stage = `primary-${method}-enrollment-notice`;
    await notification(page, 'RememberMe setup confirmed for this browser.');
    stage = `primary-${method}-stored-keys`;
    await storedKeys(page);
    stage = `primary-${method}-native-probe`;
    await probeAndExit(page, `${method}-initial`, true);
    await context.close();
    context = undefined;
    stage = `profile-${method}`;
    page = await open(profile);
    assert.equal(await page.getByRole('tab').count(), 0);
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await connected(page);
    await storedKeys(page);
    await probeAndExit(page, `${method}-profile`);
    await context.close();
    context = undefined;
    await checkpoint(`restart-${method}`);
    stage = `service-${method}`;
    page = await open(profile);
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await connected(page);
    await probeAndExit(page, `${method}-service`);
    const proofsBefore = resumes;
    await checkpoint(`drop-group-${method}`);
    stage = `stale-group-${method}`;
    let rejectionTimer;
    const rejected = new Promise((resolve, reject) => {
      rejectionTimer = setTimeout(() => {
        groupRejection = undefined;
        reject(new Error('same-bearer group denial was not observed'));
      }, 10000);
      groupRejection = () => {
        clearTimeout(rejectionTimer);
        resolve();
      };
    });
    await duplicateTab(page);
    await rejected;
    assert.equal(
      resumes,
      proofsBefore,
      'a new connection must revalidate current groups with the same bearer, not a new Remember proof',
    );
    await checkpoint(`add-group-${method}`);
    stage = `group-restored-${method}`;
    await duplicateTab(page);
    await page.locator('[data-terminal-phase="connected"]').waitFor();
    await probeAndExit(page, `${method}-group-restored`);
    assert.equal(resumes, proofsBefore, 'restored admission must still use that same bearer');
    await context.close();
    context = undefined;
    await checkpoint(`disable-${method}`);
    stage = `denied-${method}`;
    page = await open(profile);
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await page.getByText('Access was denied.', { exact: false }).waitFor();
    assert.equal(await page.getByRole('tab').count(), 0);
    await checkpoint(`restore-${method}`);
    stage = `restored-${method}`;
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await connected(page);
    await probeAndExit(page, `${method}-restored`);
    await logoutAccess(page);
    await notification(page, 'Logout confirmed.');
    await page.reload();
    await noStoredKeys(page);
    assert.equal(
      await page.getByRole('button', { name: 'Use saved access', exact: true }).count(),
      0,
    );
    await assertUiPreferences(page, [fixture.user]);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    assert.equal((await context.cookies()).length, 0);
    await context.close();
    context = undefined;
  }
  assert.equal(credentialLeak, false);
  assert.equal(primaryLogins, 2);
  assert.equal(resumes, 8);
  assert.equal(denied, 2);
  assert.equal(groupDenied, 2);
  assert.equal(responses.length, 2);
  assert(
    failures.every(
      (failure) =>
        failure.type === 'requestfailed' &&
        expectedDenials.has(failure.id) &&
        failure.path.endsWith('/remember/prove') &&
        failure.error === 'net::ERR_ABORTED',
    ),
  );
  assert.equal(executions.length, 10);
  assert.equal(new Set(executions.map((value) => value.connection)).size, 10);
  assert.equal(new Set(executions.map((value) => value.execution)).size, 10);
  assert.equal(new Set(executions.map((value) => value.session)).size, 1);
  console.log(JSON.stringify({ executions, primaryLogins, resumes, denied, groupDenied }));
} catch (error) {
  // Playwright action errors can include a fill() argument. Never forward their
  // message/stack or raw request bodies, credentials, cookies or bearer frames.
  const privateMessage = typeof error?.message === 'string' ? error.message : '';
  const reason = /strict mode violation/u.test(privateMessage)
    ? 'ambiguous-selector'
    : /Target .*closed|browser has been closed/u.test(privateMessage)
      ? 'target-closed'
      : /IDB|indexedDB|storage/u.test(privateMessage)
        ? 'storage-operation'
        : error?.name === 'AssertionError'
          ? 'assertion'
          : 'operation-failed';
  console.error(
    JSON.stringify({
      stage,
      primaryLogins,
      resumes,
      denied,
      failures,
      responses,
      error: ['Error', 'TimeoutError', 'AssertionError'].includes(error?.name)
        ? error.name
        : 'FixtureError',
      reason,
      ui: await page
        ?.evaluate(() => ({
          phase:
            document
              .querySelector('[data-terminal-active="true"] [data-terminal-phase]')
              ?.getAttribute('data-terminal-phase') ?? null,
          dialogs: document.querySelectorAll('[role="dialog"]').length,
          tabs: document.querySelectorAll('[role="tab"]').length,
        }))
        .catch(() => null),
    }),
  );
  process.exitCode = 1;
} finally {
  input.close();
  await context?.close();
  for (const profile of profiles) {
    await rm(profile, { recursive: true, force: true });
  }
}

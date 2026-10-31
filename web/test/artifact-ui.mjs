import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import {
  activeAccess,
  assertUiPreferences,
  captureLayout,
  exactArtifactSelection,
  logoutAccess,
  notification,
  reauthenticate,
  workspace,
} from './workspace-ui.mjs';

const [origin, mode, keyPath] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(['ui-clear', 'ui-encrypted'].includes(mode));
const encrypted = mode === 'ui-encrypted';
const browser = await chromium.launch({
  headless: true,
  args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true });
  await context.addInitScript(() => {
    window.cspViolations = [];
    window.artifactStorageWrites = 0;
    for (const method of ['put', 'add']) {
      const original = IDBObjectStore.prototype[method];
      IDBObjectStore.prototype[method] = function (...args) {
        window.artifactStorageWrites++;
        return original.apply(this, args);
      };
    }
    window.addEventListener('securitypolicyviolation', (event) =>
      window.cspViolations.push(event.violatedDirective),
    );
    const WorkerType = window.Worker;
    window.ownedWorkers = [];
    window.Worker = class extends WorkerType {
      constructor(url, options) {
        super(url, options);
        this.terminated = false;
        this.requests = [];
        window.ownedWorkers.push(this);
      }
      postMessage(value, transfer) {
        this.requests.push(JSON.stringify(value));
        return super.postMessage(value, transfer);
      }
      terminate() {
        this.terminated = true;
        return super.terminate();
      }
    };
    const create = URL.createObjectURL.bind(URL);
    const revoke = URL.revokeObjectURL.bind(URL);
    window.artifactURLs = new Set();
    URL.createObjectURL = (blob) => {
      const url = create(blob);
      window.artifactURLs.add(url);
      return url;
    };
    URL.revokeObjectURL = (url) => {
      window.artifactURLs.delete(url);
      return revoke(url);
    };
  });
  const page = await context.newPage();
  const errors = [];
  const requests = [];
  const apiRequests = [];
  let sockets = 0;
  page.on('websocket', () => {
    sockets++;
  });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => {
    if (new URL(request.url()).pathname.includes('/api/')) {
      apiRequests.push(new URL(request.url()).pathname);
      const body = request.postData() ?? '';
      assert(
        !body.includes('PRIVATE KEY') &&
          !body.includes('fixture secret') &&
          !body.includes('offline-private'),
      );
      if (request.url().includes('/management/artifacts/')) {
        requests.push(JSON.parse(body));
      }
    }
  });
  const reply = await page.goto(`${origin}/Work`);
  assert.equal(reply.status(), 200);
  assert(!reply.headers()['content-security-policy'].includes('wasm-unsafe-eval'));
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByLabel('Password', { exact: true }).fill('correct');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await activeAccess(page, 'alice');
  await workspace(page, 'Server');
  await page.getByRole('button', { name: 'Load flows', exact: true }).click();
  await page
    .getByRole('table', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  const entry = await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-id', { credentials: 'omit' }).then((response) =>
      response.json(),
    ),
  );
  const panel = page.getByRole('region', {
    name: 'Artifacts and client-side evidence',
    exact: true,
  });
  await exactArtifactSelection(page);
  try {
    await panel.getByRole('textbox', { name: 'Artifact auditlog', exact: true }).fill('default');
  } catch (error) {
    throw new Error(
      JSON.stringify({
        errors,
        artifacts: await panel.ariaSnapshot(),
        headings: await page.getByRole('heading').allTextContents(),
      }),
      { cause: error },
    );
  }
  await panel.getByRole('textbox', { name: 'Recording ID', exact: true }).fill(entry.id);
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await panel
    .getByText('Transport complete — evidence is still unverified.', { exact: false })
    .waitFor();
  assert.equal(
    await panel.getByRole('region', { name: 'Evidence result', exact: true }).count(),
    0,
  );
  assert.equal(await panel.getByLabel('Expected producer ID', { exact: false }).inputValue(), '');
  const callsBeforeNavigation = apiRequests.length;
  await workspace(page, 'Server');
  await workspace(page, 'Recordings & audit');
  assert.equal(
    apiRequests.length,
    callsBeforeNavigation,
    'switching views must not replay a transfer',
  );
  assert.equal(await panel.getByLabel('Expected producer ID', { exact: false }).inputValue(), '');
  await captureLayout(page, `artifact-${mode}-verification`);
  await page.setViewportSize({ width: 390, height: 844 });
  await captureLayout(page, `artifact-${mode}-mobile`);
  await page.setViewportSize({ width: 1280, height: 720 });
  assert.equal(
    await panel
      .getByRole('combobox', { name: 'Expected encryption', exact: true })
      .locator('..')
      .locator('input')
      .inputValue(),
    '',
  );
  assert.equal(
    await panel
      .getByRole('checkbox', { name: 'Explicitly allow an untrusted producer', exact: false })
      .isChecked(),
    false,
  );
  assert.equal(
    await panel.getByRole('button', { name: 'Save checked export', exact: false }).count(),
    0,
  );
  const choose = async (label, option) => {
    if (label === 'Verification depth' || label === 'Audit verification scope') {
      const advanced = panel.getByText('Advanced verification options', { exact: true });
      if (!(await advanced.locator('..').evaluate((node) => node.open))) {
        await advanced.click();
      }
    }
    await panel.getByRole('combobox', { name: label, exact: true }).click();
    await page.getByRole('option', { name: option, exact: true }).click();
  };
  const producer = panel.getByLabel('Expected producer ID', { exact: false });
  const localKey = async (password = 'tab fixture secret') => {
    if (!encrypted) {
      return;
    }
    await panel.getByLabel('Decryption key file (local only)', { exact: true }).setInputFiles({
      name: 'offline-private',
      mimeType: 'application/octet-stream',
      buffer: readFileSync(keyPath),
    });
    await panel
      .getByLabel('Decryption passphrase (optional, local only)', { exact: true })
      .fill(password);
  };
  const verify = () => panel.getByRole('button', { name: 'Verify locally', exact: true }).click();
  const result = panel.getByRole('region', { name: 'Evidence result', exact: true });
  await choose(
    'Expected encryption',
    encrypted ? 'Expect SSH-recipient encrypted data' : 'Expect unencrypted data',
  );
  if (encrypted) {
    assert.equal(
      await panel.getByLabel('Expected recipient fingerprint', { exact: false }).inputValue(),
      '',
    );
    await panel
      .getByLabel('Expected recipient fingerprint', { exact: false })
      .fill(entry.recipient);
  }
  await producer.fill('a'.repeat(64));
  await verify();
  await panel.getByText('Evidence verification failed.', { exact: false }).waitFor();
  assert.equal(await result.count(), 0);
  await producer.fill(entry.producer);
  if (encrypted) {
    await panel
      .getByLabel('Expected recipient fingerprint', { exact: false })
      .fill(`SHA256:${'A'.repeat(43)}`);
    await verify();
    await panel.getByText('Evidence verification failed.', { exact: false }).waitFor();
    assert.equal(await result.count(), 0);
    await panel
      .getByLabel('Expected recipient fingerprint', { exact: false })
      .fill(entry.recipient);
  }
  await verify();
  await result
    .getByText('Signing producer matches the independent expected ID', { exact: true })
    .waitFor();
  await result
    .getByText('Outer signatures/container only — no private verification', { exact: true })
    .waitFor();
  if (encrypted) {
    await result
      .getByText('Not checked — outer verification does not prove decryption', { exact: true })
      .waitFor();
  }
  assert.equal(
    await panel.getByRole('button', { name: 'Save checked export', exact: false }).count(),
    0,
  );
  await panel
    .getByRole('radio', { name: 'Open content, prepare playback or export', exact: true })
    .check();
  assert.equal(await result.count(), 0, 'changing expectations must retire the old result');
  await panel.getByText('Advanced verification options', { exact: true }).click();
  assert.equal(
    await panel
      .getByRole('checkbox', {
        name: 'Prepare a verified local export after full success',
        exact: true,
      })
      .isChecked(),
    true,
    'opening content is an explicit request to prepare a local export, never to auto-save or play',
  );
  if (encrypted) {
    await localKey('wrong fixture secret');
    await verify();
    await panel
      .getByText('The local decryption key could not be imported', { exact: false })
      .waitFor();
    assert.equal(await result.count(), 0);
    assert.equal(
      await panel
        .getByLabel('Decryption passphrase (optional, local only)', { exact: true })
        .inputValue(),
      '',
    );
    assert.equal(
      await panel
        .getByLabel('Decryption key file (local only)', { exact: true })
        .evaluate((input) => input.files.length),
      0,
    );
  }
  await localKey();
  await verify();
  await result
    .getByText('Full private semantics (decrypt when encrypted)', { exact: true })
    .waitFor();
  await result
    .getByText(
      encrypted
        ? 'Authenticated decryption and private verification succeeded'
        : 'Not encrypted; no decryption key was needed',
      { exact: true },
    )
    .waitFor();
  await result
    .getByText('Not established; newer evidence may exist or have been withheld', { exact: true })
    .waitFor();
  const save = async () => {
    const downloading = page.waitForEvent('download');
    await result.getByRole('button', { name: 'Save checked export', exact: false }).click();
    const downloaded = await downloading;
    const chunks = [];
    for await (const chunk of await downloaded.createReadStream()) {
      chunks.push(chunk);
    }
    return { filename: downloaded.suggestedFilename(), bytes: Buffer.concat(chunks) };
  };
  const cast = await save();
  assert.equal(cast.filename, `recording-${entry.id}.cast`);
  assert(cast.bytes.toString().includes('# bifroest:signature:v1 '));
  const playback = panel.getByRole('region', { name: 'Local recording playback', exact: true });
  const beforePlayback = apiRequests.length;
  const titleBefore = await page.title();
  const pagesBefore = context.pages().length;
  await playback.getByRole('button', { name: 'Prepare local playback', exact: true }).click();
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  assert.equal(
    (await playback.locator('.xterm-rows').textContent()).includes('PLAYBACK_ONLY'),
    false,
    'preparation must not auto-play',
  );
  await playback.getByRole('button', { name: 'Play locally', exact: true }).click();
  await playback.locator('[data-playback-phase="ended"]').waitFor();
  await playback
    .getByRole('region', { name: 'Read-only recording viewport', exact: true })
    .scrollIntoViewIfNeeded();
  await page.waitForFunction(() =>
    document.querySelector('.playback-surface .xterm-rows')?.textContent?.includes('PLAYBACK_ONLY'),
  );
  assert.equal(await page.title(), titleBefore, 'recorded OSC title cannot rename the application');
  const link = await playback
    .locator('.xterm-rows')
    .getByText('blocked-playback-link', { exact: true })
    .boundingBox();
  assert(link !== null);
  await page.mouse.click(link.x + link.width / 2, link.y + link.height / 2);
  assert.equal(context.pages().length, pagesBefore, 'recorded links cannot open windows');
  assert.equal(
    new URL(page.url()).origin,
    origin,
    'recorded links cannot navigate the existing page',
  );
  await playback.getByRole('button', { name: 'Reset playback to start', exact: true }).click();
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  assert.equal(
    (await playback.locator('.xterm-rows').textContent()).includes('PLAYBACK_ONLY'),
    false,
  );
  await playback.getByRole('combobox', { name: 'Local playback speed', exact: true }).click();
  await page.getByRole('option', { name: '2', exact: true }).click();
  await playback.getByRole('button', { name: 'Play locally', exact: true }).click();
  await playback.locator('[data-playback-phase="ended"]').waitFor();
  await playback.getByRole('button', { name: 'Reset playback to start', exact: true }).click();
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  await playback.getByRole('button', { name: 'Play locally', exact: true }).click();
  await playback.getByRole('button', { name: 'Pause playback', exact: true }).click();
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  assert.equal(apiRequests.length, beforePlayback, 'playback must not issue API requests');
  assert.equal(sockets, 0, 'local playback must not open a live terminal socket');
  assert.equal(await page.evaluate(() => window.artifactURLs.size), 1);
  await panel
    .getByRole('checkbox', { name: 'Explicitly allow an untrusted producer', exact: false })
    .check();
  assert.equal(
    await panel.locator('.playback-surface .xterm').count(),
    0,
    'changing expectations must retire rendered private output',
  );
  assert.equal(await result.count(), 0);
  assert.equal(
    await page.evaluate(() => window.artifactURLs.size),
    0,
    'changing expectations revokes plaintext URLs',
  );
  await localKey();
  await verify();
  await result
    .getByText('Valid evidence from an untrusted producer', { exact: false })
    .first()
    .waitFor();
  assert.equal(
    await result
      .getByText('Signing producer matches the independent expected ID', { exact: true })
      .count(),
    0,
  );
  await exactArtifactSelection(page);
  await choose('Artifact type', 'Audit inventory');
  assert.equal(await result.count(), 0);
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await panel
    .getByRole('heading', { name: 'Independent verification expectations', exact: true })
    .waitFor();
  assert.equal(
    await panel
      .getByRole('checkbox', { name: 'Explicitly allow an untrusted producer', exact: false })
      .isChecked(),
    false,
  );
  assert.equal(await producer.inputValue(), '');
  await producer.fill(entry.producer);
  await choose(
    'Expected encryption',
    encrypted ? 'Expect SSH-recipient encrypted data' : 'Expect unencrypted data',
  );
  if (encrypted) {
    await panel
      .getByLabel('Expected recipient fingerprint', { exact: false })
      .fill(entry.recipient);
  }
  await choose('Verification depth', 'Full private semantics (decrypt when encrypted)');
  await panel
    .getByRole('checkbox', {
      name: 'Prepare a verified local export after full success',
      exact: true,
    })
    .check();
  assert.equal(
    await panel
      .getByRole('checkbox', { name: 'Include sensitive fields', exact: false })
      .isChecked(),
    false,
  );
  await localKey();
  await verify();
  await result
    .getByText('Complete supplied chain ending at its signed head', { exact: true })
    .waitFor();
  const audit = await save();
  assert.equal(audit.filename, 'audit-default.jsonl');
  assert(audit.bytes.length > 0);
  assert(
    !audit.bytes.toString().includes('"flow"') && !audit.bytes.toString().includes('"sessionId"'),
  );
  await panel.getByRole('checkbox', { name: 'Include sensitive fields', exact: false }).check();
  assert.equal(await result.count(), 0);
  await localKey();
  await verify();
  await result.getByText('Sensitive fields explicitly included', { exact: true }).waitFor();
  const sensitiveAudit = await save();
  assert(sensitiveAudit.bytes.toString().includes('"flow"'));
  await choose('Audit verification scope', 'Captured signed prefix (not the latest head)');
  await localKey();
  await verify();
  await result.getByText('Captured signed prefix (not the latest head)', { exact: true }).waitFor();
  await result
    .getByText('Not established; newer evidence may exist or have been withheld', { exact: true })
    .waitFor();
  assert.deepEqual(requests, [
    { slug: 'Work', auditlog: 'default', id: entry.id },
    { slug: 'Work', auditlog: 'default' },
  ]);
  await panel
    .getByRole('button', { name: 'Discard artifact data from this view', exact: true })
    .click();
  assert.equal(await result.count(), 0);
  assert.equal(await page.evaluate(() => window.artifactURLs.size), 0);
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await panel
    .getByRole('heading', { name: 'Independent verification expectations', exact: true })
    .waitFor();
  let release;
  let entered;
  const holding = new Promise((resolve) => {
    release = resolve;
  });
  const entering = new Promise((resolve) => {
    entered = resolve;
  });
  await context.route('**/browser-evidence.wasm.gz', async (route) => {
    entered();
    await holding;
    await route.abort().catch(() => undefined);
  });
  await localKey();
  await verify();
  await entering;
  await panel.getByRole('button', { name: 'Cancel artifact operation', exact: true }).click();
  release();
  await panel.getByText('Artifact operation cancelled.', { exact: false }).waitFor();
  await panel
    .getByRole('button', { name: 'Verify locally', exact: true })
    .waitFor({ state: 'visible' });
  assert.equal(await result.count(), 0);
  await context.unroute('**/browser-evidence.wasm.gz');
  await localKey();
  await verify();
  await result
    .getByText('Signing producer matches the independent expected ID', { exact: true })
    .waitFor();
  await save();
  const aliceURLs = await page.evaluate(() => window.artifactURLs.size);
  assert(aliceURLs > 0, 'the original access owns its prepared local export');
  await reauthenticate(page);
  await page.getByLabel('User name', { exact: true }).fill('bob');
  await page.getByLabel('Password', { exact: true }).fill('correct');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await activeAccess(page, 'bob');
  await workspace(page, 'Recordings & audit');
  assert.equal(
    await panel
      .getByRole('heading', { name: 'Independent verification expectations', exact: true })
      .count(),
    0,
  );
  assert.equal(
    await page.evaluate(() => window.artifactURLs.size),
    aliceURLs,
    'an additional actor gets a separate view, not ownership or destruction of the original export',
  );
  await exactArtifactSelection(page);
  await panel.getByRole('textbox', { name: 'Artifact auditlog', exact: true }).fill('default');
  await choose('Artifact type', 'Audit inventory');
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' }),
  );
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await page.evaluate(() => fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }));
  assert.equal(
    await panel
      .getByRole('heading', { name: 'Independent verification expectations', exact: true })
      .count(),
    0,
    'an incomplete audited transfer must not expose files',
  );
  await logoutAccess(page);
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
  );
  await notification(page, 'Logout confirmed.');
  await activeAccess(page, 'alice');
  await result
    .getByText('Signing producer matches the independent expected ID', { exact: true })
    .waitFor();
  assert.equal(
    await page.evaluate(() => window.artifactURLs.size),
    aliceURLs,
    'Bob logout must leave only the original Alice-owned export intact',
  );
  await logoutAccess(page);
  await page.locator('[data-connection-active="true"]').waitFor({ state: 'detached' });
  assert.equal(await panel.count(), 0);
  assert.equal(
    await page.evaluate(() => window.artifactURLs.size),
    0,
    'owning access logout revokes every retained local export',
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
  assert.equal(
    await page.evaluate(() => window.artifactStorageWrites),
    0,
    'no local keys, selectors or plaintext may be persisted by the artifact view',
  );
  assert(
    await page.evaluate(() =>
      window.ownedWorkers.every(
        (worker) =>
          worker.terminated &&
          worker.requests.every(
            (request) =>
              !request.includes('bwa1.') &&
              !request.includes('fixture secret') &&
              !request.includes('offline-private'),
          ),
      ),
    ),
  );
  console.log(JSON.stringify({ success: true }));
} finally {
  await browser.close();
}

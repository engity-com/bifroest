import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
assert(
  [
    'ui-clear',
    'ui-encrypted',
    'ui-audit-clear',
    'ui-audit-encrypted',
    'ui-cancel-clear',
    'ui-cancel-encrypted',
  ].includes(mode),
);
const encrypted = mode.endsWith('-encrypted');
const scenario = mode.startsWith('ui-audit-')
  ? 'audit'
  : mode.startsWith('ui-cancel-')
    ? 'cancel'
    : 'recording';
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
        this.workerName = options?.name ?? '';
        this.requests = [];
        this.playbackDigests = [];
        this.ready = false;
        this.sentVerification = false;
        this.failureCode = null;
        this.addEventListener('message', (event) => {
          if (event.data?.kind === 'ready') {
            this.ready = true;
          }
          if (event.data?.kind === 'failed') {
            this.failureCode = ['input', 'key', 'verification', 'limit', 'unavailable'].includes(
              event.data.code,
            )
              ? event.data.code
              : 'unknown';
          }
        });
        window.ownedWorkers.push(this);
      }
      postMessage(value, transfer) {
        this.requests.push(JSON.stringify(value));
        if (value.kind === 'verify') {
          this.sentVerification = true;
        }
        if (value.kind === 'playback' && value.data instanceof Blob) {
          this.playbackDigests.push(
            value.data
              .arrayBuffer()
              .then((bytes) => crypto.subtle.digest('SHA-256', bytes))
              .then((digest) =>
                [...new Uint8Array(digest)]
                  .map((byte) => byte.toString(16).padStart(2, '0'))
                  .join(''),
              ),
          );
        }
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
  const sessionGrants = [];
  const logoutGrants = [];
  let sockets = 0;
  page.on('websocket', () => {
    sockets++;
  });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => {
    if (new URL(request.url()).pathname.includes('/api/')) {
      apiRequests.push(new URL(request.url()).pathname);
      if (request.url().endsWith('/management/sessions/list')) {
        sessionGrants.push(request.headers().authorization);
      }
      if (request.url().endsWith('/logout')) {
        logoutGrants.push(request.headers().authorization);
      }
      const body = request.postData() ?? '';
      assert(
        !body.includes('PRIVATE KEY') &&
          !body.includes('fixture secret') &&
          !body.includes('offline-private'),
      );
      if (request.url().endsWith('/management/version/show')) {
        assert.deepEqual(
          JSON.parse(body),
          { slug: 'Work', long: 'false' },
          'the first Server view requests only the short version',
        );
      }
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
  await page.getByRole('table', { name: 'Live session metadata', exact: true }).waitFor();
  const alicePaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
  const alicePane = page.locator(`#${alicePaneID}`);
  const aliceNode = await alicePane.elementHandle();
  assert.deepEqual(
    apiRequests
      .filter((path) => path.includes('/management/'))
      .map((path) => path.split('/management/')[1]),
    ['sessions/list'],
    'sign-in reads only the first active Sessions page, without downloading or preparing evidence',
  );
  await workspace(page, 'Server');
  await page
    .getByRole('table', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  const entry = await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-id', { credentials: 'omit' }).then((response) =>
      response.json(),
    ),
  );
  const panel = page.getByRole('region', {
    name: 'Recordings & audit',
    exact: true,
  });
  await workspace(page, 'Recordings & audit');
  const recordings = panel.getByRole('table', { name: 'Recordings · default', exact: true });
  await recordings
    .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
    .waitFor();
  assert.deepEqual(
    apiRequests
      .filter((path) => path.includes('/management/'))
      .map((path) => path.split('/management/')[1]),
    ['sessions/list', 'version/show', 'flows/list', 'auditlogs/list', 'recordings/list'],
    'first visible views read their exact metadata paths; a single recording source loads its page once',
  );
  assert.deepEqual(requests, [], 'finding a recording must never download it automatically');
  await recordings.getByRole('button', { name: `Open recording ${entry.id}`, exact: true }).click();
  await panel.getByRole('heading', { name: 'Check the recording', exact: true }).waitFor();
  assert.equal(
    await panel.getByRole('region', { name: 'Verification details', exact: true }).count(),
    0,
  );
  await panel
    .getByText(
      'Choose how this recording should be protected. No server-supplied identity is trusted automatically.',
      { exact: true },
    )
    .waitFor();
  assert.equal(await panel.getByLabel('Trusted signing ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel.getByLabel('Trusted signing ID', { exact: false }).getAttribute('maxlength'),
    '64',
  );
  assert.equal(
    await panel.getByRole('button', { name: 'Check and open', exact: true }).isEnabled(),
    false,
  );
  assert.deepEqual(
    requests,
    [{ slug: 'Work', auditlog: 'default', id: entry.id }],
    'the row Open action downloads its exact target once',
  );
  const callsBeforeNavigation = apiRequests.length;
  await workspace(page, 'Server');
  await workspace(page, 'Recordings & audit');
  assert.equal(
    apiRequests.length,
    callsBeforeNavigation,
    'switching views must not replay a transfer',
  );
  assert.equal(await panel.getByLabel('Trusted signing ID', { exact: false }).inputValue(), '');
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
      .getByRole('checkbox', {
        name: 'Continue without independently confirming the signing identity',
        exact: true,
      })
      .isChecked(),
    false,
  );
  assert.equal(
    await panel.getByRole('button', { name: 'Save verified export', exact: true }).count(),
    0,
  );
  const advanced = async () => {
    const summary = panel.getByText('Advanced verification options', { exact: true });
    if (!(await summary.locator('..').evaluate((node) => node.open))) {
      await summary.click();
    }
  };
  const result = panel.getByRole('region', { name: 'Verification details', exact: true });
  let lastVerificationInputs = null;
  const resultDetails = async (stage = 'verification') => {
    const failed = panel.getByRole('status').filter({
      hasText:
        /^(?:Evidence verification failed\.|The local decryption key could not be imported|Check the exact selectors, independent expectations|The artifact exceeded|Local evidence processing failed|Artifact operation cancelled\.)/u,
    });
    try {
      await result.or(failed).waitFor();
      assert.equal(
        await failed.count(),
        0,
        'the explicitly requested verification must succeed, not merely leave a missing result',
      );
    } catch (cause) {
      const workerState = await page.evaluate(() => {
        const worker = window.ownedWorkers
          .filter((entry) => entry.workerName === 'bifroest-evidence')
          .at(-1);
        return {
          available: worker !== undefined,
          ready: worker?.ready === true,
          verificationSent: worker?.sentVerification === true,
          terminated: worker?.terminated === true,
          code: worker?.failureCode ?? 'none',
        };
      });
      throw new Error(JSON.stringify({ stage, fields: lastVerificationInputs, workerState }), {
        cause,
      });
    }
    const summary = result.getByText('Signature, source and export details', { exact: true });
    if (!(await summary.locator('..').evaluate((node) => node.open))) {
      await summary.click();
    }
  };
  const editVerification = async () => {
    await result.getByRole('button', { name: 'Change verification settings', exact: true }).click();
    assert.equal(await result.count(), 0, 'changing expectations must retire the old result');
    await panel.getByRole('heading', { name: 'Check the recording', exact: true }).waitFor();
    if (await panel.getByLabel('Decryption key file (local only)', { exact: true }).count()) {
      assert.equal(
        await panel
          .getByLabel('Decryption key file (local only)', { exact: true })
          .evaluate((input) => input.files.length),
        0,
        'reopening expectations cannot retain the local key input',
      );
      assert.equal(
        await panel
          .getByLabel('Decryption passphrase (optional, local only)', { exact: true })
          .evaluate((input) => input.value === ''),
        true,
      );
    }
  };
  const choose = async (label, option) => {
    if (label === 'Verification depth' || label === 'Audit verification scope') {
      await advanced();
    }
    await panel.getByRole('combobox', { name: label, exact: true }).click();
    await page.getByRole('option', { name: option, exact: true }).click();
  };
  const producer = panel.getByLabel('Trusted signing ID', { exact: false });
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
  const verify = async () => {
    lastVerificationInputs = await panel.locator('.artifact-verification').evaluate((form) => {
      const pin = form.querySelector('input[maxlength="64"]');
      const recipient = form.querySelector('input[maxlength="50"]');
      const key = form.querySelector('[name="evidence-private"]');
      const password = form.querySelector('[name="evidence-passphrase"]');
      const option = (label, allowed) => {
        const control = [...form.querySelectorAll('[role="combobox"]')].find((entry) =>
          (entry.getAttribute('aria-labelledby') ?? '')
            .split(/\s+/u)
            .some((id) => document.getElementById(id)?.textContent?.startsWith(label)),
        );
        const value = control?.parentElement?.querySelector('input')?.value;
        return value === undefined ? 'unavailable' : allowed.includes(value) ? value : 'invalid';
      };
      return {
        pinAvailable: pin !== null,
        pinValid: /^[0-9a-f]{64}$/u.test(pin?.value ?? '') && !/^0+$/u.test(pin?.value ?? ''),
        recipientAvailable: recipient !== null,
        recipientValid: /^SHA256:[A-Za-z0-9+/]{43}$/u.test(recipient?.value ?? ''),
        keyAvailable: key !== null,
        keySelected: key?.files?.length === 1,
        keyValid:
          key?.files?.length === 1 && key.files[0].size > 0 && key.files[0].size <= 64 << 10,
        passphraseAvailable: password !== null,
        passphrasePresent: (password?.value.length ?? 0) > 0,
        passphraseValid:
          password !== null && password.value.length <= 4096 && password.value.isWellFormed(),
        inputsValid: [...form.querySelectorAll('input')].every((input) => input.validity.valid),
        encryption: option('Expected encryption', ['', 'clear', 'encrypted']),
        level: option('Verification depth', ['outer', 'private']),
        auditScope: option('Audit verification scope', ['complete', 'captured-prefix']),
      };
    });
    await panel.getByRole('button', { name: 'Check and open', exact: true }).click();
  };
  const save = async () => {
    const downloading = page.waitForEvent('download');
    await result.getByRole('button', { name: 'Save verified export', exact: true }).click();
    const downloaded = await downloading;
    const chunks = [];
    for await (const chunk of await downloaded.createReadStream()) {
      chunks.push(chunk);
    }
    return { filename: downloaded.suggestedFilename(), bytes: Buffer.concat(chunks) };
  };

  async function recordingScenario() {
    await advanced();
    assert.equal(
      await panel
        .getByRole('radio', { name: 'Open content, prepare playback or export', exact: true })
        .isChecked(),
      true,
    );
    assert.equal(
      await panel
        .getByRole('checkbox', {
          name: 'Prepare a verified local export after full success',
          exact: true,
        })
        .isChecked(),
      true,
    );
    await panel
      .getByRole('radio', { name: 'Check signatures only (no content or playback)', exact: true })
      .check();
    await choose(
      'Expected encryption',
      encrypted ? 'This recording should be encrypted' : 'This recording should be unencrypted',
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
    await resultDetails();
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
      await panel.getByRole('button', { name: 'Save verified export', exact: true }).count(),
      0,
    );
    await editVerification();
    await advanced();
    await panel
      .getByRole('radio', { name: 'Open content, prepare playback or export', exact: true })
      .check();
    assert.equal(await result.count(), 0, 'changing expectations must retire the old result');
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
          .evaluate((input) => input.value === ''),
        true,
      );
      assert.equal(
        await panel
          .getByLabel('Decryption key file (local only)', { exact: true })
          .evaluate((input) => input.files.length),
        0,
      );
    }
    await localKey();
    const beforePlayback = apiRequests.length;
    const titleBefore = await page.title();
    const pagesBefore = context.pages().length;
    await verify();
    await resultDetails();
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
    const cast = await save();
    assert.equal(cast.filename, `recording-${entry.id}.cast`);
    assert(cast.bytes.toString().includes('# bifroest:signature:v1 '));
    const playback = panel.getByRole('region', { name: 'Recording playback', exact: true });
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    assert.equal(
      await panel.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
      0,
      'the expectations form retires after success',
    );
    const playbackPreparations = () =>
      page.evaluate(() =>
        window.ownedWorkers
          .filter((worker) => worker.workerName === 'bifroest-playback')
          .map((worker) => worker.requests.map((request) => JSON.parse(request))),
      );
    const prepared = await playbackPreparations();
    assert.equal(
      prepared.length,
      1,
      'the explicit Open intent prepares the exact verified Cast once',
    );
    assert.deepEqual(
      prepared[0]
        .filter((request) => request.kind === 'playback')
        .map((request) => request.options),
      [{ id: entry.id, producer: entry.producer, allowUntrusted: false }],
    );
    assert.deepEqual(
      await page.evaluate(() =>
        Promise.all(
          window.ownedWorkers
            .filter((worker) => worker.workerName === 'bifroest-playback')
            .flatMap((worker) => worker.playbackDigests),
        ),
      ),
      [createHash('sha256').update(cast.bytes).digest('hex')],
      'the player’s Go verifier must receive the exact independently checked Cast bytes',
    );
    assert.equal(
      (await playback.locator('.xterm-accessibility-tree').textContent()).includes('PLAYBACK_ONLY'),
      false,
      'preparation must not auto-play',
    );
    await playback.getByRole('button', { name: 'Play', exact: true }).click();
    await playback.locator('[data-playback-phase="ended"]').waitFor();
    assert.equal(
      await playback.getByRole('button', { name: 'Play again', exact: true }).isEnabled(),
      true,
    );
    await playback
      .getByRole('region', { name: 'Read-only recording viewport', exact: true })
      .scrollIntoViewIfNeeded();
    await page.waitForFunction(() =>
      document
        .querySelector('.playback-surface .xterm-accessibility-tree')
        ?.textContent?.includes('PLAYBACK_ONLY'),
    );
    assert.equal(
      await page.title(),
      titleBefore,
      'recorded OSC title cannot rename the application',
    );
    const link = await playback
      .locator('.xterm-accessibility-tree')
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
    await playback.getByRole('button', { name: 'Start over', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    // Playback state and xterm's asynchronously updated accessibility view have
    // separate completion events. Require the actual cleared view, not a delay.
    await page.waitForFunction(() => {
      const view = document.querySelector('.playback-surface .xterm-accessibility-tree');
      return view !== null && !view.textContent.includes('PLAYBACK_ONLY');
    });
    assert.equal(
      (await playback.locator('.xterm-accessibility-tree').textContent()).includes('PLAYBACK_ONLY'),
      false,
    );
    await playback.getByRole('combobox', { name: 'Speed', exact: true }).click();
    await page.getByRole('option', { name: '2', exact: true }).click();
    await playback.getByRole('button', { name: 'Play', exact: true }).click();
    await playback.locator('[data-playback-phase="ended"]').waitFor();
    await playback.getByRole('button', { name: 'Start over', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    await playback.getByRole('button', { name: 'Play', exact: true }).click();
    await playback.getByRole('button', { name: 'Pause', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    assert.equal(apiRequests.length, beforePlayback, 'playback must not issue API requests');
    assert.equal(sockets, 0, 'local playback must not open a live terminal socket');
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 1);
    await playback.getByRole('button', { name: 'Close player', exact: true }).click();
    assert.equal(await playback.locator('.xterm').count(), 0);
    await workspace(page, 'Server');
    await workspace(page, 'Recordings & audit');
    await page.evaluate(
      () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
    );
    assert.equal(
      (await playbackPreparations()).length,
      1,
      'returning to the view cannot restart a closed player',
    );
    assert.equal(await playback.locator('.xterm').count(), 0);
    assert.equal(
      apiRequests.length,
      beforePlayback,
      'closing or reopening the view must not replay a transfer or authentication',
    );
    await playback.getByRole('button', { name: 'Prepare player', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    assert.equal(
      (await playbackPreparations()).length,
      2,
      'a closed player requires one explicit new preparation',
    );
    assert.equal(apiRequests.length, beforePlayback);
    await editVerification();
    await panel
      .getByRole('checkbox', {
        name: 'Continue without independently confirming the signing identity',
        exact: true,
      })
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
      .getByText('Signature checked. The signing identity has not been independently confirmed.', {
        exact: true,
      })
      .first()
      .waitFor();
    await resultDetails();
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
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    await save();
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 1);
  }

  async function openAudit() {
    await exactArtifactSelection(page);
    assert.equal(
      await panel.locator('.playback-surface .xterm').count(),
      0,
      'opening another artifact retires the recording renderer',
    );
    assert.equal(
      await page.evaluate(() => window.artifactURLs.size),
      0,
      'changing artifacts revokes the preceding plaintext export',
    );
    await choose('Artifact type', 'Audit inventory');
    assert.equal(await result.count(), 0);
    await panel.getByRole('button', { name: 'Open audit log', exact: true }).click();
    await panel.getByRole('heading', { name: 'Check the recording', exact: true }).waitFor();
    assert.equal(
      await panel
        .getByRole('checkbox', {
          name: 'Continue without independently confirming the signing identity',
          exact: true,
        })
        .isChecked(),
      false,
    );
    assert.equal(await producer.inputValue(), '');
    await producer.fill(entry.producer);
    await choose(
      'Expected encryption',
      encrypted ? 'This recording should be encrypted' : 'This recording should be unencrypted',
    );
    if (encrypted) {
      await panel
        .getByLabel('Expected recipient fingerprint', { exact: false })
        .fill(entry.recipient);
    }
  }

  async function auditScenario() {
    // Preserve the real recording -> audit trust-reset boundary, without also
    // running every independent player attack/verification attempt in this peer.
    await producer.fill(entry.producer);
    await panel
      .getByRole('checkbox', {
        name: 'Continue without independently confirming the signing identity',
        exact: true,
      })
      .check();
    await choose(
      'Expected encryption',
      encrypted ? 'This recording should be encrypted' : 'This recording should be unencrypted',
    );
    if (encrypted) {
      await panel
        .getByLabel('Expected recipient fingerprint', { exact: false })
        .fill(entry.recipient);
    }
    await localKey();
    await verify();
    await resultDetails();
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
    await panel
      .getByRole('region', { name: 'Recording playback', exact: true })
      .locator('[data-playback-phase="paused"]')
      .waitFor();
    await save();
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 1);
    await openAudit();
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
    await resultDetails();
    await result
      .getByText('Complete supplied chain ending at its signed head', { exact: true })
      .waitFor();
    const audit = await save();
    assert.equal(audit.filename, 'audit-default.jsonl');
    assert(audit.bytes.length > 0);
    assert(
      !audit.bytes.toString().includes('"flow"') && !audit.bytes.toString().includes('"sessionId"'),
    );
    await editVerification();
    await advanced();
    await panel.getByRole('checkbox', { name: 'Include sensitive fields', exact: false }).check();
    assert.equal(await result.count(), 0);
    await localKey();
    await verify();
    await resultDetails();
    await result.getByText('Sensitive fields explicitly included', { exact: true }).waitFor();
    const sensitiveAudit = await save();
    assert(sensitiveAudit.bytes.toString().includes('"flow"'));
    await editVerification();
    await choose('Audit verification scope', 'Captured signed prefix (not the latest head)');
    await localKey();
    await verify();
    await resultDetails();
    await result
      .getByText('Captured signed prefix (not the latest head)', { exact: true })
      .waitFor();
    await result
      .getByText('Not established; newer evidence may exist or have been withheld', { exact: true })
      .waitFor();
    assert.deepEqual(requests, [
      { slug: 'Work', auditlog: 'default', id: entry.id },
      { slug: 'Work', auditlog: 'default' },
    ]);
    const prefix = await save();
    assert.equal(prefix.filename, 'audit-default.jsonl');
    assert(prefix.bytes.length > 0);
  }

  async function cancelScenario() {
    await openAudit();
    await localKey();
    await verify();
    await resultDetails();
    await result
      .getByText('Complete supplied chain ending at its signed head', { exact: true })
      .waitFor();
    await save();
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 1);
    assert.deepEqual(requests, [
      { slug: 'Work', auditlog: 'default', id: entry.id },
      { slug: 'Work', auditlog: 'default' },
    ]);
    await panel.getByRole('button', { name: 'Close recording', exact: true }).click();
    assert.equal(await result.count(), 0);
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 0);
    await exactArtifactSelection(page);
    await panel.getByRole('button', { name: 'Open audit log', exact: true }).click();
    await panel.getByRole('heading', { name: 'Check the recording', exact: true }).waitFor();
    assert.equal(await producer.inputValue(), '');
    await producer.fill(entry.producer);
    await choose(
      'Expected encryption',
      encrypted ? 'This recording should be encrypted' : 'This recording should be unencrypted',
    );
    if (encrypted) {
      await panel
        .getByLabel('Expected recipient fingerprint', { exact: false })
        .fill(entry.recipient);
    }
    let release;
    let entered;
    let retired;
    const holding = new Promise((resolve) => {
      release = resolve;
    });
    const entering = new Promise((resolve) => {
      entered = resolve;
    });
    const retiring = new Promise((resolve) => {
      retired = resolve;
    });
    await context.route('**/browser-evidence.wasm.gz', async (route) => {
      entered();
      await holding;
      try {
        await route.abort().catch(() => undefined);
      } finally {
        retired();
      }
    });
    await localKey();
    await verify();
    await entering;
    await panel.getByRole('button', { name: 'Cancel artifact operation', exact: true }).click();
    release();
    await retiring;
    await panel.getByText('Artifact operation cancelled.', { exact: false }).waitFor();
    await panel
      .getByRole('button', { name: 'Cancel artifact operation', exact: true })
      .waitFor({ state: 'hidden' });
    await panel
      .getByRole('button', { name: 'Check and open', exact: true })
      .waitFor({ state: 'visible' });
    assert.equal(await result.count(), 0);
    if (encrypted) {
      assert.equal(
        await panel
          .getByLabel('Decryption key file (local only)', { exact: true })
          .evaluate((input) => input.files.length),
        0,
      );
      assert.equal(
        await panel
          .getByLabel('Decryption passphrase (optional, local only)', { exact: true })
          .evaluate((input) => input.value === ''),
        true,
      );
    }
    await context.unroute('**/browser-evidence.wasm.gz');
    await localKey();
    await verify();
    assert.equal(
      lastVerificationInputs.inputsValid,
      true,
      'the explicit post-cancel attempt must submit valid inputs',
    );
    assert.equal(lastVerificationInputs.level, 'private');
    assert.equal(lastVerificationInputs.auditScope, 'complete');
    if (encrypted) {
      assert.equal(lastVerificationInputs.encryption, 'encrypted');
      assert.equal(
        lastVerificationInputs.keySelected &&
          lastVerificationInputs.keyValid &&
          lastVerificationInputs.passphrasePresent &&
          lastVerificationInputs.passphraseValid,
        true,
        'the post-cancel attempt must explicitly reselect its local key and passphrase before submitting',
      );
    }
    await resultDetails('after-cancel');
    await result
      .getByText('Signing producer matches the independent expected ID', { exact: true })
      .waitFor();
    await save();
    const aliceURLs = await page.evaluate(() => window.artifactURLs.size);
    assert(aliceURLs > 0, 'the original access owns its prepared local export');
    await reauthenticate(page);
    await page.getByLabel('User name', { exact: true }).fill('bob');
    await page.getByLabel('Password', { exact: true }).fill('correct');
    const bobSessionsReply = page.waitForResponse((response) =>
      response.url().endsWith('/management/sessions/list'),
    );
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, 'bob');
    assert.equal((await bobSessionsReply).status(), 200);
    const bobPaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
    const bobPane = page.locator(`#${bobPaneID}`);
    assert.equal(bobPaneID !== alicePaneID, true);
    assert.equal(await bobPane.getAttribute('data-connection-principal'), 'bob');
    await bobPane.getByRole('table', { name: 'Live session metadata', exact: true }).waitFor();
    assert.equal(sessionGrants.length, 2);
    assert.equal(
      sessionGrants[0] !== undefined &&
        sessionGrants[1] !== undefined &&
        sessionGrants[0] !== sessionGrants[1],
      true,
      'the two panes must own distinct authenticated grants',
    );
    await workspace(page, 'Recordings & audit');
    await panel.getByRole('table', { name: 'Recordings · default', exact: true }).waitFor();
    assert.equal(
      await panel.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
      0,
    );
    assert.equal(await result.count(), 0, 'Bob must not inherit Alice’s verification result');
    assert.equal(
      await panel.getByRole('region', { name: 'Recording playback', exact: true }).count(),
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
    await panel.getByRole('button', { name: 'Open audit log', exact: true }).click();
    await page.evaluate(() => fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }));
    assert.equal(
      await panel.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
      0,
      'an incomplete audited transfer must not expose files',
    );
    const bobLogoutReply = page.waitForResponse((response) => response.url().endsWith('/logout'));
    await logoutAccess(page);
    await page.evaluate(() =>
      fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
    );
    const bobLogout = await bobLogoutReply;
    assert.equal(bobLogout.status(), 204);
    assert.equal(
      bobLogout.request().headers().authorization === sessionGrants[1],
      true,
      'the interrupted transfer owner, Bob, is the exact logout target',
    );
    await bobPane.waitFor({ state: 'detached' });
    await notification(page, 'Logout confirmed.');
    await activeAccess(page, 'alice');
    assert.equal(
      await aliceNode.evaluate((node) => node.isConnected),
      true,
      'Bob logout must not remount or retire Alice’s evidence owner',
    );
    assert.equal(await page.getByRole('tab').count(), 1);
    assert.equal(logoutGrants.length, 1, 'Bob logout must not silently log out Alice as well');
    await result
      .getByText('Signing producer matches the independent expected ID', { exact: true })
      .waitFor();
    assert.equal(
      await page.evaluate(() => window.artifactURLs.size),
      aliceURLs,
      'Bob logout must leave only the original Alice-owned export intact',
    );
    assert.deepEqual(
      requests,
      [
        { slug: 'Work', auditlog: 'default', id: entry.id },
        { slug: 'Work', auditlog: 'default' },
        { slug: 'Work', auditlog: 'default' },
        { slug: 'Work', auditlog: 'default' },
      ],
      'one recording Open, two deliberate Alice audit Opens and one interrupted Bob audit Open; no replay from verification, playback or actor navigation',
    );
    assert.equal(
      apiRequests.filter((path) => path.endsWith('/login/password')).length,
      2,
      'only the two explicit actor sign-ins authenticate',
    );
    assert.equal(
      apiRequests.filter((path) => path.includes('/remember/')).length,
      0,
      'artifact actions must not enroll or resume authentication',
    );
  }

  // Every mode is its own Go-created server/peer budget. No admission reset,
  // waiting for a fresh minute, automatic retry, or skipped cleanup is involved.
  if (scenario === 'recording') {
    await recordingScenario();
  } else if (scenario === 'audit') {
    await auditScenario();
  } else {
    await cancelScenario();
  }
  const expectedTransfers = [
    { slug: 'Work', auditlog: 'default', id: entry.id },
    ...(scenario === 'recording' ? [] : [{ slug: 'Work', auditlog: 'default' }]),
    ...(scenario === 'cancel'
      ? [
          { slug: 'Work', auditlog: 'default' },
          { slug: 'Work', auditlog: 'default' },
        ]
      : []),
  ];
  assert.deepEqual(
    requests,
    expectedTransfers,
    'only the scenario’s exact explicit Opens may transfer artifacts',
  );
  assert.equal(
    apiRequests.filter((path) => path.endsWith('/login/password')).length,
    scenario === 'cancel' ? 2 : 1,
  );
  assert.equal(apiRequests.filter((path) => path.includes('/remember/')).length, 0);
  assert.equal(sockets, 0, 'all artifact scenarios stay local and must never open a live terminal');
  assert.equal(
    await page.evaluate(() => window.artifactURLs.size),
    1,
    'the owner has exactly its deliberately saved export before explicit logout',
  );
  const aliceLogoutReply = page.waitForResponse((response) => response.url().endsWith('/logout'));
  await logoutAccess(page);
  const aliceLogout = await aliceLogoutReply;
  assert.equal(aliceLogout.status(), 204);
  assert.equal(
    aliceLogout.request().headers().authorization === sessionGrants[0],
    true,
    'retiring Alice’s evidence requires the separately requested logout of her exact grant',
  );
  await alicePane.waitFor({ state: 'detached' });
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.equal(
    logoutGrants.length,
    scenario === 'cancel' ? 2 : 1,
    'only the explicitly requested owner-specific logout requests are permitted',
  );
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

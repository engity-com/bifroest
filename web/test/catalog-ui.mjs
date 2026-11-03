import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import {
  activeAccess,
  assertUiPreferences,
  logoutAccess,
  notification,
  reauthenticate,
  workspace,
} from './workspace-ui.mjs';

const [origin, mode] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(['catalog-clear', 'catalog-encrypted', 'catalog-startup-failure'].includes(mode));
const browser = await chromium.launch({
  headless: true,
  args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
const failedResources = [];
const failedRequests = [];
const artifactErrors = [];
const workerAssets = [];
let observedPage;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addCookies([
    { name: 'unrelated', value: 'not-authentication', url: origin, secure: true },
  ]);
  await context.addInitScript(() => {
    window.cspViolations = [];
    window.addEventListener('securitypolicyviolation', (event) =>
      window.cspViolations.push(event.violatedDirective),
    );
  });
  const page = await context.newPage();
  observedPage = page;
  const errors = [];
  const requests = [];
  const artifactResponses = [];
  page.on('console', async (message) => {
    if (
      message.type() !== 'error' ||
      message.args().length !== 2 ||
      !['[Bifröst/artifact]', '[Bifröst/artifact-catalog]'].includes(
        message.text().split(' ', 1)[0],
      )
    ) {
      return;
    }
    const code = await message
      .args()[1]
      .evaluate((error) => Object.getOwnPropertyDescriptor(error, 'code')?.value);
    artifactErrors.push(
      [
        'unavailable',
        'busy',
        'cancelled',
        'denied',
        'rate-limited',
        'input',
        'artifact-too-large',
      ].includes(code)
        ? code
        : 'unknown',
    );
  });
  context.on('response', (response) => {
    const path = new URL(response.url()).pathname;
    if (/\/(?:browser-transfer-worker\.js|browser-transfer\.wasm|go-wasm-exec\.js)$/u.test(path)) {
      workerAssets.push({ path, status: response.status() });
    }
    if (path.includes('/management/artifacts/')) {
      artifactResponses.push({ path, status: response.status() });
    }
    if (path.startsWith('/_bifroest/') && response.status() >= 400 && failedResources.length < 32) {
      failedResources.push({ path, status: response.status(), at: Date.now() });
    }
  });
  context.on('requestfailed', (request) => {
    const path = new URL(request.url()).pathname;
    if (failedRequests.length < 32) {
      const code = request.failure()?.errorText;
      failedRequests.push({
        path,
        code: /^net::ERR_[A-Z_]+$/u.test(code ?? '') ? code : 'unknown',
        at: Date.now(),
      });
    }
  });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => {
    if (new URL(request.url()).pathname.includes('/management/')) {
      const body = JSON.parse(request.postData() ?? '{}');
      assert(
        !Object.keys(body).some((key) =>
          [
            'command',
            'args',
            'privateKey',
            'passphrase',
            'allowArtifactTransfer',
            'includingCredentials',
            'producer',
            'recipient',
          ].includes(key),
        ),
      );
      assert.equal(new URL(request.url()).search, '');
      assert.equal(request.headers().cookie, undefined);
      requests.push({ path: new URL(request.url()).pathname, body });
    }
  });
  const login = async (user) => {
    await page.getByLabel('User name', { exact: true }).fill(user);
    await page.getByLabel('Password', { exact: true }).fill('correct');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, user);
  };
  const response = await page.goto(`${origin}/Work`);
  assert.equal(response.status(), 200);
  await login('alice');
  await page.getByRole('table', { name: 'Live session metadata', exact: true }).waitFor();
  assert.deepEqual(
    requests.map((request) => request.path.split('/management/')[1]),
    ['sessions/list'],
    'the active Sessions view reads once; sign-in cannot discover artifacts or download',
  );
  const firstSourcesReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/auditlogs/list'),
  );
  await workspace(page, 'Recordings & audit');
  const catalog = page.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  const panel = page.getByRole('region', {
    name: 'Recordings & audit',
    exact: true,
  });
  await panel.evaluate((panel) => {
    window.catalogDownloadProbe = { submits: 0, invalid: 0 };
    const form = panel.querySelector(
      '.artifact-selection > .artifact-selection-grid > details > form',
    );
    form.addEventListener(
      'submit',
      () => {
        window.catalogDownloadProbe.submits++;
      },
      true,
    );
    form.addEventListener(
      'invalid',
      () => {
        window.catalogDownloadProbe.invalid++;
      },
      true,
    );
  });
  async function readPage(response, kind) {
    assert.equal(response.status(), 200);
    const body = await response.json();
    assert.equal(body.version, 1);
    assert.equal(body.operation, `${kind}.list`);
    return body[kind];
  }
  const firstSources = await readPage(await firstSourcesReply, 'auditlogs');
  assert.equal(firstSources.items.length, 20);
  assert.deepEqual(
    firstSources.items.map((row) => row.name),
    Array.from({ length: 20 }, (_, index) => `catalog${String(index).padStart(2, '0')}`),
  );
  assert.match(firstSources.next, /^bmp1\./u);
  assert.deepEqual(
    requests.map((request) => request.path.split('/management/')[1]),
    ['sessions/list', 'auditlogs/list'],
    'only first-visible source metadata loads; multiple sources require an explicit choice',
  );
  await catalog.getByText('Audit log exports', { exact: true }).click();
  const logs = catalog.getByRole('table', {
    name: 'Configured auditlogs (server metadata)',
    exact: true,
  });
  await logs.getByText('catalog00', { exact: true }).waitFor();
  assert.equal(await logs.locator('tbody tr').count(), 20);
  const nextSourcesReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/auditlogs/list'),
  );
  await catalog.getByRole('button', { name: 'More recording sources', exact: true }).click();
  const nextSources = await readPage(await nextSourcesReply, 'auditlogs');
  assert.deepEqual(
    nextSources.items.map((row) => row.name),
    ['catalog20', 'default'],
  );
  assert.equal(nextSources.next, '');
  await logs.getByText('catalog20', { exact: true }).waitFor();
  assert.equal(
    await logs.locator('tbody tr').count(),
    22,
    'source pagination retains the first 20 and appends exactly the two final sources',
  );
  assert.equal(
    await catalog.getByRole('button', { name: 'More recording sources', exact: true }).count(),
    0,
  );
  assert(
    await logs.getByRole('button', { name: 'Open audit log catalog20', exact: true }).isEnabled(),
    'every configured audit log is active; there is no separate enabled flag',
  );
  await logs
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'catalog20', exact: true }) })
    .getByText('Recording disabled', { exact: false })
    .waitFor();
  await catalog.getByRole('combobox', { name: 'Recording source', exact: true }).click();
  assert.equal(await page.getByRole('option').count(), 21);
  assert.equal(
    await page.getByRole('option', { name: 'catalog20', exact: true }).count(),
    0,
    'recording remains a separate opt-in: the recording-disabled logger is not a recording source',
  );
  await page.keyboard.press('Escape');
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 0);
  const beforeAuditOpen = requests.length;
  await logs.getByRole('button', { name: 'Open audit log default', exact: true }).click();
  await waitDownload('audit-open');
  await panel.getByText('Unverified server hints and original files', { exact: true }).click();
  await panel
    .getByRole('region', { name: 'Unverified server hints and original files', exact: true })
    .getByText('default', { exact: true })
    .waitFor();
  assert.equal(await panel.getByLabel('Trusted signing ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel.getByRole('region', { name: 'Verification details', exact: true }).count(),
    0,
  );
  assert.deepEqual(
    requests
      .slice(beforeAuditOpen)
      .map((request) => [request.path.split('/management/')[1], request.body]),
    [['artifacts/audit', { slug: 'Work', auditlog: 'default' }]],
    'opening an audit row is one explicit transfer of its exact target, not a separate selection plus download',
  );
  const beforeBack = requests.length;
  await panel.getByRole('button', { name: 'Back to recordings', exact: true }).click();
  await logs.getByText('catalog20', { exact: true }).waitFor();
  assert.equal(await logs.locator('tbody tr').count(), 22);
  assert.equal(
    requests.length,
    beforeBack,
    'Back retains the catalog without rereading or replaying its open action',
  );
  const firstRecordingsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/recordings/list'),
  );
  await catalog.getByRole('combobox', { name: 'Recording source', exact: true }).click();
  await page.getByRole('option', { name: 'catalog00', exact: true }).click();
  const firstRecordings = await readPage(await firstRecordingsReply, 'recordings');
  const recordings = catalog.getByRole('table', {
    name: 'Recordings · catalog00',
    exact: true,
  });
  await recordings
    .getByRole('button', { name: `Open recording ${firstRecordings.items[0].id}`, exact: true })
    .waitFor();
  assert.equal(firstRecordings.items.length, 20);
  assert.equal(await recordings.locator('tbody tr').count(), 20);
  assert.deepEqual(
    await recordings
      .getByRole('button', { name: /^Open recording / })
      .evaluateAll((buttons) =>
        buttons.map((button) => button.getAttribute('aria-label').slice('Open recording '.length)),
      ),
    firstRecordings.items.map((row) => row.id),
  );
  await catalog
    .getByText('Details reported by the server; not independent verification.', { exact: true })
    .waitFor();
  assert.match(firstRecordings.next, /^bmp1\./u);
  const nextRecordingsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/recordings/list'),
  );
  await catalog.getByRole('button', { name: 'More recordings', exact: true }).click();
  const nextRecordings = await readPage(await nextRecordingsReply, 'recordings');
  assert.equal(nextRecordings.items.length, 1);
  assert.equal(nextRecordings.next, '');
  const allRecordings = [...firstRecordings.items, ...nextRecordings.items];
  assert.deepEqual(
    allRecordings.map((row) => row.id).sort(),
    Array.from(
      { length: 21 },
      (_, index) => `${(index + 1).toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`,
    ),
    'both real cursor pages contain exactly the 21 fixture recordings, without duplicates or omissions',
  );
  for (const [index, row] of allRecordings.entries()) {
    assert.equal(
      row.verificationScope,
      mode === 'catalog-encrypted' ? 'outer' : 'full',
      'server inspection scope remains metadata, never browser verification',
    );
    assert.equal(row.encrypted, mode === 'catalog-encrypted');
    assert.equal(row.format, mode === 'catalog-encrypted' ? 'becast-cbor/v1' : 'bcast/v1');
    if (index > 0) {
      const previous = allRecordings[index - 1];
      assert(
        previous.startedAt > row.startedAt ||
          (previous.startedAt === row.startedAt && previous.id < row.id),
        'newest order must apply globally across the real server cursor boundary',
      );
    }
  }
  const id = nextRecordings.items[0].id;
  await recordings.getByRole('button', { name: `Open recording ${id}`, exact: true }).waitFor();
  assert.equal(await recordings.locator('tbody tr').count(), 1);
  await catalog.getByText('Page 2', { exact: true }).waitFor();
  assert.equal(
    await catalog.getByRole('button', { name: 'More recordings', exact: true }).count(),
    0,
  );
  assert.equal(requests.filter((request) => request.path.endsWith('/artifacts/audit')).length, 1);
  assert.equal(
    requests.filter((request) => request.path.endsWith('/artifacts/recording')).length,
    0,
    'source choice and pagination must not download recordings',
  );
  await recordings.getByRole('button', { name: `Open recording ${id}`, exact: true }).click();
  async function waitDownload(stage) {
    try {
      const heading = panel.getByRole('heading', {
        name: 'Check the recording',
        exact: true,
      });
      const failed = panel
        .getByRole('status')
        .filter({ hasText: 'The artifact download could not be confirmed or is not permitted.' });
      await heading.or(failed).waitFor();
      assert.equal(
        await failed.count(),
        0,
        'a download failure must be reported immediately, not hidden behind a later missing-heading timeout',
      );
      await heading.waitFor();
    } catch (error) {
      const state = await panel.evaluate((panel) => {
        const form = panel.querySelector(
          '.artifact-selection > .artifact-selection-grid > details > form',
        );
        return {
          ...window.catalogDownloadProbe,
          disabled: form.querySelector('button[type="submit"]').disabled,
          invalidControls: [...form.querySelectorAll(':invalid')].map((input) => ({
            tag: input.tagName,
            missing: input.validity?.valueMissing,
            pattern: input.validity?.patternMismatch,
          })),
          receiving: panel.textContent.includes('Opening recording…'),
          statuses: [...panel.querySelectorAll('[role="status"]')].length,
          hidden: panel.closest('[hidden]') !== null,
        };
      });
      throw new Error(
        JSON.stringify({
          stage,
          requestCount: requests.filter((request) => request.path.includes('/artifacts/')).length,
          artifactResponses,
          workerAssets,
          artifactErrors,
          failedResources,
          failedRequests,
          publicState: state,
        }),
        { cause: error },
      );
    }
  }
  await waitDownload('first-download');
  await panel.getByText('Unverified server hints and original files', { exact: true }).click();
  await panel
    .getByRole('region', { name: 'Unverified server hints and original files', exact: true })
    .getByText(`catalog00 / ${id}`, { exact: true })
    .waitFor();
  assert.equal(await panel.getByLabel('Trusted signing ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel.getByLabel('Trusted signing ID', { exact: false }).getAttribute('maxlength'),
    '64',
  );
  assert.equal(
    await panel
      .getByRole('combobox', { name: 'Expected encryption', exact: true })
      .locator('..')
      .locator('input')
      .inputValue(),
    '',
  );
  await panel.getByRole('combobox', { name: 'Expected encryption', exact: true }).click();
  await page
    .getByRole('option', { name: 'This recording should be encrypted', exact: true })
    .click();
  assert.equal(
    await panel.getByLabel('Expected recipient fingerprint', { exact: false }).inputValue(),
    '',
  );
  await panel.getByLabel('Trusted signing ID', { exact: false }).fill('a'.repeat(64));
  await panel
    .getByLabel('Expected recipient fingerprint', { exact: false })
    .fill(`SHA256:${'A'.repeat(43)}`);
  assert.equal(
    await panel.getByRole('button', { name: 'Check and open', exact: true }).isEnabled(),
    false,
    'private verification also requires the local decryption key',
  );
  const beforeReturn = requests.length;
  await panel.getByRole('button', { name: 'Back to recordings', exact: true }).click();
  await recordings.getByRole('button', { name: `Open recording ${id}`, exact: true }).waitFor();
  assert.equal(await recordings.locator('tbody tr').count(), 1);
  assert.equal(
    requests.length,
    beforeReturn,
    'returning to page 2 cannot replay metadata reads or downloads',
  );
  assert.equal(
    await panel.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
    0,
  );
  assert.equal(
    await panel.getByRole('region', { name: 'Verification details', exact: true }).count(),
    0,
  );
  if (mode === 'catalog-startup-failure') {
    let blockedStarts = 0;
    await context.route(
      '**/_bifroest/files/browser-transfer-worker.js',
      (route) => {
        blockedStarts++;
        return route.abort('connectionfailed');
      },
      { times: 1 },
    );
    await recordings.getByRole('button', { name: `Open recording ${id}`, exact: true }).click();
    await panel
      .getByRole('status')
      .filter({ hasText: 'The artifact download could not be confirmed or is not permitted.' })
      .waitFor();
    assert.equal(blockedStarts, 1);
    assert.equal(
      requests.filter((request) => request.path.endsWith('/artifacts/recording')).length,
      1,
      'a worker startup failure must not start a recording request or replay the previous download',
    );
    assert.equal(
      await panel.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
      0,
    );
    assert.equal(
      await panel.getByRole('region', { name: 'Verification details', exact: true }).count(),
      0,
    );
    await page.evaluate(
      () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
    );
    assert.equal(blockedStarts, 1, 'there must be no automatic worker restart');
    assert.equal(
      requests.filter((request) => request.path.endsWith('/artifacts/recording')).length,
      1,
    );
    assert.equal(requests.filter((request) => request.path.endsWith('/artifacts/audit')).length, 1);
    await panel.getByRole('button', { name: 'Try opening again', exact: true }).click();
  } else {
    await recordings.getByRole('button', { name: `Open recording ${id}`, exact: true }).click();
  }
  await waitDownload('second-download');
  assert.equal(await panel.getByLabel('Trusted signing ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel
      .getByRole('combobox', { name: 'Expected encryption', exact: true })
      .locator('..')
      .locator('input')
      .inputValue(),
    '',
  );
  assert.equal(
    requests.filter((request) => request.path.endsWith('/artifacts/recording')).length,
    2,
    'only the two explicit clicks with a ready worker may download',
  );
  assert.deepEqual(
    requests
      .filter((request) => request.path.includes('/artifacts/'))
      .map((request) => [request.path.split('/management/')[1], request.body]),
    [
      ['artifacts/audit', { slug: 'Work', auditlog: 'default' }],
      ['artifacts/recording', { slug: 'Work', auditlog: 'catalog00', id }],
      ['artifacts/recording', { slug: 'Work', auditlog: 'catalog00', id }],
    ],
    'the audit Open and two ready recording Opens are the only transfers; startup failure and Back never replay',
  );
  const recordPages = requests.filter((request) => request.path.endsWith('/recordings/list'));
  assert.equal(recordPages.length, 2);
  assert.equal(recordPages[0].body.auditlog, 'catalog00');
  assert.equal(recordPages[0].body.after, '');
  assert.equal(recordPages[0].body.sort, 'started-desc');
  assert.equal(recordPages[1].body.auditlog, 'catalog00');
  assert.equal(recordPages[1].body.after, firstRecordings.next);
  assert.match(recordPages[1].body.after, /^bmp1\./u);
  const sourcePages = requests.filter((request) => request.path.endsWith('/auditlogs/list'));
  assert.equal(sourcePages.length, 2);
  assert.equal(sourcePages[0].body.after, '');
  assert.equal(sourcePages[1].body.after, firstSources.next);
  await reauthenticate(page);
  await login('bob');
  await page.getByRole('table', { name: 'Live session metadata', exact: true }).waitFor();
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' }),
  );
  // Arm before the first visible catalog: its deliberate initial source read is
  // the provisional operation, and must still wait for the final audit gate.
  const beforeBobCatalog = requests.length;
  await workspace(page, 'Recordings & audit');
  await page.evaluate(() => fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }));
  assert.equal(
    await catalog.locator('table').count(),
    0,
    'new actor must not inherit old catalog data, including collapsed tables',
  );
  assert.equal(
    await catalog.locator('table').count(),
    0,
    'a provisional page must not bypass final audit',
  );
  assert.deepEqual(
    requests.slice(beforeBobCatalog).map((request) => request.path.split('/management/')[1]),
    ['auditlogs/list'],
    'only the new actor’s first-visible source read is in progress; no transfer or old-source recording read',
  );
  await catalog.getByRole('button', { name: 'Cancel catalog request', exact: true }).click();
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
  );
  await catalog.getByText('Catalog request cancelled.', { exact: false }).waitFor();
  assert.equal(await catalog.locator('table').count(), 0);
  const afterCancellation = requests.length;
  await workspace(page, 'Sessions');
  await workspace(page, 'Recordings & audit');
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    requests.length,
    afterCancellation,
    'navigation cannot retry a cancelled first-visible read',
  );
  assert.equal(await catalog.locator('table').count(), 0);
  await catalog.getByRole('button', { name: 'Refresh recordings', exact: true }).click();
  await catalog.getByText('Audit log exports', { exact: true }).click();
  await logs.getByText('catalog00', { exact: true }).waitFor();
  assert.equal(await logs.locator('tbody tr').count(), 20);
  assert.equal(
    requests.filter((request) => request.path.endsWith('/auditlogs/list')).length,
    4,
    'two Alice source pages, one cancelled Bob initial read and one explicit Bob refresh',
  );
  assert.equal(requests.filter((request) => request.path.endsWith('/recordings/list')).length, 2);
  assert.equal(
    requests.filter((request) => request.path.includes('/artifacts/')).length,
    3,
    'catalog cancellation and refresh never start or replay a transfer',
  );
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  assert.equal(await catalog.count(), 0);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
  console.log(JSON.stringify({ success: true }));
} catch (error) {
  const publicState = await observedPage
    ?.evaluate(() => ({
      download: window.catalogDownloadProbe,
      statusCount: document.querySelectorAll('[role="status"]').length,
      recordedAt: Date.now(),
    }))
    .catch(() => ({ unavailable: true }));
  throw new Error(
    JSON.stringify({ failedResources, failedRequests, artifactErrors, workerAssets, publicState }),
    { cause: error },
  );
} finally {
  await browser.close();
}

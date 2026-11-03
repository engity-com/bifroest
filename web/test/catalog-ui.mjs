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
  await workspace(page, 'Recordings & audit');
  const catalog = page.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  const panel = page.getByRole('region', {
    name: 'Artifacts and client-side evidence',
    exact: true,
  });
  await panel.evaluate((panel) => {
    window.catalogDownloadProbe = { submits: 0, invalid: 0 };
    const form = panel.querySelector('.artifact-selection form');
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
  assert.equal(requests.length, 0, 'login must not automatically list or download artifacts');
  await catalog.getByRole('button', { name: 'Load auditlogs', exact: true }).click();
  const logs = catalog.getByRole('table', {
    name: 'Configured auditlogs (server metadata)',
    exact: true,
  });
  await logs.getByText('catalog00', { exact: true }).waitFor();
  assert.equal(await logs.locator('tbody tr').count(), 20);
  await catalog.getByRole('button', { name: 'Next auditlog page', exact: true }).click();
  await logs.getByText('catalog20', { exact: true }).waitFor();
  assert.equal(await logs.locator('tbody tr').count(), 2);
  assert(
    await logs
      .getByRole('button', { name: 'Select audit inventory catalog20', exact: true })
      .isEnabled(),
    'every configured audit log is active; there is no separate enabled flag',
  );
  assert(
    await logs
      .getByRole('button', { name: 'List sealed recordings catalog20', exact: true })
      .isDisabled(),
    'recording remains a separate opt-in and unavailable recording actions stay disabled',
  );
  await catalog
    .getByRole('button', { name: 'Select audit inventory default', exact: true })
    .click();
  assert.equal(
    await panel.getByRole('textbox', { name: 'Artifact auditlog', exact: true }).inputValue(),
    'default',
  );
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 0);
  await catalog.getByRole('button', { name: 'Load auditlogs', exact: true }).click();
  await catalog
    .getByRole('button', { name: 'List sealed recordings catalog00', exact: true })
    .click();
  const recordings = catalog.getByRole('table', {
    name: 'Sealed recordings (server metadata only)',
    exact: true,
  });
  await recordings.getByText('00000001-0000-4000-8000-000000000000', { exact: true }).waitFor();
  assert.equal(await recordings.locator('tbody tr').count(), 20);
  await recordings
    .getByText(
      mode !== 'catalog-encrypted'
        ? 'Server claims full inspection; not browser verification'
        : 'Server claims outer inspection only; not browser verification',
      { exact: true },
    )
    .first()
    .waitFor();
  await catalog.getByRole('button', { name: 'Next recording page', exact: true }).click();
  const id = '00000015-0000-4000-8000-000000000000';
  await recordings.getByText(id, { exact: true }).waitFor();
  assert.equal(await recordings.locator('tbody tr').count(), 1);
  assert.equal(
    await catalog.getByRole('button', { name: 'Next recording page', exact: true }).count(),
    0,
  );
  await recordings.getByRole('button', { name: `Select recording ${id}`, exact: true }).click();
  assert.equal(
    await panel.getByRole('textbox', { name: 'Artifact auditlog', exact: true }).inputValue(),
    'catalog00',
  );
  assert.equal(
    await panel.getByRole('textbox', { name: 'Recording ID', exact: true }).inputValue(),
    id,
  );
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 0);
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  async function waitDownload(stage) {
    try {
      const heading = panel.getByRole('heading', {
        name: 'Independent verification expectations',
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
        const form = panel.querySelector('.artifact-selection form');
        return {
          ...window.catalogDownloadProbe,
          disabled: form.querySelector('button[type="submit"]').disabled,
          invalidControls: [...form.querySelectorAll(':invalid')].map((input) => ({
            tag: input.tagName,
            missing: input.validity?.valueMissing,
            pattern: input.validity?.patternMismatch,
          })),
          receiving: panel.textContent.includes(
            'Receiving artifact; waiting for complete audited transfer…',
          ),
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
  assert.equal(await panel.getByLabel('Expected producer ID', { exact: false }).inputValue(), '');
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
    .getByRole('option', { name: 'Expect SSH-recipient encrypted data', exact: true })
    .click();
  assert.equal(
    await panel.getByLabel('Expected recipient fingerprint', { exact: false }).inputValue(),
    '',
  );
  await panel.getByLabel('Expected producer ID', { exact: false }).fill('a'.repeat(64));
  await panel
    .getByLabel('Expected recipient fingerprint', { exact: false })
    .fill(`SHA256:${'A'.repeat(43)}`);
  await panel.locator('.artifact-selection > summary').click();
  await recordings.getByRole('button', { name: `Select recording ${id}`, exact: true }).click();
  assert.equal(
    await panel
      .getByRole('heading', { name: 'Independent verification expectations', exact: true })
      .count(),
    0,
  );
  assert.equal(
    await panel.getByRole('region', { name: 'Evidence result', exact: true }).count(),
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
    await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
    await panel
      .getByRole('status')
      .filter({ hasText: 'The artifact download could not be confirmed or is not permitted.' })
      .waitFor();
    assert.equal(blockedStarts, 1);
    assert.equal(
      requests.filter((request) => request.path.includes('/artifacts/')).length,
      1,
      'a worker startup failure must not start an artifact request or replay the previous download',
    );
    assert.equal(
      await panel
        .getByRole('heading', { name: 'Independent verification expectations', exact: true })
        .count(),
      0,
    );
    assert.equal(
      await panel.getByRole('region', { name: 'Evidence result', exact: true }).count(),
      0,
    );
    await page.evaluate(
      () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
    );
    assert.equal(blockedStarts, 1, 'there must be no automatic worker restart');
    assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 1);
  }
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await waitDownload('second-download');
  assert.equal(await panel.getByLabel('Expected producer ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel
      .getByRole('combobox', { name: 'Expected encryption', exact: true })
      .locator('..')
      .locator('input')
      .inputValue(),
    '',
  );
  assert.equal(
    requests.filter((request) => request.path.includes('/artifacts/')).length,
    2,
    'only the two explicit clicks with a ready worker may download',
  );
  const recordPages = requests.filter((request) => request.path.endsWith('/recordings/list'));
  assert.equal(recordPages.length, 2);
  assert.equal(recordPages[0].body.auditlog, 'catalog00');
  assert.equal(recordPages[0].body.after, '');
  assert.match(recordPages[1].body.after, /^bmp1\./u);
  await reauthenticate(page);
  await login('bob');
  await workspace(page, 'Recordings & audit');
  assert.equal(
    await catalog.getByRole('table').count(),
    0,
    'new actor must not inherit old catalog data',
  );
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' }),
  );
  await catalog.getByRole('button', { name: 'Load auditlogs', exact: true }).click();
  await page.evaluate(() => fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }));
  assert.equal(
    await catalog.getByRole('table').count(),
    0,
    'a provisional page must not bypass final audit',
  );
  await catalog.getByRole('button', { name: 'Cancel catalog request', exact: true }).click();
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
  );
  await catalog.getByText('Catalog request cancelled.', { exact: false }).waitFor();
  assert.equal(await catalog.getByRole('table').count(), 0);
  await catalog.getByRole('button', { name: 'Load auditlogs', exact: true }).click();
  await logs.getByText('catalog00', { exact: true }).waitFor();
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

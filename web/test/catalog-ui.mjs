import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { managementWire } from './management-wire.mjs';
import { assertCatalogRequestPrivacy, captureJsonResponse } from './response-capture.mjs';
import {
  activeAccess,
  assertUiPreferences,
  confirmFullVerification,
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
  const wire = managementWire(page);
  const requests = [];
  const progress = [];
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  wire.on('progress', (value) => {
    assert(
      [
        'waiting',
        'inventory',
        'metadata',
        'searching',
        'verifying',
        'reverifying',
        'finalizing',
      ].includes(value.phase),
    );
    assert(Number.isSafeInteger(value.completed) && value.completed >= 0);
    assert(Number.isSafeInteger(value.total) && value.total >= -1);
    assert(value.total < 0 || value.completed <= value.total);
    progress.push(value);
  });
  wire.on('request', (request) => {
    const body = JSON.parse(request.postData());
    assertCatalogRequestPrivacy(request);
    assert.equal(request.slug(), 'Work');
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
    requests.push({ path: new URL(request.url()).pathname, body, channel: request.channel() });
  });
  const read = (captured, kind) => {
    assert.equal(captured.error, undefined, 'capture must join the real RPC completion');
    assert.equal(captured.status, 200);
    assert.equal(captured.body.version, 1);
    assert.equal(captured.body.operation, `${kind}.list`);
    return captured.body[kind];
  };
  const capture = (kind) => captureJsonResponse(page, `/_bifroest/api/v1/management/${kind}/list`);
  const login = async (user) => {
    await page.getByLabel('User name', { exact: true }).fill(user);
    await page.getByLabel('Password', { exact: true }).fill('correct');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, user);
    await page
      .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
      .waitFor();
  };
  assert.equal((await page.goto(`${origin}/Work`)).status(), 200);
  await login('alice');
  const firstSourcesReply = capture('auditlogs');
  await workspace(page, 'Recordings');
  const recordPanel = () =>
    page
      .locator('[data-connection-active="true"]')
      .getByRole('region', { name: 'Recordings', exact: true });
  const catalog = () =>
    recordPanel().getByRole('region', { name: 'Artifact catalog (server metadata)', exact: true });
  const firstSources = read(await firstSourcesReply, 'auditlogs');
  assert(
    progress.some(
      (value) =>
        new URL(value.request.url()).pathname.endsWith('/auditlogs/list') &&
        value.phase === 'inventory',
    ),
  );
  assert.equal(firstSources.items.length, 20);
  assert.deepEqual(
    firstSources.items.map((row) => row.name),
    Array.from({ length: 20 }, (_, index) => `catalog${String(index).padStart(2, '0')}`),
  );
  assert.match(firstSources.next, /^bmp1\./u);
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 0);
  const remainingSourcesReply = capture('auditlogs');
  await catalog().getByRole('button', { name: 'More recording sources', exact: true }).click();
  const remaining = read(await remainingSourcesReply, 'auditlogs');
  assert.deepEqual(
    remaining.items.map((row) => row.name),
    ['catalog20', 'default'],
  );
  assert.equal(remaining.next, '');
  await catalog().getByRole('combobox', { name: 'Recording source', exact: true }).click();
  assert.equal(await page.getByRole('option').count(), 21);
  assert.equal(
    await page.getByRole('option', { name: 'catalog20', exact: true }).count(),
    0,
    'a recording-disabled audit log cannot become a recording source',
  );
  await page.keyboard.press('Escape');
  const firstAuditReply = capture('auditlogs');
  await workspace(page, 'Audit logs');
  const auditPanel = () =>
    page
      .locator('[data-connection-active="true"]')
      .getByRole('region', { name: 'Audit logs', exact: true });
  const logs = () =>
    auditPanel().getByRole('grid', { name: 'Configured auditlogs (server metadata)', exact: true });
  const firstAudit = read(await firstAuditReply, 'auditlogs');
  assert.equal(firstAudit.items.length, 20);
  await logs().getByRole('gridcell', { name: 'catalog00', exact: true }).waitFor();
  const lastAuditReply = capture('auditlogs');
  await logs()
    .locator('xpath=ancestor::div[@class="admin-data-grid"][1]')
    .getByRole('button', { name: 'Go to next page', exact: true })
    .click();
  const lastAudit = read(await lastAuditReply, 'auditlogs');
  assert.deepEqual(lastAudit.items, remaining.items);
  await logs().getByRole('gridcell', { name: 'catalog20', exact: true }).waitFor();
  assert.equal(await logs().locator('[role="row"][data-id]').count(), 2);
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 0);
  const beforeAudit = requests.length;
  const previewReply = captureJsonResponse(page, '/_bifroest/api/v1/management/audit-events/list');
  await logs().getByRole('button', { name: 'Open audit log default', exact: true }).click();
  const preview = await previewReply;
  assert.equal(preview.error, undefined);
  assert.equal(preview.status, 200);
  assert.equal(preview.body.operation, 'audit-events.list');
  assert.equal(preview.body.auditEventSource.verification, 'server-overview');
  assert.equal(
    requests.filter((request) => request.path.includes('/artifacts/')).length,
    0,
    'opening an auditlog is metadata-only until explicit verification',
  );
  await confirmFullVerification(page, auditPanel(), 'default');
  const opened = async (current) => {
    const audit = (await current.getAttribute('aria-label')) === 'Audit logs';
    if (!audit) {
      await current
        .and(page.locator('[data-evidence-phase="idle"][data-evidence-input="true"]'))
        .waitFor();
      assert.equal(
        await current.getByRole('region', { name: 'Recording playback', exact: true }).count(),
        0,
      );
      await current.getByRole('button', { name: 'Verify …', exact: true }).click();
      if (mode !== 'catalog-encrypted') {
        await page
          .getByRole('dialog', { name: 'Verification options', exact: true })
          .getByRole('button', { name: 'Start verification', exact: true })
          .click();
      }
    }
    if (mode === 'catalog-encrypted') {
      if (audit) {
        await current.getByRole('button', { name: 'Verify …', exact: true }).click();
      }
      const owner = page.getByRole('dialog', { name: 'Verification options', exact: true });
      try {
        await owner.getByLabel('Decryption key file (local only)', { exact: true }).waitFor();
      } catch (error) {
        throw new Error(
          JSON.stringify({
            stage: 'encrypted-catalog-open',
            route: { pathname: new URL(page.url()).pathname, search: new URL(page.url()).search },
            notices: await current.getByRole('status').allTextContents(),
            transfers: requests
              .filter((request) => request.path.includes('/artifacts/'))
              .map((request) => ({
                path: request.path.split('/management/')[1],
                body: request.body,
              })),
            headings: await current.getByRole('heading').allTextContents(),
          }),
          { cause: error },
        );
      }
      assert.equal(
        await (audit
          ? current.getByRole('region', { name: 'Local audit verification', exact: true })
          : current
        )
          .getByRole('grid', { name: 'Audit events', exact: true })
          .count(),
        0,
      );
      await owner.getByRole('button', { name: 'Cancel', exact: true }).click();
    } else {
      await current
        .getByRole('button', { name: 'Signature, source and export details', exact: true })
        .waitFor();
      await current.locator('[data-verification-result="success"]:visible').waitFor();
    }
  };
  await opened(auditPanel());
  assert.deepEqual(
    requests
      .slice(beforeAudit)
      .map((request) => [request.path.split('/management/')[1], request.body]),
    [
      [
        'audit-events/list',
        { limit: '20', after: '', sort: 'recorded-desc', auditlog: 'default', sensitive: 'false' },
      ],
      ['artifacts/audit', { auditlog: 'default' }],
    ],
    'overview is a page read; explicit local verification is exactly one separate transfer',
  );
  assert.equal(
    await auditPanel()
      .getByRole('button', { name: /^Save unverified original/u })
      .count(),
    0,
    'raw files are not the primary audit view',
  );
  const beforeBack = requests.length;
  const direct = auditPanel().getByRole('button', {
    name: 'Direct data from the server',
    exact: true,
  });
  if (mode === 'catalog-encrypted') {
    assert.equal(await direct.count(), 0, 'awaiting a key is not a locally verified dataset');
  } else {
    await direct.click();
  }
  await auditPanel()
    .getByRole('region', { name: 'Audit overview (server-reported)', exact: true })
    .waitFor();
  await page
    .getByRole('navigation', { name: 'Breadcrumb', exact: true })
    .getByRole('button', { name: 'Audit logs', exact: true })
    .click();
  await logs().getByRole('gridcell', { name: 'catalog20', exact: true }).waitFor();
  assert.equal(requests.length, beforeBack, 'Back retains the native audit page without replay');
  await workspace(page, 'Recordings');
  const firstRecordingsReply = capture('recordings');
  await catalog().getByRole('combobox', { name: 'Recording source', exact: true }).click();
  await page.getByRole('option', { name: 'catalog00', exact: true }).click();
  const first = read(await firstRecordingsReply, 'recordings');
  assert(
    progress.some(
      (value) =>
        new URL(value.request.url()).pathname.endsWith('/recordings/list') &&
        value.phase === 'metadata' &&
        value.completed === 21 &&
        value.total === 21,
    ),
    'normal listing reads metadata, not a whole-source verification',
  );
  assert.equal(
    progress.some(
      (value) =>
        new URL(value.request.url()).pathname.endsWith('/recordings/list') &&
        value.phase === 'verifying',
    ),
    false,
  );
  assert.equal(first.items.length, 20);
  assert.match(first.next, /^bmp1\./u);
  const recordings = () =>
    catalog().getByRole('grid', { name: 'Recordings · catalog00', exact: true });
  await recordings()
    .getByRole('button', { name: `Open recording ${first.items[0].id}`, exact: true })
    .waitFor();
  const visible = await recordings()
    .getByRole('button', { name: /^Open recording /u })
    .evaluateAll((nodes) =>
      nodes.map((node) => node.getAttribute('aria-label').slice('Open recording '.length)),
    );
  assert(visible.length > 0 && visible.length <= 20);
  assert.deepEqual(
    visible,
    first.items.slice(0, visible.length).map((row) => row.id),
  );
  const nextRecordingsReply = capture('recordings');
  await recordings()
    .locator('xpath=ancestor::div[@class="admin-data-grid"][1]')
    .getByRole('button', { name: 'Go to next page', exact: true })
    .click();
  const last = read(await nextRecordingsReply, 'recordings');
  assert.equal(last.items.length, 1);
  assert.equal(last.next, '');
  const all = [...first.items, ...last.items];
  assert.deepEqual(
    all.map((row) => row.id).sort(),
    Array.from(
      { length: 21 },
      (_, index) => `${(index + 1).toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`,
    ),
  );
  for (const [index, row] of all.entries()) {
    assert.equal(row.encrypted, mode === 'catalog-encrypted');
    assert.equal(row.verificationScope, mode === 'catalog-encrypted' ? 'outer' : 'full');
    assert.equal(row.format, mode === 'catalog-encrypted' ? 'becast-cbor/v1' : 'bcast/v1');
    if (index) {
      const previous = all[index - 1];
      assert(
        previous.startedAt > row.startedAt ||
          (previous.startedAt === row.startedAt && previous.id < row.id),
      );
    }
  }
  const id = last.items[0].id;
  const pagesBeforeFull = requests.filter((request) =>
    request.path.endsWith('/recordings/list'),
  ).length;
  const fullReply = captureJsonResponse(page, '/_bifroest/api/v1/management/recordings/verify');
  await confirmFullVerification(page, catalog(), 'catalog00');
  const full = await fullReply;
  assert.equal(full.error, undefined);
  assert.equal(full.status, 200);
  assert.equal(full.body.operation, 'recordings.verify');
  assert.deepEqual(full.body.verification, {
    auditlog: 'catalog00',
    checked: 21,
    full: mode === 'catalog-encrypted' ? 0 : 21,
    outer: mode === 'catalog-encrypted' ? 21 : 0,
    independent: false,
  });
  await recordings()
    .getByRole('button', { name: `Open recording ${id}`, exact: true })
    .waitFor();
  assert.equal(await recordings().locator('[role="row"][data-id]').count(), 1);
  assert.equal(
    requests.filter((request) => request.path.endsWith('/recordings/list')).length,
    pagesBeforeFull,
    'full verification must not reset/reload the displayed page',
  );
  await recordings()
    .getByRole('button', { name: `Open recording ${id}`, exact: true })
    .click();
  await opened(recordPanel());
  assert.equal(
    await recordPanel().getByRole('combobox', { name: 'Expected encryption', exact: true }).count(),
    0,
  );
  assert.equal(
    await recordPanel().getByLabel('Expected recipient fingerprint', { exact: false }).count(),
    0,
  );
  const afterOpen = requests.length;
  await page
    .getByRole('navigation', { name: 'Breadcrumb', exact: true })
    .getByRole('button', { name: 'Recordings', exact: true })
    .click();
  await recordings()
    .getByRole('button', { name: `Open recording ${id}`, exact: true })
    .waitFor();
  assert.equal(requests.length, afterOpen);
  if (mode === 'catalog-startup-failure') {
    let blocked = 0;
    await context.route(
      '**/_bifroest/files/browser-transfer-worker.js',
      (route) => {
        blocked++;
        return route.abort('connectionfailed');
      },
      { times: 1 },
    );
    await recordings()
      .getByRole('button', { name: `Open recording ${id}`, exact: true })
      .click();
    await recordPanel().locator('.recording-video [data-verification-result="failure"]').click();
    const failureDialog = page.getByRole('dialog', {
      name: 'Signature, source and export details',
      exact: true,
    });
    await failureDialog
      .getByText('The artifact download could not be confirmed or is not permitted.', {
        exact: false,
      })
      .waitFor();
    assert.equal(blocked, 1);
    assert.equal(
      requests.filter((request) => request.path.endsWith('/artifacts/recording')).length,
      1,
      'failed worker startup cannot issue or replay a transfer',
    );
    await failureDialog.getByRole('button', { name: 'Try opening again', exact: true }).click();
  } else {
    await recordings()
      .getByRole('button', { name: `Open recording ${id}`, exact: true })
      .click();
  }
  await opened(recordPanel());
  assert.deepEqual(
    requests
      .filter((request) => request.path.includes('/artifacts/'))
      .map((request) => [request.path.split('/management/')[1], request.body]),
    [
      ['artifacts/audit', { auditlog: 'default' }],
      ['artifacts/recording', { auditlog: 'catalog00', id }],
      ['artifacts/recording', { auditlog: 'catalog00', id }],
    ],
  );
  const pages = requests.filter((request) => request.path.endsWith('/recordings/list'));
  assert.equal(pages.length, 2);
  assert.equal(pages[0].body.after, '');
  assert.equal(pages[1].body.after, first.next);
  assert.equal(pages[0].body.sort, 'started-desc');
  assert.equal(pages[1].body.sort, 'started-desc');
  await reauthenticate(page);
  await login('bob');
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' }),
  );
  const beforeBob = requests.length;
  const bobSourcesReply = capture('auditlogs');
  await workspace(page, 'Recordings');
  await page.evaluate(() => fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }));
  assert.equal(
    await catalog().getByRole('grid').locator('[role="row"][data-id]').count(),
    0,
    'new or provisional metadata cannot inherit the other actor rows',
  );
  assert.deepEqual(
    requests.slice(beforeBob).map((request) => request.path.split('/management/')[1]),
    ['auditlogs/list'],
  );
  const loadingGrid = await catalog().getByRole('grid').elementHandle();
  assert.equal(
    await catalog().getByRole('button', { name: 'Refresh recordings', exact: true }).count(),
    0,
  );
  assert.equal(
    await catalog().getByRole('button', { name: 'Cancel catalog request', exact: true }).count(),
    1,
  );
  assert.equal(
    await catalog()
      .getByRole('button', { name: 'Cancel catalog request', exact: true })
      .isEnabled(),
    true,
  );
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
  );
  assert.equal(read(await bobSourcesReply, 'auditlogs').items.length, 20);
  await catalog().getByRole('button', { name: 'Refresh recordings', exact: true }).waitFor();
  assert.equal(
    await loadingGrid.evaluate((node) => node.isConnected),
    true,
    'the same grid survives discovery completion',
  );
  const completed = requests.length;
  await workspace(page, 'Bifröst');
  await workspace(page, 'Recordings');
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    requests.length,
    completed,
    'activation does not repeat the completed bounded metadata read',
  );
  assert.equal(await catalog().getByRole('grid').locator('[role="row"][data-id]').count(), 0);
  const refreshedReply = capture('auditlogs');
  await catalog().getByRole('button', { name: 'Refresh recordings', exact: true }).click();
  assert.equal(read(await refreshedReply, 'auditlogs').items.length, 20);
  assert.equal(requests.filter((request) => request.path.endsWith('/auditlogs/list')).length, 6);
  assert.equal(requests.filter((request) => request.path.endsWith('/recordings/list')).length, 2);
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 3);
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  await activeAccess(page, 'alice');
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  assert.equal(await page.getByRole('tab').count(), 0);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
  console.log(JSON.stringify({ success: true }));
} finally {
  await browser.close();
}

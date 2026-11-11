import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { uuidClassic, uuidText } from '../src/shared/uuid.ts';
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
  const sourceEntries = [];
  const sourceCompletions = [];
  wire.on('source-entry', (value) => sourceEntries.push(value));
  wire.on('source-entry-complete', (value) => sourceCompletions.push(value));
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
  const capture = (kind) => captureJsonResponse(page, `/api/v1/management/${kind}/list`);
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
  await workspace(page, 'Audit logs');
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
  const auditPanel = () =>
    page
      .locator('[data-connection-active="true"]')
      .getByRole('region', { name: 'Audit logs', exact: true });
  const logs = () =>
    auditPanel().getByRole('grid', { name: 'Configured auditlogs (server metadata)', exact: true });
  const sourceControls = () => logs().locator('xpath=ancestor::div[@class="admin-data-grid"][1]');
  const remainingSourcesReply = capture('auditlogs');
  await sourceControls().getByRole('button', { name: 'Go to next page', exact: true }).click();
  const remaining = read(await remainingSourcesReply, 'auditlogs');
  assert.deepEqual(
    remaining.items.map((row) => row.name),
    ['catalog20', 'default'],
  );
  assert.equal(remaining.next, '');
  assert.equal(
    await logs().getByRole('button', { name: 'Recordings catalog20', exact: true }).isEnabled(),
    false,
    'recording-disabled sources retain a disabled recording action',
  );
  assert.equal(
    await auditPanel().getByRole('combobox', { name: 'Recording source', exact: true }).count(),
    0,
  );
  await logs().getByRole('gridcell', { name: 'catalog20', exact: true }).waitFor();
  assert.equal(await logs().locator('[role="row"][data-id]').count(), 2);
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 0);
  const beforeAudit = requests.length;
  const previewReply = captureJsonResponse(page, '/api/v1/management/audit-events/list');
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
  const opened = async (current, audit = false) => {
    if (!audit) {
      await page
        .locator(
          '[data-connection-active="true"] .artifact-panel[aria-label="Recordings"][data-evidence-phase="idle"][data-evidence-input="true"]',
        )
        .waitFor({ state: 'attached' });
      if (mode !== 'catalog-encrypted') {
        // The byte-digest match can finish after download disposal. Await the
        // inherited verdict itself, not an earlier generic idle transition.
        await current
          .locator('.recording-verification [data-verification-result="success"]')
          .waitFor();
      }
      assert.equal(
        await page
          .locator(
            '[data-connection-active="true"] .artifact-panel[aria-label="Recordings"] .recording-verification [data-verification-result]',
          )
          .count(),
        mode === 'catalog-encrypted' ? 0 : 1,
        'only identical bytes from the completed private source verification inherit a verdict',
      );
      if (mode !== 'catalog-encrypted') {
        assert.equal(
          await current
            .locator('.recording-verification')
            .getByRole('button', { name: 'Verify …', exact: true })
            .count(),
          0,
          'reused full verification must not be offered as a new check',
        );
        await current
          .getByRole('region', { name: 'Recording playback', exact: true })
          .locator('[data-playback-phase="paused"]')
          .waitFor();
        return;
      }
    }
    if (mode === 'catalog-encrypted') {
      if (audit) {
        const direct = current.getByRole('button', {
          name: 'Direct data from the server',
          exact: true,
        });
        await direct.waitFor();
        await current
          .getByRole('button', { name: 'Signature, source and export details', exact: true })
          .click();
        const failure = page.getByRole('dialog', {
          name: 'Signature, source and export details',
          exact: true,
        });
        await failure.getByText('key-required', { exact: true }).waitFor();
        await failure.getByRole('button', { name: 'Close', exact: true }).click();
        await failure.waitFor({ state: 'hidden' });
        await direct.click();
        await current.getByRole('button', { name: 'Verify …', exact: true }).click();
      }
      const owner = page.getByRole('dialog', {
        name: audit ? 'Verification options' : 'Decrypt recording',
        exact: true,
      });
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
      await owner.getByRole('button', { name: audit ? 'Cancel' : 'Close', exact: true }).click();
    } else {
      await current
        .getByRole('button', { name: 'Signature, source and export details', exact: true })
        .waitFor();
      await current.locator('[data-verification-result="success"]:visible').waitFor();
    }
  };
  await opened(auditPanel(), true);
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
    .getByRole('link', { name: 'Audit logs', exact: true })
    .click();
  await logs().getByRole('gridcell', { name: 'catalog20', exact: true }).waitFor();
  assert.equal(requests.length, beforeBack, 'Back retains the native audit page without replay');
  const firstRecordingsReply = capture('recordings');
  const previousSourceReply = capture('auditlogs');
  await sourceControls().getByRole('button', { name: 'Go to previous page', exact: true }).click();
  assert.deepEqual(read(await previousSourceReply, 'auditlogs').items, firstSources.items);
  await auditPanel().getByRole('button', { name: 'Recordings catalog00', exact: true }).click();
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
  try {
    await recordings().locator('[role="row"][data-id]').first().waitFor();
  } catch (error) {
    throw new Error(
      JSON.stringify({
        stage: 'recordings-page-render',
        hash: new URL(page.url()).hash,
        errors,
        notices: await recordPanel().getByRole('status').allTextContents(),
        grids: await page.locator('[role="grid"]').evaluateAll((nodes) =>
          nodes.map((node) => ({
            label: node.getAttribute('aria-label'),
            busy: node.getAttribute('aria-busy'),
            visible: node.checkVisibility(),
            rows: [...node.querySelectorAll('[role="row"][data-id]')]
              .map((row) => row.getAttribute('data-id'))
              .slice(0, 20),
            status: [...node.querySelectorAll('[role="status"]')].map((status) =>
              status.textContent?.slice(0, 256),
            ),
          })),
        ),
      }),
      { cause: error },
    );
  }
  await recordings()
    .locator('.MuiDataGrid-virtualScroller')
    .evaluate((node) => node.scrollTo({ left: node.scrollWidth, top: 0 }));
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
    all.map((row) => uuidClassic(row.id)).sort(),
    Array.from(
      { length: 21 },
      (_, index) => `${(index + 1).toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`,
    ),
  );
  for (const [index, row] of all.entries()) {
    assert.equal(row.id, uuidText(row.id), 'wire IDs use canonical Base58');
    assert.equal(row.encrypted, mode === 'catalog-encrypted');
    assert.equal(row.verificationScope, mode === 'catalog-encrypted' ? 'outer' : 'full');
    assert.equal(row.format, mode === 'catalog-encrypted' ? 'becast-cbor/v1' : 'bcast/v1');
    if (index) {
      const previous = all[index - 1];
      assert(
        previous.startedAt > row.startedAt ||
          (previous.startedAt === row.startedAt && uuidClassic(previous.id) < uuidClassic(row.id)),
      );
    }
  }
  const id = last.items[0].id;
  const pagesBeforeFull = requests.filter((request) =>
    request.path.endsWith('/recordings/list'),
  ).length;
  await confirmFullVerification(
    page,
    catalog(),
    'catalog00',
    mode === 'catalog-encrypted' ? 'outer' : 'private',
  );
  await catalog().locator('[data-verification-result="success"]:visible').waitFor();
  await catalog()
    .getByRole('button', { name: 'Signature, source and export details', exact: true })
    .click();
  const resultDialog = page.getByRole('dialog', {
    name: 'Signature, source and export details',
    exact: true,
  });
  const values = await resultDialog
    .locator('dl')
    .evaluate((node) =>
      Object.fromEntries(
        [...node.querySelectorAll('dt')].map((key) => [
          key.textContent,
          key.nextElementSibling?.textContent,
        ]),
      ),
    );
  assert.equal(values['Verification source'], 'catalog00');
  assert.equal(values['Checked recordings'], '21');
  assert.equal(values['Full content'], mode === 'catalog-encrypted' ? '0' : '21');
  assert.equal(values['Encrypted outer envelopes'], mode === 'catalog-encrypted' ? '21' : '0');
  assert.equal(
    values['Producer trust'],
    'Server-provided signing ID; not independently confirmed.',
  );
  await resultDialog.getByRole('button', { name: 'Close', exact: true }).click();
  await resultDialog.waitFor({ state: 'hidden' });
  assert.equal(requests.filter((request) => request.path.endsWith('/recordings/verify')).length, 0);
  assert.equal(
    requests.filter((request) => request.path.endsWith('/artifacts/recordings')).length,
    1,
  );
  assert.equal(sourceEntries.length, 21);
  assert.equal(sourceCompletions.length, 21);
  assert.deepEqual(
    sourceEntries.map((entry) => entry.recordingId).sort(),
    all.map((row) => row.id).sort(),
  );
  assert.deepEqual(
    sourceEntries.map((entry) => entry.index),
    Array.from({ length: 21 }, (_, index) => index + 1),
  );
  assert.deepEqual(
    sourceCompletions.map((entry) => entry.index),
    sourceEntries.map((entry) => entry.index),
  );
  assert(
    sourceEntries.every(
      (entry) =>
        entry.request.postData() === '{"auditlog":"catalog00"}' &&
        entry.encrypted === (mode === 'catalog-encrypted'),
    ),
  );
  await recordings()
    .getByRole('button', { name: `Open recording ${id}`, exact: true })
    .waitFor();
  assert.equal(await recordings().locator('[role="row"][data-id]').count(), 1);
  assert.equal(
    requests.filter((request) => request.path.endsWith('/recordings/list')).length,
    pagesBeforeFull,
    'the source stream never resets or reloads the displayed metadata page',
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
    .getByRole('link', { name: 'Recordings', exact: true })
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
    await recordPanel()
      .locator('.recording-video')
      .getByRole('button', { name: 'Details', exact: true })
      .click();
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
      ['artifacts/recordings', { auditlog: 'catalog00' }],
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
  assert(
    pages.every(
      (request) =>
        request.body.auditlog === 'catalog00' &&
        request.body.limit === '20' &&
        request.body.sort === 'started-desc',
    ),
  );
  await reauthenticate(page);
  await login('bob');
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' }),
  );
  const beforeBob = requests.length;
  const bobSourcesReply = capture('auditlogs');
  await workspace(page, 'Audit logs');
  await page.evaluate(() => fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }));
  assert.equal(
    await logs().locator('[role="row"][data-id]').count(),
    0,
    'new or provisional metadata cannot inherit the other actor rows',
  );
  assert.deepEqual(
    requests.slice(beforeBob).map((request) => request.path.split('/management/')[1]),
    ['auditlogs/list'],
  );
  const loadingGrid = await logs().elementHandle();
  assert.equal(
    await sourceControls().getByRole('button', { name: 'Refresh audit logs', exact: true }).count(),
    0,
  );
  assert.equal(
    await sourceControls()
      .getByRole('button', { name: 'Cancel catalog request', exact: true })
      .count(),
    1,
  );
  assert.equal(
    await sourceControls()
      .getByRole('button', { name: 'Cancel catalog request', exact: true })
      .isEnabled(),
    true,
  );
  await page.evaluate(() =>
    fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
  );
  assert.equal(read(await bobSourcesReply, 'auditlogs').items.length, 20);
  await sourceControls().getByRole('button', { name: 'Refresh audit logs', exact: true }).waitFor();
  assert.equal(
    await loadingGrid.evaluate((node) => node.isConnected),
    true,
    'the same grid survives discovery completion',
  );
  const completed = requests.length;
  const retainedSourceRows = await logs()
    .locator('[role="row"][data-id]')
    .evaluateAll((nodes) => nodes.map((node) => node.getAttribute('data-id')));
  assert(
    retainedSourceRows.length > 0 && retainedSourceRows.length <= 20,
    'the source grid materializes only its visible part of the completed 20-row page',
  );
  await workspace(page, 'Bifröst');
  await workspace(page, 'Audit logs');
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    requests.length,
    completed,
    'activation does not repeat the completed bounded metadata read',
  );
  assert.deepEqual(
    await logs()
      .locator('[role="row"][data-id]')
      .evaluateAll((nodes) => nodes.map((node) => node.getAttribute('data-id'))),
    retainedSourceRows,
    'activation preserves the same materialized source rows',
  );
  const refreshedReply = capture('auditlogs');
  await sourceControls().getByRole('button', { name: 'Refresh audit logs', exact: true }).click();
  assert.equal(read(await refreshedReply, 'auditlogs').items.length, 20);
  assert.equal(
    requests.filter((request) => request.path.endsWith('/auditlogs/list')).length,
    5,
    'selected source metadata is reused only inside its owning actor',
  );
  assert.equal(requests.filter((request) => request.path.endsWith('/recordings/list')).length, 2);
  assert.equal(requests.filter((request) => request.path.includes('/artifacts/')).length, 4);
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

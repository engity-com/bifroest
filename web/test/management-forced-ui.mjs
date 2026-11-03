import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  activeAccess,
  assertUiPreferences,
  chooseLoginMethod,
  exactArtifactSelection,
  workspace,
} from './workspace-ui.mjs';

export async function forcedKeyLogin(page, file) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  await chooseLoginMethod(page, 'SSH key login');
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByLabel('Private key file (local only)', { exact: true }).setInputFiles({
    name: 'local-fixture',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from(fixture.ed),
  });
  await page
    .getByLabel('Key passphrase (optional, local only)', { exact: true })
    .fill(fixture.passphrase);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await activeAccess(page, 'alice');
}

export async function exerciseManagementForcedVersion(page, file, logout) {
  const calls = [];
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes('/api/v1/management/')) {
      calls.push({ path, body: JSON.parse(request.postData() ?? '{}') });
    }
  });
  const initialRead = page.waitForResponse((response) =>
    response.url().endsWith('/management/sessions/list'),
  );
  await forcedKeyLogin(page, file);
  assert.equal((await initialRead).status(), 403);
  assert.deepEqual(
    calls.map((call) => call.path.split('/management/')[1]),
    ['sessions/list'],
    'no server metadata reads before entering Server',
  );
  const shortReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/version/show'),
  );
  const flowsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/flows/list'),
  );
  await workspace(page, 'Server');
  assert.equal((await shortReply).status(), 200);
  assert.equal((await flowsReply).status(), 403);
  const version = page.getByRole('region', { name: 'Server version', exact: true });
  await version.locator('.server-version').waitFor();
  const text = await version.locator('.server-version').textContent();
  assert(text.includes('<b>version fixture</b><script>window.versionInjected = true</script>'));
  assert(!text.includes('Go:') && !text.includes('Features:'));
  assert.equal(await version.locator('b, script, pre').count(), 0);
  assert.equal(await page.evaluate(() => window.versionInjected), undefined);
  await page.locator('.build-details > summary').click();
  const denied = page.waitForResponse(
    (response) => response.url().endsWith('/management/version/show') && response.status() === 403,
  );
  await page.getByRole('button', { name: 'Load detailed build information', exact: true }).click();
  await denied;
  assert.equal(await page.locator('.build-details pre').count(), 0);
  assert.equal(
    await version.locator('.server-version').textContent(),
    text,
    'denied build details do not clear the separately authorized short version',
  );
  assert.deepEqual(
    calls.map((call) => [call.path.split('/management/')[1], call.body.long]),
    [
      ['sessions/list', undefined],
      ['version/show', 'false'],
      ['flows/list', undefined],
      ['version/show', 'true'],
    ],
  );
  for (const call of calls) {
    assert.equal(call.body.command, undefined);
    assert.equal(call.body.args, undefined);
  }
  await page
    .getByText('This sign-in is not permitted to read these details.', {
      exact: false,
    })
    .waitFor();
  assert.equal(await page.getByRole('table').count(), 0);
  await logout(page);
  assert.equal(await page.getByRole('region', { name: 'Server version', exact: true }).count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

export async function exerciseManagementForced(page, file, logout) {
  await forcedKeyLogin(page, file);
  await page.evaluate(async () => {
    const { BrowserClient } = await import('/_bifroest/test/client.js');
    await new BrowserClient({ origin: location.origin, slug: 'Work' }).password('bob', 'correct');
  });
  const flowsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/flows/list'),
  );
  await workspace(page, 'Server');
  assert.equal((await flowsReply).status(), 403);
  await page
    .getByText('This sign-in is not permitted to read these details.', {
      exact: false,
    })
    .waitFor();
  await workspace(page, 'Sessions');
  await page.locator('.session-filter-details > summary').click();
  await page.getByRole('combobox', { name: 'Session state', exact: true }).click();
  await page.getByRole('option', { name: 'All statuses', exact: true }).click();
  await page.getByRole('button', { name: 'Search sessions', exact: true }).click();
  const table = page.getByRole('table', { name: 'Live session metadata', exact: true });
  await table.getByText('alice', { exact: true }).waitFor();
  assert.equal(await table.locator('tbody tr').count(), 1);
  await page
    .getByText('Some fields are withheld under the configured forced-command policy.', {
      exact: false,
    })
    .waitFor();
  await table.getByText('Not returned under this forced-command policy', { exact: true }).waitFor();
  assert.equal(
    await table.getByText('No verified association available', { exact: true }).count(),
    0,
    'withholding must not invent absent ownership',
  );
  await table.getByRole('button', { name: /^Session details / }).click();
  await page
    .getByText('This sign-in is not permitted to read these details.', {
      exact: false,
    })
    .waitFor();
  assert.equal(await page.getByRole('region', { name: 'Session details', exact: true }).count(), 0);
  assert.equal(await page.getByRole('button', { name: 'End session', exact: true }).count(), 0);
  const auditlogsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/auditlogs/list'),
  );
  await workspace(page, 'Recordings & audit');
  assert.equal((await auditlogsReply).status(), 403);
  const artifacts = page.getByRole('region', {
    name: 'Recordings & audit',
    exact: true,
  });
  const catalog = artifacts.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  await catalog
    .getByText('This sign-in cannot list recordings from this source.', { exact: false })
    .waitFor();
  assert.equal(await catalog.getByRole('table').count(), 0);
  await exactArtifactSelection(page);
  await artifacts.getByRole('textbox', { name: 'Artifact auditlog', exact: true }).fill('default');
  await artifacts
    .getByRole('textbox', { name: 'Recording ID', exact: true })
    .fill('34e34ab8-7457-4d88-a5e4-c57791775c3a');
  await artifacts.getByRole('button', { name: 'Open recording', exact: true }).click();
  await artifacts
    .getByText('This sign-in is not permitted to open this recording or audit log.', {
      exact: false,
    })
    .waitFor();
  assert.equal(
    await artifacts.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
    0,
  );
  await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

export async function exerciseManagementForcedAudit(page, file, logout) {
  const calls = [];
  const network = [];
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes('/api/v1/management/')) {
      calls.push(path);
    }
  });
  page.on('response', (response) => {
    const path = new URL(response.url()).pathname;
    if (path.includes('/api/v1/management/')) {
      network.push({
        path,
        status: response.status(),
        type: response.headers()['content-type'] ?? '',
      });
    }
  });
  page.on('requestfailed', (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes('/api/v1/management/')) {
      network.push({ path, failure: request.failure()?.errorText ?? 'unavailable' });
    }
  });
  const initialRead = page.waitForResponse((response) =>
    response.url().endsWith('/management/sessions/list'),
  );
  await forcedKeyLogin(page, file);
  assert.equal((await initialRead).status(), 403);
  const auditlogsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/auditlogs/list'),
  );
  await workspace(page, 'Recordings & audit');
  assert.equal((await auditlogsReply).status(), 200);
  const artifacts = page.getByRole('region', {
    name: 'Recordings & audit',
    exact: true,
  });
  const catalog = artifacts.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  assert.deepEqual(
    calls.map((path) => path.split('/management/')[1]),
    ['sessions/list', 'auditlogs/list'],
    'each first visible view attempts only its authorized metadata read; no artifact download',
  );
  await catalog.getByText('Audit log exports', { exact: true }).click();
  const table = catalog.getByRole('table', {
    name: 'Configured auditlogs (server metadata)',
    exact: true,
  });
  try {
    await table.getByRole('cell', { name: 'audit00', exact: true }).waitFor();
  } catch (error) {
    throw new Error(
      JSON.stringify({
        network,
        notices: await catalog.getByRole('status').allTextContents(),
        tables: await catalog.getByRole('table').count(),
      }),
      { cause: error },
    );
  }
  assert.equal(await table.locator('tbody tr').count(), 20);
  assert((await table.textContent()).includes('Encryption configured'));
  const deniedRecordingsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/recordings/list'),
  );
  await catalog.getByRole('button', { name: 'More recording sources', exact: true }).click();
  await table.getByRole('cell', { name: 'audit20', exact: true }).waitFor();
  await table.getByRole('cell', { name: 'default', exact: true }).waitFor();
  assert.equal(await table.locator('tbody tr').count(), 22);
  assert.equal(
    await catalog.getByRole('button', { name: 'More recording sources', exact: true }).count(),
    0,
  );
  assert.equal(calls.filter((path) => path.endsWith('/auditlogs/list')).length, 2);
  assert.equal(calls.filter((path) => path.includes('/artifacts/')).length, 0);
  assert.equal(
    (await deniedRecordingsReply).status(),
    403,
    'after the final source page the sole source is selected without adding list permission',
  );
  assert.equal(
    await catalog.getByRole('combobox', { name: 'Recording source', exact: true }).count(),
    0,
    'the complete inventory has one recording source; no redundant chooser strands it',
  );
  await catalog
    .getByText('This sign-in cannot list recordings from this source.', { exact: false })
    .waitFor();
  assert.equal(await catalog.locator('.recording-table').count(), 0);
  assert.equal(calls.filter((path) => path.endsWith('/recordings/list')).length, 1);
  assert.equal(
    calls.filter((path) => path.includes('/artifacts/')).length,
    0,
    'source metadata navigation does not transfer artifacts',
  );
  await table.getByRole('button', { name: 'Open audit log default', exact: true }).click();
  await artifacts
    .getByText('This sign-in is not permitted to open this recording or audit log.', {
      exact: false,
    })
    .waitFor();
  assert.equal(calls.filter((path) => path.endsWith('/artifacts/audit')).length, 1);
  assert.equal(
    await artifacts.getByRole('heading', { name: 'Check the recording', exact: true }).count(),
    0,
  );
  for (const secret of [
    'private audit directory',
    'private identity file',
    'private recipient file',
  ]) {
    assert(!(await artifacts.textContent()).includes(secret));
  }
  const flowsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/flows/list'),
  );
  await workspace(page, 'Server');
  assert.equal((await flowsReply).status(), 403);
  await page
    .getByText('This sign-in is not permitted to read these details.', {
      exact: false,
    })
    .waitFor();
  assert.equal(
    await page
      .getByRole('table', { name: 'Configured flows (not public discovery links)', exact: true })
      .count(),
    0,
  );
  await logout(page);
  assert.equal(
    await page.getByRole('region', { name: 'Recordings & audit', exact: true }).count(),
    0,
  );
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

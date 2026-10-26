import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

async function forcedKeyLogin(page, file) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  await page.getByText('SSH key login', { exact: true }).click();
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
  await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
}

export async function exerciseManagementForced(page, file, logout) {
  await forcedKeyLogin(page, file);
  await page.evaluate(async () => {
    const { BrowserClient } = await import('/_bifroest/test/client.js');
    await new BrowserClient({ origin: location.origin, slug: 'Work' }).password('bob', 'correct');
  });
  await page.getByRole('button', { name: 'Load flows', exact: true }).click();
  await page
    .getByText('The management request could not be confirmed or is not permitted.', {
      exact: false,
    })
    .waitFor();
  await page.getByRole('combobox', { name: 'Session state', exact: true }).click();
  await page.getByRole('option', { name: 'all', exact: true }).click();
  await page.getByRole('button', { name: 'Load sessions', exact: true }).click();
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
    .getByText('The management request could not be confirmed or is not permitted.', {
      exact: false,
    })
    .waitFor();
  assert.equal(await page.getByRole('region', { name: 'Session details', exact: true }).count(), 0);
  assert.equal(await page.getByRole('button', { name: 'Dispose session', exact: true }).count(), 0);
  const artifacts = page.getByRole('region', {
    name: 'Artifacts and client-side evidence',
    exact: true,
  });
  const catalog = artifacts.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  await catalog.getByRole('button', { name: 'Load auditlogs', exact: true }).click();
  await catalog
    .getByText('The catalog request could not be confirmed or is not permitted.', { exact: false })
    .waitFor();
  assert.equal(await catalog.getByRole('table').count(), 0);
  await artifacts.getByRole('textbox', { name: 'Artifact auditlog', exact: true }).fill('default');
  await artifacts
    .getByRole('textbox', { name: 'Recording ID', exact: true })
    .fill('34e34ab8-7457-4d88-a5e4-c57791775c3a');
  await artifacts.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await artifacts
    .getByText('The artifact download could not be confirmed or is not permitted.', {
      exact: false,
    })
    .waitFor();
  assert.equal(
    await artifacts
      .getByRole('heading', { name: 'Independent verification expectations', exact: true })
      .count(),
    0,
  );
  await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
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
  await forcedKeyLogin(page, file);
  const artifacts = page.getByRole('region', {
    name: 'Artifacts and client-side evidence',
    exact: true,
  });
  const catalog = artifacts.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  assert.deepEqual(
    calls,
    [],
    'forced login cannot automatically enumerate metadata or download artifacts',
  );
  await catalog.getByRole('button', { name: 'Load auditlogs', exact: true }).click();
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
  await catalog.getByRole('button', { name: 'Next auditlog page', exact: true }).click();
  await table.getByRole('cell', { name: 'audit20', exact: true }).waitFor();
  await table.getByRole('cell', { name: 'default', exact: true }).waitFor();
  assert.equal(await table.locator('tbody tr').count(), 2);
  assert.equal(
    await catalog.getByRole('button', { name: 'Next auditlog page', exact: true }).count(),
    0,
  );
  assert.equal(calls.filter((path) => path.endsWith('/auditlogs/list')).length, 2);
  assert.equal(calls.filter((path) => path.includes('/artifacts/')).length, 0);
  await table.getByRole('button', { name: 'List sealed recordings default', exact: true }).click();
  await catalog
    .getByText('The catalog request could not be confirmed or is not permitted.', { exact: false })
    .waitFor();
  assert.equal(
    await catalog.getByRole('region', { name: 'Sealed recording catalog', exact: true }).count(),
    0,
  );
  assert.equal(calls.filter((path) => path.endsWith('/recordings/list')).length, 1);
  const beforeSelection = calls.length;
  await table.getByRole('button', { name: 'Select audit inventory default', exact: true }).click();
  assert.equal(calls.length, beforeSelection, 'metadata selection cannot start an operation');
  await artifacts.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await artifacts
    .getByText('The artifact download could not be confirmed or is not permitted.', {
      exact: false,
    })
    .waitFor();
  assert.equal(calls.filter((path) => path.endsWith('/artifacts/audit')).length, 1);
  assert.equal(
    await artifacts
      .getByRole('heading', { name: 'Independent verification expectations', exact: true })
      .count(),
    0,
  );
  await page.getByRole('button', { name: 'Load flows', exact: true }).click();
  await page
    .getByText('The management request could not be confirmed or is not permitted.', {
      exact: false,
    })
    .waitFor();
  assert.equal(
    await page
      .getByRole('table', { name: 'Configured flows (not public discovery links)', exact: true })
      .count(),
    0,
  );
  for (const secret of [
    'private audit directory',
    'private identity file',
    'private recipient file',
  ]) {
    assert(!(await catalog.textContent()).includes(secret));
  }
  await logout(page);
  assert.equal(
    await page
      .getByRole('region', { name: 'Artifacts and client-side evidence', exact: true })
      .count(),
    0,
  );
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

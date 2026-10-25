import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export async function exerciseManagementForced(page, file, logout) {
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
  await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

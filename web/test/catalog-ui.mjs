import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const [origin, mode] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(['catalog-clear', 'catalog-encrypted'].includes(mode));
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
  const errors = [];
  const requests = [];
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
    await page.getByRole('heading', { name: `Signed in as ${user}`, exact: true }).waitFor();
  };
  const response = await page.goto(`${origin}/Work`);
  assert.equal(response.status(), 200);
  await login('alice');
  const catalog = page.getByRole('region', {
    name: 'Artifact catalog (server metadata)',
    exact: true,
  });
  const panel = page.getByRole('region', {
    name: 'Artifacts and client-side evidence',
    exact: true,
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
      .isDisabled(),
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
      mode === 'catalog-clear'
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
  await panel
    .getByRole('heading', { name: 'Independent verification expectations', exact: true })
    .waitFor();
  assert.equal(await panel.getByLabel('Expected producer ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel.getByRole('combobox', { name: 'Expected encryption', exact: true }).inputValue(),
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
  await panel.getByRole('button', { name: 'Download into this tab', exact: true }).click();
  await panel
    .getByRole('heading', { name: 'Independent verification expectations', exact: true })
    .waitFor();
  assert.equal(await panel.getByLabel('Expected producer ID', { exact: false }).inputValue(), '');
  assert.equal(
    await panel.getByRole('combobox', { name: 'Expected encryption', exact: true }).inputValue(),
    '',
  );
  assert.equal(
    requests.filter((request) => request.path.includes('/artifacts/')).length,
    2,
    'only the two explicit clicks may download',
  );
  const recordPages = requests.filter((request) => request.path.endsWith('/recordings/list'));
  assert.equal(recordPages.length, 2);
  assert.equal(recordPages[0].body.auditlog, 'catalog00');
  assert.equal(recordPages[0].body.after, '');
  assert.match(recordPages[1].body.after, /^bmp1\./u);
  await page
    .getByRole('button', { name: 'Sign in again for new connections', exact: true })
    .click();
  await login('bob');
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
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await page.getByText('Logout confirmed.', { exact: true }).waitFor();
  assert.equal(await catalog.count(), 0);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  console.log(JSON.stringify({ success: true }));
} finally {
  await browser.close();
}

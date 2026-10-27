import assert from 'node:assert/strict';

export async function exerciseManagement(page, login, logout) {
  const bodyForFailure = async (response) => {
    try {
      return await response.text();
    } catch {
      return `DevTools body unavailable (HTTP ${response.status()})`;
    }
  };
  const requests = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/v1/management/')) {
      requests.push({
        url: request.url(),
        headers: request.headers(),
        body: JSON.parse(request.postData() ?? '{}'),
      });
    }
  });
  await login(page, false);
  await page.getByRole('heading', { name: 'Management overview', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Load server version', exact: true }).click();
  const version = page.getByRole('region', { name: 'Server version', exact: true });
  await version
    .getByText('Server-reported build metadata, not an independent attestation.', { exact: true })
    .waitFor();
  assert((await version.locator('pre').textContent()).includes('Version:  test'));
  assert.equal(await page.getByRole('heading', { name: 'Terminal', exact: true }).count(), 0);
  assert.equal(await page.getByRole('button', { name: /dispose|disconnect|delete/i }).count(), 0);
  const firstReply = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/management/flows/list'),
  );
  await page.getByRole('button', { name: 'Load flows', exact: true }).click();
  const first = await firstReply;
  assert.equal(
    first.status(),
    200,
    first.status() === 200 ? undefined : await bodyForFailure(first),
  );
  const flows = page.getByRole('table', {
    name: 'Configured flows (not public discovery links)',
    exact: true,
  });
  try {
    await flows.getByText('manager00', { exact: true }).waitFor();
  } catch (error) {
    throw new Error(
      JSON.stringify({
        response: await bodyForFailure(first),
        notices: await page.getByRole('status').allTextContents(),
      }),
      { cause: error },
    );
  }
  assert.equal(await flows.locator('tbody tr').count(), 20);
  const secondReply = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/management/flows/list'),
  );
  await page.getByRole('button', { name: 'Next flow page', exact: true }).click();
  const second = await secondReply;
  assert.equal(
    second.status(),
    200,
    second.status() === 200 ? undefined : await bodyForFailure(second),
  );
  try {
    await flows.getByText('manager20', { exact: true }).waitFor();
  } catch (error) {
    throw new Error(
      JSON.stringify({
        response: await bodyForFailure(second),
        notices: await page.getByRole('status').allTextContents(),
      }),
      { cause: error },
    );
  }
  assert.equal(await flows.locator('tbody tr').count(), 1);
  await page.getByRole('button', { name: 'Load sessions', exact: true }).click();
  const sessions = page.getByRole('table', { name: 'Live session metadata', exact: true });
  await sessions.getByText('alice', { exact: true }).waitFor();
  assert.match(await sessions.textContent(), /alice/);
  assert.match(await sessions.textContent(), /Verified issuer \/ subject/);
  await sessions
    .getByRole('button', { name: /^Session details / })
    .first()
    .click();
  await page.getByRole('region', { name: 'Session details', exact: true }).waitFor();
  assert(
    !(await page
      .locator('body')
      .textContent()
      .then((text) => text.includes('plain:correct'))),
  );
  await page
    .getByRole('button', { name: 'Sign in again for new connections', exact: true })
    .click();
  await login(page, false, 'bob');
  assert.equal(await page.getByRole('region', { name: 'Server version', exact: true }).count(), 0);
  // No previous actor's result may appear under the newly authenticated actor.
  assert.equal(await page.getByRole('table').count(), 0);
  assert.equal(await page.getByRole('region', { name: 'Session details', exact: true }).count(), 0);
  await page.getByRole('button', { name: 'Load sessions', exact: true }).click();
  await sessions.getByText('bob', { exact: true }).waitFor();
  assert.equal(await sessions.locator('tbody tr').count(), 2);
  await logout(page);
  assert(requests.length >= 5);
  for (const request of requests) {
    assert.equal(new URL(request.url).search, '');
    assert.match(request.headers.authorization, /^Bearer bwa1\./);
    assert.equal(request.headers.cookie, undefined);
    assert.equal(request.body.slug, 'Work');
    assert.equal(request.body.args, undefined);
    assert.equal(request.body.command, undefined);
  }
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

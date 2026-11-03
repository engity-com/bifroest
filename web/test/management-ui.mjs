import assert from 'node:assert/strict';
import { assertUiPreferences, reauthenticate, workspace } from './workspace-ui.mjs';

export async function exerciseManagement(page, login, logout) {
  const bodyForFailure = async (response) => {
    try {
      const body = await response.json();
      return JSON.stringify({
        code: response.status(),
        fieldsAvailable: {
          version: Object.hasOwn(body, 'version'),
          operation: Object.hasOwn(body, 'operation'),
          flows: Array.isArray(body.flows?.items),
        },
      });
    } catch {
      return JSON.stringify({ code: response.status(), fieldsAvailable: false });
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
  await page.getByRole('heading', { name: 'Sessions', exact: true }).waitFor();
  const sessions = page.getByRole('table', { name: 'Live session metadata', exact: true });
  await sessions.getByText('alice', { exact: true }).waitFor();
  const alicePaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
  const alicePane = page.locator(`#${alicePaneID}`);
  assert.deepEqual(
    requests.map((request) => new URL(request.url).pathname.split('/management/')[1]),
    ['sessions/list'],
    'the first authenticated active Sessions view reads only its session page, once',
  );
  const aliceAuthorization = requests[0].headers.authorization;
  const firstReply = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/management/flows/list'),
  );
  await workspace(page, 'Server');
  const version = page.getByRole('region', { name: 'Server version', exact: true });
  await version
    .getByText('Reported by this server; not an independent verification.', { exact: true })
    .waitFor();
  assert((await version.locator('.server-version').textContent()).includes('test'));
  assert.equal(await version.locator('pre').count(), 0, 'the initial version is compact');
  assert.equal(await page.getByRole('heading', { name: 'Terminal', exact: true }).count(), 0);
  assert.equal(await page.getByRole('button', { name: /dispose|disconnect|delete/i }).count(), 0);
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
  assert.deepEqual(
    requests.map((request) => new URL(request.url).pathname.split('/management/')[1]),
    ['sessions/list', 'version/show', 'flows/list'],
    'initial server reads are explicit view intent and stay in their exact serial path',
  );
  assert.equal(requests[1].body.long, 'false');
  await page.locator('.build-details > summary').click();
  await page.getByRole('button', { name: 'Load detailed build information', exact: true }).click();
  await page.locator('.build-details pre').waitFor();
  assert((await page.locator('.build-details pre').textContent()).includes('Version:  test'));
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
  const beforeReturn = requests.length;
  await workspace(page, 'Sessions');
  await sessions.getByText('alice', { exact: true }).waitFor();
  assert.equal(requests.length, beforeReturn, 'returning to a loaded view must not reread');
  assert.match(await sessions.textContent(), /alice/);
  assert(
    !(await sessions.textContent()).includes('Verified issuer / subject'),
    'identity internals belong in details',
  );
  await sessions
    .getByRole('button', { name: /^Session details / })
    .first()
    .click();
  await page.getByRole('region', { name: 'Session details', exact: true }).waitFor();
  await page
    .getByRole('region', { name: 'Session details', exact: true })
    .getByText('Verified issuer', { exact: true })
    .waitFor();
  assert(
    !(await page
      .locator('body')
      .textContent()
      .then((text) => text.includes('plain:correct'))),
  );
  await reauthenticate(page);
  const beforeBob = requests.length;
  const bobSessionsReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/sessions/list'),
  );
  await login(page, false, 'bob');
  const bobReply = await bobSessionsReply;
  assert.equal(bobReply.status(), 200);
  const bobAuthorization = bobReply.request().headers().authorization;
  assert.equal(
    bobAuthorization !== undefined && bobAuthorization !== aliceAuthorization,
    true,
    'Bob’s first read must use his new grant, not Alice’s retained grant',
  );
  const bobData = await bobReply.json();
  assert.equal(bobData.operation, 'sessions.list');
  assert.equal(bobData.sessions.items.length, 2);
  const bobPaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
  const bobPane = page.locator(`#${bobPaneID}`);
  assert.equal(bobPaneID !== alicePaneID, true);
  assert.equal(await bobPane.getAttribute('data-connection-principal'), 'bob');
  assert.equal(await bobPane.getAttribute('data-connection-scope'), 'Work');
  const bobSessions = bobPane.getByRole('table', { name: 'Live session metadata', exact: true });
  await bobSessions.getByText('bob', { exact: true }).waitFor();
  assert.equal(await bobSessions.locator('tbody tr').count(), 2);
  const shownTargets = await bobSessions
    .locator('tbody tr')
    .evaluateAll((rows) =>
      rows.map((row) => [
        row.cells[1].textContent,
        row.querySelector('button')?.getAttribute('aria-label')?.slice('Session details '.length),
      ]),
    );
  assert.equal(
    JSON.stringify(shownTargets) ===
      JSON.stringify(bobData.sessions.items.map((item) => [item.flow, item.id])),
    true,
    'Bob’s visible rows must come from the fresh successful response to his authenticated read',
  );
  assert.equal(await bobPane.locator('.session-details').count(), 0);
  assert.equal(
    await bobPane.locator('.build-details pre').count(),
    0,
    'the new pane cannot inherit Alice’s detailed version',
  );
  assert.equal(
    await alicePane.locator('.session-details').count(),
    1,
    'Alice’s independently owned detail remains in her hidden pane',
  );
  assert.equal(await alicePane.locator('.build-details pre').count(), 1);
  const newVersionReply = page.waitForResponse((response) =>
    response.url().endsWith('/management/version/show'),
  );
  const newServerReply = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/management/flows/list'),
  );
  await workspace(page, 'Server');
  const bobVersion = await newVersionReply;
  assert.equal(bobVersion.status(), 200);
  assert.equal(bobVersion.request().headers().authorization === bobAuthorization, true);
  assert.equal((await bobVersion.json()).versionInfo.detail, 'short');
  const bobFlows = await newServerReply;
  assert.equal(bobFlows.status(), 200);
  assert.equal(bobFlows.request().headers().authorization === bobAuthorization, true);
  const freshFlows = bobPane.getByRole('table', {
    name: 'Configured flows (not public discovery links)',
    exact: true,
  });
  await freshFlows.getByText('manager00', { exact: true }).waitFor();
  assert.equal(
    await freshFlows.locator('tbody tr').count(),
    20,
    'the new owner starts at its own first page, not the previous owner’s page',
  );
  assert.equal(await bobPane.locator('.build-details pre').count(), 0);
  assert.equal(await bobPane.locator('.session-details').count(), 0);
  assert.equal(
    await alicePane.locator('.build-details pre').count(),
    1,
    'retaining Alice’s own data is not a leak into Bob’s pane',
  );
  assert.deepEqual(
    requests
      .slice(beforeBob)
      .map((request) => new URL(request.url).pathname.split('/management/')[1]),
    ['sessions/list', 'version/show', 'flows/list'],
    'Bob receives exactly his own first-view reads, without inherited-result reloads or extra reads',
  );
  await workspace(page, 'Sessions');
  await sessions.getByText('bob', { exact: true }).waitFor();
  assert.equal(await sessions.locator('tbody tr').count(), 2);
  await logout(page);
  assert(requests.length >= 5);
  for (const request of requests) {
    assert.equal(new URL(request.url).search, '');
    assert.equal(/^Bearer bwa1\./u.test(request.headers.authorization ?? ''), true);
    assert.equal(request.headers.cookie === undefined, true);
    assert.equal(request.body.slug, 'Work');
    assert.equal(request.body.args, undefined);
    assert.equal(request.body.command, undefined);
  }
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

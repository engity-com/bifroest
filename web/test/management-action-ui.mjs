import assert from 'node:assert/strict';
import { managementInterruption } from './management-interruption.mjs';
import { managementWire } from './management-wire.mjs';
import {
  assertAccessActionsBlocked,
  assertUiPreferences,
  captureLayout,
  gridColumnFilter,
  reauthenticate,
  sessionTarget,
  workspace,
} from './workspace-ui.mjs';

async function sessionLayout(page, id, requestCount) {
  const viewport = page.viewportSize();
  await captureLayout(page, 'sessions-desktop');
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    const beforeReturn = requestCount();
    await page
      .getByRole('navigation', { name: 'Breadcrumb', exact: true })
      .getByRole('button', { name: 'Sessions', exact: true })
      .click();
    assert.equal(
      requestCount(),
      beforeReturn,
      'returning through the breadcrumb uses retained metadata, never another read',
    );
    const cards = page.getByRole('grid', { name: 'Live session metadata', exact: true });
    await cards.waitFor();
    assert.equal(await cards.count(), 1, 'the mobile list uses the native grid');
    await cards.getByRole('button', { name: `Session details ${id}`, exact: true }).click();
    await page.getByRole('region', { name: 'Session details', exact: true }).waitFor();
    assert.equal(
      await page.getByRole('grid', { name: 'Live session metadata', exact: true }).count(),
      0,
      'opening a detail replaces the list while its metadata remains retained',
    );
    await captureLayout(page, `sessions-${width}`);
  }
  await page.setViewportSize(viewport);
}

export async function exerciseManagementActions(page, login, logout) {
  const wire = managementWire(page);
  const interruption = await managementInterruption(page);
  let commits = 0;
  let managementCalls = 0;
  const managementPaths = [];
  const responses = [];
  const networkFailures = [];
  wire.on('response', (response) => {
    if (new URL(response.url()).pathname.includes('/management/')) {
      responses.push(response);
    }
  });
  page.on('requestfailed', (request) => {
    networkFailures.push({
      path: new URL(request.url()).pathname,
      method: request.method(),
      error: request.failure()?.errorText,
    });
  });
  wire.on('request', (request) => {
    if (new URL(request.url()).pathname.includes('/api/v1/management/')) {
      managementCalls++;
      managementPaths.push(new URL(request.url()).pathname.split('/management/')[1]);
    }
    if (request.url().endsWith('/management/sessions/confirm')) {
      commits++;
    }
  });
  await login(page, false);
  await page
    .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  await workspace(page, 'Sessions');
  const list = page.getByRole('grid', { name: 'Live session metadata', exact: true });
  await list.waitFor();
  const bounds = await list.boundingBox();
  assert(bounds && bounds.y < 350, 'the Sessions grid must start in the initial desktop viewport');
  assert.equal(
    await page.getByRole('heading', { name: 'Sessions', exact: true }).count(),
    0,
    'breadcrumbs replace the redundant page heading',
  );
  assert.equal(
    await page.getByRole('button', { name: 'Prepare session action', exact: true }).count(),
    0,
    'the exact-ID specialist path starts collapsed',
  );
  await captureLayout(page, 'sessions-initial');
  await page.getByRole('grid', { name: 'Live session metadata', exact: true }).waitFor();
  const draftID = (
    await page
      .getByRole('grid', { name: 'Live session metadata', exact: true })
      .getByRole('button', { name: /^Session details / })
      .first()
      .getAttribute('aria-label')
  ).slice('Session details '.length);
  let direct = await sessionTarget(page);
  await direct.getByLabel('Target flow', { exact: false }).fill('work');
  await direct.getByLabel('Target session ID', { exact: false }).fill(draftID);
  await page.keyboard.press('Escape');
  await workspace(page, 'Server');
  await page
    .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  assert.deepEqual(
    managementPaths,
    ['flows/list', 'sessions/list'],
    'only the exact authorized first-view reads, never preparation or download',
  );
  await workspace(page, 'Recordings & audit');
  await page.getByRole('grid', { name: 'Recordings · default', exact: true }).waitFor();
  assert.deepEqual(
    managementPaths,
    ['flows/list', 'sessions/list', 'auditlogs/list', 'recordings/list'],
    'the first Artifacts visit reads only its sources and sole recording source; never transfers or prepares',
  );
  const afterFirstViews = managementCalls;
  await workspace(page, 'Sessions');
  direct = await sessionTarget(page);
  assert.equal(await direct.getByLabel('Target flow', { exact: false }).inputValue(), 'work');
  assert.equal(
    await direct.getByLabel('Target session ID', { exact: false }).inputValue(),
    draftID,
  );
  await page.keyboard.press('Escape');
  for (const name of ['Server', 'Recordings & audit', 'Sessions']) {
    await workspace(page, name);
  }
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    managementCalls,
    afterFirstViews,
    'returning to initialized views must not repeat any reads, downloads or preparations',
  );
  assert.equal(afterFirstViews, 4);
  direct = await sessionTarget(page);
  assert.equal(await direct.getByLabel('Target flow', { exact: false }).inputValue(), 'work');
  assert.equal(
    await direct.getByLabel('Target session ID', { exact: false }).inputValue(),
    draftID,
  );
  await page.keyboard.press('Escape');
  async function connection() {
    return page.evaluate(async () => {
      const { BrowserClient } = await import('/_bifroest/test/client.js');
      window.managementTargetAccess ??= await new BrowserClient({
        origin: location.origin,
        slug: 'Worker',
      }).password('bob', 'correct');
      window.managementTargetSockets ??= [];
      const socket = new WebSocket(
        `${location.origin.replace('https:', 'wss:')}/_bifroest/api/v1/terminal`,
        'bifroest-terminal.v1',
      );
      socket.binaryType = 'arraybuffer';
      const index = window.managementTargetSockets.push(socket) - 1;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('target did not run')), 5000);
        socket.onerror = () => reject(new Error('target socket failed'));
        socket.onopen = () =>
          socket.send(
            JSON.stringify({
              type: 'open',
              slug: 'Worker',
              accessToken: window.managementTargetAccess.terminalToken(),
              task: 'exec',
              command: 'fixture-hold',
            }),
          );
        socket.onmessage = (event) => {
          if (
            event.data instanceof ArrayBuffer &&
            new TextDecoder()
              .decode(new Uint8Array(event.data).subarray(1))
              .includes('management-target-live')
          ) {
            clearTimeout(timer);
            resolve();
          }
        };
      });
      return index;
    });
  }
  await connection();
  await connection();
  const table = page.getByRole('grid', { name: 'Live session metadata', exact: true });
  async function target() {
    const back = page
      .getByRole('navigation', { name: 'Breadcrumb', exact: true })
      .getByRole('button', { name: 'Sessions', exact: true });
    if (await back.count()) {
      const beforeReturn = managementCalls;
      await back.click();
      assert.equal(
        managementCalls,
        beforeReturn,
        'local detail navigation must not refresh or prepare anything',
      );
    }
    await table.waitFor();
    await page.getByRole('button', { name: 'Refresh sessions', exact: true }).click();
    const row = table
      .locator('[role="row"][data-id]')
      .filter({ has: page.getByText('bob', { exact: true }) });
    await row.waitFor();
    await row.getByRole('button', { name: /^Session details / }).click();
    try {
      await page.getByRole('region', { name: 'Session details', exact: true }).waitFor();
    } catch (error) {
      const replies = [];
      for (const response of responses) {
        const path = new URL(response.url()).pathname;
        const reply = {
          path,
          status: response.status(),
          mediaType: response.contentType(),
        };
        if (path.endsWith('/sessions/show') && response.status() === 200) {
          try {
            const body = await response.json();
            // Only shape/selector diagnostics, never credentials, auth bodies,
            // confirmation handles or arbitrary backend data.
            reply.shape = {
              fields: Object.keys(body),
              version: body.version,
              operation: body.operation,
              sessionFields:
                body.session === null || typeof body.session !== 'object'
                  ? null
                  : Object.keys(body.session),
            };
          } catch {
            reply.shape = 'unavailable';
          }
        }
        replies.push(reply);
      }
      throw new Error(
        JSON.stringify({
          step: 'session-details',
          replies,
          networkFailures,
          notices: await page.getByRole('status').allTextContents(),
          headings: await page.getByRole('heading').allTextContents(),
          csp: await page.evaluate(() => window.cspViolations),
        }),
        { cause: error },
      );
    }
    const details = page.getByRole('region', { name: 'Session details', exact: true });
    const id = await details
      .locator('dt')
      .filter({ hasText: /^Session ID$/ })
      .evaluate((node) => node.nextElementSibling.textContent);
    return `worker/${id}`;
  }
  const id = await target();
  await sessionLayout(page, id.split('/')[1], () => managementCalls);
  await page.getByRole('button', { name: 'End session', exact: true }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByText(id, { exact: true }).waitFor();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(
    await page.evaluate(
      () =>
        window.managementTargetSockets.filter((socket) => socket.readyState === WebSocket.OPEN)
          .length,
    ),
    2,
  );
  assert.equal(commits, 0);
  await page.getByRole('button', { name: 'Disconnect connections', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByText(id, { exact: true }).waitFor();
  const confirm = dialog.getByRole('button', { name: 'Confirm session action', exact: true });
  assert.equal(await confirm.isEnabled(), false);
  await dialog
    .getByLabel('Type the exact flow/session ID shown above', { exact: true })
    .fill('wrong-target');
  assert.equal(await confirm.isEnabled(), false);
  await dialog.getByLabel('Type the exact flow/session ID shown above', { exact: true }).fill(id);
  await confirm.click();
  await page
    .getByText(
      'The server confirmed this session action and its configured audit/recording lifecycle.',
      { exact: false },
    )
    .waitFor();
  await page.waitForFunction(() =>
    window.managementTargetSockets.every((socket) => socket.readyState === WebSocket.CLOSED),
  );
  await connection(); // Explicit new execution on the same retained target grant.
  assert.equal(await target(), id, 'disconnect must preserve the same persistent session');
  await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/interrupt-management-confirm', {
      method: 'POST',
      credentials: 'omit',
      mode: 'same-origin',
    });
    if (response.status !== 204) {
      throw new Error('fixture not armed');
    }
  });
  interruption.arm('management/sessions/confirm');
  await page.getByRole('button', { name: 'End session', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByLabel('Type the exact flow/session ID shown above', { exact: true }).fill(id);
  await dialog.getByRole('button', { name: 'Confirm session action', exact: true }).click();
  await page.getByText('The session action result is unknown.', { exact: false }).waitFor();
  const navigation = page.getByRole('navigation', {
    name: 'Workspace',
    exact: true,
    includeHidden: true,
  });
  assert.equal(
    await navigation
      .getByRole('button', { name: 'Recordings', exact: true, includeHidden: true })
      .isEnabled(),
    false,
  );
  assert.equal(
    await navigation
      .getByRole('button', { name: 'Overview', exact: true, includeHidden: true })
      .isEnabled(),
    false,
    'view changes cannot dismiss the unknown outcome or its action lock',
  );
  await assertAccessActionsBlocked(page);
  assert.equal(
    await page.getByRole('button', { name: 'New connection', exact: true }).isEnabled(),
    false,
    'another flow cannot dismiss an unknown action outcome',
  );
  for (const tab of await page
    .getByRole('tablist', { name: 'Connections and terminals', exact: true })
    .getByRole('tab')
    .all()) {
    assert.equal(await tab.isEnabled(), false);
  }
  await page.waitForFunction(() =>
    window.managementTargetSockets.every((socket) => socket.readyState === WebSocket.CLOSED),
  );
  await page.waitForTimeout(1300);
  assert.equal(commits, 2, 'no automatic confirmation replay after a lost response');
  assert.equal(interruption.losses(), 1, 'exactly one real committed action lost its completion');
  assert.equal(
    await page
      .getByRole('button', { name: 'Refresh sessions', exact: true, includeHidden: true })
      .isEnabled(),
    false,
    'a lost management channel cannot silently fall back to HTTP',
  );
  await page
    .getByRole('button', { name: 'Dismiss local warning (does not confirm result)', exact: true })
    .click();
  await reauthenticate(page);
  await login(page, false);
  await page
    .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  await workspace(page, 'Sessions');
  await gridColumnFilter(page, table, 'Status', 'is', 'Ended');
  await table
    .locator('[role="row"][data-id]')
    .filter({ has: page.getByText('bob', { exact: true }) })
    .getByText('Ended', { exact: true })
    .waitFor();
  await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

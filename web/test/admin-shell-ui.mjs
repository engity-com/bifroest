import assert from 'node:assert/strict';
import { managementWire } from './management-wire.mjs';
import { assertUiPreferences, captureLayout, terminalAction, workspace } from './workspace-ui.mjs';

export async function exerciseAdminShell(page, login, logout) {
  const sockets = [];
  const sent = [];
  const received = [];
  page.on('websocket', (socket) => {
    sockets.push(new URL(socket.url()).pathname);
    socket.on('framesent', ({ payload }) => {
      assert.equal(typeof payload, 'string', 'management never uploads terminal/workload bytes');
      const value = JSON.parse(payload);
      if (value.type === 'open') {
        assert.match(value.accessToken, /^bwa1\.[A-Za-z0-9_-]{43}$/u);
        sent.push({ type: 'open', slug: value.slug });
      } else {
        assert.equal(JSON.stringify(value).includes('bwa1.'), false);
        sent.push(value);
      }
    });
    socket.on('framereceived', ({ payload }) => {
      if (typeof payload === 'string') {
        const value = JSON.parse(payload);
        received.push({ type: value.type, requestId: value.requestId, status: value.status });
      }
    });
  });
  const firstReply = managementWire(page).waitForResponse((response) =>
    response.url().endsWith('/management/flows/list'),
  );
  await login(page, false);
  assert.equal((await firstReply).status(), 200);
  const pane = page.locator('[data-connection-active="true"]');
  const shell = pane.locator('.admin-shell');
  const breadcrumb = pane.getByRole('navigation', { name: 'Breadcrumb', exact: true });
  await pane
    .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
    .waitFor();
  assert.equal(await breadcrumb.textContent(), 'Bifröst/Overview');
  const tabLabel = page.getByRole('tab', { selected: true }).getByText('Overview', { exact: true });
  assert.equal(
    await tabLabel.evaluate((node) => node.scrollWidth <= node.clientWidth),
    true,
    'short primary-page tab titles must not be unnecessarily truncated on desktop',
  );
  assert.equal(await breadcrumb.getByRole('button', { name: 'Bifröst', exact: true }).count(), 0);
  assert.equal(await shell.getAttribute('data-admin-drawer'), 'persistent');
  await captureLayout(page, 'admin-overview-desktop');
  assert.deepEqual(
    sent.filter((value) => value.type === 'request').map((value) => value.action),
    ['management/flows/list'],
  );
  assert.equal(
    await pane.getByRole('tablist').count(),
    0,
    'only connection tabs remain; no nested primary admin tabs',
  );
  await workspace(page, 'Sessions');
  const grid = pane.getByRole('grid', { name: 'Live session metadata', exact: true });
  await grid.getByText('alice', { exact: true }).waitFor();
  await grid.getByRole('button', { name: /^Session details /u }).click();
  const details = pane.getByRole('region', { name: 'Session details', exact: true });
  await details.waitFor();
  const selected = sent.filter((value) => value.action === 'management/sessions/show').at(-1)
    .fields.id;
  assert((await breadcrumb.textContent()).includes(selected));
  assert((await breadcrumb.textContent()).includes('Bifröst'));
  const target = sent.filter((value) => value.action === 'management/sessions/show').at(-1).fields;
  assert.equal(await breadcrumb.textContent(), `Bifröst/Sessions/${target.flow}/${selected}`);
  assert.equal(await details.locator('h3,.session-actions').count(), 0);
  assert.equal(
    await details
      .locator('.metadata-grid')
      .getByRole('button', { name: 'Disconnect connections', exact: true })
      .count(),
    1,
  );
  await captureLayout(page, 'admin-session-detail');
  await breadcrumb.getByRole('button', { name: 'Sessions', exact: true }).click();
  await grid.waitFor();
  await grid.getByRole('columnheader', { name: /Flow/u }).click();
  await page.waitForFunction(
    () =>
      document.querySelector('.admin-data-grid [data-field="flow"][aria-sort="descending"]') !==
      null,
  );
  assert.equal(
    sent.filter((value) => value.action === 'management/sessions/list').at(-1).fields.sort,
    'flow-desc',
  );
  await terminalAction(page, 'Connection settings');
  const settings = page.getByRole('dialog', { name: 'Connection settings', exact: true });
  await settings.waitFor();
  await settings.getByLabel('Keepalive interval', { exact: true }).fill('1s');
  await settings.getByRole('button', { name: 'Apply connection settings', exact: true }).click();
  await settings.waitFor({ state: 'hidden' });
  assert.equal(sent.filter((value) => value.type === 'keepalive').at(-1).interval, '1s');
  assert.equal(
    await page.evaluate(() => localStorage.getItem('bifroest-ui-v1:keepalive:Work')),
    '1s',
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(
    () => document.querySelector('.admin-shell')?.getAttribute('data-admin-drawer') === 'temporary',
  );
  await pane.getByRole('button', { name: 'Open management navigation', exact: true }).click();
  const overlay = await shell.locator('.admin-drawer-backdrop').boundingBox();
  const bounds = await shell.boundingBox();
  assert(overlay && bounds);
  assert(
    overlay.y >= bounds.y && overlay.height <= bounds.height + 1,
    'overlay stays beneath global connection navigation',
  );
  await captureLayout(page, 'admin-drawer-mobile-open');
  await shell.getByRole('button', { name: 'Recordings', exact: true }).click();
  await pane
    .getByRole('region', { name: 'Artifact catalog (server metadata)', exact: true })
    .waitFor();
  assert((await breadcrumb.textContent()).includes('Recordings'));
  await workspace(page, 'Audit logs');
  assert((await breadcrumb.textContent()).includes('Audit logs'));
  const expiry = await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/expire-current-access', {
      method: 'POST',
      credentials: 'omit',
      mode: 'same-origin',
    });
    if (!response.ok) {
      throw new Error('expiry fixture failed');
    }
    return response.json();
  });
  await page.clock.setFixedTime(new Date(expiry.advanceTo));
  await workspace(page, 'Sessions');
  await page.waitForFunction(() =>
    [...document.querySelectorAll('[data-connection-active="true"] button')].some(
      (node) => node.getAttribute('aria-label') === 'Refresh sessions' && !node.disabled,
    ),
  );
  const before = sent.length;
  const lastIssued = Math.max(
    0,
    ...sent.filter((value) => value.type === 'request').map((value) => Number(value.requestId)),
  );
  const refreshed = managementWire(page).waitForResponse(
    (response) =>
      response.url().endsWith('/management/sessions/list') &&
      Number(response.request().requestId()) > lastIssued,
  );
  await pane.getByRole('button', { name: 'Refresh sessions', exact: true }).click();
  const reply = await refreshed;
  await reply.finished();
  const result = await reply.json();
  assert.equal(result.operation, 'sessions.list');
  assert(result.sessions.items.some((row) => row.user === 'alice'));
  await grid.getByText('alice', { exact: true }).waitFor();
  assert(
    sent.length > before,
    'an explicit read after real server and browser expiry uses the existing channel',
  );
  // Other catalog requests/progress may still be completing. Assert this exact
  // explicit read and receipt, never the unrelated globally last socket frame.
  const request = sent.find(
    (value) => value.type === 'request' && value.requestId === reply.request().requestId(),
  );
  assert(sent.indexOf(request) >= before);
  assert.equal(request.action, 'management/sessions/list');
  await page.waitForFunction(
    () =>
      document.querySelector('[data-connection-active="true"][data-access-status="active"]') !==
        null ||
      document.querySelector('[data-access-status="active"][aria-selected="true"]') !== null,
  );
  assert.equal(reply.status(), 200);
  assert(
    received.some((value) => value.type === 'complete' && value.requestId === request.requestId),
  );
  assert.deepEqual(sockets, ['/_bifroest/api/v1/management/channel']);
  assert.equal(
    sent.some((value) => value.task !== undefined || value.command !== undefined),
    false,
  );
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await logout(page);
  await assertUiPreferences(page);
}

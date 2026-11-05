import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { forcedKeyLogin } from './management-forced-ui.mjs';
import { managementInterruption } from './management-interruption.mjs';
import { managementWire } from './management-wire.mjs';
import { assertUiPreferences, workspace } from './workspace-ui.mjs';

export async function exerciseManagementForcedAction(page, file, logout) {
  const { action, flow, id } = JSON.parse(await readFile(file, 'utf8'));
  const wire = managementWire(page);
  const interruption = action === 'dispose' ? await managementInterruption(page) : null;
  const calls = [];
  wire.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes('/api/v1/management/')) {
      calls.push(path);
    }
  });
  const initialRead = wire.waitForResponse((response) =>
    response.url().endsWith('/management/flows/list'),
  );
  await forcedKeyLogin(page, file);
  assert.equal((await initialRead).status(), 403);
  const initialSessions = wire.waitForResponse((response) =>
    response.url().endsWith('/management/sessions/list'),
  );
  await workspace(page, 'Sessions');
  assert.equal(
    (await initialSessions).status(),
    403,
    'the active Sessions view does not gain list permission',
  );
  assert.deepEqual(
    calls.map((path) => path.split('/management/')[1]),
    ['flows/list', 'sessions/list'],
    'only the entry-view reads and intentional Sessions read, never automatic preparation',
  );
  async function connect() {
    await page.evaluate(async () => {
      const { BrowserClient } = await import('/_bifroest/test/client.js');
      window.targetAccess ??= await new BrowserClient({
        origin: location.origin,
        slug: 'Worker',
      }).password('bob', 'correct');
      window.targetSockets ??= [];
      const socket = new WebSocket(
        `${location.origin.replace('https:', 'wss:')}/_bifroest/api/v1/terminal`,
        'bifroest-terminal.v1',
      );
      window.targetSockets.push(socket);
      socket.binaryType = 'arraybuffer';
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('target did not run')), 5000);
        socket.onerror = () => reject(new Error('target connection failed'));
        socket.onopen = () =>
          socket.send(
            JSON.stringify({
              type: 'open',
              slug: 'Worker',
              accessToken: window.targetAccess.terminalToken(),
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
    });
  }
  await connect();
  await connect();
  await page.locator('.advanced-action > summary').click();
  const direct = page.getByRole('region', { name: 'Advanced: target by ID', exact: true });
  await direct.waitFor();
  await direct.getByLabel('Target flow', { exact: false }).fill(flow);
  await direct.getByLabel('Target session ID', { exact: false }).fill(id);
  async function choose(value) {
    await direct.getByRole('combobox', { name: 'Session action', exact: true }).click();
    await page
      .getByRole('option', {
        name: value === 'dispose' ? 'End session' : 'Disconnect connections',
        exact: true,
      })
      .click();
  }
  await choose(action === 'dispose' ? 'disconnect' : 'dispose');
  const denied = wire.waitForResponse(
    (response) => response.url().endsWith('/sessions/prepare') && response.status() === 403,
  );
  await direct.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  await denied;
  assert.equal(await page.getByRole('dialog').count(), 0);
  await choose(action);
  const preparationReply = wire.waitForResponse(
    (response) => response.url().endsWith('/sessions/prepare') && response.status() === 202,
  );
  await direct.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  let dialog = page.getByRole('dialog');
  await dialog
    .getByText('Session details are not returned under this action-only policy.', { exact: false })
    .waitFor();
  const preparation = await (await preparationReply).json();
  assert.deepEqual(Object.keys(preparation.target).sort(), ['flow', 'id']);
  assert.deepEqual(
    preparation.target,
    { flow, id },
    'the real channel receipt must contain only the action selector, never ShowSession metadata',
  );
  assert.equal(
    await dialog.getByText('No verified association available', { exact: true }).count(),
    0,
  );
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(calls.filter((path) => path.endsWith('/confirm')).length, 0);
  assert.equal(
    await page.evaluate(() =>
      window.targetSockets.every((socket) => socket.readyState === WebSocket.OPEN),
    ),
    true,
  );
  await direct.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByText(`${flow}/${id}`, { exact: true }).waitFor();
  await dialog
    .getByLabel('Type the exact flow/session ID shown above', { exact: true })
    .fill('wrong-target');
  assert.equal(
    await dialog.getByRole('button', { name: 'Confirm session action', exact: true }).isEnabled(),
    false,
  );
  await dialog
    .getByLabel('Type the exact flow/session ID shown above', { exact: true })
    .fill(`${flow}/${id}`);
  if (action === 'dispose') {
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
  }
  await dialog.getByRole('button', { name: 'Confirm session action', exact: true }).click();
  await page
    .getByText(
      action === 'dispose'
        ? 'The session action result is unknown.'
        : 'The server confirmed this session action and its configured audit/recording lifecycle.',
      { exact: false },
    )
    .waitFor();
  await page.waitForFunction(() =>
    window.targetSockets.every((socket) => socket.readyState === WebSocket.CLOSED),
  );
  assert.deepEqual(
    calls
      .filter((path) => path.endsWith('/show') || path.endsWith('/list'))
      .map((path) => path.split('/management/')[1]),
    ['flows/list', 'sessions/list'],
    'the initial denied view read is not a prerequisite for acting; no target inspection or additional list read',
  );
  if (action === 'disconnect') {
    await connect();
    await page.evaluate(() => window.targetSockets.at(-1).close());
  } else {
    assert.equal(
      interruption.losses(),
      1,
      'one real successful server completion was lost, without replay',
    );
    assert.equal(
      await page.getByRole('button', { name: 'Connection options', exact: true }).isEnabled(),
      false,
    );
    assert.equal(
      await direct.getByRole('button', { name: 'Prepare session action', exact: true }).isEnabled(),
      false,
    );
    await page
      .getByRole('button', { name: 'Dismiss local warning (does not confirm result)', exact: true })
      .click();
  }
  assert.equal(
    calls.filter((path) => path.endsWith('/confirm')).length,
    1,
    'no replay or cancel-as-undo',
  );
  await logout(page);
  assert.equal(await direct.getByLabel('Target session ID', { exact: false }).count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

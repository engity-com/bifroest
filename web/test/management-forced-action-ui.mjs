import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { forcedKeyLogin } from './management-forced-ui.mjs';

export async function exerciseManagementForcedAction(page, file, logout) {
  const { action, flow, id } = JSON.parse(await readFile(file, 'utf8'));
  const calls = [];
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes('/api/v1/management/')) {
      calls.push(path);
    }
  });
  await forcedKeyLogin(page, file);
  assert.deepEqual(calls, [], 'login must not enumerate sessions or prepare automatically');
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
  const direct = page.getByRole('region', { name: 'Action on a known session', exact: true });
  await direct.waitFor();
  await direct.getByLabel('Target flow', { exact: false }).fill(flow);
  await direct.getByLabel('Target session ID', { exact: false }).fill(id);
  async function choose(value) {
    await direct.getByRole('combobox', { name: 'Session action', exact: true }).click();
    await page.getByRole('option', { name: value, exact: true }).click();
  }
  await choose(action === 'dispose' ? 'disconnect' : 'dispose');
  const denied = page.waitForResponse(
    (response) => response.url().endsWith('/sessions/prepare') && response.status() === 403,
  );
  await direct.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  await denied;
  assert.equal(await page.getByRole('dialog').count(), 0);
  await choose(action);
  const preparation = page.waitForResponse(
    (response) => response.url().endsWith('/sessions/prepare') && response.status() === 202,
  );
  await direct.getByRole('button', { name: 'Prepare session action', exact: true }).click();
  const body = await (await preparation).json();
  assert.deepEqual(body.target, { flow, id }, 'no ShowSession metadata in a preparation');
  let dialog = page.getByRole('dialog');
  await dialog
    .getByText('Session details are not returned under this action-only policy.', { exact: false })
    .waitFor();
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
  assert.equal(
    calls.filter((path) => path.endsWith('/show') || path.endsWith('/list')).length,
    0,
    'no hidden read needed to act',
  );
  if (action === 'disconnect') {
    await connect();
    await page.evaluate(() => window.targetSockets.at(-1).close());
  } else {
    assert.equal(
      await page.getByRole('button', { name: 'Log out', exact: true }).isEnabled(),
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
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

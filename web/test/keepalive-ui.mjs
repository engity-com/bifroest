import assert from 'node:assert/strict';
import {
  activeAccess,
  assertUiPreferences,
  duplicateTab,
  terminalAction,
} from './workspace-ui.mjs';

export async function exerciseKeepAlive(page, login) {
  const openings = [];
  const changes = [];
  let captureInput = false;
  let settingsInputBytes = 0;
  page.on('websocket', (socket) =>
    socket.on('framesent', ({ payload }) => {
      if (typeof payload === 'string') {
        const body = JSON.parse(payload);
        if (body.type === 'open') {
          openings.push({ slug: body.slug, keepAlive: body.keepAlive });
        }
        if (body.type === 'keepalive') {
          changes.push({ interval: body.interval, requestId: body.requestId });
        }
      } else if (captureInput) {
        settingsInputBytes += payload.length;
      }
    }),
  );
  const connected = (view) =>
    page
      .locator(
        `#terminal-pane-${view}[data-connection-active="true"] [data-terminal-phase="connected"]`,
      )
      .waitFor();
  const settings = () => page.getByRole('dialog', { name: 'Connection settings', exact: true });
  const interval = () => settings().getByLabel('Keepalive interval', { exact: true });
  const stored = (slug) =>
    page.evaluate(
      (slug) => localStorage.getItem(`bifroest-ui-v1:keepalive:${encodeURIComponent(slug)}`),
      slug,
    );
  async function openSettings(expected, locked = false) {
    await terminalAction(page, 'Connection settings');
    await settings().waitFor();
    assert.equal(await interval().inputValue(), expected);
    assert.equal(await interval().isDisabled(), locked);
  }
  await login(page, false);
  await activeAccess(page, 'alice');
  await connected(1);
  await openSettings('10s');
  captureInput = true;
  await interval().fill('0s');
  assert.equal(
    await settings()
      .getByRole('button', { name: 'Apply connection settings', exact: true })
      .isEnabled(),
    false,
  );
  await interval().fill('1s');
  await settings().getByRole('button', { name: 'Apply connection settings', exact: true }).click();
  await settings().waitFor({ state: 'hidden' });
  captureInput = false;
  assert.equal(settingsInputBytes, 0, 'connection settings must never become terminal input');
  assert.equal(openings.length, 1, 'changing keepalive must preserve the running execution');
  assert.deepEqual(changes, [{ interval: '1s', requestId: '1' }]);
  assert.equal(await stored('Work'), '1s');
  await duplicateTab(page);
  await connected(2);
  assert.deepEqual(openings[1], { slug: 'Work', keepAlive: '1s' });
  await openSettings('1s');
  await settings().getByRole('button', { name: 'Close', exact: true }).click();

  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await login(page, false, 'bob');
  await activeAccess(page, 'bob');
  await connected(3);
  assert.equal(
    openings[2].keepAlive,
    undefined,
    'an enforced policy ignores a saved editable preference',
  );
  await openSettings('20s', true);
  await settings()
    .getByText('This interval is enforced by the flow and cannot be changed.', { exact: true })
    .waitFor();
  assert.equal(
    await settings()
      .getByRole('button', { name: 'Apply connection settings', exact: true })
      .isEnabled(),
    false,
  );
  await settings().getByRole('button', { name: 'Close', exact: true }).click();
  assert.equal(changes.length, 1);

  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await page.getByLabel('Slug', { exact: true }).click();
  await page.getByRole('option', { name: 'Other', exact: true }).click();
  await page.waitForFunction(
    () => document.querySelector('.login-dialog [role="combobox"]')?.textContent === 'Other',
  );
  await login(page, false);
  await activeAccess(page, 'alice');
  await connected(4);
  assert.equal(openings[3].keepAlive, undefined);
  await openSettings('30s');
  await interval().fill('20s');
  await settings().getByRole('button', { name: 'Apply connection settings', exact: true }).click();
  await settings().waitFor({ state: 'hidden' });
  assert.equal(await stored('Other'), '20s');
  assert.equal(await stored('Work'), '1s');

  await page.reload();
  assert.equal(new URL(page.url()).pathname, '/');
  assert.equal(
    decodeURIComponent(new URL(page.url()).hash.slice(1).split('/')[0]),
    'Other',
    'reload retains the selected Slug',
  );
  await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor();
  assert.equal(openings.length, 4, 'preferences cannot authenticate or start a shell after reload');
  await login(page, false);
  await connected(1);
  assert.deepEqual(openings[4], { slug: 'Other', keepAlive: '20s' });
  await openSettings('20s');
  await settings().getByRole('button', { name: 'Close', exact: true }).click();
  await assertUiPreferences(page);
}

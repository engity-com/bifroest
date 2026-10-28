import assert from 'node:assert/strict';
import { captureLayout, reauthenticate } from './workspace-ui.mjs';

export async function exerciseTerminal(page, login) {
  let sockets = 0;
  const openings = [];
  page.on('websocket', (socket) => {
    sockets++;
    socket.on('framesent', ({ payload }) => {
      if (typeof payload === 'string') {
        const value = JSON.parse(payload);
        if (value.type === 'open') {
          openings.push({ task: value.task, command: value.command, pty: Boolean(value.pty) });
        }
      }
    });
  });
  const pane = () => page.locator('[data-terminal-active="true"]');
  const output = async (text) => {
    await pane().getByRole('region', { name: 'Terminal viewport', exact: true }).waitFor();
    await page.waitForFunction(
      (text) =>
        document
          .querySelector('[data-terminal-active="true"] .xterm-rows')
          ?.textContent?.includes(text),
      text,
      { timeout: 5000 },
    );
  };
  const type = async (text) => {
    await pane().locator('.xterm-helper-textarea').focus();
    await page.keyboard.type(text);
    await page.keyboard.press('Enter');
  };
  const action = async (name) => {
    await page.getByRole('button', { name: 'Terminal actions', exact: true }).click();
    await page.getByRole('menuitem', { name, exact: true }).click();
  };
  const select = async (number, user) => {
    await page.getByRole('tab', { name: `Terminal ${number} ${user}`, exact: true }).click();
  };
  await login(page, false);
  await output('EXECUTION_START:1');
  assert.equal(sockets, 1, 'a confirmed login opens exactly one shell automatically');
  assert.equal(
    await page.getByRole('textbox', { name: 'Command to execute', exact: true }).count(),
    0,
  );
  const geometry = await pane().locator('.terminal-surface').boundingBox();
  const bar = await page.locator('.application-bar').boundingBox();
  const viewport = page.viewportSize();
  assert(
    geometry &&
      bar &&
      geometry.width >= viewport.width - 16 &&
      Math.abs(geometry.y - bar.height) < 6 &&
      geometry.y + geometry.height >= viewport.height - 4,
    'terminal must fill all space below the bar',
  );
  await output('UTF8:€');
  await output('STDERR_MARKER');
  await captureLayout(page, 'terminal-desktop');
  assert.equal(await page.title(), 'Fixture brand');
  const renderedLink = pane().locator('.xterm-rows').getByText('blocked-link', { exact: true });
  await renderedLink.waitFor({ state: 'visible' });
  const link = await renderedLink.boundingBox();
  assert(link);
  const pages = page.context().pages().length;
  await page.mouse.click(link.x + link.width / 2, link.y + link.height / 2);
  assert.equal(page.context().pages().length, pages, 'remote links must not open windows');
  await type('hello');
  await output('STDIN:hello');
  await page.setViewportSize({ width: 390, height: 844 });
  await output('RESIZE:');
  await captureLayout(page, 'terminal-mobile');
  await page.setViewportSize({ width: 320, height: 640 });
  await captureLayout(page, 'terminal-320');
  await page.setViewportSize({ width: 390, height: 844 });
  await action('Request INT signal');
  await output('SIGNAL:INT');
  await action('Send input EOF');
  await output('OUTPUT_AFTER_EOF');
  await page.locator('[data-terminal-phase="exited"]').waitFor();
  assert.equal(
    await page.locator('[data-terminal-phase="exited"]').textContent(),
    'Validated exit status: 7',
    'the exact validated exit status is independent of the actor label',
  );
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await output('EXECUTION_START:2');
  await reauthenticate(page);
  await login(page, false, 'bob');
  await output('EXECUTION_START:3');
  assert.equal(sockets, 3, 'reauthentication opens a new tab without replacing the old execution');
  assert(!(await pane().locator('.xterm-rows').textContent()).includes('EXECUTION_START:2'));
  await select(2, 'alice');
  await type('still-running');
  await output('STDIN:still-running');
  await select(3, 'bob');
  await type('drop');
  await page.locator('[data-terminal-phase="interrupted"]').waitFor();
  assert.equal(sockets, 3, 'an interrupted shell must not be replayed automatically');
  assert.equal(await page.locator('[data-terminal-phase="exited"]').count(), 0);
  await select(2, 'alice');
  await page.getByRole('button', { name: 'Close terminal 2', exact: true }).click();
  const closing = page.getByRole('dialog', { name: 'Close this terminal?', exact: true });
  await closing.getByText('Terminal 2 · alice', { exact: true }).waitFor();
  await closing.getByRole('button', { name: 'Cancel', exact: true }).click();
  await type('kept-after-cancel');
  await output('STDIN:kept-after-cancel');
  await page.getByRole('button', { name: 'Close terminal 2', exact: true }).click();
  await closing.getByRole('button', { name: 'Close terminal', exact: true }).click();
  assert.equal(await page.getByRole('tab', { name: 'Terminal 2 alice', exact: true }).count(), 0);
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await output('EXECUTION_START:4');
  await action('Send input EOF');
  await page.locator('[data-terminal-phase="exited"]').waitFor();
  await select(1, 'alice');
  await output('EXECUTION_START:1');
  assert(
    (await pane().locator('.xterm-rows').textContent()).includes('STDIN:hello'),
    'switching tabs retains its own original output',
  );
  assert.deepEqual(
    openings,
    Array.from({ length: 4 }, () => ({ task: 'shell', command: undefined, pty: true })),
  );
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

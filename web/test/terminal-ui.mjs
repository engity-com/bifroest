import assert from 'node:assert/strict';

// Drives only the real application and its xterm textarea; no exposed emulator
// internals, fake transport or CLI actions. The Go side supplies a test backend.
export async function exerciseTerminal(page, login) {
  const output = async (text) => {
    await page.locator('.terminal-surface').scrollIntoViewIfNeeded(); // xterm intentionally pauses off-screen DOM rendering.
    try {
      await page.waitForFunction(
        (text) => document.querySelector('.xterm-rows')?.textContent?.includes(text),
        text,
        { timeout: 5000 },
      );
    } catch {
      throw new Error(
        JSON.stringify({
          expected: text,
          phase: await page.locator('[data-terminal-phase]').getAttribute('data-terminal-phase'),
          output: await page.locator('.xterm-rows').textContent(),
          viewport: await page.locator('.terminal-surface').evaluate((node) => ({
            rectangle: node.getBoundingClientRect().toJSON(),
            height: window.innerHeight,
            rows: node.querySelector('.xterm-rows')?.childElementCount,
          })),
          csp: await page.evaluate(() => window.cspViolations),
        }),
      );
    }
  };
  const type = async (text) => {
    await page.locator('.xterm-helper-textarea').focus();
    await page.keyboard.type(text);
    await page.keyboard.press('Enter');
  };
  const start = async (number) => {
    await page.getByRole('button', { name: 'Start new execution', exact: true }).click();
    await page.locator('[data-terminal-phase="connected"]').waitFor();
    await output(`EXECUTION_START:${number}`);
  };
  await login(page, false);
  await start(1);
  await output('UTF8:€');
  await output('STDERR_MARKER');
  assert.equal(
    await page.title(),
    'Fixture brand',
    'remote OSC title must not rename the application',
  );
  const pages = page.context().pages().length;
  const link = await page.getByText('blocked-link', { exact: true }).boundingBox();
  assert(link !== null);
  // xterm intentionally delegates row pointer events to its screen element.
  await page.mouse.move(link.x + link.width / 2, link.y + link.height / 2);
  await page.mouse.click(link.x + link.width / 2, link.y + link.height / 2);
  assert.equal(page.context().pages().length, pages, 'remote links must not open windows');
  await type('hello');
  await output('STDIN:hello');
  await page.setViewportSize({ width: 500, height: 1000 });
  await output('RESIZE:');
  await page.getByRole('button', { name: 'Request INT signal', exact: true }).click();
  await output('SIGNAL:INT');
  await page.getByRole('button', { name: 'Send input EOF', exact: true }).click();
  await output('OUTPUT_AFTER_EOF');
  await page.locator('[data-terminal-phase="exited"]').waitFor();
  assert((await page.locator('[data-terminal-phase="exited"]').textContent()).includes('7'));
  await start(2);
  await page
    .getByRole('button', { name: 'Sign in again for new connections', exact: true })
    .click();
  await login(page, false, 'bob');
  assert.equal(
    await page.locator('[data-terminal-phase="connected"]').count(),
    1,
    'reauthentication must not replace the active execution',
  );
  await page.getByText('This execution was started as: alice', { exact: true }).waitFor();
  await type('still-running');
  await output('STDIN:still-running');
  await page.getByRole('button', { name: 'Disconnect execution', exact: true }).click();
  await page.locator('[data-terminal-phase="disconnected"]').waitFor();
  await start(3);
  await type('drop');
  await page.getByText('This execution was started as: bob', { exact: true }).waitFor();
  await page.locator('[data-terminal-phase="interrupted"]').waitFor();
  assert.equal(
    await page.locator('[data-terminal-phase="exited"]').count(),
    0,
    'a dropped connection must not invent exit zero',
  );
  await page.getByText('Command', { exact: true }).click();
  await page.getByLabel('Command to execute', { exact: true }).fill('printf fixture');
  await page.getByRole('checkbox', { name: 'Request a PTY', exact: true }).uncheck();
  await start(4);
  await output('PTY:false');
  await output('COMMAND:printf fixture');
  await page.getByRole('button', { name: 'Log out', exact: true }).click();
  await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
  assert.equal(await page.locator('.xterm').count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

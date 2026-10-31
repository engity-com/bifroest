import assert from 'node:assert/strict';
import {
  activeAccessCount,
  answerAuthentication,
  assertUiPreferences,
  authenticationConsole,
  captureLayout,
  chooseLoginMethod,
  logoutAccess,
  notification,
  settledLogin,
} from './workspace-ui.mjs';

export async function exerciseInteractive(page, login, logout) {
  await login(page, false);
  await logout(page);
  let shells = 0;
  let replies = 0;
  page.on('websocket', () => shells++);
  page.on('request', (request) => {
    if (request.url().endsWith('/api/v1/login/reply')) {
      replies++;
    }
  });
  await chooseLoginMethod(page, 'Interactive / device login');
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  let console = await authenticationConsole(page, {
    text: '<b>plain provider text</b><script>window.providerInjected = true</script>',
    kind: 'info',
  });
  assert.equal(await page.evaluate(() => window.providerInjected), undefined);
  assert.equal(shells, 0, 'a local authentication console is not an early server shell');
  await captureLayout(page, 'material-authentication-info');
  assert.equal(
    await console.locator('b, script').count(),
    0,
    'provider text must not become DOM markup',
  );
  await answerAuthentication(page);
  await answerAuthentication(page, '', { text: 'Provider warning, shown as text', kind: 'error' });
  console = await authenticationConsole(page, {
    text: 'Echo is allowed for this response',
    kind: 'prompt',
    echo: true,
  });
  await console.evaluate((node) => {
    const input = node.querySelector('textarea');
    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    input.value = '公開';
    input.dispatchEvent(new CompositionEvent('compositionupdate', { bubbles: true, data: '公開' }));
  });
  assert.equal(
    await console.locator('.composition-view').textContent(),
    '公開',
    'the provider explicitly allows public preedit echo',
  );
  await console
    .locator('textarea')
    .evaluate((input) =>
      input.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: '公開' })),
    );
  await page.waitForFunction(() =>
    document
      .querySelector('[data-auth-terminal-active="true"] .xterm-rows')
      ?.textContent?.includes('公開'),
  );
  await console.evaluate((node) => {
    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', 'visible-not-an-identity\r\ncorrect');
    node
      .querySelector('textarea')
      .dispatchEvent(
        new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData }),
      );
  });
  console = await authenticationConsole(page, { kind: 'prompt', echo: false });
  assert.equal(shells, 0, 'a pasted tail cannot answer the following secret prompt');
  await page.waitForFunction(() =>
    document
      .querySelector('[data-auth-terminal-active="true"] .xterm-rows')
      ?.textContent?.includes('visible-not-an-identity'),
  );
  assert.equal(
    await console.locator('textarea').inputValue(),
    '',
    'next secret prompt must not inherit the previous answer',
  );
  await answerAuthentication(page, 'secret-transition', {
    text: 'Secret transition response',
    echo: false,
  });
  await answerAuthentication(page, 'public-transition', {
    text: 'Public transition response',
    echo: true,
  });
  console = await authenticationConsole(page, { kind: 'prompt', echo: false });
  await console.locator('textarea').focus();
  const nativeIME = await page.context().newCDPSession(page);
  await page.evaluate(() =>
    document.addEventListener(
      'compositionend',
      (event) => {
        window.nativeCompositionEndTrusted = event.isTrusted;
      },
      { once: true },
    ),
  );
  await nativeIME.send('Input.imeSetComposition', {
    text: 'correct',
    selectionStart: 7,
    selectionEnd: 7,
  });
  assert.equal(
    await console.locator('.composition-view').textContent(),
    '',
    'secret IME preedit is suppressed BEFORE xterm can copy it to a visible DOM node',
  );
  assert.equal((await console.textContent()).includes('correct'), false);
  await nativeIME.send('Input.insertText', { text: 'correct' });
  // CDP's IME driver exercises Blink/xterm composition, but Chromium marks its
  // compositionend untrusted. Do not claim this is a physical OS-IME event.
  assert.notEqual(
    await page.evaluate(() => window.nativeCompositionEndTrusted),
    undefined,
    'the browser IME driver must emit compositionend',
  );
  await nativeIME.detach();
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(
    (await console.locator('.xterm-rows').textContent()).includes('correct'),
    false,
    'secret response never enters the rendered transcript',
  );
  await captureLayout(page, 'material-authentication-secret');
  await page.keyboard.press('Enter');
  await settledLogin(page, 'alice');
  await notification(page, 'RememberMe setup confirmed for this browser.');
  assert.equal(await page.getByRole('dialog').count(), 0);
  await logout(page);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await authenticationConsole(page, {
    text: '<b>plain provider text</b><script>window.providerInjected = true</script>',
  });
  const stopped = page.waitForResponse(
    (response) => response.url().endsWith('/api/v1/login/cancel') && response.status() === 204,
  );
  await page.locator('[data-auth-terminal-active="true"] textarea').focus();
  await page.keyboard.press('Control+c');
  await stopped;
  await notification(page, 'Operation cancelled. Cancellation is not server logout.');
  assert.equal(await activeAccessCount(page, 'alice'), 0);
  // A paste must not advance a prompt while an IME gesture still owns it.
  // Cancel the ambiguous attempt, then exercise its late events against a new
  // public prompt: they must neither gain echo nor become that prompt's input.
  async function interactiveToPublic() {
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await chooseLoginMethod(page, 'Interactive / device login');
    await page.getByLabel('User name', { exact: true }).fill('alice');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await answerAuthentication(page, '', { kind: 'info' });
    await answerAuthentication(page, '', { kind: 'error' });
    return authenticationConsole(page, { text: 'Echo is allowed for this response', echo: true });
  }
  await interactiveToPublic();
  await answerAuthentication(page, 'public-before-overlap');
  const overlap = await authenticationConsole(page, {
    text: 'Secret transition response',
    echo: false,
  });
  const staleInput = await overlap.locator('textarea').elementHandle();
  await staleInput.evaluate((input) => {
    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    input.value = 'old-secret-preedit';
    input.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: 'old-secret-preedit' }),
    );
  });
  const beforeOverlap = replies;
  const overlapCancelled = page.waitForResponse(
    (response) => response.url().endsWith('/api/v1/login/cancel') && response.status() === 204,
  );
  await overlap.evaluate((node) => {
    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', 'overlap-answer\r');
    node
      .querySelector('textarea')
      .dispatchEvent(
        new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData }),
      );
  });
  await overlapCancelled;
  await page.locator('[data-auth-terminal-active="true"]').waitFor({ state: 'detached' });
  assert.equal(
    replies,
    beforeOverlap,
    'overlapping composition/paste is cancelled before any prompt reply',
  );
  await notification(page, 'Operation cancelled.');
  const freshPublic = await interactiveToPublic();
  const beforeLate = replies;
  await staleInput.evaluate((input) => {
    input.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: 'old-secret-preedit' }),
    );
    input.dispatchEvent(
      new CompositionEvent('compositionend', { bubbles: true, data: 'old-secret-preedit' }),
    );
  });
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal(replies, beforeLate);
  assert.equal((await freshPublic.textContent()).includes('old-secret-preedit'), false);
  await freshPublic.locator('textarea').focus();
  await page.keyboard.press('Control+c');
  await notification(page, 'Operation cancelled.');
  assert.equal(await activeAccessCount(page, 'alice'), 0);
  await staleInput.dispose();
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

export async function exerciseDevice(page, cancel) {
  assert.equal(await page.getByLabel('User name', { exact: true }).count(), 0);
  await chooseLoginMethod(page, 'Interactive / device login');
  if (!cancel) {
    await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  }
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await authenticationConsole(page, { text: 'test-code', kind: 'info' });
  const console = page.locator('[data-auth-terminal-active="true"]');
  const link = console.getByRole('link');
  const target = await link.getAttribute('href');
  assert.match(target, /^https:\/\/127\.0\.0\.1:[0-9]+\/verify$/);
  assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
  assert.equal(await console.locator('iframe').count(), 0);
  // The Go cancellation fixture holds this real reply until its provider call
  // has started; no extra browser fetch or request replay is needed to observe it.
  const providerStarted = cancel
    ? page.waitForResponse(
        (response) => response.url().endsWith('/api/v1/login/reply') && response.status() === 202,
      )
    : null;
  await answerAuthentication(page);
  if (cancel) {
    await providerStarted;
    const stopped = page.waitForResponse(
      (response) => response.url().endsWith('/api/v1/login/cancel') && response.status() === 204,
    );
    await page.getByRole('button', { name: 'Cancel authentication', exact: true }).click();
    await stopped;
    await notification(page, 'Operation cancelled. Cancellation is not server logout.');
    assert.equal(await activeAccessCount(page, 'verified-subject'), 0);
  } else {
    await page.waitForFunction(() =>
      document
        .querySelector('[data-auth-terminal-active="true"] .xterm-rows')
        ?.textContent?.includes('Waiting for authentication'),
    );
    assert.equal(
      await link.getAttribute('href'),
      target,
      'the current provider link must remain available while waiting',
    );
    assert((await console.locator('.xterm-rows').textContent()).includes('test-code'));
    assert.equal(
      await console.getByRole('radio').count(),
      0,
      'pending device auth is not a disabled new-login form',
    );
    await settledLogin(page, 'verified-subject');
    await notification(page, 'RememberMe setup confirmed for this browser.');
    await page.reload();
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await settledLogin(page, 'verified-subject');
    await logoutAccess(page);
    await page.locator('[data-connection-active="true"]').waitFor({ state: 'detached' });
  }
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

export async function exerciseLostClaim(page, login, logout) {
  let shells = 0;
  page.on('websocket', () => {
    shells++;
  });
  await chooseLoginMethod(page, 'Interactive / device login');
  await page.getByLabel('User name', { exact: true }).fill('alice');
  let polls = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/api/v1/login/poll')) {
      polls++;
    }
  });
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await answerAuthentication(page, 'correct', { kind: 'prompt', echo: false });
  await page.waitForFunction(() =>
    document
      .querySelector('[data-auth-terminal-active="true"] .xterm-rows')
      ?.textContent?.includes('The login claim/reply result could not be confirmed.'),
  );
  assert.equal(await activeAccessCount(page, 'alice'), 0);
  const before = polls;
  assert.equal(shells, 0, 'an unconfirmed login response must never open a shell');
  await page.waitForTimeout(1600); // Deliberate quiet window: no automatic poll replay after the lost claim.
  assert.equal(polls, before);
  await page.getByRole('button', { name: 'Cancel authentication', exact: true }).click();
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await chooseLoginMethod(page, 'Password login');
  await login(page, false);
  await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await assertUiPreferences(page);
}

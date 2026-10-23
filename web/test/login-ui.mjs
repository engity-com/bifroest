import assert from 'node:assert/strict';

export async function exerciseInteractive(page, login, logout) {
  await login(page, false); await logout(page);
  await page.getByText('Interactive / device login', { exact: true }).click();
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByText('<b>plain provider text</b><script>window.providerInjected = true</script>', { exact: true }).waitFor();
  assert.equal(await page.evaluate(() => window.providerInjected), undefined);
  assert.equal(await dialog.locator('b, script').count(), 0, 'provider text must not become DOM markup');
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click();
  await dialog.getByText('Provider warning, shown as text', { exact: true }).waitFor();
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click();
  await dialog.getByText('Echo is allowed for this response', { exact: true }).waitFor();
  assert.equal(await dialog.getByLabel('Response', { exact: true }).evaluate(input => input.type), 'text');
  await dialog.getByLabel('Response', { exact: true }).fill('visible-not-an-identity');
  await dialog.getByRole('button', { name: 'Send response', exact: true }).click();
  await dialog.getByLabel('Response', { exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelector('[name="answer"]')?.getAttribute('type') === 'password');
  assert.equal(await dialog.getByLabel('Response', { exact: true }).inputValue(), '', 'next secret prompt must not inherit the previous answer');
  await dialog.getByLabel('Response', { exact: true }).fill('correct');
  await dialog.getByRole('button', { name: 'Send response', exact: true }).click();
  await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
  await page.getByText('RememberMe setup confirmed for this browser.', { exact: true }).waitFor();
  assert.equal(await page.getByRole('dialog').count(), 0);
  await logout(page);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByText('<b>plain provider text</b><script>window.providerInjected = true</script>', { exact: true }).waitFor();
  const stopped = page.waitForResponse(response => response.url().endsWith('/api/v1/login/cancel') && response.status() === 204);
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).last().click();
  await stopped;
  await page.getByText('Operation cancelled. Cancellation is not server logout.', { exact: true }).waitFor();
  assert.equal(await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).count(), 0);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

export async function exerciseDevice(page, cancel) {
  assert.equal(await page.getByLabel('User name', { exact: true }).count(), 0);
  await page.getByText('Interactive / device login', { exact: true }).click();
  if (!cancel) await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByText('test-code', { exact: false }).waitFor();
  const link = dialog.getByRole('link');
  const target = await link.getAttribute('href');
  assert.match(target, /^https:\/\/127\.0\.0\.1:[0-9]+\/verify$/);
  assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
  assert.equal(await dialog.locator('iframe').count(), 0);
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click();
  if (cancel) {
    await page.evaluate(async () => {
      const response = await fetch('/_bifroest/test/provider-started', { credentials: 'omit', mode: 'same-origin', signal: AbortSignal.timeout(5000) });
      if (response.status !== 204) throw new Error('provider token request did not start');
    });
    const stopped = page.waitForResponse(response => response.url().endsWith('/api/v1/login/cancel') && response.status() === 204);
    await page.getByRole('button', { name: 'Cancel', exact: true }).last().click();
    await stopped;
    await page.getByText('Operation cancelled. Cancellation is not server logout.', { exact: true }).waitFor();
    assert.equal(await page.getByRole('heading', { name: 'Signed in as verified-subject', exact: true }).count(), 0);
  } else {
    await page.getByRole('heading', { name: 'Signed in as verified-subject', exact: true }).waitFor();
    await page.getByText('RememberMe setup confirmed for this browser.', { exact: true }).waitFor();
    await page.reload();
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await page.getByRole('heading', { name: 'Signed in as verified-subject', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
  }
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

export async function exerciseLostClaim(page, login, logout) {
  await page.getByText('Interactive / device login', { exact: true }).click();
  await page.getByLabel('User name', { exact: true }).fill('alice');
  let polls = 0;
  page.on('request', request => { if (request.url().endsWith('/api/v1/login/poll')) polls++; });
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('dialog').getByLabel('Response', { exact: true }).fill('correct');
  await page.getByRole('dialog').getByRole('button', { name: 'Send response', exact: true }).click();
  await page.getByText('The login claim/reply result could not be confirmed.', { exact: false }).waitFor();
  assert.equal(await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).count(), 0);
  const before = polls;
  await page.waitForTimeout(1600); // Deliberate quiet window: no automatic poll replay after the lost claim.
  assert.equal(polls, before);
  await page.getByText('Password login', { exact: true }).click();
  await login(page, false); await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}

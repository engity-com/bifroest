import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';

const origin = process.argv[2];
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/);
const profile = await mkdtemp(join(tmpdir(), 'bifroest-ui-'));
let context;
const errors = [];
try {
  const open = async () => {
    context = await chromium.launchPersistentContext(profile, { headless: true, ignoreHTTPSErrors: true, args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'] });
    await context.addInitScript(() => {
      window.cspViolations = [];
      window.addEventListener('securitypolicyviolation', event => window.cspViolations.push(event.violatedDirective));
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    const response = await page.goto(`${origin}/Work`);
    assert.equal(response.status(), 200);
    const policy = response.headers()['content-security-policy'];
    assert(policy.includes("frame-ancestors 'none'") && policy.includes("'nonce-") && !policy.includes('unsafe-inline') && !policy.includes('unsafe-eval'));
    await page.getByRole('heading', { name: 'Fixture brand', exact: true }).waitFor();
    assert.equal(await page.locator('html').getAttribute('lang'), 'en-US');
    assert.equal(await page.locator('.workspace').evaluate(node => getComputedStyle(node).borderTopColor), 'rgb(1, 2, 3)');
    assert.equal(await page.evaluate(() => window.fixtureInline), true, 'trusted inline HTML extension needs the fresh document nonce');
    return page;
  };
  const local = async page => page.evaluate(async () => {
    const { BrowserBinding } = await import('/_bifroest/test/client.js');
    const handle = await BrowserBinding.load({ origin: location.origin, slug: 'Work' });
    return handle === null ? 'missing' : handle.binding === null ? 'pending' : 'ready';
  });
  const login = async (page, remember) => {
    await page.getByLabel('User name', { exact: true }).fill('alice');
    await page.getByLabel('Password', { exact: true }).fill('correct');
    if (remember) await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
  };
  const logout = async page => {
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
    assert.equal(await local(page), 'missing');
  };
  async function exercise() {
  let page = await open();
  if (process.argv[3] === 'name-free') {
    assert.equal(await page.getByLabel('User name', { exact: true }).count(), 0);
    await page.getByLabel('Password', { exact: true }).fill('correct');
    const request = page.waitForRequest(request => request.url().endsWith('/api/v1/login/password'));
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    assert.equal(JSON.parse((await request).postData()).user, '');
    await page.getByText('Access was denied.', { exact: false }).waitFor();
    assert.equal(await page.getByLabel('Password', { exact: true }).inputValue(), '', 'failed sign-in must not repopulate the submitted password');
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    return;
  }
  assert.equal(await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).isChecked(), false);
  await login(page, false);
  assert.equal(await local(page), 'missing');
  await logout(page);
  await login(page, true);
  await page.getByText('RememberMe setup confirmed for this browser.', { exact: true }).waitFor();
  assert.equal(await local(page), 'ready');
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  await context.close();
  page = await open();
  await page.getByRole('button', { name: 'Use saved access', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Forget saved browser access', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(await local(page), 'ready');
  await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
  await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
  await logout(page);
  await page.evaluate(async () => {
    const response = await fetch('/_bifroest/test/interrupt-enrollment', { method: 'POST', credentials: 'omit', mode: 'same-origin' });
    if (response.status !== 204) throw new Error('fault fixture was not armed');
  });
  await login(page, true);
  await page.getByText('RememberMe setup may have created a server permission.', { exact: false }).waitFor();
  assert.equal(await local(page), 'pending');
  await logout(page);
  await page.evaluate(async () => {
    const { BrowserBinding } = await import('/_bifroest/test/client.js');
    await BrowserBinding.prepare({ origin: location.origin, slug: 'Work' }, { explicitOptIn: true });
  });
  await page.reload();
  await page.getByRole('button', { name: 'Remove interrupted local setup', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Remove local data only', exact: true }).click();
  await page.getByText('Local setup removed. No server logout or revocation was claimed.', { exact: true }).waitFor();
  assert.equal(await local(page), 'missing');
  await page.evaluate(async () => {
    const { BrowserBinding } = await import('/_bifroest/test/client.js');
    const handle = await BrowserBinding.prepare({ origin: location.origin, slug: 'Work' }, { explicitOptIn: true });
    await handle.complete({ flow: 'work', sessionId: crypto.randomUUID(), bindingId: `bbr1.${'A'.repeat(43)}` });
  });
  await page.reload();
  await page.getByRole('button', { name: 'Forget saved browser access', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Revoke browser permission', exact: true }).click();
  await page.getByText('Access was denied.', { exact: false }).waitFor();
  assert.equal(await local(page), 'ready', 'failed remote revoke must not silently delete local keys');
  await page.getByRole('button', { name: 'Remove local data only', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Remove local data only', exact: true }).click();
  await page.getByText('Local setup removed. No server logout or revocation was claimed.', { exact: true }).waitFor();
  assert.equal(await local(page), 'missing');
  await page.getByText('Dark', { exact: true }).click();
  await page.locator('html[data-mantine-color-scheme="dark"]').waitFor();
  assert.equal(await page.locator('html').getAttribute('data-mantine-color-scheme'), 'dark');
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(errors, []);
  if (process.env.BIFROEST_TEST_UI_SCREENSHOT) await page.screenshot({ path: process.env.BIFROEST_TEST_UI_SCREENSHOT, fullPage: true });
  await page.evaluate(() => {
    const probe = document.createElement('script');
    probe.textContent = 'window.untrustedInlineRan = true';
    document.body.appendChild(probe);
  });
  assert.equal(await page.evaluate(() => window.untrustedInlineRan), undefined, 'un-nonced inline scripts must remain blocked');
  }
  await exercise();
  console.log(JSON.stringify({ success: true }));
} finally {
  await context?.close();
  await rm(profile, { recursive: true, force: true });
}

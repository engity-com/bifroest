import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { exerciseCompactWorkspace } from './compact-workspace-ui.mjs';
import { exerciseConnectionRaces, exerciseManagementOwner } from './connection-races-ui.mjs';
import { exerciseConnections } from './connections-ui.mjs';
import { exerciseKey, exerciseKeyVariant } from './key-ui.mjs';
import { exerciseDevice, exerciseInteractive, exerciseLostClaim } from './login-ui.mjs';
import { exerciseManagementActions } from './management-action-ui.mjs';
import { exerciseManagementForcedAction } from './management-forced-action-ui.mjs';
import {
  exerciseManagementForced,
  exerciseManagementForcedAudit,
  exerciseManagementForcedVersion,
} from './management-forced-ui.mjs';
import { exerciseManagement } from './management-ui.mjs';
import { exerciseTerminalExpiry } from './terminal-expiry-ui.mjs';
import { exerciseLostTerminalLogout } from './terminal-logout-ui.mjs';
import { exerciseTerminalTabs } from './terminal-tabs-ui.mjs';
import { exerciseTerminal } from './terminal-ui.mjs';
import {
  answerAuthentication,
  changeTheme,
  chooseLoginMethod,
  loginLayout,
  logoutAccess,
  notification,
  settledLogin,
} from './workspace-ui.mjs';

const origin = process.argv[2];
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/);
const profile = await mkdtemp(join(tmpdir(), 'bifroest-ui-'));
let context;
const errors = [];
const failedResources = [];
const failedRequests = [];
const loginResponses = [];
try {
  const open = async () => {
    context = await chromium.launchPersistentContext(profile, {
      headless: true,
      hasTouch: process.argv[3] === 'compact',
      ignoreHTTPSErrors: true,
      args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
    });
    await context.addInitScript(() => {
      window.cspViolations = [];
      window.addEventListener('securitypolicyviolation', (event) =>
        window.cspViolations.push(event.violatedDirective),
      );
    });
    const page = await context.newPage();
    const initializationErrors = [];
    const initializationConsole = (message) => {
      if (message.type() === 'error') {
        initializationErrors.push(message.text().slice(0, 4096));
      }
    };
    page.on('console', initializationConsole);
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('requestfailed', (request) => {
      // Paths and transport errors only, never request bodies, tokens or headers.
      failedRequests.push({
        path: new URL(request.url()).pathname,
        failure: request.failure()?.errorText,
      });
    });
    page.on('response', (response) => {
      const path = new URL(response.url()).pathname;
      if (path.endsWith('/api/v1/login/password')) {
        // Never log response bodies, credentials or Authorization headers.
        loginResponses.push({ path, status: response.status() });
      }
      if (response.status() >= 400) {
        failedResources.push({ path, status: response.status() });
      }
    });
    const response = await page.goto(`${origin}/Work`);
    assert.equal(response.status(), 200);
    const policy = response.headers()['content-security-policy'];
    assert(
      policy.includes("frame-ancestors 'none'") &&
        policy.includes("'nonce-") &&
        !policy.includes('unsafe-inline') &&
        !policy.includes('unsafe-eval'),
    );
    try {
      // MUI correctly removes the background main from the accessibility tree
      // while the initial sign-in dialog owns focus; it must still be rendered.
      await page
        .getByRole('main', { name: 'Fixture brand', exact: true, includeHidden: true })
        .waitFor();
    } catch (error) {
      throw new Error(
        JSON.stringify({
          pageErrors: errors,
          initializationErrors,
          failedResources,
          csp: await page.evaluate(() => window.cspViolations),
          root: await page.locator('#root').textContent(),
        }),
        { cause: error },
      );
    } finally {
      page.off('console', initializationConsole);
    }
    assert.equal(await page.locator('html').getAttribute('lang'), 'en-US');
    assert.equal(
      await page.locator('.workspace').evaluate((node) => getComputedStyle(node).borderTopColor),
      'rgb(1, 2, 3)',
    );
    assert.equal(
      await page.evaluate(() => window.fixtureInline),
      true,
      'trusted inline HTML extension needs the fresh document nonce',
    );
    if (process.argv[3] === 'management-actions') {
      await loginLayout(page);
    }
    return page;
  };
  const local = async (page) =>
    page.evaluate(async () => {
      const { BrowserBinding } = await import('/_bifroest/test/client.js');
      const handle = await BrowserBinding.load({ origin: location.origin, slug: 'Work' });
      return handle === null ? 'missing' : handle.binding === null ? 'pending' : 'ready';
    });
  const login = async (page, remember, user = 'alice') => {
    const nativeInteractive = process.argv[3] === 'local-interactive-profile';
    if (nativeInteractive) {
      await chooseLoginMethod(page, 'Interactive / device login');
    }
    await page.getByLabel('User name', { exact: true }).fill(user);
    if (!nativeInteractive) {
      await page.getByLabel('Password', { exact: true }).fill('correct');
    }
    if (remember) {
      await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
    }
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    if (nativeInteractive) {
      await answerAuthentication(page, 'correct', { kind: 'prompt', echo: false });
    }
    try {
      await settledLogin(
        page,
        user,
        ['terminal', 'terminal-expiry', 'terminal-logout-lost', 'workspace'].includes(
          process.argv[3],
        ),
      );
    } catch (error) {
      throw new Error(
        JSON.stringify({
          pageErrors: errors,
          failedResources,
          loginResponses,
          notices: await page.getByRole('status').allTextContents(),
          headings: await page.getByRole('heading').allTextContents(),
          csp: await page.evaluate(() => window.cspViolations),
        }),
        { cause: error },
      );
    }
  };
  const logout = async (page) => {
    const notification = page.getByRole('dialog', { name: 'Notification details', exact: true });
    if (
      (await notification.isVisible()) &&
      !(await notification.getByRole('button', { name: 'Log out', exact: true }).count())
    ) {
      await notification.getByRole('button', { name: 'Close', exact: true }).click();
    }
    // Fixture cleanup deliberately logs out each independent access once. A
    // scoped logout no longer closes another actor/flow's tabs as a side effect.
    for (let remaining = 8; remaining > 0; remaining--) {
      if (
        !(await page.getByRole('tablist').getByRole('tab').count()) &&
        !(
          (await notification.isVisible()) &&
          (await notification.getByRole('button', { name: 'Log out', exact: true }).count())
        )
      ) {
        break;
      }
      const before = await page.getByRole('tab').count();
      const recovery = page.getByRole('dialog', { name: 'Notification details', exact: true });
      const recovering = await recovery
        .getByRole('button', { name: 'Log out', exact: true })
        .count();
      const confirmed = page.waitForResponse(
        (response) => response.url().endsWith('/api/v1/logout') && response.status() === 204,
      );
      await logoutAccess(page);
      await confirmed;
      if (recovering) {
        await recovery.waitFor({ state: 'hidden' });
      } else {
        await page.waitForFunction(
          (before) =>
            document.querySelectorAll('[role="tab"]').length < before ||
            !document.querySelector('[data-connection-active="true"]'),
          before,
        );
      }
    }
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor();
    assert.equal(await local(page), 'missing');
  };
  async function exercise() {
    let page = await open();
    if (process.argv[3] === 'compact') {
      await exerciseCompactWorkspace(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'workspace-races') {
      await exerciseConnectionRaces(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'workspace-actions' || process.argv[3] === 'workspace-actions-close') {
      await exerciseManagementOwner(
        page,
        process.argv[4],
        login,
        logout,
        process.argv[3] === 'workspace-actions-close',
      );
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'workspace') {
      await exerciseConnections(page, login);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'terminal-logout-lost') {
      await exerciseLostTerminalLogout(page, login);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'terminal-expiry') {
      await exerciseTerminalExpiry(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'terminal-tabs') {
      await exerciseTerminalTabs(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (
      process.argv[3] === 'management-forced-disconnect' ||
      process.argv[3] === 'management-forced-dispose'
    ) {
      await exerciseManagementForcedAction(page, process.argv[4], logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'management-forced') {
      await exerciseManagementForced(page, process.argv[4], logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'management-forced-audit') {
      await exerciseManagementForcedAudit(page, process.argv[4], logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'management-forced-version') {
      await exerciseManagementForcedVersion(page, process.argv[4], logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'management-actions') {
      await exerciseManagementActions(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'management') {
      await exerciseManagement(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'key') {
      await exerciseKey(page, process.argv[4], logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3].startsWith('key-')) {
      await exerciseKeyVariant(page, process.argv[4], process.argv[3].slice(4), logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'terminal') {
      await exerciseTerminal(page, login);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'interactive') {
      await exerciseInteractive(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'interactive-lost') {
      await exerciseLostClaim(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'oidc' || process.argv[3] === 'oidc-cancel') {
      await exerciseDevice(page, process.argv[3] === 'oidc-cancel');
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'name-free') {
      assert.equal(await page.getByLabel('User name', { exact: true }).count(), 0);
      await page.getByLabel('Password', { exact: true }).fill('correct');
      const request = page.waitForRequest((request) =>
        request.url().endsWith('/api/v1/login/password'),
      );
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      assert.equal(JSON.parse((await request).postData()).user, '');
      await page.getByText('Access was denied.', { exact: false }).waitFor();
      assert.equal(
        await page.getByLabel('Password', { exact: true }).inputValue(),
        '',
        'failed sign-in must not repopulate the submitted password',
      );
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
      return;
    }
    assert.equal(
      await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).isChecked(),
      false,
    );
    await login(page, false);
    assert.equal(await local(page), 'missing');
    await logout(page);
    await login(page, true);
    await notification(page, 'RememberMe setup confirmed for this browser.');
    assert.equal(await local(page), 'ready');
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await context.close();
    page = await open();
    await page.getByRole('button', { name: 'Use saved access', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Saved access options', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Forget saved browser access', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Revoke saved browser access?', exact: true })
      .getByRole('button', { name: 'Cancel', exact: true })
      .click();
    assert.equal(await local(page), 'ready');
    await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await settledLogin(page, 'alice');
    await logout(page);
    await page.evaluate(async () => {
      const response = await fetch('/_bifroest/test/interrupt-enrollment', {
        method: 'POST',
        credentials: 'omit',
        mode: 'same-origin',
      });
      if (response.status !== 204) {
        throw new Error('fault fixture was not armed');
      }
    });
    await login(page, true);
    await page
      .getByText('RememberMe setup may have created a server permission.', { exact: false })
      .waitFor();
    assert.equal(await local(page), 'pending');
    await logout(page);
    await page.evaluate(async () => {
      const { BrowserBinding } = await import('/_bifroest/test/client.js');
      await BrowserBinding.prepare(
        { origin: location.origin, slug: 'Work' },
        { explicitOptIn: true },
      );
    });
    await page.reload();
    await page.getByRole('button', { name: 'Remove interrupted local setup', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Remove local data only?', exact: true })
      .getByRole('button', { name: 'Remove local data only', exact: true })
      .click();
    await page
      .getByRole('dialog', { name: 'Remove local data only?', exact: true, includeHidden: true })
      .waitFor({ state: 'hidden' });
    await page
      .getByText('Local setup removed. No server logout or revocation was claimed.', {
        exact: true,
      })
      .waitFor();
    assert.equal(await local(page), 'missing');
    await page.evaluate(async () => {
      const { BrowserBinding } = await import('/_bifroest/test/client.js');
      const handle = await BrowserBinding.prepare(
        { origin: location.origin, slug: 'Work' },
        { explicitOptIn: true },
      );
      await handle.complete({
        flow: 'work',
        sessionId: crypto.randomUUID(),
        bindingId: `bbr1.${'A'.repeat(43)}`,
      });
    });
    await page.reload();
    await page.getByRole('button', { name: 'Saved access options', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Forget saved browser access', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Revoke saved browser access?', exact: true })
      .getByRole('button', { name: 'Revoke browser permission', exact: true })
      .click();
    await page
      .getByRole('dialog', {
        name: 'Revoke saved browser access?',
        exact: true,
        includeHidden: true,
      })
      .waitFor({ state: 'hidden' });
    await page.getByText('Access was denied.', { exact: false }).waitFor();
    assert.equal(
      await local(page),
      'ready',
      'failed remote revoke must not silently delete local keys',
    );
    await page.getByRole('button', { name: 'Saved access options', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Remove local data only', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Remove local data only?', exact: true })
      .getByRole('button', { name: 'Remove local data only', exact: true })
      .click();
    await page
      .getByRole('dialog', { name: 'Remove local data only?', exact: true, includeHidden: true })
      .waitFor({ state: 'hidden' });
    await page
      .getByText('Local setup removed. No server logout or revocation was claimed.', {
        exact: true,
      })
      .waitFor();
    assert.equal(await local(page), 'missing');
    await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'visible' });
    await changeTheme(page, 'Dark');
    await page.locator('html[data-color-scheme="dark"]').waitFor();
    assert.equal(await page.locator('html').getAttribute('data-color-scheme'), 'dark');
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.deepEqual(errors, []);
    if (process.env.BIFROEST_TEST_UI_SCREENSHOT) {
      await page.screenshot({ path: process.env.BIFROEST_TEST_UI_SCREENSHOT, fullPage: true });
    }
    await page.evaluate(() => {
      const probe = document.createElement('script');
      probe.textContent = 'window.untrustedInlineRan = true';
      document.body.appendChild(probe);
    });
    assert.equal(
      await page.evaluate(() => window.untrustedInlineRan),
      undefined,
      'un-nonced inline scripts must remain blocked',
    );
  }
  await exercise();
  console.log(JSON.stringify({ success: true }));
} catch (error) {
  throw new Error(
    JSON.stringify({ mode: process.argv[3], pageErrors: errors, failedResources, failedRequests }),
    { cause: error },
  );
} finally {
  await context?.close();
  await rm(profile, { recursive: true, force: true });
}

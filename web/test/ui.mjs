import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { exerciseAdminShell } from './admin-shell-ui.mjs';
import { exerciseCompactWorkspace } from './compact-workspace-ui.mjs';
import { exerciseConnectionRaces, exerciseManagementOwner } from './connection-races-ui.mjs';
import { exerciseConnections } from './connections-ui.mjs';
import { exerciseKeepAlive } from './keepalive-ui.mjs';
import { exerciseKey, exerciseKeyDiagnostic, exerciseKeyVariant } from './key-ui.mjs';
import {
  exerciseLoginOptions,
  exerciseRootAccess,
  exerciseRootDirectory,
  exerciseSingleRootDirectory,
  observeSingleRootDirectory,
} from './login-options-ui.mjs';
import { exerciseDevice, exerciseInteractive, exerciseLostClaim } from './login-ui.mjs';
import { exerciseManagementActions } from './management-action-ui.mjs';
import { exerciseManagementForcedAction } from './management-forced-action-ui.mjs';
import {
  exerciseManagementForced,
  exerciseManagementForcedAudit,
  exerciseManagementForcedVersion,
} from './management-forced-ui.mjs';
import { exerciseManagementRelations } from './management-relations-ui.mjs';
import { exerciseManagement } from './management-ui.mjs';
import { managementWire } from './management-wire.mjs';
import { exercisePreferences } from './preferences-ui.mjs';
import { exerciseProfileReset } from './profile-reset-ui.mjs';
import { exerciseSlugHistory } from './slug-history-ui.mjs';
import { exerciseStoppedAuthRoute } from './stopped-auth-route-ui.mjs';
import { exerciseTerminalExpiry } from './terminal-expiry-ui.mjs';
import { exerciseLostTerminalLogout } from './terminal-logout-ui.mjs';
import { exerciseTerminalTabs } from './terminal-tabs-ui.mjs';
import { exerciseTerminal } from './terminal-ui.mjs';
import {
  answerAuthentication,
  assertUiPreferences,
  changeTheme,
  chooseLoginMethod,
  loginLayout,
  logoutAccess,
  notification,
  settledLogin,
} from './workspace-ui.mjs';

const origin = process.argv[2];
const faviconSource = await readFile(
  new URL('../../docs/assets/favicon.svg', import.meta.url),
  'utf8',
);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/);
const profile = await mkdtemp(join(tmpdir(), 'bifroest-ui-'));
let context;
const errors = [];
const failedResources = [];
const failedRequests = [];
const loginResponses = [];
let singleRootState;
try {
  const open = async () => {
    context = await chromium.launchPersistentContext(profile, {
      headless: true,
      hasTouch: process.argv[3] === 'compact',
      ignoreHTTPSErrors: true,
      args: [
        '--host-resolver-rules=MAP app.example.org 127.0.0.1',
        '--no-proxy-server',
        ...(process.argv[3] === 'terminal' ? ['--enable-unsafe-swiftshader'] : []),
      ],
    });
    await context.addInitScript(() => {
      window.cspViolations = [];
      window.addEventListener('securitypolicyviolation', (event) =>
        window.cspViolations.push(event.violatedDirective),
      );
    });
    const page = await context.newPage();
    managementWire(page);
    if (process.argv[3] === 'single-root-directory') {
      singleRootState = observeSingleRootDirectory(page);
      await context.addInitScript(() => {
        window.singleRootInitialHistoryLength = history.length;
        window.singleRootHistoryEvents = [];
        for (const method of ['pushState', 'replaceState']) {
          const original = history[method].bind(history);
          history[method] = (state, unused, url) => {
            original(state, unused, url);
            window.singleRootHistoryEvents.push({ method, path: location.pathname });
          };
        }
      });
    }
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
    const initialSlug = ['root-directory', 'root-access', 'single-root-directory'].includes(
      process.argv[3],
    )
      ? ''
      : process.argv[3] === 'login-options'
        ? 'Mixed'
        : process.argv[3] === 'slug-history'
          ? 'bla-bla'
          : 'Work';
    const response = await page.goto(`${origin}/${initialSlug}`);
    assert.equal(response.status(), 200);
    const policy = response.headers()['content-security-policy'];
    assert(
      policy.includes("frame-ancestors 'none'") &&
        policy.includes("'nonce-") &&
        !policy.includes('unsafe-inline') &&
        !policy.includes('unsafe-eval'),
    );
    if (process.argv[3] === 'bootstrap-retry') {
      await page
        .getByText('Access-link metadata is unavailable or invalid.', { exact: true })
        .waitFor();
      await page.getByRole('button', { name: 'Retry loading options', exact: true }).waitFor();
      assert.equal(await page.locator('.login-dialog').count(), 0);
      await page.evaluate(() => {
        const button = document.querySelector('#root button');
        button.click();
        button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      });
    }
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
    const favicon = page.locator('link[rel="icon"]');
    assert.equal(await favicon.getAttribute('type'), 'image/svg+xml');
    const faviconURL = new URL(await favicon.getAttribute('href'), origin);
    assert.equal(faviconURL.origin, origin);
    assert.match(faviconURL.pathname, /^\/_bifroest\/files\/assets\/favicon-[A-Za-z0-9_-]+\.svg$/u);
    assert.equal(faviconURL.search, '');
    const image = await page.evaluate(async (url) => {
      const response = await fetch(url, {
        credentials: 'omit',
        redirect: 'error',
        mode: 'same-origin',
      });
      const svg = await response.text();
      const image = new Image();
      image.src = url;
      await image.decode();
      return { status: response.status, kind: response.headers.get('content-type'), svg };
    }, faviconURL.href);
    assert.equal(image.status, 200);
    assert.equal(image.kind, 'image/svg+xml');
    assert.equal(
      image.svg,
      faviconSource,
      'reuse the documentation favicon unchanged under the real HTTPS/CSP boundary',
    );
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
      await loginLayout(page, ['Password login', 'Interactive / device login']);
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
        [
          'terminal',
          'terminal-expiry',
          'terminal-logout-lost',
          'workspace',
          'keepalive',
          'slug-history',
        ].includes(process.argv[3]),
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
        !(await page
          .getByRole('tablist', { name: 'Connections and terminals', exact: true })
          .getByRole('tab')
          .count()) &&
        !(
          (await notification.isVisible()) &&
          (await notification.getByRole('button', { name: 'Log out', exact: true }).count())
        )
      ) {
        break;
      }
      const before = await page
        .getByRole('tablist', { name: 'Connections and terminals', exact: true })
        .getByRole('tab')
        .count();
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
            document.querySelectorAll('[aria-label="Connections and terminals"] [role="tab"]')
              .length < before || !document.querySelector('[data-connection-active="true"]'),
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
    if (process.argv[3] === 'admin-shell') {
      await exerciseAdminShell(page, login, logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'dummy-banner') {
      await login(page, false);
      const expected = ['DUMMY_BANNER_ONE', 'DUMMY_BANNER_TWO', 'DUMMY_BANNER_THREE'];
      await page.waitForFunction((expected) => {
        const text =
          document.querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
            ?.textContent ?? '';
        return expected.every((value) => text.includes(value));
      }, expected);
      const lines = await page
        .locator('[data-terminal-active="true"] .xterm-accessibility-tree > div')
        .evaluateAll((nodes) =>
          nodes
            .map((node) => (node.textContent ?? '').replaceAll('\u00a0', ' ').trimEnd())
            .filter((line) => line.trim().length),
        );
      assert.deepEqual(
        lines,
        expected,
        'each real dummy banner line starts at column zero; output is not globally converted by xterm',
      );
      assert.equal(await page.locator('[data-terminal-phase="exited"]').count(), 1);
      assert.deepEqual(errors, []);
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
      await assertUiPreferences(page);
      return;
    }
    if (process.argv[3] === 'stopped-auth-route') {
      await exerciseStoppedAuthRoute(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'bootstrap-retry') {
      await page.getByLabel('User name', { exact: true }).waitFor();
      assert.deepEqual(errors, []);
      assert.deepEqual(failedResources, [{ path: '/Work', status: 503 }]);
      assert.equal(loginResponses.length, 0, 'retrying metadata must not authenticate');
      assert.equal(await page.locator('[data-connection-principal]').count(), 0);
      return;
    }
    if (process.argv[3] === 'login-options') {
      await exerciseLoginOptions(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'root-access') {
      await exerciseRootAccess(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'root-directory') {
      await exerciseRootDirectory(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'single-root-directory') {
      await exerciseSingleRootDirectory(page, singleRootState);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'slug-history') {
      await exerciseSlugHistory(page, login);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'keepalive') {
      await exerciseKeepAlive(page, login);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'preferences') {
      await exercisePreferences(page);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'profile-reset') {
      await exerciseProfileReset(page, login);
      assert.deepEqual(errors, []);
      return;
    }
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
    if (process.argv[3] === 'management-relations') {
      await exerciseManagementRelations(page, login);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3] === 'key') {
      await exerciseKey(page, process.argv[4], logout);
      assert.deepEqual(errors, []);
      return;
    }
    if (process.argv[3].startsWith('key-diagnostic-')) {
      await exerciseKeyDiagnostic(
        page,
        process.argv[4],
        process.argv[3].slice('key-diagnostic-'.length),
      );
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
      assert.equal(await page.getByLabel('Password', { exact: true }).count(), 0);
      assert.equal(await page.locator('#key-private').count(), 0);
      assert.equal(
        await page.locator('[data-connection-principal]').count(),
        0,
        'secretless access still requires an explicit action',
      );
      const request = page.waitForRequest((request) =>
        request.url().endsWith('/api/v1/login/password'),
      );
      await page.getByRole('button', { name: 'Continue without credentials', exact: true }).click();
      assert.deepEqual(JSON.parse((await request).postData()), {
        slug: 'Work',
        user: '',
        password: '',
      });
      await page
        .locator('[data-connection-principal="anonymous"][data-connection-scope="Work"]')
        .waitFor();
      await page.locator('[data-terminal-phase="exited"]').waitFor();
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
      return;
    }
    if (process.argv[3] === 'no-login-options') {
      await page
        .getByText('No sign-in method is available for this access link.', { exact: true })
        .waitFor();
      assert.equal(await page.getByLabel('User name', { exact: true }).count(), 0);
      assert.equal(await page.getByLabel('Password', { exact: true }).count(), 0);
      assert.equal(await page.locator('#key-private').count(), 0);
      assert.equal(await page.getByRole('button', { name: 'Sign in', exact: true }).count(), 0);
      assert.equal(await page.locator('[data-connection-principal]').count(), 0);
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
    await assertUiPreferences(page);
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

import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

// Storage is allowed only for the explicitly requested, non-auth UI prefs.
// Reject any token/password/selector payload rather than dropping the old
// no-local-login assertion just because username/theme persistence was added.
export async function assertUiPreferences(page, usernames = ['alice', 'bob', 'e2e']) {
    const state = await page.evaluate(() => ({
        session: sessionStorage.length,
        values: Object.fromEntries(
            Object.keys(localStorage).map((key) => [key, localStorage.getItem(key)]),
        ),
    }));
    assert.equal(state.session, 0, 'sessionStorage must not retain login data');
    for (const [key, value] of Object.entries(state.values)) {
        if (key === 'bifroest-ui-v1:theme') {
            assert(['auto', 'light', 'dark'].includes(value));
        } else if (key === 'bifroest-ui-v1:terminal-font-size') {
            assert(
                /^\d{1,2}$/u.test(value) && Number(value) >= 8 && Number(value) <= 40,
                'only the bounded non-authentication font preference may be stored',
            );
        } else if (key === 'bifroest-ui-v1:details') {
            assert(
                ['full', 'compact'].includes(value),
                'only the explicit display preference, never metadata or credentials, may be stored',
            );
        } else if (key.startsWith('bifroest-ui-v1:keepalive:')) {
            assert(
                ['1s', '10s', '15s', '20s', '1m0s'].includes(value),
                'only accepted fixture keepalive intervals may be stored',
            );
        } else {
            assert(
                key.startsWith('bifroest-ui-v1:username:'),
                'only UI preference keys may be persisted',
            );
            const slug = decodeURIComponent(key.slice('bifroest-ui-v1:username:'.length));
            assert(/^(?:[A-Za-z0-9-]{1,64}(?:\/[A-Za-z0-9-]{1,64})?)?$/u.test(slug));
            assert(
                usernames.includes(value),
                'only original fixture usernames, never credentials/principals/tokens, may be persisted',
            );
        }
    }
}

export async function settledLogin(page, user, holding = false) {
    await page.waitForFunction(
        (user) =>
            document
                .querySelector('[data-connection-active="true"]')
                ?.getAttribute('data-connection-principal') === user ||
            document.querySelector('.access-notice')?.getAttribute('data-access-principal') ===
                user,
        user,
    );
    await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden' });
    await page
        .getByRole('dialog', { name: 'Authentication step', exact: true })
        .waitFor({ state: 'hidden' });
    if (!holding && (await page.locator('[data-terminal-active="true"]').count())) {
        const ended = page.locator('[data-terminal-active="true"][data-terminal-ended="true"]');
        await ended.waitFor();
        assert.equal(await ended.getAttribute('data-terminal-exit-status'), '7');
        await page.waitForFunction(() =>
            document
                .querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
                ?.textContent?.includes('Terminal ended with exit code: 7'),
        );
    }
}

export async function activeAccess(page, user) {
    await page.waitForFunction(
        (user) =>
            document
                .querySelector('[data-connection-active="true"]')
                ?.getAttribute('data-connection-principal') === user,
        user,
    );
}

export async function activeAccessCount(page, user) {
    return page.evaluate(
        (user) =>
            [...document.querySelectorAll('[data-connection-active="true"]')].filter(
                (node) => node.getAttribute('data-connection-principal') === user,
            ).length,
        user,
    );
}

export async function chooseLoginMethod(page, name) {
    const input = page.getByRole('radio', { name, exact: true });
    await input.click();
    assert.equal(await input.isChecked(), true);
}

export async function assertAccessActionsBlocked(page) {
    assert.equal(
        await page
            .getByRole('button', { name: 'New connection', exact: true, includeHidden: true })
            .isEnabled(),
        false,
    );
    assert.equal(
        await page
            .getByRole('button', { name: 'Connection options', exact: true, includeHidden: true })
            .isEnabled(),
        false,
    );
    for (const tab of await page
        .getByRole('tablist', {
            name: 'Connections and terminals',
            exact: true,
            includeHidden: true,
        })
        .getByRole('tab', { includeHidden: true })
        .all()) {
        assert.equal(await tab.isEnabled(), false);
    }
    await page
        .getByRole('tablist', {
            name: 'Connections and terminals',
            exact: true,
            includeHidden: true,
        })
        .getByRole('tab', { selected: true, includeHidden: true })
        .dispatchEvent('contextmenu');
    assert.equal(await page.getByRole('menuitem', { name: 'Log out', exact: true }).count(), 0);
    assert.equal(await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).count(), 0);
}

export async function tabMenu(page) {
    await page
        .getByRole('tablist', { name: 'Connections and terminals', exact: true })
        .getByRole('tab', { selected: true })
        .click({ button: 'right' });
}

export async function duplicateTab(page) {
    await tabMenu(page);
    await page.getByRole('menuitem', { name: 'Duplicate', exact: true }).click();
}

export async function terminalAction(page, name) {
    await tabMenu(page);
    await page.getByRole('menuitem', { name, exact: true }).click();
}

export async function authenticationConsole(page, { text, kind, echo } = {}) {
    const console = page.locator(
        '[data-auth-terminal-active="true"] .authentication-surface[data-auth-ready="true"]',
    );
    await console.waitFor();
    if (text !== undefined) {
        await page.waitForFunction(
            (text) =>
                document
                    .querySelector('[data-auth-terminal-active="true"] .xterm-rows')
                    ?.textContent?.includes(text),
            text,
        );
    }
    if (kind !== undefined) {
        assert.equal(await console.getAttribute('data-auth-kind'), kind);
    }
    if (echo !== undefined) {
        assert.equal(await console.getAttribute('data-auth-echo'), String(echo));
    }
    assert.equal(
        await page.getByRole('dialog', { name: 'Authentication step', exact: true }).count(),
        0,
    );
    return console;
}

export async function answerAuthentication(page, answer = '', options = {}) {
    const console = await authenticationConsole(page, options);
    await console.locator('textarea').focus();
    if (answer) {
        await page.keyboard.type(answer);
    }
    await page.keyboard.press('Enter');
}

export async function logoutAccess(page) {
    const recovery = page.getByRole('dialog', { name: 'Notification details', exact: true });
    if (await recovery.getByRole('button', { name: 'Log out', exact: true }).count()) {
        await recovery.getByRole('button', { name: 'Log out', exact: true }).click();
    } else {
        await tabMenu(page);
        await page.getByRole('menuitem', { name: 'Log out', exact: true }).click();
    }
}

export async function confirmFullVerification(page, panel, source, level) {
    await panel.getByRole('button', { name: 'Verify …', exact: true }).click();
    const dialog = page.getByRole('dialog', {
        name: 'Verification options',
        exact: true,
    });
    await dialog.getByText(source, { exact: true }).waitFor();
    if (level === 'outer') {
        await dialog.getByRole('combobox', { name: 'Verification depth', exact: true }).click();
        await page
            .getByRole('option', {
                name: 'Outer signatures/container only — no private verification',
                exact: true,
            })
            .click();
    }
    await dialog.getByRole('button', { name: 'Start verification', exact: true }).click();
}

export async function notification(page, text) {
    const dialog = page.getByRole('dialog', { name: 'Notification details', exact: true });
    if (!(await dialog.isVisible())) {
        await page.getByRole('button', { name: 'Notification details', exact: true }).click();
    }
    try {
        await dialog.getByText(text, { exact: false }).waitFor();
    } catch (error) {
        throw new Error(
            JSON.stringify({
                expected: text,
                notice: (await dialog.textContent())?.slice(0, 2048),
            }),
            { cause: error },
        );
    }
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    await dialog.waitFor({ state: 'hidden' });
}

export async function reauthenticate(page) {
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
}

export async function changeTheme(page, name) {
    const login = page.getByRole('dialog', { name: 'Sign in', exact: true });
    const reopen = await login.isVisible();
    if (reopen) {
        await login.getByRole('button', { name: 'Close', exact: true }).click();
        await login.waitFor({ state: 'hidden' });
    }
    const notice = page.getByRole('dialog', { name: 'Notification details', exact: true });
    if (await notice.isVisible()) {
        await notice.getByRole('button', { name: 'Close', exact: true }).click();
        await notice.waitFor({ state: 'hidden' });
    }
    const modes = ['Auto', 'Light', 'Dark'];
    const control = page.getByRole('button', { name: /^Appearance: (?:Auto|Light|Dark)$/u });
    const current = (await control.getAttribute('aria-label')).slice('Appearance: '.length);
    assert(modes.includes(current) && modes.includes(name), 'known theme cycle endpoints');
    const steps = (modes.indexOf(name) - modes.indexOf(current) + modes.length) % modes.length;
    for (let step = 0; step < steps; step++) {
        await page
            .getByRole('button', {
                name: `Appearance: ${modes[(modes.indexOf(current) + step) % modes.length]}`,
                exact: true,
            })
            .click();
    }
    await page.getByRole('button', { name: `Appearance: ${name}`, exact: true }).waitFor();
    if (reopen) {
        await page.getByRole('button', { name: 'New connection', exact: true }).click();
    }
}

export async function captureLayout(page, name) {
    const dimensions = await page.evaluate(() => {
        const width = innerWidth;
        const content = document.documentElement.scrollWidth;
        const offenders =
            content <= width
                ? []
                : [...document.querySelectorAll('body *')]
                      .flatMap((node) => {
                          const box = node.getBoundingClientRect();
                          if (box.width === 0 || box.height === 0 || box.right <= width + 1) {
                              return [];
                          }
                          const style = getComputedStyle(node);
                          let clipped = false;
                          for (
                              let parent = node.parentElement;
                              parent && parent !== document.body;
                              parent = parent.parentElement
                          ) {
                              if (
                                  ['hidden', 'clip', 'auto', 'scroll'].includes(
                                      getComputedStyle(parent).overflowX,
                                  )
                              ) {
                                  clipped = true;
                                  break;
                              }
                          }
                          return [
                              {
                                  tag: node.tagName,
                                  classes: (node.getAttribute('class') ?? '').slice(0, 160),
                                  role: node.getAttribute('role'),
                                  left: box.left,
                                  right: box.right,
                                  width: box.width,
                                  top: box.top,
                                  position: style.position,
                                  visibility: style.visibility,
                                  opacity: style.opacity,
                                  overflowX: style.overflowX,
                                  clipped,
                              },
                          ];
                      })
                      .sort((a, b) => Number(a.clipped) - Number(b.clipped) || b.right - a.right)
                      .slice(0, 24);
        return { width, content, offenders };
    });
    assert(
        dimensions.content <= dimensions.width,
        `${name}: page overflows (${dimensions.content}/${dimensions.width}); structural diagnostics=${JSON.stringify(dimensions.offenders)}`,
    );
    const directory = process.env.BIFROEST_TEST_UI_REVIEW_DIRECTORY;
    if (directory) {
        const scroll = await page.evaluate(() => ({ x: scrollX, y: scrollY }));
        await mkdir(directory, { recursive: true });
        await page.screenshot({
            path: join(directory, `${name}.png`),
            fullPage: true,
            animations: 'disabled',
        });
        if (
            name === 'sessions-initial' ||
            name === 'terminal-desktop' ||
            name.endsWith('-verification')
        ) {
            await changeTheme(page, 'Dark');
            await page.locator('html[data-color-scheme="dark"]').waitFor();
            await page.screenshot({
                path: join(directory, `${name}-dark.png`),
                fullPage: true,
                animations: 'disabled',
            });
            await changeTheme(page, 'Auto');
        }
        await page.evaluate(({ x, y }) => window.scrollTo(x, y), scroll);
    }
}

export async function loginLayout(page, methods) {
    assert(methods.length > 0, 'layout checks require the configured method set');
    assert.equal(await page.getByRole('radio').count(), methods.length);
    const viewport = page.viewportSize();
    for (const width of [1280, 390, 320]) {
        await page.setViewportSize({ width, height: 844 });
        for (const name of methods) {
            const label = await page
                .getByRole('radio', { name, exact: true })
                .locator('..')
                .boundingBox();
            assert(
                label && label.x >= 0 && label.x + label.width <= width,
                `${name} must remain visible at ${width}px`,
            );
        }
        await captureLayout(page, `login-${width}`);
    }
    const keyboardMethod = methods.includes('SSH key login') ? 'SSH key login' : methods.at(-1);
    await chooseLoginMethod(page, keyboardMethod);
    if (keyboardMethod === 'SSH key login') {
        await page.getByLabel('Private key file (local only)', { exact: true }).waitFor();
        await captureLayout(page, 'login-key-320');
    }
    const previous =
        methods[(methods.indexOf(keyboardMethod) + methods.length - 1) % methods.length];
    await page.getByRole('radio', { name: keyboardMethod, exact: true }).press('ArrowLeft');
    assert.equal(
        await page.getByRole('radio', { name: previous, exact: true }).isChecked(),
        true,
        'login methods must also be reachable with the keyboard',
    );
    await chooseLoginMethod(page, methods[0]);
    await page.setViewportSize(viewport);
}

export async function sessionLayout(page, id) {
    const viewport = page.viewportSize();
    await captureLayout(page, 'sessions-desktop');
    for (const width of [390, 320]) {
        await page.setViewportSize({ width, height: 844 });
        const back = page
            .getByRole('navigation', { name: 'Breadcrumb', exact: true })
            .getByRole('link', { name: 'Sessions', exact: true });
        if (await back.count()) {
            await back.click();
        }
        const grid = page.getByRole('grid', { name: 'Live session metadata', exact: true });
        await grid.getByRole('button', { name: `Session details ${id}`, exact: true }).click();
        await page.getByRole('region', { name: 'Session details', exact: true }).waitFor();
        assert.equal(
            await page.getByRole('grid', { name: 'Live session metadata', exact: true }).count(),
            0,
            'the detail view replaces the retained native mobile grid',
        );
        await captureLayout(page, `sessions-${width}`);
    }
    await page.setViewportSize(viewport);
}

export async function workspace(page, name, source = 'default') {
    if (name === 'Recordings' || name === 'Recordings & audit') {
        await workspace(page, 'Audit logs');
        const pane = page.locator('[data-connection-active="true"]');
        assert.equal(
            await pane
                .getByRole('navigation', { name: 'Workspace', exact: true })
                .getByRole('link', { name: 'Recordings', exact: true })
                .count(),
            0,
        );
        const sources = pane.getByRole('grid', {
            name: 'Configured auditlogs (server metadata)',
            exact: true,
        });
        await sources.locator('[role="row"][data-id]').first().waitFor();
        await sources
            .locator('.MuiDataGrid-virtualScroller')
            .evaluate((node) => node.scrollTo({ left: node.scrollWidth }));
        await pane
            .getByRole('region', { name: 'Audit logs', exact: true })
            .getByRole('button', { name: `Recordings ${source}`, exact: true })
            .click();
        await pane
            .getByRole('region', { name: 'Recordings', exact: true })
            .getByRole('grid', { name: `Recordings · ${source}`, exact: true })
            .waitFor();
        return;
    }
    const pane = page.locator('[data-connection-active="true"]');
    await pane.locator('.admin-shell').waitFor();
    await page.waitForFunction(() => {
        const shell = document.querySelector('[data-connection-active="true"] .admin-shell');
        return (
            shell?.getAttribute('data-admin-drawer') ===
            (shell?.clientWidth > 1136 ? 'persistent' : 'temporary')
        );
    });
    const button = pane
        .getByRole('navigation', { name: 'Workspace', exact: true })
        .getByRole('link', {
            name: name === 'Server' || name === 'Bifröst' ? 'Overview' : name,
            exact: true,
        });
    const toggle = pane.locator('.admin-page-heading button[aria-expanded]');
    if ((await toggle.getAttribute('aria-expanded')) !== 'true') {
        await toggle.click();
    }
    await button.click();
    // React Router commits navigation asynchronously; assert the committed page,
    // not the preceding in-memory view immediately after the pointer event.
    await page.waitForFunction(
        (node) => node?.getAttribute('aria-current') === 'page',
        await button.elementHandle(),
    );
    assert.equal(await button.getAttribute('aria-current'), 'page');
}

export async function exactArtifactSelection(page, view = 'Recordings') {
    await workspace(page, view);
    const panel = page
        .locator('[data-connection-active="true"]')
        .getByRole('region', { name: view, exact: true });
    const pin = panel.getByRole('button', { name: 'Open by ID', exact: true });
    if (!(await pin.isVisible())) {
        await page
            .getByRole('navigation', { name: 'Breadcrumb', exact: true })
            .getByRole('link', { name: view, exact: true })
            .click();
    }
    await pin.click();
    await page.getByRole('dialog', { name: 'Open by ID', exact: true }).waitFor();
}

export async function sessionTarget(page, owner = page.locator('[data-connection-active="true"]')) {
    await owner.getByRole('button', { name: 'Open by ID', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Open by ID', exact: true });
    await dialog.waitFor();
    return dialog;
}

export async function chooseSessionTargetAction(page, dialog, label) {
    await dialog.getByRole('combobox', { name: 'Session action', exact: true }).click();
    await page.getByRole('option', { name: label, exact: true }).click();
}

export async function gridColumnFilter(page, grid, column, operator, value) {
    const frame = grid.locator('xpath=ancestor::div[@class="admin-data-grid"][1]');
    await frame.getByRole('button', { name: 'Filters', exact: true }).click();
    await page.locator('.MuiDataGrid-filterFormColumnInput').getByRole('combobox').click();
    await page.getByRole('option', { name: column, exact: true }).click();
    await page.locator('.MuiDataGrid-filterFormOperatorInput').getByRole('combobox').click();
    await page.getByRole('option', { name: operator, exact: true }).click();
    const input = page.locator('.MuiDataGrid-filterFormValueInput');
    if (await input.getByRole('combobox').count()) {
        await input.getByRole('combobox').click();
        await page.getByRole('option', { name: value, exact: true }).click();
    } else {
        await input.locator('input').fill(value);
    }
    // Loading now closes/locks the panel. Close it only if it remained open.
    if (await page.locator('.MuiDataGrid-filterFormColumnInput').isVisible()) {
        await frame.getByRole('button', { name: 'Filters', exact: true }).click();
    }
}

import assert from 'node:assert/strict';
import { activeAccess, answerAuthentication, duplicateTab } from './workspace-ui.mjs';

export async function exerciseStoppedAuthRoute(page) {
    let sockets = 0;
    page.on('websocket', () => sockets++);
    const signIn = () => page.getByRole('dialog', { name: 'Sign in', exact: true });
    const tabs = () =>
        page
            .getByRole('tablist', {
                name: 'Connections and terminals',
                exact: true,
                includeHidden: true,
            })
            .getByRole('tab', { includeHidden: true });
    async function slug(value) {
        await signIn().getByLabel('Slug', { exact: true }).click();
        await page.getByRole('option', { name: value, exact: true }).click();
        await page.waitForURL(
            (url) =>
                url.pathname === '/' &&
                url.search === '' &&
                url.hash === `#${encodeURIComponent(value)}`,
        );
        await page.waitForFunction(
            (value) =>
                document
                    .querySelector('.login-dialog [data-login-ready="true"]')
                    ?.getAttribute('data-login-scope') === value,
            value,
        );
    }
    await signIn().getByLabel('User name', { exact: true }).fill('alice');
    await signIn().getByLabel('Password', { exact: true }).fill('correct');
    await signIn().getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, 'alice');
    await page
        .locator('[data-connection-active="true"] [data-terminal-phase="connected"]')
        .waitFor();
    for (let index = 1; index < 7; index++) {
        await duplicateTab(page);
        await page.getByRole('tab', { name: `Terminal ${index + 1} alice`, exact: true }).waitFor();
        await page
            .locator(
                `#terminal-pane-${index + 1}[data-connection-active="true"] [data-terminal-phase="connected"]`,
            )
            .waitFor();
    }
    assert.equal(await tabs().count(), 7);
    assert.equal(sockets, 7);
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await slug('Other');
    await slug('Work');
    await signIn().getByRole('radio', { name: 'Interactive / device login', exact: true }).click();
    await signIn().getByLabel('User name', { exact: true }).fill('alice');
    await signIn().getByRole('button', { name: 'Sign in', exact: true }).click();
    await answerAuthentication(page, 'wrong', { kind: 'prompt', echo: false });
    await page.getByText('Sign-in stopped', { exact: true }).waitFor();
    assert.equal(await tabs().count(), 8);
    await page.goBack();
    await page.waitForURL((url) => url.pathname === '/' && url.hash === '#Other');
    await signIn().getByLabel('User name', { exact: true }).waitFor();
    assert.equal(
        await page.locator('#authentication-pane').count(),
        0,
        'the stopped console must retire with its old generation',
    );
    assert.equal(await tabs().count(), 7);
    await signIn().getByRole('button', { name: 'Close', exact: true }).click();
    await activeAccess(page, 'alice');
    await page.locator('[data-terminal-active="true"] textarea').focus();
    await page.keyboard.type('recovered-after-stopped-auth\n');
    await page.waitForFunction(() =>
        document
            .querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
            ?.textContent?.includes('STDIN:recovered-after-stopped-auth'),
    );
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await signIn().getByLabel('User name', { exact: true }).waitFor();
    assert.equal(
        await page.getByText('This window already has eight', { exact: false }).count(),
        0,
    );
    await signIn().getByRole('button', { name: 'Close', exact: true }).click();
    assert.equal(sockets, 7);
    for (let number = 1; number <= 7; number++) {
        await page.getByRole('tab', { name: `Terminal ${number} alice`, exact: true }).click();
        await page
            .locator(
                `#terminal-pane-${number}[data-connection-active="true"] [data-terminal-phase="connected"]`,
            )
            .waitFor();
    }
}

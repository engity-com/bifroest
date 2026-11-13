import assert from 'node:assert/strict';
import { captureLayout, changeTheme, workspace } from './workspace-ui.mjs';

const countBindings = (page) =>
    page.evaluate(async () => {
        const db = await new Promise((resolve, reject) => {
            const request = indexedDB.open('bifroest-browser-remember-v1');
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new Error('Fixture storage unavailable'));
        });
        try {
            return await new Promise((resolve, reject) => {
                const transaction = db.transaction('bindings', 'readonly');
                const request = transaction.objectStore('bindings').count();
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(new Error('Fixture storage count failed'));
            });
        } finally {
            db.close();
        }
    });
async function bulk(page, name) {
    await page.getByRole('button', { name: 'Application menu', exact: true }).click();
    await page.getByRole('menuitem', { name, exact: true }).click();
    return page.getByRole('dialog', { name, exact: true });
}

export async function exerciseProfileReset(page, login) {
    const calls = [];
    const observe = (request) => {
        if (request.method() === 'POST') {
            calls.push(new URL(request.url()).pathname);
        }
    };
    page.on('request', observe);
    await login(page, true);
    await workspace(page, 'Overview');
    assert.equal(await countBindings(page), 1);
    const previousOwner = await page.locator('[data-connection-active="true"]').elementHandle();
    assert(previousOwner);
    try {
        await page.getByRole('button', { name: 'New connection', exact: true }).click();
        await login(page, false);
        // Both accesses use alice. A matching principal and a closed login dialog
        // do not prove that the new tab owns the committed workspace yet. Otherwise
        // Playwright can pin its click to the old, still-attached hidden link.
        await page.waitForFunction((previous) => {
            const active = document.querySelector('[data-connection-active="true"]');
            return (
                active !== null &&
                active !== previous &&
                previous.getAttribute('data-connection-active') === 'false'
            );
        }, previousOwner);
    } finally {
        await previousOwner.dispose();
    }
    await workspace(page, 'Overview');
    assert.equal(await page.getByRole('tab').count(), 2);
    await changeTheme(page, 'Dark');
    const before = calls.length;
    let confirm = await bulk(page, 'Close all sessions');
    await confirm.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByRole('tab', { name: 'Management 1 alice', exact: true }).waitFor();
    assert.equal(await page.getByRole('tab').count(), 2);
    assert.equal(calls.length, before);
    confirm = await bulk(page, 'Close all sessions');
    await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll('[role="tab"]').length === 0);
    assert.equal(calls.length, before, 'closing tabs never invokes logout, revocation or disposal');
    assert.equal(await countBindings(page), 1);
    assert.equal(await page.evaluate(() => localStorage.getItem('bifroest-ui-v1:theme')), 'dark');
    await page.reload();
    const signIn = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await signIn.getByRole('button', { name: 'Use saved access', exact: true }).waitFor();
    assert.equal(calls.length, before, 'reload must not log in or resume');
    await signIn.getByRole('button', { name: 'Use saved access', exact: true }).click();
    await page.locator('[data-connection-active="true"]').waitFor();
    const peer = await page.context().newPage();
    const peerErrors = [];
    peer.on('pageerror', (error) => peerErrors.push(error.name));
    peer.on('request', observe);
    try {
        assert.equal((await peer.goto(new URL('/Other', page.url()).href)).status(), 200);
        await login(peer, true);
        await workspace(peer, 'Overview');
        assert.equal(await countBindings(page), 2);
        await page.evaluate(() => {
            sessionStorage.setItem('bifroest-ui-fixture', 'forget');
        });
        confirm = await bulk(page, 'Reset all settings and credentials');
        await captureLayout(page, 'profile-reset-confirm');
        await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
        const result = page.getByRole('dialog', { name: 'Notification details', exact: true });
        try {
            await result.waitFor();
        } catch (error) {
            throw new Error(
                JSON.stringify({
                    stage: 'profile-reset-result',
                    hash: new URL(page.url()).hash,
                    dialogs: (await page.getByRole('dialog').allTextContents()).map((text) =>
                        text.slice(0, 2048),
                    ),
                    notices: await page.getByRole('status').allTextContents(),
                    tabs: await page.getByRole('tab').count(),
                    bindings: await countBindings(page),
                    operations: calls.map((path) => path.split('/api/v1/')[1]),
                }),
                { cause: error },
            );
        }
        assert.equal(
            await result
                .getByText(
                    'Bifröst settings and credentials were forgotten; requested remote logouts and revocations were confirmed.',
                    { exact: true },
                )
                .count(),
            1,
            JSON.stringify({
                stage: 'profile-reset-result',
                statuses: await result.locator('.metadata-grid dd').allTextContents(),
                operations: calls.map((path) => path.split('/api/v1/')[1]),
            }),
        );
        await result
            .getByText(
                'Bifröst settings and credentials were forgotten; requested remote logouts and revocations were confirmed.',
                { exact: true },
            )
            .waitFor();
        assert.equal(await countBindings(page), 0);
        assert.equal(await page.locator('[role="tab"]').count(), 0);
        await peer.waitForFunction(() => document.querySelectorAll('[role="tab"]').length === 0);
        for (const owner of [page, peer]) {
            assert.deepEqual(
                await owner.evaluate(() => ({
                    local: Object.keys(localStorage).filter((key) => key.startsWith('bifroest-')),
                    session: Object.keys(sessionStorage).filter((key) =>
                        key.startsWith('bifroest-'),
                    ),
                })),
                { local: [], session: [] },
            );
            assert.equal(
                await owner
                    .getByRole('button', {
                        name: 'Appearance: Auto',
                        exact: true,
                        includeHidden: true,
                    })
                    .count(),
                1,
            );
        }
        assert.equal(calls.filter((path) => path.endsWith('/remember/resume')).length, 1);
        assert.equal(calls.filter((path) => path.endsWith('/remember/revoke')).length, 2);
        assert.equal(calls.filter((path) => path.endsWith('/remember/enroll')).length, 2);
        assert.equal(calls.filter((path) => path.endsWith('/login/password')).length, 3);
        assert.equal(
            calls.some(
                (path) => path.includes('/sessions/prepare') || path.includes('/sessions/confirm'),
            ),
            false,
        );
        assert.deepEqual(peerErrors, []);
        await captureLayout(page, 'profile-reset-complete');
    } finally {
        await peer.close();
    }
}

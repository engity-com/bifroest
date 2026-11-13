import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { managementInterruption } from './management-interruption.mjs';
import { managementWire } from './management-wire.mjs';
import {
    activeAccess,
    assertAccessActionsBlocked,
    chooseSessionTargetAction,
    duplicateTab,
    logoutAccess,
    notification,
    sessionTarget,
    settledLogin,
    terminalAction,
    workspace,
} from './workspace-ui.mjs';

const frames = (page) =>
    page.evaluate(
        () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
    );
const terminal = (page, number, user) =>
    page.getByRole('tab', { name: `Terminal ${number} ${user}`, exact: true });
const activeOutput = (page, text) =>
    page.waitForFunction(
        (text) =>
            document
                .querySelector('[data-terminal-active="true"] .xterm-accessibility-tree')
                ?.textContent?.includes(text),
        text,
    );

async function submitPassword(page, user, remember = false) {
    const dialog = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await dialog.getByLabel('User name', { exact: true }).fill(user);
    await dialog.getByLabel('Password', { exact: true }).fill('correct');
    if (remember) {
        await dialog.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
    }
    await dialog.getByRole('button', { name: 'Sign in', exact: true }).click();
}

export async function exerciseConnectionRaces(page) {
    let sockets = 0;
    page.on('websocket', () => sockets++);
    await submitPassword(page, 'alice');
    await settledLogin(page, 'alice', true);
    await activeOutput(page, 'EXECUTION_START:1');
    let reached;
    const connected = new Promise((resolve) => {
        reached = resolve;
    });
    let held = false;
    await page.routeWebSocket('**/api/v1/terminal', (socket) => {
        const server = socket.connectToServer();
        if (held) {
            return;
        }
        held = true;
        let received = '';
        server.onMessage((message) => {
            // Delay this one real connection's ready/output only. Never record or
            // replace its opening bearer, and never replay it as another connection.
            received = (
                received +
                (typeof message === 'string' ? message : new TextDecoder().decode(message))
            ).slice(-8192);
            if (received.includes('EXECUTION_START:2')) {
                reached();
            }
        });
    });
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await submitPassword(page, 'bob');
    await terminal(page, 2, 'bob').waitFor();
    await connected;
    let release;
    const holding = new Promise((resolve) => {
        release = resolve;
    });
    let entered;
    const entering = new Promise((resolve) => {
        entered = resolve;
    });
    await page.route('**/Other', async (route) => {
        entered();
        await holding;
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                scope: { origin: new URL(page.url()).origin, slug: 'Wrong' },
                loginOptions: [
                    { method: 'password', requestUser: true, certificateRequired: false },
                ],
                rootAvailable: false,
            }),
        });
    });
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    const signIn = page.getByRole('dialog', { name: 'Sign in', exact: true });
    await signIn.getByLabel('Slug', { exact: true }).click();
    await page.getByRole('option', { name: 'Other', exact: true }).click();
    await entering;
    await page.locator('#terminal-tab-2').waitFor({ state: 'detached' });
    await activeAccess(page, 'alice');
    release();
    await signIn
        .getByText(
            'Sign-in options for this Slug could not be loaded. Existing connections are unchanged.',
            { exact: true },
        )
        .waitFor();
    await signIn.getByRole('button', { name: 'Close', exact: true }).click();
    await page.unroute('**/Other');
    assert.equal(await terminal(page, 1, 'alice').getAttribute('aria-selected'), 'true');
    await duplicateTab(page);
    await activeOutput(page, 'EXECUTION_START:3');
    assert.equal(await terminal(page, 3, 'alice').getAttribute('aria-selected'), 'true');
    await terminalAction(page, 'Request INT signal');
    await activeOutput(page, 'SIGNAL:INT');
    await page.evaluate(async () => {
        const response = await fetch('/_bifroest/test/interrupt-enrollment', {
            method: 'POST',
            credentials: 'omit',
        });
        if (response.status !== 204) {
            throw new Error('controlled enrollment fault was not armed');
        }
    });
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await submitPassword(page, 'bob', true);
    const notice = page.getByRole('dialog', { name: 'Notification details', exact: true });
    await notice
        .getByText('RememberMe setup may have created a server permission.', { exact: false })
        .waitFor();
    await notice.getByRole('button', { name: 'Close', exact: true }).click();
    await notice.waitFor({ state: 'hidden' });
    assert.equal(sockets, 3);
    assert.equal(await page.getByRole('tab').count(), 2);
    assert.equal(
        await page.getByRole('button', { name: 'New connection', exact: true }).isEnabled(),
        false,
    );
    await page.getByRole('button', { name: 'Notification details', exact: true }).click();
    await notice.waitFor({ state: 'visible' });
    await logoutAccess(page);
    await notification(page, 'Logout confirmed.');
    await activeAccess(page, 'alice');
    await frames(page);
    assert.equal(
        sockets,
        3,
        'logging out an unadmitted uncertain Bob candidate must not start another Alice execution',
    );
    assert.equal(await page.getByRole('tab').count(), 2);
    await page.locator('[data-terminal-active="true"] .xterm-helper-textarea').focus();
    await page.keyboard.type('original-alice-still-running');
    await page.keyboard.press('Enter');
    await activeOutput(page, 'STDIN:original-alice-still-running');
    await logoutAccess(page);
    await page.locator('[data-connection-active="true"]').waitFor({ state: 'detached' });
    assert.equal(await page.getByRole('tab').count(), 0);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

export async function exerciseManagementOwner(page, fixture, login, logout, closeProbe = false) {
    const target = JSON.parse(readFileSync(fixture, 'utf8'));
    const wire = managementWire(page);
    const interruption = await managementInterruption(page, { holdPreparation: true });
    const committedView = async (id, user) => {
        // Alice and Bob use the same Slug. Wait for this exact local view after the
        // route commit, not merely a matching principal or ready login metadata.
        await page.waitForFunction(
            ({ id, user }) => {
                const pane = document.getElementById(`terminal-pane-${id}`);
                return (
                    document.getElementById(`terminal-tab-${id}`)?.getAttribute('aria-selected') ===
                        'true' &&
                    pane?.getAttribute('data-connection-active') === 'true' &&
                    pane.getAttribute('data-connection-principal') === user &&
                    location.pathname === '/' &&
                    location.search === '' &&
                    decodeURIComponent(location.hash.slice(1).split('/')[0]) ===
                        pane.getAttribute('data-connection-scope') &&
                    history.state?.usr?.view === id
                );
            },
            { id, user },
        );
    };
    let commits = 0;
    const reads = [];
    wire.on('request', (request) => {
        if (
            /\/management\/(?:sessions|flows|version)\/(?:list|show)$/u.test(
                new URL(request.url()).pathname,
            )
        ) {
            reads.push(new URL(request.url()).pathname.split('/management/')[1]);
        }
        if (request.url().endsWith('/management/sessions/confirm')) {
            commits++;
        }
    });
    await login(page, false);
    await committedView(1, 'alice');
    await page
        .getByRole('tabpanel', { name: 'Management 1 alice', exact: true })
        .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
        .waitFor();
    await workspace(page, 'Sessions');
    await page.getByRole('grid', { name: 'Live session metadata', exact: true }).waitFor();
    await page.getByRole('button', { name: 'New connection', exact: true }).click();
    await login(page, false, 'bob');
    await committedView(2, 'bob');
    await page
        .getByRole('grid', { name: 'Configured flows (not public discovery links)', exact: true })
        .waitFor();
    await workspace(page, 'Sessions');
    await page.getByRole('grid', { name: 'Live session metadata', exact: true }).waitFor();
    assert.deepEqual(
        reads,
        ['flows/list', 'sessions/list', 'flows/list', 'sessions/list'],
        'each actor reads only its own entry metadata and explicit Sessions page',
    );
    const alice = page.getByRole('tab', { name: 'Management 1 alice', exact: true });
    const bob = page.getByRole('tab', { name: 'Management 2 bob', exact: true });
    const alicePanel = page.getByRole('tabpanel', { name: 'Management 1 alice', exact: true });
    const bobPanel = page.getByRole('tabpanel', { name: 'Management 2 bob', exact: true });
    const aliceNode = await page.locator('#terminal-pane-1').elementHandle();
    const bobNode = await page.locator('#terminal-pane-2').elementHandle();
    await alice.click();
    await committedView(1, 'alice');
    let targetForm = await sessionTarget(page, alicePanel);
    await page.getByRole('textbox', { name: /^Target flow/u }).fill(target.flow);
    await page.getByRole('textbox', { name: /^Target session ID/u }).fill(target.id);
    await chooseSessionTargetAction(page, targetForm, 'Disconnect connections');
    await targetForm.getByRole('button', { name: 'Go', exact: true }).click();
    await page.evaluate(async () => {
        const response = await fetch('/_bifroest/test/preparation-entered', {
            credentials: 'omit',
        });
        if (response.status !== 204) {
            throw new Error('controlled preparation did not enter its barrier');
        }
    });
    if (closeProbe) {
        await page.getByRole('button', { name: 'Close management view 1', exact: true }).click();
        await page
            .getByRole('dialog', { name: 'Close this management view?', exact: true })
            .waitFor();
    } else {
        await bob.click();
        await committedView(2, 'bob');
    }
    await page.evaluate(async () => {
        const response = await fetch('/_bifroest/test/preparation-release', {
            method: 'POST',
            credentials: 'omit',
        });
        if (response.status !== 204) {
            throw new Error('controlled preparation did not leave its barrier');
        }
    });
    interruption.releasePreparation();
    await frames(page);
    if (closeProbe) {
        const closing = page.getByRole('dialog', {
            name: 'Close this management view?',
            exact: true,
        });
        assert.equal(
            await page.getByRole('dialog').count(),
            1,
            'late preparation must not overlay the older close dialog',
        );
        assert.equal(
            await page.getByRole('button', { name: 'Confirm session action', exact: true }).count(),
            0,
        );
        await closing.getByRole('button', { name: 'Cancel', exact: true }).click();
        await committedView(1, 'alice');
    } else {
        assert.equal(
            await page.getByRole('dialog').count(),
            0,
            'a late Alice preparation cannot open a portal over Bob',
        );
        await committedView(2, 'bob');
        targetForm = await sessionTarget(page, bobPanel);
        assert.equal(
            await targetForm.getByRole('textbox', { name: /^Target flow/u }).inputValue(),
            '',
            'Alice preparation must not populate Bob action fields',
        );
        assert.equal(
            await targetForm.getByRole('textbox', { name: /^Target session ID/u }).inputValue(),
            '',
            'Alice preparation must not populate Bob target session',
        );
        await page.keyboard.press('Escape');
    }
    assert.equal(commits, 0);
    await alice.click();
    await committedView(1, 'alice');
    assert.equal(
        await page.getByRole('dialog').count(),
        0,
        'the unused hidden confirmation is retired, not resurrected',
    );
    targetForm = await sessionTarget(page, alicePanel);
    assert.equal(
        (await targetForm.getByRole('textbox', { name: /^Target flow/u }).inputValue()) ===
            target.flow,
        true,
        'reactivating Alice must preserve her independently owned target flow',
    );
    assert.equal(
        (await targetForm.getByRole('textbox', { name: /^Target session ID/u }).inputValue()) ===
            target.id,
        true,
        'reactivating Alice must preserve her independently owned target session',
    );
    await page.getByRole('combobox', { name: 'Session action', exact: true }).click();
    await page.getByRole('option', { name: 'End session', exact: true }).click();
    await page.evaluate(async () => {
        const response = await fetch('/_bifroest/test/interrupt-management-confirm', {
            method: 'POST',
            credentials: 'omit',
        });
        if (response.status !== 204) {
            throw new Error('controlled management fault was not armed');
        }
    });
    interruption.arm('management/sessions/confirm');
    await targetForm.getByRole('button', { name: 'Go', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByText('Work · alice', { exact: true }).waitFor();
    await dialog
        .getByLabel('Type the exact flow/session ID shown above', { exact: true })
        .fill(`${target.flow}/${target.id}`);
    await dialog.getByRole('button', { name: 'Confirm session action', exact: true }).click();
    await page.getByText('The session action result is unknown.', { exact: false }).waitFor();
    await frames(page);
    assert.equal(commits, 1, 'the lost reply must not replay confirmation');
    assert.equal(interruption.losses(), 1);
    assert.equal(
        await aliceNode.evaluate((node) => node.isConnected),
        true,
        'the unknown action owner must remain mounted',
    );
    assert.equal(
        await bobNode.evaluate((node) => node.isConnected),
        true,
        'switching and locking owners must not unmount the sibling',
    );
    assert.deepEqual(
        reads,
        ['flows/list', 'sessions/list', 'flows/list', 'sessions/list'],
        'view activation and mutation outcomes cannot repeat metadata reads',
    );
    assert.equal(await page.locator('#terminal-tab-1').getAttribute('aria-selected'), 'true');
    assert.equal(
        await page.locator('#terminal-tab-1').getAttribute('data-access-status'),
        'closed',
        'the lost owner remains mounted but cannot borrow another channel or fall back to HTTP',
    );
    assert.equal(await bob.isEnabled(), false);
    assert.equal(
        await page
            .getByRole('button', { name: 'Close management view 1', exact: true })
            .isEnabled(),
        false,
    );
    assert.equal(
        await page
            .getByRole('dialog', { name: 'Close this management view?', exact: true })
            .count(),
        0,
        'no earlier close intent may survive into an unknown result',
    );
    assert.equal(
        await page.getByRole('button', { name: 'New connection', exact: true }).isEnabled(),
        false,
    );
    await assertAccessActionsBlocked(page);
    await page
        .getByRole('button', {
            name: 'Dismiss local warning (does not confirm result)',
            exact: true,
        })
        .click();
    assert.equal(commits, 1);
    await logout(page);
    assert.equal(await page.getByRole('tab').count(), 0);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
}

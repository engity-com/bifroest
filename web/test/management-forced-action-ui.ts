import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { Logout, Page } from './fixture-types.ts';
import { forcedKeyLogin } from './management-forced-ui.ts';
import { managementInterruption } from './management-interruption.ts';
import { managementWire } from './management-wire.ts';
import { required } from './required.ts';
import { assertUiPreferences, sessionTarget, workspace } from './workspace-ui.ts';

export async function exerciseManagementForcedAction(page: Page, file: string, logout: Logout) {
    const { action, flow, id } = JSON.parse(await readFile(file, 'utf8'));
    const wire = managementWire(page);
    const interruption = action === 'dispose' ? await managementInterruption(page) : null;
    const calls: string[] = [];
    wire.on('request', (request) => {
        const path = new URL(request.url()).pathname;
        if (path.includes('/api/v1/management/')) {
            calls.push(path);
        }
    });
    await forcedKeyLogin(page, file);
    await workspace(page, 'Sessions');
    assert.deepEqual(
        calls.map((path) => path.split('/management/')[1]),
        [],
        'an action-only sign-in performs no metadata reads or automatic preparation',
    );
    async function connect() {
        await page.evaluate(async () => {
            const { BrowserClient } = await import('/_bifroest/test/client.js');
            window.targetAccess ??= await new BrowserClient({
                origin: location.origin,
                slug: 'Worker',
            }).password('bob', 'correct');
            window.targetSockets ??= [];
            const socket = new WebSocket(
                `${location.origin.replace('https:', 'wss:')}/api/v1/terminal`,
                'bifroest-terminal.v1',
            );
            window.targetSockets.push(socket);
            socket.binaryType = 'arraybuffer';
            await new Promise<void>((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error('target did not run')), 5000);
                socket.onerror = () => reject(new Error('target connection failed'));
                socket.onopen = () =>
                    socket.send(
                        JSON.stringify({
                            type: 'open',
                            slug: 'Worker',
                            accessToken: window.targetAccess.terminalToken(),
                            task: 'exec',
                            command: 'fixture-hold',
                        }),
                    );
                socket.onmessage = (event) => {
                    if (
                        event.data instanceof ArrayBuffer &&
                        new TextDecoder()
                            .decode(new Uint8Array(event.data).subarray(1))
                            .includes('management-target-live')
                    ) {
                        clearTimeout(timer);
                        resolve();
                    }
                };
            });
        });
    }
    await connect();
    await connect();
    let direct = await sessionTarget(page);
    await direct.waitFor();
    await direct.getByLabel('Target flow', { exact: false }).fill(flow);
    await direct.getByLabel('Target session ID', { exact: false }).fill(id);
    await direct.getByRole('combobox', { name: 'Session action', exact: true }).click();
    assert.equal(
        await page
            .getByRole('option', {
                name: action === 'dispose' ? 'Disconnect connections' : 'End session',
                exact: true,
            })
            .count(),
        0,
    );
    await page
        .getByRole('option', {
            name: action === 'dispose' ? 'End session' : 'Disconnect connections',
            exact: true,
        })
        .click();
    const preparationReply = wire.waitForResponse(
        (response) => response.url().endsWith('/sessions/prepare') && response.status() === 202,
    );
    await direct.getByRole('button', { name: 'Go', exact: true }).click();
    let dialog = page.getByRole('dialog');
    await dialog
        .getByText('Session details are not returned under this action-only policy.', {
            exact: false,
        })
        .waitFor();
    const preparation = await (await preparationReply).json();
    assert.deepEqual(Object.keys(preparation.target).sort(), ['flow', 'id']);
    assert.deepEqual(
        preparation.target,
        { flow, id },
        'the real channel receipt must contain only the action selector, never ShowSession metadata',
    );
    assert.equal(
        await dialog.getByText('No verified association available', { exact: true }).count(),
        0,
    );
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await dialog.waitFor({ state: 'hidden' });
    assert.equal(calls.filter((path) => path.endsWith('/confirm')).length, 0);
    assert.equal(
        await page.evaluate(() =>
            window.targetSockets.every((socket) => socket.readyState === WebSocket.OPEN),
        ),
        true,
    );
    direct = await sessionTarget(page);
    await direct.getByRole('button', { name: 'Go', exact: true }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByText(`${flow}/${id}`, { exact: true }).waitFor();
    await dialog
        .getByLabel('Type the exact flow/session ID shown above', { exact: true })
        .fill('wrong-target');
    assert.equal(
        await dialog
            .getByRole('button', { name: 'Confirm session action', exact: true })
            .isEnabled(),
        false,
    );
    await dialog
        .getByLabel('Type the exact flow/session ID shown above', { exact: true })
        .fill(`${flow}/${id}`);
    if (action === 'dispose') {
        await page.evaluate(async () => {
            const response = await fetch('/_bifroest/test/interrupt-management-confirm', {
                method: 'POST',
                credentials: 'omit',
                mode: 'same-origin',
            });
            if (response.status !== 204) {
                throw new Error('fixture not armed');
            }
        });
        required(interruption).arm('management/sessions/confirm');
    }
    await dialog.getByRole('button', { name: 'Confirm session action', exact: true }).click();
    await page
        .getByText(
            action === 'dispose'
                ? 'The session action result is unknown.'
                : 'The server confirmed this session action and its configured audit/recording lifecycle.',
            { exact: false },
        )
        .waitFor();
    await page.waitForFunction(() =>
        window.targetSockets.every((socket) => socket.readyState === WebSocket.CLOSED),
    );
    assert.deepEqual(
        calls
            .filter((path) => path.endsWith('/show') || path.endsWith('/list'))
            .map((path) => path.split('/management/')[1]),
        [],
        'acting requires neither target inspection nor any list read',
    );
    if (action === 'disconnect') {
        await connect();
        await page.evaluate(() => {
            const socket = window.targetSockets.at(-1);
            if (!socket) {
                throw new Error('Expected target socket');
            }
            socket.close();
        });
    } else {
        assert.equal(
            required(interruption).losses(),
            1,
            'one real successful server completion was lost, without replay',
        );
        assert.equal(
            await page.getByRole('button', { name: 'Connection options', exact: true }).isEnabled(),
            false,
        );
        assert.equal(
            await direct.getByRole('button', { name: 'Go', exact: true }).isEnabled(),
            false,
        );
        await page
            .getByRole('button', {
                name: 'Dismiss local warning (does not confirm result)',
                exact: true,
            })
            .click();
    }
    assert.equal(
        calls.filter((path) => path.endsWith('/confirm')).length,
        1,
        'no replay or cancel-as-undo',
    );
    await logout(page);
    // The new sign-in dialog must not expose the preceding actor's target form.
    assert.equal(
        await page.getByRole('textbox', { name: 'Target session ID', exact: false }).count(),
        0,
    );
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await assertUiPreferences(page);
}

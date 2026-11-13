import assert from 'node:assert/strict';
import { managementWire } from './management-wire.mjs';
import { assertUiPreferences, captureLayout, reauthenticate, workspace } from './workspace-ui.mjs';

export async function exerciseManagement(page, login, logout) {
    const wire = managementWire(page);
    const requests = [];
    wire.on('request', (request) =>
        requests.push({
            path: new URL(request.url()).pathname.split('/management/')[1],
            channel: request.channel(),
            slug: request.slug(),
            body: JSON.parse(request.postData()),
        }),
    );
    const firstReply = wire.waitForResponse((response) =>
        response.url().endsWith('/management/flows/list'),
    );
    await login(page, false);
    const first = await firstReply;
    assert.equal(first.status(), 200);
    const firstData = await first.json();
    assert.equal(firstData.flows.items.length, 20);
    const alicePaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
    const alicePane = page.locator(`#${alicePaneID}`);
    assert.equal(await page.getByRole('heading', { name: 'Terminal', exact: true }).count(), 0);
    assert.equal(
        await page.getByRole('button', { name: /dispose|disconnect|delete/iu }).count(),
        0,
    );
    assert.deepEqual(
        requests.map((request) => request.path),
        ['flows/list'],
        'Overview reads only its own flow metadata',
    );
    const aliceChannel = requests[0].channel;
    assert.match(aliceChannel, /^[1-9A-HJ-NP-Za-km-z]{16,22}$/u);
    const flows = alicePane.getByRole('grid', {
        name: 'Configured flows (not public discovery links)',
        exact: true,
    });
    await flows.getByText('manager00', { exact: true }).waitFor();
    const versionReply = wire.waitForResponse(
        (response) =>
            response.url().endsWith('/management/version/show') &&
            JSON.parse(response.request().postData()).long === 'true',
    );
    await workspace(page, 'Version');
    const versionURL = page.url();
    const versionResponse = await versionReply;
    assert.equal(versionResponse.status(), 200);
    const build = (await versionResponse.json()).versionInfo.build;
    assert.equal(build.version, 'test');
    const version = alicePane.getByRole('region', { name: 'Server version', exact: true });
    await version.getByRole('region', { name: 'Build information', exact: true }).waitFor();
    assert.equal(await version.locator('pre').count(), 0);
    assert.equal(await version.locator('details').count(), 0);
    await captureLayout(page, 'admin-version-structured');
    await workspace(page, 'Overview');
    const secondReply = wire.waitForResponse((response) =>
        response.url().endsWith('/management/flows/list'),
    );
    assert.notEqual(
        firstData.flows.next,
        '',
        'the first bounded page must carry its real server cursor',
    );
    await flows
        .locator('xpath=ancestor::div[@class="admin-data-grid"][1]')
        .getByRole('button', { name: 'Go to next page', exact: true })
        .click();
    const second = await secondReply;
    assert.equal(second.status(), 200);
    assert.equal((await second.json()).flows.items.length, 1);
    await flows.getByText('manager20', { exact: true }).waitFor();
    assert.equal(await flows.locator('[role="row"][data-id]').count(), 1);
    await workspace(page, 'Sessions');
    const sessions = alicePane.getByRole('grid', { name: 'Live session metadata', exact: true });
    await sessions.getByText('alice', { exact: true }).waitFor();
    const beforeReturn = requests.length;
    await workspace(page, 'Bifröst');
    await workspace(page, 'Sessions');
    assert.equal(requests.length, beforeReturn, 'loaded views are retained without another read');
    assert(!(await sessions.textContent()).includes('Verified issuer / subject'));
    await sessions
        .getByRole('button', { name: /^Session details /u })
        .first()
        .click();
    await page
        .getByRole('region', { name: 'Session details', exact: true })
        .getByText('Verified issuer', { exact: true })
        .waitFor();
    assert(!(await page.locator('body').textContent()).includes('plain:correct'));
    await reauthenticate(page);
    const beforeBob = requests.length;
    const bobFlowsReply = wire.waitForResponse((response) =>
        response.url().endsWith('/management/flows/list'),
    );
    await login(page, false, 'bob');
    const bobFlows = await bobFlowsReply;
    assert.equal(bobFlows.status(), 200);
    assert.equal((await bobFlows.json()).flows.items.length, 20);
    const bobChannel = bobFlows.request().channel();
    assert.equal(
        bobChannel !== aliceChannel,
        true,
        'the new owner has a distinct admitted channel',
    );
    assert.equal(bobFlows.request().channel(), bobChannel);
    const bobPaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
    const bobPane = page.locator(`#${bobPaneID}`);
    assert.notEqual(bobPaneID, alicePaneID);
    assert.equal(await bobPane.getAttribute('data-connection-principal'), 'bob');
    assert.equal(await bobPane.getAttribute('data-connection-scope'), 'Work');
    const freshFlows = bobPane.getByRole('grid', {
        name: 'Configured flows (not public discovery links)',
        exact: true,
    });
    await freshFlows.getByText('manager00', { exact: true }).waitFor();
    assert.equal(
        await bobPane.getByRole('region', { name: 'Build information', exact: true }).count(),
        0,
    );
    assert.equal(await bobPane.locator('.session-details').count(), 0);
    const bobSessionsReply = wire.waitForResponse((response) =>
        response.url().endsWith('/management/sessions/list'),
    );
    await workspace(page, 'Sessions');
    const bobReply = await bobSessionsReply;
    assert.equal(bobReply.status(), 200);
    assert.equal(bobReply.request().channel(), bobChannel);
    const bobData = await bobReply.json();
    assert.equal(bobData.operation, 'sessions.list');
    assert.equal(bobData.sessions.items.length, 2);
    const bobSessions = bobPane.getByRole('grid', { name: 'Live session metadata', exact: true });
    await bobSessions.getByText('bob', { exact: true }).waitFor();
    assert.equal(await bobSessions.locator('[role="row"][data-id]').count(), 2);
    const shownTargets = await bobSessions
        .locator('[role="row"][data-id]')
        .evaluateAll((rows) =>
            rows.map((row) => [
                row.querySelector('[data-field="flow"]').textContent,
                row
                    .querySelector('button')
                    ?.getAttribute('aria-label')
                    ?.slice('Session details '.length),
            ]),
        );
    assert.deepEqual(
        shownTargets,
        bobData.sessions.items.map((item) => [item.flow, item.id]),
        'visible rows belong to this actor’s successful response',
    );
    assert.equal(await alicePane.locator('.session-details').count(), 1);
    assert.equal(
        await alicePane
            .getByRole('region', { name: 'Build information', exact: true, includeHidden: true })
            .count(),
        1,
    );
    assert.deepEqual(
        requests.slice(beforeBob).map((request) => request.path),
        ['flows/list', 'sessions/list'],
    );
    const beforeSwitch = requests.length;
    await workspace(page, 'Bifröst');
    await workspace(page, 'Sessions');
    assert.equal(requests.length, beforeSwitch);
    await logout(page);
    const cold = await page.context().newPage();
    const coldErrors = [];
    cold.on('pageerror', (error) => coldErrors.push(error.name));
    const coldWire = managementWire(cold);
    const coldReads = [];
    coldWire.on('request', (request) =>
        coldReads.push(new URL(request.url()).pathname.split('/management/')[1]),
    );
    let coldLogins = 0;
    cold.on('request', (request) => {
        if (
            request.method() === 'POST' &&
            /\/(?:login|remember)\//u.test(new URL(request.url()).pathname)
        ) {
            coldLogins++;
        }
    });
    try {
        const entry = await cold.goto(versionURL);
        assert.equal(entry.status(), 200);
        await cold.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor();
        const permanent = new URL(versionURL);
        permanent.hash = permanent.hash.replace(/^(#[^/]*\/)\w+(?=\/)/u, '$1-');
        assert.equal(
            cold.url(),
            permanent.href,
            'an unowned tab ID becomes a navigation-only placeholder before explicit sign-in',
        );
        assert.equal(coldLogins, 0);
        assert.deepEqual(coldReads, []);
        await login(cold, false);
        await cold.getByRole('region', { name: 'Build information', exact: true }).waitFor();
        const restored = new URL(cold.url());
        assert.match(restored.hash, /^#Work\/[1-9A-HJ-NP-Za-km-z]{16,22}\/version$/u);
        assert.notEqual(
            restored.hash,
            new URL(versionURL).hash,
            'explicit sign-in creates fresh tab ownership, never the stale UI ID',
        );
        restored.hash = restored.hash.replace(/^(#[^/]*\/)\w+(?=\/)/u, '$1-');
        assert.equal(
            restored.href,
            permanent.href,
            'only the requested navigation target is restored',
        );
        assert.deepEqual(coldReads, ['version/show', 'version/show']);
        assert.equal(
            (await cold.getByRole('tab', { selected: true }).textContent()).trim(),
            'Version',
        );
        assert.equal(await cold.title(), 'Fixture brand');
        assert.deepEqual(coldErrors, []);
        await logout(cold);
    } finally {
        await cold.close();
    }
    for (const request of requests) {
        assert.equal(request.slug, 'Work');
        assert.equal(request.body.slug, undefined);
        assert.equal(request.body.args, undefined);
        assert.equal(request.body.command, undefined);
        assert.equal(request.channel === aliceChannel || request.channel === bobChannel, true);
    }
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await assertUiPreferences(page);
}

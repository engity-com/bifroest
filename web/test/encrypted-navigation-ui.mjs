import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { managementWire } from './management-wire.mjs';
import { activeAccess, captureLayout, gridColumnFilter, workspace } from './workspace-ui.mjs';

const [origin, mode, keyPath] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert.equal(mode, 'ui-navigation-encrypted');
const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1500, height: 1000 },
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const calls = [];
    const wire = managementWire(page);
    wire.on('request', (request) => {
        const body = JSON.parse(request.postData());
        assert(
            !Object.keys(body).some((key) =>
                ['privateKey', 'passphrase', 'producer', 'recipient'].includes(key),
            ),
        );
        calls.push({ path: new URL(request.url()).pathname, body });
    });
    page.on('request', (request) => {
        if (new URL(request.url()).pathname.includes('/api/')) {
            assert(!(request.postData() ?? '').includes('PRIVATE KEY'));
            assert(!(request.postData() ?? '').includes('tab fixture secret'));
        }
    });
    const response = await page.goto(`${origin}/Work`);
    assert.equal(response.status(), 200);
    await page.getByLabel('User name', { exact: true }).fill('alice');
    await page.getByLabel('Password', { exact: true }).fill('correct');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, 'alice');
    const entry = await page.evaluate(() =>
        fetch('/_bifroest/test/artifact-id', { credentials: 'omit' }).then((value) => value.json()),
    );
    assert(entry.flow);
    const pane = page.locator('[data-connection-active="true"]');
    const audit = () => pane.getByRole('region', { name: 'Audit logs', exact: true });
    const grid = () => audit().getByRole('grid', { name: 'Audit events', exact: true });
    const auditControls = () => grid().locator('xpath=ancestor::div[@class="admin-data-grid"][1]');
    const count = (suffix) => calls.filter((call) => call.path.endsWith(suffix)).length;
    await workspace(page, 'Audit logs');
    await audit().getByRole('button', { name: 'Open audit log default', exact: true }).waitFor();
    await captureLayout(page, 'audit-source-entry-actions');
    await audit().getByRole('button', { name: 'Open audit log default', exact: true }).click();
    await grid().locator('[role="row"][data-id]').first().waitFor();
    assert.equal(count('/audit-events/list'), 1);
    await grid()
        .locator('[role="gridcell"][data-field="flow"]')
        .first()
        .getByText('Encrypted', { exact: true })
        .waitFor();
    await captureLayout(page, 'encrypted-public-audit');
    const retained = await grid().elementHandle();
    const originalRows = await retained.evaluate(
        (node) => node.querySelectorAll('[role="row"][data-id]').length,
    );
    await auditControls()
        .getByRole('button', { name: 'Decrypt and show private details…', exact: true })
        .click();
    const options = page.getByRole('dialog', { name: 'Verification options', exact: true });
    await options.getByLabel('Decryption key file (local only)', { exact: true }).waitFor();
    assert.equal(count('/artifacts/audit'), 0);
    assert.equal(count('/audit-events/list'), 1);
    assert.equal(
        await retained.evaluate((node) => node.querySelectorAll('[role="row"][data-id]').length),
        originalRows,
    );
    await captureLayout(page, 'encrypted-local-key-options');
    await options.getByRole('button', { name: 'Cancel', exact: true }).click();
    await options.waitFor({ state: 'hidden' });
    await grid().locator('[role="row"][data-id]').first().waitFor();
    for (let index = 0; index < 3; index++) {
        await page
            .getByRole('navigation', { name: 'Breadcrumb', exact: true })
            .getByRole('link', { name: 'Audit logs', exact: true })
            .click();
        await audit().getByRole('button', { name: 'Open audit log default', exact: true }).click();
        await grid().locator('[role="row"][data-id]').first().waitFor();
        assert.equal(await grid().evaluate((node, old) => node === old, retained), true);
        assert.equal(
            count('/audit-events/list'),
            1,
            'source-catalog navigation must not consume a new heavy read',
        );
    }
    await auditControls()
        .getByRole('button', { name: 'Hide sensitive data – currently visible', exact: true })
        .click();
    await auditControls()
        .getByRole('button', { name: 'Decrypt and show private details…', exact: true })
        .click();
    await options.getByLabel('Decryption key file (local only)', { exact: true }).setInputFiles({
        name: 'offline-recipient.pem',
        mimeType: 'application/octet-stream',
        buffer: readFileSync(keyPath),
    });
    await options
        .getByLabel('Decryption passphrase (optional, local only)', { exact: true })
        .fill('tab fixture secret');
    await options.getByRole('button', { name: 'Start verification', exact: true }).click();
    await options.waitFor({ state: 'hidden' });
    await audit().and(page.locator('[data-audit-view="local"][data-audit-phase="idle"]')).waitFor();
    await grid()
        .locator('[role="gridcell"][data-field="flow"]')
        .filter({ hasText: entry.flow })
        .first()
        .waitFor();
    assert.equal(count('/artifacts/audit'), 1);
    assert.equal(count('/audit-events/list'), 1);
    await audit().locator('[data-verification-result="success"]:visible').waitFor();
    await captureLayout(page, 'encrypted-decrypted-audit-flow');
    await grid()
        .locator('[role="row"][data-id]')
        .first()
        .getByRole('button', { name: /^Audit event details /u })
        .click();
    const details = page.getByRole('region', { name: 'Audit event details', exact: true });
    await details.waitFor();
    assert((await details.textContent()).includes(entry.flow));
    assert.equal(new URL(page.url()).pathname, '/');
    assert.equal(new URL(page.url()).search, '');
    assert.match(new URL(page.url()).hash, /\/default\/events\/[1-9A-HJ-NP-Za-km-z]{16,22}$/u);
    assert.equal(
        new URLSearchParams(new URL(page.url()).hash.split('?')[1]).has('flow'),
        false,
        'opening a detail must not invent a list filter',
    );
    await page
        .getByRole('navigation', { name: 'Breadcrumb', exact: true })
        .getByRole('link', { name: 'default', exact: true })
        .click();
    await audit().getByRole('button', { name: 'Direct data from the server', exact: true }).click();
    await grid().locator('[role="row"][data-id]').first().waitFor();
    assert.equal(count('/audit-events/list'), 1);
    await workspace(page, 'Recordings');
    const recording = pane.getByRole('region', { name: 'Recordings', exact: true });
    const recordings = recording.getByRole('grid', { name: 'Recordings · default', exact: true });
    await recordings
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .waitFor();
    assert.equal(count('/recordings/list'), 1);
    const before = count('/recordings/list');
    const eye = recordings
        .locator('xpath=ancestor::div[@class="admin-data-grid"][1]')
        .getByRole('button', { name: 'Decrypt and show recording details…', exact: true });
    await eye.click();
    const recordingOptions = page.getByRole('dialog', {
        name: 'Verification options',
        exact: true,
    });
    await recordingOptions.waitFor();
    await recordingOptions.getByRole('button', { name: 'Cancel', exact: true }).click();
    await recordingOptions.waitFor({ state: 'hidden' });
    assert.equal(
        count('/recordings/list'),
        before,
        'presentation toggles must not consume heavy reads',
    );
    await gridColumnFilter(page, recordings, 'Flow', 'equals', entry.flow);
    await recordings
        .getByText('The server cannot match encrypted flow, session or identity fields.', {
            exact: false,
        })
        .waitFor();
    assert.equal(count('/recordings/list'), 2);
    assert.equal(count('/artifacts/recording'), 0);
    await captureLayout(page, 'encrypted-recording-private-filter');
    await recordings
        .getByRole('button', { name: 'Show source without private filters', exact: true })
        .click();
    await recordings
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .waitFor();
    assert.equal(count('/recordings/list'), 3);
    await recordings
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .click();
    const playback = recording.getByRole('region', { name: 'Recording playback', exact: true });
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    assert.equal(
        await page.getByRole('dialog', { name: 'Decrypt recording', exact: true }).count(),
        0,
        'same actor/tab may reuse its authenticated recipient key',
    );
    assert.equal(count('/artifacts/recording'), 1);
    assert.equal(
        await recording.locator('[data-verification-result]').count(),
        0,
        'opening/decrypting is not a signature verdict',
    );
    await page
        .getByRole('navigation', { name: 'Breadcrumb', exact: true })
        .getByRole('link', { name: 'Recordings', exact: true })
        .click();
    const controls = recordings.locator('xpath=ancestor::div[@class="admin-data-grid"][1]');
    await controls.getByRole('button', { name: 'Verify …', exact: true }).click();
    await recordingOptions.getByRole('button', { name: 'Start verification', exact: true }).click();
    await controls.locator('[data-verification-result="success"]').waitFor();
    await controls
        .getByRole('button', { name: 'Show sensitive data – currently hidden', exact: true })
        .click();
    await recordings
        .locator('[role="gridcell"][data-field="flow"]')
        .filter({ hasText: entry.flow })
        .first()
        .waitFor();
    await gridColumnFilter(page, recordings, 'Flow', 'equals', entry.flow);
    await recordings
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .waitFor();
    assert.equal(
        count('/recordings/list'),
        3,
        'a completed private metadata index filters locally',
    );
    assert.equal(
        count('/artifacts/recording'),
        1,
        'metadata indexing must use its confirmed source stream, not per-row HTTP downloads',
    );
    // Retain a local, non-scope predicate before returning to the unchanged
    // Events dataset. This is not an inferred flow association for that view.
    await gridColumnFilter(page, recordings, 'Flow', 'contains', entry.flow);
    await recordings
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .waitFor();
    assert.equal(count('/recordings/list'), 3);
    await recordings
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    await recording
        .locator('.recording-verification [data-verification-result="success"]')
        .waitFor();
    assert.equal(
        await recording
            .locator('.recording-verification')
            .getByRole('button', { name: 'Verify …', exact: true })
            .count(),
        0,
        'identical fully verified bytes reuse their source verdict instead of offering another check',
    );
    assert.equal(count('/artifacts/recording'), 2);
    await page
        .getByRole('navigation', { name: 'Breadcrumb', exact: true })
        .getByRole('link', { name: 'Recordings', exact: true })
        .click();
    await recording.getByRole('link', { name: 'Events default', exact: true }).click();
    await grid().locator('[role="row"][data-id]').first().waitFor();
    assert.equal(count('/audit-events/list'), 1);
    assert.equal(count('/artifacts/audit'), 1);
    const deep = await context.newPage();
    const deepCalls = [];
    managementWire(deep).on('request', (request) => deepCalls.push(request));
    const deepURL = `${origin}/#Work/-/auditlogs/default/events?flow=${entry.flow}`;
    assert.equal((await deep.goto(deepURL)).status(), 200);
    await deep.getByLabel('User name', { exact: true }).waitFor();
    assert.equal(new URL(deep.url()).hash, `#Work/-/auditlogs/default/events?flow=${entry.flow}`);
    assert.equal(new URL(deep.url()).pathname, '/');
    assert.equal(new URL(deep.url()).search, '');
    assert.equal(
        new URLSearchParams(new URL(deep.url()).hash.split('?')[1]).get('flow'),
        entry.flow,
    );
    assert.deepEqual(
        deepCalls,
        [],
        'a deep-link reload is public routing, not a new login or resumed grant',
    );
    await deep.close();
    assert.deepEqual(errors, []);
    await context.close();
    console.log(
        JSON.stringify({ success: true, auditReads: 1, recordingReads: 3, sourceRoundTrips: 3 }),
    );
} finally {
    await browser.close();
}

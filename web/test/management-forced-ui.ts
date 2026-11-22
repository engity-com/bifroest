import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { Logout, ManagementCall, NetworkObservation, Page } from './fixture-types.ts';
import { managementWire } from './management-wire.ts';
import { required } from './required.ts';
import { activeAccess, assertUiPreferences, chooseLoginMethod, workspace } from './workspace-ui.ts';

export async function forcedKeyLogin(page: Page, file: string) {
    const fixture = JSON.parse(await readFile(file, 'utf8'));
    await chooseLoginMethod(page, 'SSH key login');
    await page.getByLabel('User name', { exact: true }).fill('alice');
    await page.getByLabel('Private key file (local only)', { exact: true }).setInputFiles({
        name: 'local-fixture',
        mimeType: 'application/octet-stream',
        buffer: Buffer.from(fixture.ed),
    });
    await page
        .getByLabel('Key passphrase (optional, local only)', { exact: true })
        .fill(fixture.passphrase);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await activeAccess(page, 'alice');
}

export async function exerciseManagementForcedVersion(page: Page, file: string, logout: Logout) {
    const wire = managementWire(page);
    const calls: ManagementCall[] = [];
    wire.on('request', (request) => {
        const path = new URL(request.url()).pathname;
        if (path.includes('/api/v1/management/')) {
            calls.push({ path, body: JSON.parse(request.postData() ?? '{}') });
        }
    });
    const initialRead = wire.waitForResponse((response) =>
        response.url().endsWith('/management/version/show'),
    );
    await forcedKeyLogin(page, file);
    assert.deepEqual(
        calls.map((call) => call.path.split('/management/')[1]),
        [],
        'the forbidden entry view performs no metadata reads',
    );
    const denied = wire.waitForResponse(
        (response) =>
            response.url().endsWith('/management/version/show') && response.status() === 403,
    );
    await workspace(page, 'Version');
    const navigation = page.getByRole('navigation', { name: 'Workspace', exact: true });
    assert.equal(await navigation.getByRole('link', { name: 'Overview', exact: true }).count(), 0);
    assert.equal(await navigation.getByRole('link', { name: 'Sessions', exact: true }).count(), 0);
    assert.equal((await initialRead).status(), 200);
    await denied;
    const version = page.getByRole('region', { name: 'Server version', exact: true });
    await version.locator('.server-version').waitFor();
    const text = await version.locator('.server-version').textContent();
    assert(text !== null);
    assert(text.includes('<b>version fixture</b><script>window.versionInjected = true</script>'));
    assert(!text.includes('Go:') && !text.includes('Features:'));
    assert.equal(await version.locator('b, script, pre').count(), 0);
    assert.equal(await page.evaluate(() => window.versionInjected), undefined);
    assert.equal(
        await version.getByRole('region', { name: 'Build information', exact: true }).count(),
        0,
    );
    assert.equal(
        await version.locator('.server-version').textContent(),
        text,
        'denied build details do not clear the separately authorized short version',
    );
    assert.deepEqual(
        calls.map((call) => [call.path.split('/management/')[1], call.body.long]),
        [
            ['version/show', 'false'],
            ['version/show', 'true'],
        ],
    );
    for (const call of calls) {
        assert.equal(call.body.command, undefined);
        assert.equal(call.body.args, undefined);
    }
    await page
        .getByText('This sign-in is not permitted to read these details.', {
            exact: false,
        })
        .waitFor();
    assert.equal(await page.getByRole('grid').count(), 0);
    await logout(page);
    assert.equal(
        await page.getByRole('region', { name: 'Server version', exact: true }).count(),
        0,
    );
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await assertUiPreferences(page);
}

export async function exerciseManagementForced(page: Page, file: string, logout: Logout) {
    const wire = managementWire(page);
    const calls: string[] = [];
    wire.on('request', (request) => calls.push(new URL(request.url()).pathname));
    await forcedKeyLogin(page, file);
    await page.evaluate(async () => {
        const { BrowserClient } = await import('/_bifroest/test/client.js');
        await new BrowserClient({ origin: location.origin, slug: 'Work' }).password(
            'bob',
            'correct',
        );
    });
    await workspace(page, 'Sessions');
    const navigation = page.getByRole('navigation', { name: 'Workspace', exact: true });
    assert.equal(await navigation.getByRole('link', { name: 'Overview', exact: true }).count(), 0);
    assert.equal(
        await navigation.getByRole('link', { name: 'Audit logs', exact: true }).count(),
        0,
    );
    const table = page.getByRole('grid', { name: 'Live session metadata', exact: true });
    await table.getByText('alice', { exact: true }).waitFor();
    assert.equal(await table.locator('[role="row"][data-id]').count(), 1);
    await table
        .getByText('Not returned under this forced-command policy', { exact: true })
        .waitFor();
    assert.equal(
        await table.getByText('No verified association available', { exact: true }).count(),
        0,
        'withholding must not invent absent ownership',
    );
    await table.getByRole('button', { name: /^Session details / }).click();
    await page
        .getByText('This sign-in is not permitted to read these details.', {
            exact: false,
        })
        .waitFor();
    assert.equal(
        await page.getByRole('region', { name: 'Session details', exact: true }).count(),
        0,
    );
    assert.equal(await page.getByRole('button', { name: 'End session', exact: true }).count(), 0);
    assert.deepEqual(
        calls.map((path) => path.split('/management/')[1]),
        ['sessions/list', 'sessions/show'],
        'forbidden resources have no navigation controls or automatic requests',
    );
    await logout(page);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await assertUiPreferences(page);
}

export async function exerciseManagementForcedAudit(page: Page, file: string, logout: Logout) {
    const wire = managementWire(page);
    const calls: string[] = [];
    const network: NetworkObservation[] = [];
    wire.on('request', (request) => {
        const path = new URL(request.url()).pathname;
        if (path.includes('/api/v1/management/')) {
            calls.push(path);
        }
    });
    wire.on('response', (response) => {
        const path = new URL(response.url()).pathname;
        if (path.includes('/api/v1/management/')) {
            network.push({
                path,
                status: response.status(),
                type: response.contentType(),
            });
        }
    });
    page.on('requestfailed', (request) => {
        const path = new URL(request.url()).pathname;
        if (path.includes('/api/v1/management/')) {
            network.push({ path, failure: request.failure()?.errorText ?? 'unavailable' });
        }
    });
    await forcedKeyLogin(page, file);
    const auditlogsReply = wire.waitForResponse((response) =>
        response.url().endsWith('/management/auditlogs/list'),
    );
    await workspace(page, 'Audit logs');
    const auditlogsResponse = await auditlogsReply;
    assert.equal(auditlogsResponse.status(), 200);
    const artifacts = page.getByRole('region', {
        name: 'Audit logs',
        exact: true,
    });
    const catalog = artifacts;
    assert.deepEqual(
        calls.map((path) => path.split('/management/')[1]),
        ['auditlogs/list'],
        'only authorized metadata is requested; no unrelated reads or artifact download',
    );
    const table = catalog.getByRole('grid', {
        name: 'Configured auditlogs (server metadata)',
        exact: true,
    });
    try {
        await table.getByRole('gridcell', { name: 'audit00', exact: true }).waitFor();
    } catch (error) {
        throw new Error(
            JSON.stringify({
                network,
                notices: await catalog.getByRole('status').allTextContents(),
                grids: await catalog.getByRole('grid').count(),
            }),
            { cause: error },
        );
    }
    const auditPage = (await auditlogsResponse.json()).auditlogs;
    assert.equal(auditPage.items.length, 20);
    assert(auditPage.items.every((row: { encrypted: boolean }) => row.encrypted === true));
    await table.locator('[data-field="encrypted"] svg[data-value="true"]').first().waitFor();
    const lastAuditPageReply = wire.waitForResponse((response) =>
        response.url().endsWith('/management/auditlogs/list'),
    );
    await table
        .locator('xpath=ancestor::div[@class="admin-data-grid"][1]')
        .getByRole('button', { name: 'Go to next page', exact: true })
        .click();
    const lastAuditPage = await lastAuditPageReply;
    assert.equal(lastAuditPage.status(), 200);
    assert.equal((await lastAuditPage.json()).auditlogs.items.length, 2);
    await table.getByRole('gridcell', { name: 'audit20', exact: true }).waitFor();
    await table.getByRole('gridcell', { name: 'default', exact: true }).waitFor();
    assert.equal(await table.locator('[role="row"][data-id]').count(), 2);
    assert.equal(
        await catalog.getByRole('button', { name: 'More recording sources', exact: true }).count(),
        0,
    );
    assert.equal(calls.filter((path) => path.endsWith('/auditlogs/list')).length, 2);
    assert.equal(calls.filter((path) => path.includes('/artifacts/')).length, 0);
    assert.equal(
        await catalog.getByRole('combobox', { name: 'Recording source', exact: true }).count(),
        0,
        'the audit page has no unrelated Recording source chooser',
    );
    assert.equal(await catalog.getByRole('grid', { name: /^Recordings · /u }).count(), 0);
    assert.equal(calls.filter((path) => path.endsWith('/recordings/list')).length, 0);
    assert.equal(
        calls.filter((path) => path.includes('/artifacts/')).length,
        0,
        'source metadata navigation does not transfer artifacts',
    );
    assert.equal(
        await table
            .getByRole('button', { name: 'Open audit log default', exact: true })
            .isEnabled(),
        false,
    );
    assert.equal(
        await table.getByRole('button', { name: 'Recordings default', exact: true }).isEnabled(),
        false,
    );
    assert.equal(await catalog.getByRole('button', { name: 'Open by ID', exact: true }).count(), 0);
    assert.equal(
        calls.filter((path) => path.endsWith('/audit-events/list')).length,
        0,
        'metadata access exposes no event-reading control',
    );
    assert.equal(
        calls.filter((path) => path.endsWith('/artifacts/audit')).length,
        0,
        'opening the source never implicitly transfers its journal',
    );
    assert.equal(
        await artifacts.getByRole('grid', { name: 'Audit events', exact: true }).count(),
        0,
    );
    for (const secret of [
        'private audit directory',
        'private identity file',
        'private recipient file',
    ]) {
        assert(!required(await artifacts.textContent()).includes(secret));
    }
    assert.deepEqual(
        calls.map((path) => path.split('/management/')[1]),
        ['auditlogs/list', 'auditlogs/list'],
    );
    const navigation = page.getByRole('navigation', { name: 'Workspace', exact: true });
    assert.equal(await navigation.getByRole('link', { name: 'Overview', exact: true }).count(), 0);
    assert.equal(await navigation.getByRole('link', { name: 'Sessions', exact: true }).count(), 0);
    await logout(page);
    assert.equal(await page.getByRole('region', { name: 'Audit logs', exact: true }).count(), 0);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await assertUiPreferences(page);
}

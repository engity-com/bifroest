import assert from 'node:assert/strict';
import { managementWire } from './management-wire.mjs';
import { captureJsonResponse } from './response-capture.mjs';
import { activeAccess, captureLayout, workspace } from './workspace-ui.mjs';

export async function exerciseManagementRelations(page, login) {
    const calls = [];
    const wire = managementWire(page);
    wire.on('request', (request) =>
        calls.push({ path: new URL(request.url()).pathname, body: JSON.parse(request.postData()) }),
    );
    await login(page, false, 'alice');
    await activeAccess(page, 'alice');
    const sessionsReply = captureJsonResponse(page, '/api/v1/management/sessions/list');
    await workspace(page, 'Sessions');
    const sessions = await sessionsReply;
    assert.equal(sessions.error, undefined);
    assert.equal(sessions.status, 200);
    const selected = sessions.body.sessions.items[0];
    assert(selected);
    assert.equal(selected.user, 'alice');
    assert.equal(selected.auditlog, 'default');
    assert.equal(new URL(page.url()).pathname, '/');
    assert.equal(new URL(page.url()).search, '');
    const prefix = new URL(page.url()).hash.replace(/\/sessions$/u, '');
    const pane = page.locator('[data-connection-active="true"]');
    const sessionGrid = pane.getByRole('grid', { name: 'Live session metadata', exact: true });
    await sessionGrid.locator('[role="row"][data-id]').first().waitFor();
    assert.equal(
        await sessionGrid.getByRole('columnheader').first().getAttribute('data-field'),
        'id',
    );
    await sessionGrid
        .locator('.MuiDataGrid-virtualScroller')
        .evaluate((node) => node.scrollTo({ left: node.scrollWidth }));
    const recordingsReply = captureJsonResponse(page, '/api/v1/management/recordings/list');
    await sessionGrid
        .getByRole('link', { name: `Show recordings ${selected.id}`, exact: true })
        .click();
    const recordings = await recordingsReply;
    assert.equal(recordings.error, undefined);
    assert.equal(recordings.status, 200);
    assert(recordings.body.recordings.items.length > 0);
    assert(
        recordings.body.recordings.items.every(
            (row) => row.flow === selected.flow && row.sessionId === selected.id,
        ),
    );
    assert.equal(new URL(page.url()).hash.split('?')[0], `${prefix}/auditlogs/default/recordings`);
    const query = new URLSearchParams(new URL(page.url()).hash.split('?')[1]);
    assert.equal(query.get('sessionId'), selected.id);
    assert.equal(query.get('flow'), selected.flow);
    const recordingGrid = pane.getByRole('grid', { name: 'Recordings · default', exact: true });
    await recordingGrid.locator('[role="row"][data-id]').first().waitFor();
    await recordingGrid
        .locator('.MuiDataGrid-virtualScroller')
        .evaluate((node) => node.scrollTo({ left: node.scrollWidth }));
    const showSessionReply = captureJsonResponse(page, '/api/v1/management/sessions/show');
    await recordingGrid
        .getByRole('link', { name: `Show session ${selected.id}`, exact: true })
        .first()
        .click();
    const shown = await showSessionReply;
    assert.equal(shown.error, undefined);
    assert.equal(shown.status, 200);
    assert.equal(shown.body.session.id, selected.id);
    assert.equal(shown.body.session.flow, selected.flow);
    assert.equal(shown.body.session.user, 'alice');
    assert.equal(
        calls.filter((call) => call.path.includes('/artifacts/')).length,
        0,
        'relationship actions navigate without opening an artifact',
    );
    const details = pane.getByRole('region', { name: 'Session details', exact: true });
    await details.waitFor();
    assert.equal(await details.getByRole('button', { name: 'Close', exact: true }).count(), 0);
    await details.getByRole('link', { name: 'Show recordings', exact: true }).waitFor();
    const auditReply = captureJsonResponse(page, '/api/v1/management/audit-events/list');
    await details.getByRole('link', { name: 'Show audit logs', exact: true }).click();
    const audit = await auditReply;
    assert.equal(audit.error, undefined);
    assert.equal(audit.status, 200);
    assert.equal(new URL(page.url()).search, '');
    assert.equal(
        new URLSearchParams(new URL(page.url()).hash.split('?')[1]).get('sessionId'),
        selected.id,
    );
    assert(audit.body.auditEvents.items.length > 0);
    assert(
        audit.body.auditEvents.items.every(
            (row) =>
                !Object.hasOwn(row.event, 'sessionId') && !Object.hasOwn(row.event, 'recordingId'),
        ),
    );
    const events = pane.getByRole('grid', { name: 'Audit events', exact: true });
    await events.locator('[role="row"][data-id]').first().waitFor();
    const toolbar = events.locator('xpath=ancestor::div[@class="admin-data-grid"][1]');
    const privateReply = captureJsonResponse(page, '/api/v1/management/audit-events/list');
    await toolbar
        .getByRole('button', { name: 'Show sensitive data – currently hidden', exact: true })
        .click();
    const privateEvents = await privateReply;
    assert.equal(privateEvents.error, undefined);
    assert.equal(privateEvents.status, 200);
    assert(
        privateEvents.body.auditEvents.items.every(
            (row) => row.event.sessionId === selected.id && row.event.flow === selected.flow,
        ),
    );
    const related = privateEvents.body.auditEvents.items.find((row) => row.event.recordingId);
    assert(
        related,
        'native session events must expose their actual recording correlation after opt-in',
    );
    await events
        .locator('.MuiDataGrid-virtualScroller')
        .evaluate((node) => node.scrollTo({ left: node.scrollWidth }));
    await events
        .getByRole('link', { name: `Show recording ${related.event.recordingId}`, exact: true })
        .first()
        .click();
    const recordingPanel = pane.getByRole('region', { name: 'Recordings', exact: true });
    await recordingPanel.getByRole('button', { name: 'Verify …', exact: true }).click();
    await page
        .getByRole('dialog', { name: 'Verification options', exact: true })
        .getByRole('button', { name: 'Start verification', exact: true })
        .click();
    await recordingPanel.getByRole('region', { name: 'Recording playback', exact: true }).waitFor();
    const metadata = recordingPanel.locator('.recording-evidence');
    await metadata.getByRole('heading', { name: 'Details', exact: true }).waitFor();
    const target = `/${prefix.replace(/\/[^/]+$/u, '/-')}/sessions/${selected.flow}/${selected.id}`;
    assert.equal(
        await metadata.getByRole('link', { name: selected.id, exact: true }).getAttribute('href'),
        target,
    );
    assert.equal(
        await metadata
            .getByRole('link', { name: 'Show session', exact: true })
            .getAttribute('href'),
        target,
    );
    assert.equal(
        await recordingPanel.getByRole('button', { name: 'Back to list', exact: true }).count(),
        0,
    );
    await captureLayout(page, 'native-session-recording-event-relations');
    assert.equal(
        calls.filter(
            (call) =>
                call.path.endsWith('/recordings/verify') || call.path.endsWith('/artifacts/audit'),
        ).length,
        0,
        'jump links never start a whole-source verification',
    );
    assert.equal(calls.filter((call) => call.path.endsWith('/artifacts/recording')).length, 1);
}

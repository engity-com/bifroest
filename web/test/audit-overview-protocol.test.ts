import { expect, it } from 'vitest';
import {
    auditEventFields,
    auditOverviewPage,
    catalogVerification,
} from '../src/management/audit-overview';

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const payload = () => ({
    version: 1,
    operation: 'audit-events.list',
    auditEventSource: {
        auditlog: 'default',
        encrypted: false,
        sensitive: false,
        verification: 'server-overview',
    },
    auditEvents: {
        items: [
            {
                key: `1:0:${id}`,
                id,
                recordedAt: '2026-11-05T00:00:00Z',
                event: { name: 'session.task.completed', outcome: 'success' },
            },
        ],
        next: '',
        skipped: 0,
    },
});
it('keeps overview source/provenance and explicit private projection separate from evidence verification', () => {
    const fields = auditEventFields('default', {});
    expect(fields).toMatchObject({
        auditlog: 'default',
        limit: '20',
        after: '',
        sensitive: 'false',
        sort: 'recorded-desc',
    });
    const page = auditOverviewPage(payload(), fields);
    expect(page.source.verification).toBe('server-overview');
    expect(page.items[0]?.id).toBe(id);
    expect(Object.isFrozen(page.items)).toBe(true);
    for (const mutate of [
        (body: ReturnType<typeof payload>) => {
            body.auditEventSource.auditlog = 'other';
        },
        (body: ReturnType<typeof payload>) => {
            body.auditEventSource.verification = 'verified';
        },
        (body: ReturnType<typeof payload>) => {
            Object.assign(body.auditEvents.items[0]?.event ?? {}, { flow: 'hidden-private-flow' });
        },
        (body: ReturnType<typeof payload>) => {
            Object.assign(body.auditEvents.items[0]?.event ?? {}, {
                accessToken: 'must-not-escape',
            });
        },
    ]) {
        const body = payload();
        mutate(body);
        expect(() => auditOverviewPage(body, fields)).toThrow('unavailable');
    }
});
it('does not let private flags, scope hints or cursors bypass strict overview selectors', () => {
    const fields = auditEventFields('default', { flow: 'docker', id, sensitive: true });
    expect(fields).toMatchObject({ flow: 'docker', id, sensitive: 'true' });
    const body = payload();
    body.auditEventSource.sensitive = true;
    Object.assign(body.auditEvents.items[0]?.event ?? {}, { flow: 'other' });
    expect(() => auditOverviewPage(body, fields)).toThrow('unavailable');
    for (const input of [
        { after: 'bmp1.wrong' },
        { after: '../file' },
        { limit: 21 },
        { id: 'not-an-id' },
        { id, after: 'bae1.cursor' },
    ]) {
        expect(() => auditEventFields('default', input)).toThrow('unavailable');
    }
});
it('a server full-check result cannot claim independent trust or another source', () => {
    const result = {
        version: 1,
        operation: 'recordings.verify',
        verification: { auditlog: 'default', checked: 3, full: 2, outer: 1, independent: false },
    };
    expect(catalogVerification(result, 'default')).toMatchObject({
        checked: 3,
        independent: false,
    });
    for (const changed of [
        { independent: true },
        { auditlog: 'other' },
        { checked: 4 },
        { full: -1 },
    ]) {
        expect(() =>
            catalogVerification(
                { ...result, verification: { ...result.verification, ...changed } },
                'default',
            ),
        ).toThrow('unavailable');
    }
});

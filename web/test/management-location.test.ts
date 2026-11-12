import { expect, it } from 'vitest';
import { uuidText } from '../src/shared/uuid';
import { managementCrumbs } from '../src/ui/management-crumbs';
import {
    exactFlow,
    type ManagementLocation,
    managementPath,
    parseManagementLocation,
} from '../src/ui/management-location';

it('formats only UUID identity fields, never UUID-shaped flow or source names', () => {
    const name = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
    const labels = managementCrumbs(
        { managementFlow: 'admin', page: 'recordings', auditlogHint: name, flow: name, id: name },
        () => {},
    ).map((item) => item.label);
    expect(labels).toEqual(['Bifröst', 'Audit logs', name, 'Recordings', uuidText(name)]);
    expect(
        managementCrumbs(
            { managementFlow: 'admin', page: 'sessions', flow: name, id: name },
            () => {},
        ).map((item) => item.label),
    ).toEqual(['Bifröst', 'Sessions', name, uuidText(name)]);
});

const scope = { origin: 'https://app.example.org', slug: 'team/Admin' };
const uuid = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
it('roundtrips the explicit management prefix and every supported dataset/detail path', () => {
    for (const route of [
        { managementFlow: 'admin', page: 'server' },
        { managementFlow: 'admin', page: 'version' },
        { managementFlow: 'admin', page: 'sessions' },
        { managementFlow: 'admin', page: 'sessions', flow: 'docker' },
        { managementFlow: 'admin', page: 'sessions', flow: 'docker', id: uuid },
        { managementFlow: 'admin', page: 'recordings' },
        {
            managementFlow: 'admin',
            page: 'recordings',
            auditlogHint: 'default',
            recordingHint: uuid,
        },
        { managementFlow: 'admin', page: 'recordings', flow: 'docker' },
        {
            managementFlow: 'admin',
            page: 'recordings',
            flow: 'docker',
            sessionId: uuid,
            auditlogHint: 'default',
        },
        {
            managementFlow: 'admin',
            page: 'recordings',
            flow: 'docker',
            id: uuid,
            sessionId: uuid,
            auditlogHint: 'default',
        },
        {
            managementFlow: 'admin',
            page: 'recordings',
            flow: 'docker',
            id: uuid,
            auditlogHint: 'default',
        },
        { managementFlow: 'admin', page: 'auditlogs' },
        { managementFlow: 'admin', page: 'auditlogs', auditlog: 'default' },
        { managementFlow: 'admin', page: 'auditlogs', auditlog: 'default', flow: 'docker' },
        { managementFlow: 'admin', page: 'auditlogs', auditlog: 'default', flow: '-', id: uuid },
        { managementFlow: 'admin', page: 'auditlogs', auditlog: 'default', eventHint: uuid },
        {
            managementFlow: 'admin',
            page: 'auditlogs',
            auditlog: 'default',
            flow: 'docker',
            sessionId: uuid,
        },
        {
            managementFlow: 'admin',
            page: 'auditlogs',
            auditlog: 'default',
            flow: 'docker',
            sessionId: uuid,
            id: uuid,
        },
    ] as const) {
        const path = managementPath(scope, route);
        const url = new URL(path, scope.origin);
        expect(path.startsWith('/team/Admin/admin')).toBe(true);
        expect(parseManagementLocation(scope, url)).toEqual(route);
    }
    expect(
        managementPath(
            { ...scope, slug: '' },
            { managementFlow: 'admin', page: 'sessions', flow: 'docker' },
        ),
    ).toBe('/admin/sessions/docker');
});
it('rejects malformed paths, unsupported or duplicated query data, IDs in the wrong position and encoded aliases', () => {
    for (const suffix of [
        '/',
        '/unknown',
        `/sessions/../${uuid}`,
        '/sessions/docker/invalid',
        `/recordings/docker/${uuid}?accessToken=secret`,
        `/recordings/docker/${uuid}?auditlog=a&auditlog=b`,
        `/auditlogs?event=${uuid}`,
        `/auditlogs/default/docker/${uuid}?event=${uuid}`,
        '/sessions/%64ocker',
        `/sessions/docker/${uuid}/extra`,
        `/sessions/docker?sessionId=${uuid}`,
        `/recordings?sessionId=${uuid}&sessionId=${uuid}`,
        '/auditlogs/default?sessionId=not-an-id',
        '/auditlogs/default?sessionId=00000000-0000-0000-0000-000000000000',
    ]) {
        expect(
            parseManagementLocation(
                scope,
                new URL(`https://app.example.org/team/Admin/admin${suffix}`),
            ),
        ).toBeNull();
    }
    expect(() =>
        managementPath(scope, {
            managementFlow: 'admin',
            page: 'sessions',
            id: uuid,
        } as ManagementLocation),
    ).toThrow();
    expect(exactFlow({ field: 'flow', operator: 'equals', value: 'Docker' })).toBe('Docker');
    expect(exactFlow({ field: 'flow', operator: 'contains', value: 'Docker' })).toBeUndefined();
});

it('uses explicit source collections and never turns an equal source/flow into duplicate breadcrumb levels', () => {
    for (const page of ['auditlogs', 'recordings'] as const) {
        const route: ManagementLocation = {
            managementFlow: 'admin',
            page,
            ...(page === 'auditlogs'
                ? { auditlog: 'docker-encrypted' }
                : { auditlogHint: 'docker-encrypted' }),
            flow: 'docker-encrypted',
            sessionId: uuid,
        };
        const expected = `/team/Admin/admin/auditlogs/docker-encrypted/${page === 'auditlogs' ? 'events' : 'recordings'}?flow=docker-encrypted&sessionId=${uuid}`;
        expect(managementPath(scope, route)).toBe(expected);
        expect(parseManagementLocation(scope, new URL(expected, scope.origin))).toEqual(route);
        expect(managementCrumbs(route, () => {}).map((item) => item.label)).toEqual([
            'Bifröst',
            'Audit logs',
            'docker-encrypted',
            page === 'auditlogs' ? 'Events' : 'Recordings',
        ]);
        const detail = { ...route, id: uuid };
        expect(managementCrumbs(detail, () => {}).map((item) => item.label)).toEqual([
            'Bifröst',
            'Audit logs',
            'docker-encrypted',
            page === 'auditlogs' ? 'Events' : 'Recordings',
            uuidText(uuid),
        ]);
    }
    const legacy = parseManagementLocation(
        scope,
        new URL('/team/Admin/admin/auditlogs/docker-encrypted/docker-encrypted', scope.origin),
    );
    expect(legacy).not.toBeNull();
    if (!legacy) {
        throw new Error('missing supported legacy entry');
    }
    expect(managementPath(scope, legacy)).toBe(
        '/team/Admin/admin/auditlogs/docker-encrypted/events?flow=docker-encrypted',
    );
});

it('rejects collection confusion and duplicated source or private selectors without silently dropping them', () => {
    for (const suffix of [
        `/auditlogs/default/events/${uuid}?event=${uuid}`,
        `/auditlogs/default/recordings/${uuid}?recording=${uuid}`,
        '/auditlogs/default/recordings?auditlog=other',
        `/auditlogs/default/events?recording=${uuid}`,
        `/auditlogs/default/recordings?event=${uuid}`,
        '/auditlogs/default/events?flow=a&flow=b',
        '/auditlogs/default/a?flow=b',
        '/auditlogs/default/events/invalid',
    ]) {
        expect(
            parseManagementLocation(
                scope,
                new URL(`https://app.example.org/team/Admin/admin${suffix}`),
            ),
        ).toBeNull();
    }
});

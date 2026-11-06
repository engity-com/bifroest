import { expect, it } from 'vitest';
import {
  exactFlow,
  type ManagementLocation,
  managementPath,
  parseManagementLocation,
} from '../src/ui/management-location';

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
    { managementFlow: 'admin', page: 'recordings', auditlogHint: 'default', recordingHint: uuid },
    { managementFlow: 'admin', page: 'recordings', flow: 'docker' },
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
  ]) {
    expect(
      parseManagementLocation(scope, new URL(`https://app.example.org/team/Admin/admin${suffix}`)),
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

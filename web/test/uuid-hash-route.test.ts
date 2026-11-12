import { expect, it } from 'vitest';
import { newViewID, uuidBytes, uuidClassic, uuidEqual, uuidText } from '../src/shared/uuid';
import { bookmarkPath, hashPath, parseHashTarget } from '../src/ui/hash-route';

const scope = { origin: 'https://app.example.org', slug: 'admin' };
const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
it('shares the canonical Base58 UUID contract without confusing tokens or digests with IDs', () => {
    for (const text of [
        id,
        id.toUpperCase(),
        id.replaceAll('-', ''),
        `{${id}}`,
        `urn:uuid:${id}`,
    ]) {
        expect(uuidText(text)).toBe(uuidText(id));
        expect(uuidEqual(text, uuidText(id))).toBe(true);
    }
    expect(uuidClassic(uuidText(id))).toBe(id);
    expect(uuidText('00000000-0000-0000-0000-000000000000')).toBe('1111111111111111');
    for (const value of [
        'ABCDEF1',
        '0OIl1111111111111111',
        '1'.repeat(17),
        'z'.repeat(22),
        'a'.repeat(64),
    ]) {
        expect(uuidBytes(value)).toBeNull();
    }
});
it('keeps slug, UI connection and target in the fragment and omits the management flow', () => {
    const connection = newViewID();
    const route = {
        managementFlow: 'administration',
        page: 'recordings' as const,
        auditlogHint: 'docker-encrypted',
        flow: 'docker',
        sessionId: id,
    };
    const path = hashPath(scope, connection, route);
    expect(path).toBe(
        `/#admin/${connection}/auditlogs/docker-encrypted/recordings?flow=docker&sessionId=${uuidText(id)}`,
    );
    const target = parseHashTarget(scope.origin, new URL(path, scope.origin).hash);
    expect(target).toEqual({
        scope,
        connection,
        management: { ...route, sessionId: uuidText(id), managementFlow: '' },
    });
    expect(bookmarkPath(scope, route)).toContain('/#admin/-/auditlogs/');
    expect(hashPath(scope, null)).toBe('/#admin');
});

it('allows an api-named hash scope without treating the real API path as navigation', () => {
    const api = { ...scope, slug: 'api' };
    expect(hashPath(api, null)).toBe('/#api');
    expect(parseHashTarget(api.origin, '#api')?.scope).toEqual(api);
});
it('disambiguates nested/root slugs and rejects malformed or credential-bearing targets', () => {
    for (const slug of ['', 'team/Admin']) {
        const path = hashPath({ ...scope, slug }, '-', {
            managementFlow: 'ignored',
            page: 'auditlogs',
        });
        expect(parseHashTarget(scope.origin, new URL(path, scope.origin).hash)?.scope.slug).toBe(
            slug,
        );
    }
    for (const hash of [
        '#admin/ABCDEF1/auditlogs',
        '#admin//auditlogs',
        '#team/Admin/-/auditlogs',
        '#admin/-/auditlogs?accessToken=secret',
        '#admin/-/auditlogs/foo/events?flow=a&flow=b',
        `#admin/-/sessions/../${id}`,
    ]) {
        expect(parseHashTarget(scope.origin, hash)).toBeNull();
    }
});

import { describe, expect, it, vi } from 'vitest';
import { validateScope } from '../src/remember/protocol';

vi.mock('../src/remember/protocol', { spy: true });

import {
    linkSlugs,
    loadEntryMetadata,
    loadLinkMetadata,
    loadWorkspaceEntry,
    loginOptionFor,
    loginOptionKey,
    parseLinkMetadata,
} from '../src/ui/link-metadata';

const scope = { origin: 'https://app.example.org', slug: 'Work' };
const option = { method: 'password', requestUser: true, certificateRequired: false };

describe('independent link discovery, never authorization', () => {
    it('discovers OIDC separately from device interaction and keeps saved access policy', () => {
        const metadata = parseLinkMetadata(
            {
                scope,
                rootAvailable: false,
                loginOptions: [
                    {
                        method: 'oidc',
                        requestUser: false,
                        certificateRequired: false,
                        rememberMe: 'allowed',
                    },
                    {
                        method: 'keyboard-interactive',
                        requestUser: false,
                        certificateRequired: false,
                    },
                ],
            },
            scope,
        );
        expect(metadata.loginOptions.map(loginOptionKey)).toEqual([
            'oidc:nameless',
            'keyboard-interactive:nameless',
        ]);
        expect(loginOptionFor(metadata, 'oidc:nameless')?.rememberMe).toBe('allowed');
    });
    it('binds metadata to the exact requested origin and case-sensitive link and copies it', () => {
        const inputOption = { ...option };
        const value = {
            scope: { ...scope },
            rootAvailable: false,
            frontendAvailable: true,
            loginOptions: [inputOption],
            publishedSlugs: ['Other', 'Manage/Team'],
        };
        const metadata = parseLinkMetadata(value, scope);
        value.scope.slug = 'Changed';
        value.rootAvailable = true;
        value.publishedSlugs[0] = 'Changed';
        inputOption.requestUser = false;
        expect(metadata).toEqual({
            scope,
            rootAvailable: false,
            loginOptions: [{ ...option, rememberMe: 'forbidden' }],
            publishedSlugs: ['Other', 'Manage/Team'],
        });
        expect(Object.isFrozen(metadata.scope)).toBe(true);
        expect(Object.isFrozen(metadata)).toBe(true);
        expect(Object.isFrozen(metadata.publishedSlugs)).toBe(true);
        expect(Object.isFrozen(metadata.loginOptions)).toBe(true);
        expect(Object.isFrozen(metadata.loginOptions[0])).toBe(true);
        expect(
            parseLinkMetadata({ scope, loginOptions: [], rootAvailable: false }, scope)
                .publishedSlugs,
        ).toEqual([]);
    });
    for (const value of [
        null,
        [],
        {},
        { scope: { ...scope, slug: 'work' }, loginOptions: [option], rootAvailable: false },
        {
            scope: { ...scope, origin: 'https://other.example.org' },
            loginOptions: [option],
            rootAvailable: false,
        },
        { scope, requestUser: true },
        { scope, loginOptions: [option] },
        { scope, loginOptions: [option], rootAvailable: 'false' },
        { scope, loginOptions: [option], rootAvailable: null },
        { scope, loginOptions: [option], rootAvailable: false, token: 'untrusted' },
        { scope, loginOptions: [option], rootAvailable: false, frontendAvailable: 'true' },
        ...[
            null,
            ['//other.example.org'],
            ['../Private'],
            ['%2fPrivate'],
            ['foo_bar'],
            [''],
            Array(1025).fill('Other'),
        ].map((links) => ({
            scope,
            loginOptions: [option],
            publishedSlugs: links,
            rootAvailable: false,
        })),
        ...[
            null,
            ['password'],
            [{ ...option, method: 'unknown' }],
            [{ ...option, requestUser: 'true' }],
            [{ ...option, certificateRequired: true }],
            [{ method: 'password', requestUser: true }],
            [{ ...option, token: 'untrusted' }],
            [{ ...option }, { ...option }],
            Array(9).fill(option),
        ].map((loginOptions) => ({ scope, loginOptions, rootAvailable: false })),
    ]) {
        it('rejects mismatched scopes, malformed requests and unbounded/non-path discovery', () => {
            expect(() => parseLinkMetadata(value, scope)).toThrow();
        });
    }
    it('keeps name modes separate and certificate requirements bound to public-key options', () => {
        const metadata = parseLinkMetadata(
            {
                scope,
                rootAvailable: true,
                loginOptions: [
                    option,
                    { ...option, requestUser: false },
                    { method: 'public-key', requestUser: true, certificateRequired: true },
                    { method: 'none', requestUser: false, certificateRequired: false },
                ],
            },
            scope,
        );
        expect(metadata.loginOptions.map(loginOptionKey)).toEqual([
            'password:named',
            'password:nameless',
            'public-key:named',
            'none:nameless',
        ]);
        expect(loginOptionFor(metadata, 'public-key:named')?.certificateRequired).toBe(true);
        expect(loginOptionFor(metadata, 'keyboard-interactive:nameless')).toBeNull();
        expect(loginOptionFor(metadata, 'password:nameless')?.requestUser).toBe(false);
    });
    it('rejects a foreign origin before any request, without a bearer/cookie fallback', async () => {
        const transport = vi.fn();
        await expect(loadLinkMetadata(scope, undefined, transport)).rejects.toMatchObject({
            code: 'unavailable',
        });
        expect(transport).not.toHaveBeenCalled();
    });
    it('loads fragment targets exclusively through POST bodies, never URL paths or query strings', async () => {
        const original = await vi.importActual<typeof import('../src/remember/protocol')>(
            '../src/remember/protocol',
        );
        // Only the dev harness is HTTP. Real scope/path validation still runs, with
        // its transport origin substituted at this test's protocol boundary.
        vi.mocked(validateScope).mockImplementation((value) =>
            original.validateScope(
                value.origin === location.origin ? { ...value, origin: scope.origin } : value,
            ),
        );
        const entryScope = { ...scope, origin: location.origin };
        const current = {
            pathname: '/',
            search: '',
            hash: '#alice%40example.org@Work/-/auditlogs/default/recordings',
        };
        const transport = vi.fn(
            async (_input: RequestInfo | URL, _options?: RequestInit) =>
                new Response(
                    JSON.stringify({
                        scope: entryScope,
                        rootAvailable: false,
                        loginOptions: [option],
                        publishedSlugs: ['Work'],
                    }),
                    { headers: { 'Content-Type': 'application/json' } },
                ),
        );
        try {
            expect(
                (await loadEntryMetadata(entryScope.origin, current, undefined, transport)).scope,
            ).toEqual(entryScope);
            expect(String(transport.mock.calls[0]?.[0])).toBe(
                `${entryScope.origin}/api/v1/discovery`,
            );
            expect(transport.mock.calls[0]?.[1]).toMatchObject({
                credentials: 'omit',
                mode: 'same-origin',
                redirect: 'error',
                cache: 'no-store',
                method: 'POST',
                body: JSON.stringify({ slug: 'Work' }),
                headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            });
            for (const invalid of [
                { ...current, search: '?accessToken=must-not-fetch' },
                { ...current, hash: '#private/invalid-connection' },
                { ...current, pathname: '/Work/admin/sessions/%64ocker' },
            ]) {
                await expect(
                    loadEntryMetadata(entryScope.origin, invalid, undefined, transport),
                ).rejects.toMatchObject({ code: 'unavailable' });
            }
            expect(transport).toHaveBeenCalledOnce();
            transport.mockImplementation(
                async () =>
                    new Response(
                        JSON.stringify({
                            scope: { ...entryScope, slug: 'Other' },
                            rootAvailable: false,
                            loginOptions: [option],
                        }),
                        { headers: { 'Content-Type': 'application/json' } },
                    ),
            );
            await expect(
                loadEntryMetadata(entryScope.origin, current, undefined, transport),
            ).rejects.toMatchObject({ code: 'unavailable' });
        } finally {
            vi.mocked(validateScope).mockRestore();
        }
    });

    it('keeps cold missing links in the editable workspace and only recovers published suggestions', async () => {
        vi.mocked(validateScope).mockImplementation((value) => {
            if (value.origin !== location.origin) {
                throw new Error('unexpected origin');
            }
        });
        const requests: { path: string; slug: string }[] = [];
        const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
            const body = JSON.parse(String(options?.body));
            requests.push({ path: String(input), slug: body.slug });
            return new Response(
                body.slug
                    ? ''
                    : JSON.stringify({
                          scope: { origin: location.origin, slug: '' },
                          rootAvailable: false,
                          publishedSlugs: ['Work'],
                          loginOptions: [],
                      }),
                { status: body.slug ? 404 : 200, headers: { 'Content-Type': 'application/json' } },
            );
        });
        try {
            const entry = await loadWorkspaceEntry(location.origin, {
                pathname: '/',
                search: '',
                hash: '#notexistent',
            });
            expect(entry.failure).toBe('invalid-slug');
            expect(entry.metadata.scope.slug).toBe('notexistent');
            expect(entry.metadata.loginOptions).toEqual([]);
            expect(entry.metadata.publishedSlugs).toEqual(['Work']);
            expect(requests.map((request) => request.path)).toEqual(
                Array(2).fill(`${location.origin}/api/v1/discovery`),
            );
            expect(requests.map((request) => request.slug)).toEqual(['notexistent', '']);
        } finally {
            fetch.mockRestore();
            vi.mocked(validateScope).mockRestore();
        }
    });

    it('preserves hyphenated aliases without substituting a published flow name', () => {
        const alias = { ...scope, slug: 'bla-bla' };
        const metadata = parseLinkMetadata(
            {
                scope: alias,
                rootAvailable: false,
                loginOptions: [option],
                publishedSlugs: ['docker', 'other-alias/Team-1'],
            },
            alias,
        );
        expect(metadata.scope.slug).toBe('bla-bla');
        expect(linkSlugs(metadata, metadata, 'bla-bla', [])).toEqual([
            'bla-bla',
            'docker',
            'other-alias/Team-1',
        ]);
    });

    it.each([false, true])(
        'selects root only with the explicit rootAvailable=%s flag',
        (rootAvailable) => {
            const initial = parseLinkMetadata(
                {
                    scope: { ...scope, slug: '' },
                    loginOptions: [],
                    publishedSlugs: ['Work'],
                    rootAvailable: false,
                },
                { ...scope, slug: '' },
            );
            const current = { ...initial, rootAvailable };
            const slugs = linkSlugs(initial, current, '', [
                { ...scope, slug: '' },
                { ...scope, slug: 'bla-bla' },
                { origin: 'https://foreign.example.org', slug: 'Private' },
            ]);
            expect(slugs.includes('')).toBe(rootAvailable);
            expect(slugs).toContain('Work');
            expect(slugs).toContain('bla-bla');
            expect(slugs).not.toContain('Private');
        },
    );
});

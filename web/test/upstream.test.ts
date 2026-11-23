import { afterEach, describe, expect, it, vi } from 'vitest';
import { oidcEntry } from '../src/login/oidc';
import { Http } from '../src/remember/http';
import { validateScope } from '../src/remember/protocol';
import {
    deploymentKey,
    internalPath,
    ownsPreferenceKey,
    pathPrefix,
    publicPath,
} from '../src/shared/upstream';
import { bookmarkPath } from '../src/ui/hash-route';
import { loadEntryMetadata } from '../src/ui/link-metadata';

vi.mock('../src/remember/protocol', { spy: true });

function mount(prefix: string): void {
    const meta = document.createElement('meta');
    meta.name = 'bifroest-path-prefix';
    meta.content = prefix;
    document.head.appendChild(meta);
}

afterEach(() => {
    document.querySelectorAll('meta[name="bifroest-path-prefix"]').forEach((node) => {
        node.remove();
    });
    vi.restoreAllMocks();
});

describe('reverse-proxy runtime mount', () => {
    it('keeps root behavior and validates canonical prefixes', () => {
        expect(publicPath('/api/v1/discovery')).toBe('/api/v1/discovery');
        expect(deploymentKey('bifroest-test')).toBe('bifroest-test');
        mount('/team/bifroest');
        expect(pathPrefix()).toBe('/team/bifroest');
        expect(publicPath('/assets/browser-key.wasm')).toBe(
            '/team/bifroest/assets/browser-key.wasm',
        );
        expect(internalPath('/team/bifroest/login/callback')).toBe('/login/callback');
        expect(internalPath('/team/bifroest')).toBe('/');
        expect(internalPath('/team/bifroest-other/')).toBe('');
        expect(deploymentKey('bifroest-test')).not.toBe('bifroest-test');
        expect(ownsPreferenceKey(deploymentKey('bifroest-test'))).toBe(true);
        expect(ownsPreferenceKey('bifroest-test')).toBe(false);
    });

    it('routes requests, OIDC and copied links through the same mount', async () => {
        const original = await vi.importActual<typeof import('../src/remember/protocol')>(
            '../src/remember/protocol',
        );
        // The Vitest development server is HTTP; retain the real shape and
        // HTTPS checks at the protocol boundary, as in the discovery tests.
        vi.mocked(validateScope).mockImplementation((value) =>
            original.validateScope(
                value.origin === location.origin
                    ? { ...value, origin: 'https://app.example.org' }
                    : value,
            ),
        );
        mount('/bifroest');
        const scope = { origin: location.origin, slug: 'Work' };
        const transport = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
        await new Http(scope, transport).post('logout', {}, `bwa1.${'A'.repeat(43)}`, 204);
        expect(String(transport.mock.calls[0]?.[0])).toBe(
            `${location.origin}/bifroest/api/v1/logout`,
        );
        expect(bookmarkPath(scope)).toBe('/bifroest/#Work/-');
        expect(
            oidcEntry({
                pathname: '/bifroest/login/callback',
                search: '?state=x&code=y',
                hash: '',
            }),
        ).toEqual({ action: 'callback', fields: { query: 'state=x&code=y' } });
        expect(
            oidcEntry({ pathname: '/login/callback', search: '?state=x&code=y', hash: '' }),
        ).toBeNull();
        const discovery = vi.fn().mockResolvedValue(
            new Response(
                JSON.stringify({
                    scope: { origin: location.origin, slug: '' },
                    loginOptions: [],
                    publishedSlugs: [],
                    rootAvailable: false,
                }),
                { headers: { 'Content-Type': 'application/json' } },
            ),
        );
        await loadEntryMetadata(
            location.origin,
            { pathname: '/bifroest/', search: '', hash: '' },
            undefined,
            discovery,
        );
        expect(String(discovery.mock.calls[0]?.[0])).toBe(
            `${location.origin}/bifroest/api/v1/discovery`,
        );
    });

    it('rejects ambiguous and encoded mount paths', () => {
        for (const prefix of ['//evil', '/a/../b', '/a%2fb', '/a/', 'https://evil.example']) {
            mount(prefix);
            expect(() => pathPrefix()).toThrow();
            document.querySelector('meta[name="bifroest-path-prefix"]')?.remove();
        }
    });
});

import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import { ArtifactSessionSecrets } from '../src/artifacts/artifact-secrets';
import type { VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import {
    ArtifactSecretsBoundary,
    ArtifactSecretsContext,
    useArtifactSecrets,
} from '../src/artifacts/session-secrets';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';

const fingerprint = `SHA256:${'A'.repeat(43)}`;
const key = { file: new Blob(['PRIVATE-KEY-SENTINEL']), passphrase: 'PRIVATE-PASSPHRASE-SENTINEL' };
const verified: VerifiedArtifact = {
    request: {
        kind: 'recording',
        auditlog: 'Original',
        id: '00000000-0000-0000-0000-000000000001',
    },
    provenance: 'bytes-only',
    output: null,
    metadata: {
        kind: 'recording',
        validation: 'private',
        trust: 'untrusted',
        producer: 'a'.repeat(64),
        expectedRecipient: fingerprint,
        decryption: 'authenticated',
        recordingId: '00000000-0000-0000-0000-000000000001',
        auditScope: '',
        records: '1',
        privateRecords: '1',
        outputFormat: '',
    },
};
function owner(principal: string) {
    const scope = { origin: 'https://app.example.org', slug: principal };
    return new WebAccess(
        new Http(
            scope,
            vi.fn(async (input) => {
                if (!String(input).endsWith('/logout')) {
                    throw new Error('Unexpected server request');
                }
                return new Response(null, { status: 204 });
            }),
        ),
        {
            scope,
            principal,
            expiresAt: '2100-01-01T00:00:00Z',
            environment: 'management',
            terminalAvailable: false,
            accessToken: `bwa1.${'A'.repeat(43)}`,
        },
        null,
    );
}
function Consumer({
    access,
    name,
    bind,
}: {
    access: WebAccess;
    name: string;
    bind(cache: ArtifactSessionSecrets): void;
}) {
    const cache = useArtifactSecrets(access);
    bind(cache);
    return createElement('output', { 'data-consumer': name }, JSON.stringify(cache.getSnapshot()));
}

it('shares exactly one owner cache, updates every consumer and exposes metadata only', async () => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const access = owner('Alice');
    const subscriptions = vi.spyOn(access, 'subscribeStatus');
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    const caches = new Map<string, ArtifactSessionSecrets>();
    const get = (name: string) => {
        const cache = caches.get(name);
        if (!cache) {
            throw new Error('Missing owner cache');
        }
        return cache;
    };
    try {
        const consumers = ['left', 'right'].map((name) =>
            createElement(
                ArtifactSecretsBoundary,
                { key: name, access },
                createElement(Consumer, { access, name, bind: (cache) => caches.set(name, cache) }),
            ),
        );
        await act(async () =>
            root.render(createElement(ArtifactSecretsBoundary, { access }, ...consumers)),
        );
        expect(get('left')).toBe(get('right'));
        expect(subscriptions).toHaveBeenCalledTimes(1);
        await act(async () => get('left').remember(key, verified));
        expect(
            [...container.querySelectorAll('output')].every((output) =>
                output.textContent?.includes(fingerprint),
            ),
        ).toBe(true);
        expect(container.textContent).not.toContain('PRIVATE');
        const first = get('left').getSnapshot();
        await act(async () => get('right').clear());
        expect(
            [...container.querySelectorAll('output')].every((output) =>
                output.textContent?.includes('"fingerprint":null'),
            ),
        ).toBe(true);
        expect(get('left').getSnapshot().revision).toBeGreaterThan(first.revision);
        await act(async () => get('left').remember(key, verified));
        await act(async () => {
            await access.logout();
        });
        expect(get('left').matching(fingerprint)).toBeNull();
        expect(container.textContent).not.toContain(fingerprint);
    } finally {
        await act(async () => root.unmount());
        container.remove();
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    }
});

it('does not adopt a different actor provider and retires only the standalone owner it created', async () => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const alice = owner('Alice');
    const bob = owner('Bob');
    const shared = new ArtifactSessionSecrets(alice);
    shared.remember(key, verified);
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    let bound: ArtifactSessionSecrets | undefined;
    let unmounted = false;
    try {
        await act(async () =>
            root.render(
                createElement(
                    ArtifactSecretsContext.Provider,
                    { value: shared },
                    createElement(
                        ArtifactSecretsBoundary,
                        { access: bob },
                        createElement(Consumer, {
                            access: bob,
                            name: 'bob',
                            bind: (cache) => {
                                bound = cache;
                            },
                        }),
                    ),
                ),
            ),
        );
        if (!bound) {
            throw new Error('Missing Bob cache');
        }
        expect(bound.ownedBy(bob)).toBe(true);
        expect(bound.matching(fingerprint)).toBeNull();
        expect(container.textContent).not.toContain(fingerprint);
        const cache = bound;
        await act(async () => root.unmount());
        unmounted = true;
        expect(() => cache.remember(key, verified)).toThrow();
        expect(shared.matching(fingerprint)?.passphrase).toBe(key.passphrase);
    } finally {
        if (!unmounted) {
            await act(async () => root.unmount());
        }
        container.remove();
        shared.retire();
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    }
});

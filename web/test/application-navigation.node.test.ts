import { expect, it, vi } from 'vitest';
import type { LinkMetadata } from '../src/application/link-metadata';
import {
    ApplicationNavigation,
    type ApplicationRouteIntent,
    type NavigationBoundary,
} from '../src/application/navigation';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';

const scope = { origin: 'https://app.example.org', slug: 'Original' };
const metadata: LinkMetadata = {
    scope,
    loginOptions: [],
    publishedSlugs: [],
    rootAvailable: false,
};
function fixture() {
    const load = vi.fn(async (selected: typeof scope, _signal: AbortSignal) => ({
        ...metadata,
        scope: selected,
    }));
    const accepted = vi.fn();
    const failed = vi.fn();
    const boundary: NavigationBoundary = {
        views: [],
        metadataScope: scope,
        canonicalizing: vi.fn(),
        mismatch: vi.fn(),
        activate: vi.fn(),
        releaseStoppedAuthentication: vi.fn(),
        reuse: vi.fn(),
        invalidateDiscovery: vi.fn(),
        discover: vi.fn(() => ({ current: () => true, accepted, failed })),
    };
    const owner = new ApplicationNavigation(load);
    const intent = (change: Partial<ApplicationRouteIntent> = {}): ApplicationRouteIntent => ({
        key: 'initial',
        revision: 0,
        canonicalizing: false,
        scope,
        view: null,
        management: null,
        ...change,
    });
    return { load, accepted, failed, boundary, owner, intent };
}
it('reuses initial public metadata without discovery or touching an owned access', () => {
    const f = fixture();
    f.owner.reconcile(f.intent(), f.boundary);
    expect(f.boundary.reuse).toHaveBeenCalledExactlyOnceWith(true);
    expect(f.load).not.toHaveBeenCalled();
    expect(f.boundary.discover).not.toHaveBeenCalled();
});
it('activates only an exact owned view and checks its management flow before doing so', () => {
    const f = fixture();
    const access = new WebAccess(
        new Http(scope, vi.fn()),
        {
            scope,
            principal: 'Original',
            accessToken: `bwa1.${'A'.repeat(43)}`,
            expiresAt: '2100-01-01T00:00:00Z',
            terminalAvailable: false,
            environment: 'management',
            flow: { name: 'Exact.Flow', title: 'Original' },
        },
        null,
    );
    Object.assign(f.boundary, { views: [{ id: 1, access, scope }] });
    f.owner.reconcile(
        f.intent({ view: 1, management: { managementFlow: 'Exact.Flow', page: 'sessions' } }),
        f.boundary,
    );
    expect(f.boundary.activate).toHaveBeenCalledWith(f.boundary.views[0], {
        managementFlow: 'Exact.Flow',
        page: 'sessions',
    });
    expect(f.load).not.toHaveBeenCalled();
    expect(f.boundary.discover).not.toHaveBeenCalled();
    f.owner.reconcile(
        f.intent({
            key: 'mismatch',
            view: 1,
            management: { managementFlow: 'exact.flow', page: 'sessions' },
        }),
        f.boundary,
    );
    expect(f.boundary.mismatch).toHaveBeenCalledOnce();
    expect(f.boundary.activate).toHaveBeenCalledOnce();
    f.owner.reconcile(
        f.intent({ key: 'different slug', view: 1, scope: { ...scope, slug: 'original' } }),
        f.boundary,
    );
    expect(f.boundary.activate).toHaveBeenCalledOnce();
    expect(f.boundary.discover).toHaveBeenCalledWith({ ...scope, slug: 'original' });
    f.owner.retire();
});
it('normalizes before consuming discovery intent and never retries a failed route without an explicit revision', async () => {
    const f = fixture();
    const selected = { ...scope, slug: 'Other' };
    f.owner.reconcile(f.intent({ scope: selected, canonicalizing: true }), f.boundary);
    expect(f.boundary.discover).not.toHaveBeenCalled();
    f.load.mockRejectedValueOnce(new Error('Discovery failed'));
    f.owner.reconcile(f.intent({ scope: selected }), f.boundary);
    await vi.waitFor(() => expect(f.owner.getSnapshot().phase).toBe('failed'));
    f.owner.reconcile(f.intent({ scope: selected }), f.boundary);
    expect(f.load).toHaveBeenCalledOnce();
    f.owner.reconcile(f.intent({ scope: selected, revision: 1 }), f.boundary);
    await vi.waitFor(() => expect(f.accepted).toHaveBeenCalledOnce());
    expect(f.load).toHaveBeenCalledTimes(2);
});
it('retires stale metadata publications and cannot leave a reset application stuck in routing', async () => {
    const f = fixture();
    const old = Promise.withResolvers<LinkMetadata>();
    const newer = Promise.withResolvers<LinkMetadata>();
    f.load.mockReturnValueOnce(old.promise).mockReturnValueOnce(newer.promise);
    f.owner.reconcile(f.intent({ scope: { ...scope, slug: 'First' } }), f.boundary);
    await vi.waitFor(() => expect(f.load).toHaveBeenCalledOnce());
    f.owner.reconcile(f.intent({ key: 'second', scope: { ...scope, slug: 'Second' } }), f.boundary);
    await vi.waitFor(() => expect(f.load).toHaveBeenCalledTimes(2));
    old.resolve({ ...metadata, scope: { ...scope, slug: 'First' } });
    await old.promise;
    expect(f.accepted).not.toHaveBeenCalled();
    expect(f.owner.getSnapshot().phase).toBe('loading');
    f.owner.retire();
    expect(f.owner.busy).toBe(false);
    expect(f.owner.getSnapshot().phase).toBe('failed');
    newer.resolve({ ...metadata, scope: { ...scope, slug: 'Second' } });
    await newer.promise;
    await Promise.resolve();
    expect(f.accepted).not.toHaveBeenCalled();
});

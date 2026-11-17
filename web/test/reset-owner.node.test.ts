import { expect, it, vi } from 'vitest';
import type { ProfileResetResult } from '../src/application/reset-contracts';
import { ApplicationResetOwner, type ResetBoundary } from '../src/application/reset-owner';

function fixture() {
    const result = { localCleared: true, remoteUnconfirmed: 0, viewsClosed: true };
    const publication = {
        interrupted: false,
        completed: vi.fn(),
        failed: vi.fn(),
        finish: vi.fn(),
    };
    const boundary: ResetBoundary = {
        accesses: [],
        closeViews: vi.fn(() => true),
        local: vi.fn(async () => result),
        peer: vi.fn(async () => result),
        begin: vi.fn(() => publication),
    };
    return { result, publication, boundary, owner: new ApplicationResetOwner() };
}
it('serializes resets and conservatively rejects a simultaneous peer request without starting another cleanup', async () => {
    const f = fixture();
    const pending = Promise.withResolvers<ProfileResetResult>();
    vi.mocked(f.boundary.local).mockReturnValue(pending.promise);
    const local = f.owner.run({ kind: 'local' }, f.boundary);
    expect(await f.owner.run({ kind: 'peer', covered: [] }, f.boundary)).toEqual({
        localCleared: false,
        remoteUnconfirmed: 1,
        viewsClosed: false,
    });
    expect(f.boundary.peer).not.toHaveBeenCalled();
    pending.resolve(f.result);
    await local;
    expect(f.boundary.local).toHaveBeenCalledWith({
        explicitConfirmation: true,
        accesses: [],
        closeViews: f.boundary.closeViews,
    });
    expect(f.publication.finish).toHaveBeenCalledOnce();
    expect(f.owner.busy).toBe(false);
});
it('adds interruption uncertainty only to the peer receipt and does not misreport a failed peer as completed', async () => {
    const f = fixture();
    f.publication.interrupted = true;
    expect(
        (await f.owner.run({ kind: 'peer', covered: ['opaque-selector-hash'] }, f.boundary))
            .remoteUnconfirmed,
    ).toBe(1);
    vi.mocked(f.boundary.peer).mockRejectedValue(new Error('Failed peer cleanup'));
    await expect(f.owner.run({ kind: 'peer', covered: [] }, f.boundary)).rejects.toThrow(
        'Failed peer cleanup',
    );
    expect(f.publication.completed).toHaveBeenCalledOnce();
    expect(f.owner.busy).toBe(false);
});

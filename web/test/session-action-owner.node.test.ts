import { expect, it, vi } from 'vitest';
import { SessionActionConfirmation } from '../src/management/action';
import {
    type SessionActionBoundary,
    SessionActionOwner,
} from '../src/management/session-action-owner';

const target = { flow: 'Exact.Flow', id: '7Xng23oeg4L1zHaZfeX6wB' };
const preview = { action: 'disconnect' as const, target, expiresAt: '2100-01-01T00:00:00Z' };
function fixture() {
    let available = true;
    const commit = vi.fn(async () => ({ action: preview.action, ...target }));
    const cancel = vi.fn(async () => {});
    const handle = new SessionActionConfirmation(preview, commit, cancel);
    const prepareSessionAction = vi.fn(async () => handle);
    const boundary: SessionActionBoundary = {
        canPrepare: () => available,
        canConfirm: () => available,
        lock: vi.fn(),
        dispatched: vi.fn(),
        settled: vi.fn(),
        failed: vi.fn(),
    };
    const owner = new SessionActionOwner({ prepareSessionAction }, () => boundary);
    const unmount = owner.mount();
    return {
        owner,
        unmount,
        commit,
        cancel,
        prepareSessionAction,
        boundary,
        unavailable: () => {
            available = false;
        },
    };
}
it('requires the exact typed selector and current permission before dispatching once', async () => {
    const f = fixture();
    await f.owner.prepare('disconnect', target);
    await f.owner.confirm(`${target.flow.toLowerCase()}/${target.id}`);
    expect(f.commit).not.toHaveBeenCalled();
    await f.owner.confirm(`${target.flow}/${target.id}`);
    await f.owner.confirm(`${target.flow}/${target.id}`);
    expect(f.commit).toHaveBeenCalledOnce();
    expect(f.owner.getSnapshot().phase).toBe('confirmed');
    expect(f.boundary.lock).toHaveBeenLastCalledWith(false);
    f.unmount();
    expect(f.cancel).not.toHaveBeenCalled();
});
it('retains unknown outcomes and their owner lock until explicit dismissal, without replay or cancel', async () => {
    const f = fixture();
    f.commit.mockRejectedValue(new Error('lost reply'));
    await f.owner.prepare('disconnect', target);
    await f.owner.confirm(`${target.flow}/${target.id}`);
    expect(f.owner.getSnapshot()).toEqual({ phase: 'unknown', preview });
    expect(f.boundary.lock).toHaveBeenLastCalledWith(true);
    f.owner.cancelPreparation();
    await f.owner.prepare('dispose', target);
    expect(f.prepareSessionAction).toHaveBeenCalledOnce();
    expect(f.cancel).not.toHaveBeenCalled();
    f.owner.dismissUnknown();
    expect(f.owner.getSnapshot().phase).toBe('idle');
    expect(f.boundary.lock).toHaveBeenLastCalledWith(false);
    f.unmount();
});
it('retires a hidden preparation and cancels its late exact handle, never publishing it to a different view', async () => {
    const f = fixture();
    const ready = Promise.withResolvers<SessionActionConfirmation>();
    f.prepareSessionAction.mockReturnValue(ready.promise);
    const preparing = f.owner.prepare('disconnect', target);
    f.owner.cancelPreparation();
    ready.resolve(new SessionActionConfirmation(preview, f.commit, f.cancel));
    await preparing;
    expect(f.owner.getSnapshot().phase).toBe('idle');
    expect(f.cancel).toHaveBeenCalledOnce();
    expect(f.commit).not.toHaveBeenCalled();
    f.unmount();
});
it('keeps stop-waiting unknown even after a late successful response and never treats it as undo', async () => {
    const f = fixture();
    const result = Promise.withResolvers<{ action: 'disconnect'; flow: string; id: string }>();
    f.commit.mockReturnValue(result.promise);
    await f.owner.prepare('disconnect', target);
    const confirmation = f.owner.confirm(`${target.flow}/${target.id}`);
    f.owner.stopWaiting();
    expect(f.owner.getSnapshot().phase).toBe('unknown');
    result.resolve({ action: 'disconnect', ...target });
    await confirmation;
    expect(f.owner.getSnapshot().phase).toBe('unknown');
    expect(f.boundary.settled).toHaveBeenCalledOnce();
    expect(f.boundary.lock).toHaveBeenLastCalledWith(true);
    expect(f.cancel).not.toHaveBeenCalled();
    f.unmount();
});
it('rechecks a new guard before confirmation and cancels only unused preparations at retirement', async () => {
    const f = fixture();
    await f.owner.prepare('disconnect', target);
    f.unavailable();
    await f.owner.confirm(`${target.flow}/${target.id}`);
    expect(f.commit).not.toHaveBeenCalled();
    f.unmount();
    expect(f.cancel).toHaveBeenCalledOnce();
});

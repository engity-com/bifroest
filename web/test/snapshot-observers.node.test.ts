import { expect, it, vi } from 'vitest';
import { EvidenceJob } from '../src/artifacts/evidence-job';
import { SnapshotObservers } from '../src/shared/snapshot-observers';

it('uses a stable notification inventory and excludes subscribers removed during notification', () => {
    const observers = new SnapshotObservers();
    const later = vi.fn();
    const removed = vi.fn();
    let added = false;
    let unsubscribe = () => {};
    observers.subscribe(() => {
        unsubscribe();
        if (!added) {
            added = true;
            observers.subscribe(later);
        }
    });
    unsubscribe = observers.subscribe(removed);
    observers.notify();
    expect(removed).not.toHaveBeenCalled();
    expect(later).not.toHaveBeenCalled();
    observers.notify();
    expect(later).toHaveBeenCalledOnce();
});
it('does not let observers or a broken diagnostic sink prevent evidence execution/cleanup', async () => {
    const diagnostics = vi.spyOn(console, 'error').mockImplementation(() => {
        throw new Error('DIAGNOSTIC-FAILURE');
    });
    try {
        const job = new EvidenceJob();
        const operation = vi.fn(async () => {});
        const cleanup = vi.fn();
        job.subscribe(() => {
            throw new Error('PRIVATE-OBSERVER-FAILURE');
        });
        await job.run('verifying', operation, vi.fn(), cleanup);
        await job.run('verifying', operation, vi.fn(), cleanup);
        expect(operation).toHaveBeenCalledTimes(2);
        expect(cleanup).toHaveBeenCalledTimes(2);
        expect(job.busy).toBe(false);
        expect(job.getSnapshot().phase).toBeNull();
    } finally {
        diagnostics.mockRestore();
    }
});

import { expect, it, vi } from 'vitest';
import { EvidenceJob } from '../src/artifacts/evidence-job';
import type { PlaybackImage } from '../src/artifacts/playback-protocol';
import { PreparedPlayback } from '../src/artifacts/prepared-playback';
import { CursorPages } from '../src/shared/cursor-pages';
import type { OperationLease } from '../src/shared/operation';
import { OperationSlot } from '../src/shared/operation';

it('retires an operation before abort observers run, and stale completion cannot free its replacement', () => {
    const slot = new OperationSlot();
    const first = slot.start();
    if (!first) {
        throw new Error('Missing first lease');
    }
    expect(slot.start()).toBeNull();
    first.signal.addEventListener('abort', () => expect(first.owned()).toBe(false));
    slot.retire();
    const replacement = slot.start();
    if (!replacement) {
        throw new Error('Missing replacement');
    }
    first.finish();
    expect(slot.busy).toBe(true);
    expect(replacement.current()).toBe(true);
    slot.cancel();
    expect(replacement.current()).toBe(false);
    expect(replacement.owned()).toBe(true);
    replacement.finish();
    expect(slot.busy).toBe(false);
});
it('invalidates future cursors when an earlier page completes again and rejects invented page numbers', () => {
    const pages = new CursorPages();
    pages.completed(0, 'first');
    pages.completed(1, 'second');
    expect(pages.at(2)).toBe('second');
    pages.completed(0, 'replacement');
    expect(pages.at(1)).toBe('replacement');
    expect(pages.at(2)).toBeUndefined();
    expect(() => pages.completed(5, 'invented')).toThrow();
    expect(pages.at(-1)).toBeUndefined();
    pages.reset();
    expect(pages.at(0)).toBe('');
    expect(pages.at(1)).toBeUndefined();
});
it('does not let a retired evidence task change the stage, report a failure or clean up its successor', async () => {
    const job = new EvidenceJob();
    const pending = Promise.withResolvers<void>();
    const failure = vi.fn();
    const cleanup = vi.fn();
    const old = job.run(
        'downloading',
        async (_lease, stage) => {
            await pending.promise;
            stage('verifying');
            throw new Error('stale');
        },
        failure,
        cleanup,
    );
    job.retire();
    const next = Promise.withResolvers<void>();
    const current = job.run('preparing', () => next.promise, failure, cleanup);
    pending.resolve();
    await old;
    expect(job.getSnapshot().phase).toBe('preparing');
    expect(failure).not.toHaveBeenCalled();
    expect(cleanup).not.toHaveBeenCalled();
    next.resolve();
    await current;
    expect(job.getSnapshot().phase).toBeNull();
    expect(cleanup).toHaveBeenCalledOnce();
});
it('transfers a prepared image once and never disposes a renderer-owned image from parent cleanup', () => {
    const dispose = vi.fn();
    const image = { dispose } as unknown as PlaybackImage;
    const preparation = new PreparedPlayback(image);
    expect(preparation.take()).toBe(image);
    preparation.dispose();
    expect(dispose).not.toHaveBeenCalled();
    expect(() => preparation.take()).toThrow();
    const abandoned = new PreparedPlayback(image);
    abandoned.dispose();
    abandoned.dispose();
    expect(dispose).toHaveBeenCalledOnce();
});

it('binds progress to its operation lease instead of accepting an older worker update', async () => {
    const job = new EvidenceJob();
    let oldLease: OperationLease | undefined;
    const first = Promise.withResolvers<void>();
    const old = job.run(
        'downloading',
        async (lease) => {
            oldLease = lease;
            await first.promise;
        },
        vi.fn(),
        vi.fn(),
    );
    job.retire();
    const second = Promise.withResolvers<void>();
    const next = job.run('preparing', () => second.promise, vi.fn(), vi.fn());
    if (!oldLease) {
        throw new Error('Missing old lease');
    }
    job.progress(oldLease, { phase: 'verifying', completed: 1, total: 1 });
    expect(job.getSnapshot()).toEqual({ phase: 'preparing', progress: null });
    first.resolve();
    second.resolve();
    await Promise.all([old, next]);
});
it('cannot clear a replacement started synchronously by cleanup or an abort observer', async () => {
    const job = new EvidenceJob();
    const pending = Promise.withResolvers<void>();
    let replacement: Promise<void> | undefined;
    await job.run(
        'verifying',
        async () => {},
        vi.fn(),
        () => {
            job.retire();
            replacement = job.run('preparing', () => pending.promise, vi.fn(), vi.fn());
        },
    );
    expect(job.getSnapshot().phase).toBe('preparing');
    pending.resolve();
    await replacement;
    const stopped = Promise.withResolvers<void>();
    const newer = Promise.withResolvers<void>();
    const old = job.run(
        'downloading',
        async (lease) => {
            lease.signal.addEventListener('abort', () => {
                replacement = job.run('inspecting', () => newer.promise, vi.fn(), vi.fn());
            });
            await stopped.promise;
        },
        vi.fn(),
        vi.fn(),
    );
    job.retire();
    expect(job.getSnapshot().phase).toBe('inspecting');
    stopped.resolve();
    newer.resolve();
    await old;
    await replacement;
});

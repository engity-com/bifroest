import { afterEach, describe, expect, it, vi } from 'vitest';
import { initializePlaybackCursor } from '../src/artifacts/playback-cursor';

afterEach(() => vi.useRealTimers());
describe('read-only playback cursor initialization before scheduler ownership', () => {
    it('drains one public presentation command without focus or input callbacks', async () => {
        let drained: (() => void) | undefined;
        const write = vi.fn((_bytes: string | Uint8Array, done?: () => void) => {
            drained = done;
        });
        const controller = new AbortController();
        let settled = false;
        const pending = initializePlaybackCursor({ write }, controller.signal).then(() => {
            settled = true;
        });
        expect(write).toHaveBeenCalledWith('\x1b[?47l\x1b[?25h', expect.any(Function));
        expect(settled).toBe(false);
        drained?.();
        await pending;
        expect(settled).toBe(true);
        expect(write).toHaveBeenCalledOnce();
    });
    it('rejects cancellation and ignores a late renderer completion', async () => {
        let drained: (() => void) | undefined;
        const controller = new AbortController();
        const pending = initializePlaybackCursor(
            {
                write: (_data, done) => {
                    drained = done;
                },
            },
            controller.signal,
        );
        controller.abort();
        await expect(pending).rejects.toMatchObject({ code: 'cancelled' });
        drained?.();
        const write = vi.fn();
        await expect(initializePlaybackCursor({ write }, controller.signal)).rejects.toMatchObject({
            code: 'cancelled',
        });
        expect(write).not.toHaveBeenCalled();
    });
    it('keeps the existing five-second drain bound and does not hide renderer throws', async () => {
        vi.useFakeTimers();
        const pending = initializePlaybackCursor({ write() {} }, new AbortController().signal);
        const failed = expect(pending).rejects.toMatchObject({ code: 'unavailable' });
        await vi.advanceTimersByTimeAsync(5000);
        await failed;
        await expect(
            initializePlaybackCursor(
                {
                    write(_data, done) {
                        done?.();
                        throw new Error('renderer failed');
                    },
                },
                new AbortController().signal,
            ),
        ).rejects.toMatchObject({ code: 'unavailable' });
    });
});

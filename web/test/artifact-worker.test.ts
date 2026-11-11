import { afterEach, describe, expect, it, vi } from 'vitest';
import { transferMediaType } from '../src/artifacts/protocol';
import { receiveArtifact } from '../src/artifacts/receive';
import { required } from './required';

const request = {
    kind: 'recording',
    auditlog: 'default',
    id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
} as const;

class ArtifactWorker extends EventTarget {
    static instances: ArtifactWorker[] = [];
    static hold = false;
    static failure: 'too-large' | 'unavailable' | null = null;
    static wrongID = false;
    static bootFailure = false;
    terminated = false;
    requests: unknown[] = [];

    constructor(url: string, options: WorkerOptions) {
        super();
        expect(url).toBe('/_bifroest/files/browser-transfer-worker.js');
        expect(options).toMatchObject({ type: 'module', credentials: 'omit' });
        ArtifactWorker.instances.push(this);
        queueMicrotask(() =>
            this.send(
                ArtifactWorker.bootFailure
                    ? { kind: 'failed', reason: 'unavailable' }
                    : { kind: 'ready' },
            ),
        );
    }

    postMessage(value: unknown, transfer: Transferable[]) {
        this.requests.push(value);
        structuredClone(value, { transfer });
        if (ArtifactWorker.hold) {
            return;
        }
        queueMicrotask(() => {
            if (ArtifactWorker.failure !== null) {
                this.send({ kind: 'failed', reason: ArtifactWorker.failure });
                return;
            }
            this.send({
                kind: 'received',
                metadata: {
                    Version: 1,
                    ID: ArtifactWorker.wrongID
                        ? '6d05798f-b877-4191-8aa0-4576a30411ad'
                        : request.id,
                    ProducerID: 'a'.repeat(64),
                    Size: 3,
                    SHA256: 'b'.repeat(64),
                },
                files: [{ name: 'recording', data: new Blob([new Uint8Array([1, 2, 3])]) }],
            });
        });
    }

    send(value: unknown) {
        if (!this.terminated) {
            this.dispatchEvent(new MessageEvent('message', { data: value }));
        }
    }

    terminate() {
        this.terminated = true;
    }
}

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
    ArtifactWorker.instances = [];
    ArtifactWorker.hold = false;
    ArtifactWorker.failure = null;
    ArtifactWorker.wrongID = false;
    ArtifactWorker.bootFailure = false;
});

function install() {
    vi.stubGlobal('Worker', ArtifactWorker);
}

describe('owned artifact worker RPC lifecycle (not framing/evidence verification)', () => {
    it('retires a failed startup without opening an artifact response or retrying the worker', async () => {
        install();
        ArtifactWorker.bootFailure = true;
        const open = vi.fn(async () => ({
            bytes: new ArrayBuffer(0),
            mediaType: transferMediaType,
            status: 200,
        }));
        await expect(
            receiveArtifact(request, open, new AbortController().signal),
        ).rejects.toMatchObject({ code: 'unavailable' });
        expect(open).not.toHaveBeenCalled();
        expect(ArtifactWorker.instances).toHaveLength(1);
        const worker = required(ArtifactWorker.instances[0]);
        expect(worker.terminated).toBe(true);
        expect(worker.requests).toHaveLength(0);
    });

    it('transfers the response once and releases only transport-complete unverified immutable Blobs', async () => {
        install();
        const bytes = new Uint8Array([1, 2, 3]).buffer;
        const open = vi.fn(async () => ({ bytes, mediaType: transferMediaType, status: 200 }));
        const result = await receiveArtifact(request, open, new AbortController().signal);
        expect(open).toHaveBeenCalledTimes(1);
        expect(bytes.byteLength).toBe(0);
        expect(result).toMatchObject({ request, transport: 'complete', evidence: 'unverified' });
        expect(await required(result.files[0]).data.text()).toBe('\u0001\u0002\u0003');
        const worker = required(ArtifactWorker.instances[0]);
        expect(worker.terminated).toBe(true);
        expect(worker.requests).toHaveLength(1);
        expect(JSON.stringify(worker.requests)).not.toContain('bwa1.');
        expect(Object.isFrozen(result)).toBe(true);
        expect(Object.isFrozen(result.files)).toBe(true);
    });

    it('joins the opening adapter on abort and discards late response images before returning', async () => {
        install();
        const controller = new AbortController();
        let entered: (() => void) | undefined;
        const opening = new Promise<void>((resolve) => {
            entered = resolve;
        });
        let release: (() => void) | undefined;
        const cleanup = new Promise<void>((resolve) => {
            release = resolve;
        });
        const bytes = new Uint8Array([1, 2, 3]).buffer;
        const operation = receiveArtifact(
            request,
            async (signal) => {
                entered?.();
                await new Promise<void>((resolve) =>
                    signal.addEventListener('abort', () => resolve(), { once: true }),
                );
                await cleanup;
                return { bytes, mediaType: transferMediaType, status: 200 };
            },
            controller.signal,
        );
        let done = false;
        const observed = expect(
            operation.finally(() => {
                done = true;
            }),
        ).rejects.toMatchObject({ code: 'cancelled' });
        await opening;
        controller.abort();
        expect(done).toBe(false);
        release?.();
        await observed;
        expect([...new Uint8Array(bytes)]).toEqual([0, 0, 0]);
        expect(required(ArtifactWorker.instances[0]).terminated).toBe(true);
    });

    it('discards parser failure and exposes only an explicit local limit reason', async () => {
        install();
        for (const reason of ['unavailable', 'too-large'] as const) {
            ArtifactWorker.failure = reason;
            await expect(
                receiveArtifact(
                    request,
                    async () => ({
                        bytes: new Uint8Array([1]).buffer,
                        mediaType: transferMediaType,
                        status: 200,
                    }),
                    new AbortController().signal,
                ),
            ).rejects.toMatchObject({
                code: reason === 'too-large' ? 'artifact-too-large' : 'unavailable',
            });
            expect(required(ArtifactWorker.instances.at(-1)).terminated).toBe(true);
        }
    });

    it('retires a non-answering worker on caller abort without publishing buffered data', async () => {
        install();
        ArtifactWorker.hold = true;
        const controller = new AbortController();
        const operation = receiveArtifact(
            request,
            async () => ({
                bytes: new Uint8Array([1]).buffer,
                mediaType: transferMediaType,
                status: 200,
            }),
            controller.signal,
        );
        const observed = expect(operation).rejects.toMatchObject({ code: 'cancelled' });
        await vi.waitFor(() => expect(ArtifactWorker.instances[0]?.requests.length).toBe(1));
        controller.abort();
        await observed;
        expect(required(ArtifactWorker.instances[0]).terminated).toBe(true);
    });

    it('rejects a worker selector mismatch and terminates without returning a Blob', async () => {
        install();
        ArtifactWorker.wrongID = true;
        await expect(
            receiveArtifact(
                request,
                async () => ({
                    bytes: new Uint8Array([1]).buffer,
                    mediaType: transferMediaType,
                    status: 200,
                }),
                new AbortController().signal,
            ),
        ).rejects.toMatchObject({ code: 'unavailable' });
        expect(required(ArtifactWorker.instances[0]).terminated).toBe(true);
    });

    it('keeps a slow decoder alive beyond the former total deadline and cancels it explicitly without replay or partial output', async () => {
        install();
        ArtifactWorker.hold = true;
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
            const controller = new AbortController();
            setTimeout(() => controller.abort(), milliseconds);
            return controller.signal;
        });
        const open = vi.fn(async () => ({
            bytes: new Uint8Array([1]).buffer,
            mediaType: transferMediaType,
            status: 200,
        }));
        const controller = new AbortController();
        let settled = false;
        const operation = receiveArtifact(request, open, controller.signal);
        const observed = expect(
            operation.finally(() => {
                settled = true;
            }),
        ).rejects.toMatchObject({ code: 'cancelled' });
        await vi.waitFor(() => expect(ArtifactWorker.instances[0]?.requests.length).toBe(1));
        await vi.advanceTimersByTimeAsync(120_001);
        expect(settled).toBe(false);
        expect(required(ArtifactWorker.instances[0]).terminated).toBe(false);
        controller.abort();
        await observed;
        expect(open).toHaveBeenCalledTimes(1);
        expect(required(ArtifactWorker.instances[0]).requests).toHaveLength(1);
        expect(required(ArtifactWorker.instances[0]).terminated).toBe(true);
    });
});

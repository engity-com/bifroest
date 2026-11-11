import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceOptions } from '../src/artifacts/evidence-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import {
    createRecordingRuntime,
    createRecordingVerificationBatch,
    verifyArtifact,
} from '../src/artifacts/verify';
import { required } from './required';

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const artifact: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'default', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'b'.repeat(64), Size: 3, SHA256: 'c'.repeat(64) },
    files: [{ name: 'recording', data: new Blob([new Uint8Array([1, 2, 3])]) }],
};
const options: EvidenceOptions = {
    producer: 'a'.repeat(64),
    allowUntrusted: false,
    recipient: '',
    level: 'private',
    export: true,
    sensitive: false,
    auditScope: '',
};

class EvidenceWorker extends EventTarget {
    static instances: EvidenceWorker[] = [];
    static hold = false;
    static badProducer = false;
    static failure: 'key' | 'verification' | null = null;
    static bootFailure: 'module-fetch' | 'module-decode' | 'runtime' | null = null;
    terminated = false;
    requests: Record<string, unknown>[] = [];

    constructor(url: string, config: WorkerOptions) {
        super();
        expect(url).toBe('/_bifroest/files/browser-evidence-worker.js');
        expect(config).toMatchObject({ type: 'module', credentials: 'omit' });
        EvidenceWorker.instances.push(this);
        queueMicrotask(() =>
            this.send(
                EvidenceWorker.bootFailure
                    ? { kind: 'failed', code: EvidenceWorker.bootFailure }
                    : { kind: 'ready' },
            ),
        );
    }
    send(value: unknown) {
        if (!this.terminated) {
            this.dispatchEvent(new MessageEvent('message', { data: value }));
        }
    }
    postMessage(value: Record<string, unknown>, transfer: Transferable[]) {
        this.requests.push(value);
        const body = structuredClone(value, { transfer });
        if (body.kind === 'batch-init' || body.kind === 'recording-init') {
            queueMicrotask(() => this.send({ kind: 'batch-ready' }));
            return;
        }
        if (EvidenceWorker.hold) {
            return;
        }
        queueMicrotask(() => {
            if (EvidenceWorker.failure !== null) {
                this.send({ kind: 'failed', code: EvidenceWorker.failure });
                return;
            }
            const input = body.options as EvidenceOptions;
            this.send({
                kind: 'verified',
                metadata: {
                    kind: 'recording',
                    validation: input.level,
                    trust: input.producer === '' ? 'untrusted' : 'pinned',
                    producer: EvidenceWorker.badProducer
                        ? 'b'.repeat(64)
                        : input.producer || 'a'.repeat(64),
                    expectedRecipient: input.recipient,
                    decryption: input.recipient === '' ? 'not-encrypted' : 'authenticated',
                    recordingId: id,
                    auditScope: '',
                    records: '0',
                    privateRecords: '0',
                    outputFormat: input.export ? 'cast' : '',
                },
                output: new Blob(input.export ? ['verified cast'] : []),
            });
        });
    }
    terminate() {
        this.terminated = true;
    }
}

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
    EvidenceWorker.instances = [];
    EvidenceWorker.hold = false;
    EvidenceWorker.badProducer = false;
    EvidenceWorker.failure = null;
    EvidenceWorker.bootFailure = null;
});

describe('owned evidence worker RPC (not cryptographic fixture verification)', () => {
    it('retires an idle runtime failure without reconnecting or replaying a previous request', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        const runtime = await createRecordingRuntime('default', id, new AbortController().signal);
        const worker = required(EvidenceWorker.instances[0]);
        worker.send({ kind: 'failed', code: 'runtime' });
        expect(runtime.available()).toBe(false);
        expect(worker.terminated).toBe(true);
        await expect(runtime.verify(artifact, options, null)).rejects.toMatchObject({
            code: 'cancelled',
        });
        expect(worker.requests).toHaveLength(1);
        expect(EvidenceWorker.instances).toHaveLength(1);
    });
    it('keeps one file-bound runtime after a failed pin but rechecks every explicit attempt', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        const runtime = await createRecordingRuntime('default', id, new AbortController().signal);
        await runtime.verify(artifact, options, null);
        EvidenceWorker.failure = 'verification';
        await expect(runtime.verify(artifact, options, null)).rejects.toMatchObject({
            code: 'verification',
        });
        expect(runtime.available()).toBe(true);
        EvidenceWorker.failure = null;
        await runtime.verify(artifact, options, null);
        expect(EvidenceWorker.instances).toHaveLength(1);
        expect(EvidenceWorker.instances[0]?.requests.map((request) => request.kind)).toEqual([
            'recording-init',
            'verify',
            'verify',
            'verify',
        ]);
        runtime.dispose();
        expect(runtime.available()).toBe(false);
    });
    it('cannot rebind a file runtime to another ID or survive an operation cancellation', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        const runtime = await createRecordingRuntime('default', id, new AbortController().signal);
        await expect(
            runtime.verify(
                {
                    ...artifact,
                    request: {
                        kind: 'recording',
                        auditlog: 'default',
                        id: '6d05798f-b877-4191-8aa0-4576a30411ad',
                    },
                },
                options,
                null,
            ),
        ).rejects.toMatchObject({ code: 'input' });
        expect(EvidenceWorker.instances[0]?.requests).toHaveLength(1);
        expect(runtime.available()).toBe(false);
        const current = await createRecordingRuntime('default', id, new AbortController().signal);
        EvidenceWorker.hold = true;
        const stopped = new AbortController();
        const pending = current.verify(artifact, options, null, undefined, stopped.signal);
        const observed = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
        await vi.waitFor(() => expect(EvidenceWorker.instances[1]?.requests).toHaveLength(2));
        stopped.abort();
        await observed;
        expect(current.available()).toBe(false);
        expect(EvidenceWorker.instances).toHaveLength(2);
    });
    it('reuses only one source-bound runtime while issuing a fresh full RPC for every recording', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        const batch = await createRecordingVerificationBatch(
            'default',
            new AbortController().signal,
        );
        const first = await batch.verify(artifact, { ...options, export: false }, null);
        const second = await batch.verify(artifact, { ...options, export: false }, null);
        expect(first.output).toBeNull();
        expect(second.output).toBeNull();
        expect(EvidenceWorker.instances).toHaveLength(1);
        const worker = required(EvidenceWorker.instances[0]);
        expect(worker.requests.map((request) => request.kind)).toEqual([
            'batch-init',
            'verify',
            'verify',
        ]);
        expect(worker.terminated).toBe(false);
        batch.dispose();
        expect(worker.terminated).toBe(true);
        await expect(
            batch.verify(artifact, { ...options, export: false }, null),
        ).rejects.toMatchObject({ code: 'cancelled' });
        expect(EvidenceWorker.instances).toHaveLength(1);
    });
    it.each(['source', 'export'] as const)(
        'rejects an incompatible batch %s before transferring recording or key bytes',
        async (scenario) => {
            vi.stubGlobal('Worker', EvidenceWorker);
            const batch = await createRecordingVerificationBatch(
                'default',
                new AbortController().signal,
            );
            const image =
                scenario === 'source'
                    ? { ...artifact, request: { ...artifact.request, auditlog: 'other' } }
                    : artifact;
            await expect(
                batch.verify(image, { ...options, export: scenario === 'export' }, null),
            ).rejects.toMatchObject({ code: 'input' });
            const worker = required(EvidenceWorker.instances[0]);
            expect(worker.requests).toHaveLength(1);
            expect(worker.terminated).toBe(true);
        },
    );
    it.each(['module-fetch', 'module-decode', 'runtime'] as const)(
        'reports %s without transferring keys, retrying, or claiming a signature failure',
        async (code) => {
            vi.stubGlobal('Worker', EvidenceWorker);
            EvidenceWorker.bootFailure = code;
            await expect(
                verifyArtifact(artifact, options, null, new AbortController().signal),
            ).rejects.toMatchObject({ code });
            expect(EvidenceWorker.instances).toHaveLength(1);
            expect(EvidenceWorker.instances[0]?.requests).toHaveLength(0);
            expect(EvidenceWorker.instances[0]?.terminated).toBe(true);
        },
    );
    it('uses caller pins rather than untrusted transport hints and retires before returning output', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        const result = await verifyArtifact(artifact, options, null, new AbortController().signal);
        expect(result.metadata.producer).toBe(options.producer);
        expect(result.metadata.producer).not.toBe('b'.repeat(64));
        expect(result.provenance).toBe('bytes-only');
        expect(await result.output?.text()).toBe('verified cast');
        const worker = required(EvidenceWorker.instances[0]);
        expect(worker.terminated).toBe(true);
        expect(worker.requests).toHaveLength(1);
        expect(JSON.stringify(worker.requests)).not.toContain('bwa1.');
        expect(Object.isFrozen(result)).toBe(true);
    });

    it('rejects missing independent pins, incomplete transport and unwanted keys before any worker', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        for (const input of [
            { artifact, options: { ...options, producer: '' }, key: null },
            { artifact: { ...artifact, transport: 'data-end' }, options, key: null },
            { artifact, options: { ...options, level: 'outer' }, key: null },
            { artifact, options, key: { file: new File(['key'], 'private'), passphrase: '' } },
        ]) {
            await expect(
                verifyArtifact(
                    input.artifact as ReceivedArtifact,
                    input.options as EvidenceOptions,
                    input.key,
                    new AbortController().signal,
                ),
            ).rejects.toMatchObject({ code: 'input' });
        }
        expect(EvidenceWorker.instances).toHaveLength(0);
    });

    it('keeps explicit untrusted state distinct and never promotes a worker producer mismatch', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        const untrusted = await verifyArtifact(
            artifact,
            { ...options, producer: '', allowUntrusted: true },
            null,
            new AbortController().signal,
        );
        expect(untrusted.metadata.trust).toBe('untrusted');
        EvidenceWorker.badProducer = true;
        await expect(
            verifyArtifact(artifact, options, null, new AbortController().signal),
        ).rejects.toMatchObject({ code: 'verification' });
        expect(required(EvidenceWorker.instances.at(-1)).terminated).toBe(true);
    });

    it('transfers local key buffers only to the evidence worker and reports no parser diagnostics', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        EvidenceWorker.failure = 'key';
        await expect(
            verifyArtifact(
                artifact,
                { ...options, recipient: `SHA256:${'A'.repeat(43)}` },
                {
                    file: new File(['private tab bytes'], 'never-uploaded-key'),
                    passphrase: 'private tab password',
                },
                new AbortController().signal,
            ),
        ).rejects.toMatchObject({ code: 'key' });
        const worker = required(EvidenceWorker.instances[0]);
        const request = required(worker.requests[0]);
        expect((request.privateKey as ArrayBuffer).byteLength).toBe(0);
        expect((request.passphrase as ArrayBuffer).byteLength).toBe(0);
        expect(JSON.stringify(request)).not.toContain('private tab password');
        expect(JSON.stringify(request)).not.toContain('never-uploaded-key');
        expect(worker.terminated).toBe(true);
    });

    it('cancels a pending local key read and never starts verification with partial private input', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        let entered: (() => void) | undefined;
        const reading = new Promise<void>((resolve) => {
            entered = resolve;
        });
        let aborted = false;
        class HeldReader {
            onload = null;
            onerror = null;
            onabort = null;
            result = null;
            readAsArrayBuffer() {
                entered?.();
            }
            abort() {
                aborted = true;
            }
        }
        vi.stubGlobal('FileReader', HeldReader);
        const controller = new AbortController();
        const operation = verifyArtifact(
            artifact,
            { ...options, recipient: `SHA256:${'A'.repeat(43)}` },
            { file: new File(['key'], 'private'), passphrase: 'secret' },
            controller.signal,
        );
        const observed = expect(operation).rejects.toMatchObject({ code: 'cancelled' });
        await reading;
        controller.abort();
        await observed;
        expect(aborted).toBe(true);
        expect(required(EvidenceWorker.instances[0]).requests).toHaveLength(0);
        expect(required(EvidenceWorker.instances[0]).terminated).toBe(true);
    });

    it('keeps local verification alive beyond the former total deadline and cancels its owned worker without releasing a Blob', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        EvidenceWorker.hold = true;
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
            const controller = new AbortController();
            setTimeout(() => controller.abort(), milliseconds);
            return controller.signal;
        });
        const controller = new AbortController();
        let settled = false;
        const progress = vi.fn();
        const operation = verifyArtifact(artifact, options, null, controller.signal, progress);
        const observed = expect(
            operation.finally(() => {
                settled = true;
            }),
        ).rejects.toMatchObject({ code: 'cancelled' });
        await vi.waitFor(() => expect(EvidenceWorker.instances[0]?.requests.length).toBe(1));
        await vi.advanceTimersByTimeAsync(120_001);
        const worker = required(EvidenceWorker.instances[0]);
        worker.send({ kind: 'progress', phase: 'integrity', completed: 64, total: -1 });
        expect(progress).toHaveBeenCalledExactlyOnceWith({
            phase: 'integrity',
            completed: 64,
            total: -1,
        });
        expect(settled).toBe(false);
        expect(worker.terminated).toBe(false);
        expect(worker.requests).toHaveLength(1);
        controller.abort();
        await observed;
        expect(required(EvidenceWorker.instances[0]).terminated).toBe(true);
    });
    it('rejects worker progress containing private fields rather than exposing a diagnostic or releasing output', async () => {
        vi.stubGlobal('Worker', EvidenceWorker);
        EvidenceWorker.hold = true;
        const progress = vi.fn();
        const operation = verifyArtifact(
            artifact,
            options,
            null,
            new AbortController().signal,
            progress,
        );
        const observed = expect(operation).rejects.toMatchObject({ code: 'protocol' });
        await vi.waitFor(() => expect(EvidenceWorker.instances[0]?.requests.length).toBe(1));
        required(EvidenceWorker.instances[0]).send({
            kind: 'progress',
            phase: 'integrity',
            completed: 1,
            total: 2,
            privateKey: 'must-not-escape',
        });
        await observed;
        expect(progress).not.toHaveBeenCalled();
        expect(required(EvidenceWorker.instances[0]).terminated).toBe(true);
    });
});

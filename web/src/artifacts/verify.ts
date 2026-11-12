import type { ProgressListener } from '../management/progress';
import { type ArtifactResponseImage, object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import { uuidEqual } from '../shared/uuid';
import { readLocalBytes } from '../wasm/local-file';
import type { EvidenceOptions, VerifiedArtifact } from './evidence-protocol';
import { EvidenceError, evidenceMetadata, evidenceOptions } from './evidence-protocol';
import { evidenceRPC } from './evidence-rpc';

export { evidenceRPC } from './evidence-rpc';

import { expectedFiles, transferMetadata } from './metadata';
import { openRecordingWithWorker, type RecordingInfo } from './open-recording';
import type { PlaybackImage } from './playback-protocol';
import type { ArtifactRequest, ReceivedArtifact } from './protocol';
import {
    artifactFields,
    maximumBufferedArtifactBytes,
    maximumTransferImageBytes,
    transferMediaType,
} from './protocol';

export interface EvidenceKey {
    readonly file: Blob;
    readonly passphrase: string;
}

// Only immutable completed transport Blobs and local key bytes enter this owned
// worker. No bearer, URL or server operation is accepted by the evidence RPC.
export async function verifyArtifact(
    artifact: ReceivedArtifact,
    requested: EvidenceOptions,
    key: EvidenceKey | null,
    signal: AbortSignal,
    progress?: ProgressListener,
): Promise<VerifiedArtifact> {
    return verifyArtifactImage(artifact, requested, key, signal, progress);
}

async function verifyArtifactImage(
    artifact: ReceivedArtifact,
    requested: EvidenceOptions,
    key: EvidenceKey | null,
    signal: AbortSignal,
    progress?: ProgressListener,
    session?: { worker: Worker; source: string; recordingID?: string },
): Promise<VerifiedArtifact> {
    let request: ArtifactRequest;
    let files: ReceivedArtifact['files'];
    let options: EvidenceOptions;
    try {
        const value = object(artifact, ['request', 'transport', 'evidence', 'metadata', 'files']);
        request = Object.freeze({ ...artifact.request }) as ArtifactRequest;
        artifactFields(request);
        options = evidenceOptions(request, requested);
        if (
            session &&
            (request.kind !== 'recording' ||
                request.auditlog !== session.source ||
                (!session.recordingID && options.export) ||
                (session.recordingID !== undefined &&
                    request.kind === 'recording' &&
                    !uuidEqual(request.id, session.recordingID)) ||
                options.sensitive ||
                options.auditScope !== '')
        ) {
            throw new EvidenceError('input');
        }
        if (
            value.transport !== 'complete' ||
            value.evidence !== 'unverified' ||
            !Array.isArray(value.files)
        ) {
            throw new Error();
        }
        const metadata = transferMetadata(request, value.metadata);
        const expected = expectedFiles(metadata);
        if (expected.length !== value.files.length) {
            throw new Error();
        }
        let total = 0;
        files = Object.freeze(
            value.files.map((entry, index) => {
                const file = object(entry, ['name', 'data']);
                const wanted = expected[index];
                if (
                    wanted === undefined ||
                    file.name !== wanted.name ||
                    !(file.data instanceof Blob) ||
                    file.data.size !== wanted.size
                ) {
                    throw new Error();
                }
                total += file.data.size;
                if (total > maximumBufferedArtifactBytes) {
                    throw new Error();
                }
                return Object.freeze({ name: wanted.name, data: file.data });
            }),
        );
        if (
            key !== null &&
            (options.level !== 'private' ||
                (options.recipient === '' && !options.recipientFromKey) ||
                key.file.size < 1 ||
                key.file.size > 64 << 10 ||
                key.passphrase.length > 4096 ||
                !key.passphrase.isWellFormed())
        ) {
            throw new Error();
        }
    } catch (error) {
        throw error instanceof EvidenceError ? error : new EvidenceError('input');
    }
    if (options.recipientFromKey && key === null) {
        throw new EvidenceError('key');
    }
    const stopped = signal;
    if (stopped.aborted) {
        throw new EvidenceError('cancelled');
    }
    let privateBytes: ArrayBuffer | undefined;
    const password = new TextEncoder().encode(key?.passphrase ?? '');
    if (password.byteLength > 4096) {
        password.fill(0);
        throw new EvidenceError('key');
    }
    let worker: Worker | undefined;
    const terminate = () => worker?.terminate();
    stopped.addEventListener('abort', terminate, { once: true });
    try {
        if (session) {
            worker = session.worker;
        } else {
            worker = new Worker('/_bifroest/files/browser-evidence-worker.js', {
                type: 'module',
                credentials: 'omit',
                name: 'bifroest-evidence',
            });
            await evidenceRPC(
                worker,
                'ready',
                AbortSignal.any([stopped, AbortSignal.timeout(20_000)]),
            );
        }
        if (stopped.aborted) {
            throw new EvidenceError('cancelled');
        }
        privateBytes = key === null ? new ArrayBuffer(0) : await readLocalBytes(key.file, stopped);
        if (privateBytes.byteLength > 64 << 10 || stopped.aborted) {
            throw new EvidenceError('key');
        }
        const result = await evidenceRPC(
            worker,
            'verified',
            stopped,
            {
                kind: 'verify',
                request,
                files,
                options,
                privateKey: privateBytes,
                passphrase: password.buffer,
            },
            [privateBytes, password.buffer],
            progress,
        );
        const metadata = evidenceMetadata(request, options, result.metadata);
        if (
            !(result.output instanceof Blob) ||
            result.output.size > maximumBufferedArtifactBytes ||
            (!options.export && result.output.size !== 0)
        ) {
            throw new EvidenceError('verification');
        }
        if (stopped.aborted) {
            throw new EvidenceError('cancelled');
        }
        return Object.freeze({
            request,
            provenance: 'bytes-only',
            metadata,
            output: options.export ? result.output : null,
        });
    } catch (error) {
        if (signal.aborted) {
            throw new EvidenceError('cancelled');
        }
        if (error instanceof RememberMeError && error.code === 'key-import') {
            throw new EvidenceError('key');
        }
        if (error instanceof EvidenceError && error.code !== 'cancelled') {
            throw error;
        }
        throw new EvidenceError('unavailable');
    } finally {
        stopped.removeEventListener('abort', terminate);
        if (!session) {
            worker?.terminate();
        }
        if (privateBytes?.byteLength) {
            new Uint8Array(privateBytes).fill(0);
        }
        if (password.byteLength) {
            password.fill(0);
        }
    }
}

export interface RecordingVerificationBatch {
    receive(request: ArtifactRequest, image: ArtifactResponseImage): Promise<ReceivedArtifact>;
    verify(
        image: ReceivedArtifact,
        options: EvidenceOptions,
        key: EvidenceKey | null,
        progress?: ProgressListener,
    ): Promise<VerifiedArtifact>;
    dispose(): void;
}
export interface RecordingRuntime extends RecordingVerificationBatch {
    available(): boolean;
    open(
        image: ReceivedArtifact,
        key: EvidenceKey | null,
        operationSignal: AbortSignal,
    ): Promise<{ info: RecordingInfo; image: PlaybackImage | null }>;
    verify(
        image: ReceivedArtifact,
        options: EvidenceOptions,
        key: EvidenceKey | null,
        progress?: ProgressListener,
        operationSignal?: AbortSignal,
    ): Promise<VerifiedArtifact>;
}

// Compiled runtime reuse only: no recording bytes, verification results or keys
// are cached here. A fresh complete Verify runs for each file, bound to one
// explicitly selected source. Actor/source retirement destroys this worker.
export async function createRecordingVerificationBatch(
    source: string,
    signal: AbortSignal,
): Promise<RecordingVerificationBatch> {
    return createRecordingRuntimeInstance(source, signal);
}
export async function createRecordingRuntime(
    source: string,
    id: string,
    signal: AbortSignal,
    startupSignal?: AbortSignal,
): Promise<RecordingRuntime> {
    artifactFields({ kind: 'recording', auditlog: source, id });
    return createRecordingRuntimeInstance(source, signal, id, startupSignal);
}
async function createRecordingRuntimeInstance(
    source: string,
    signal: AbortSignal,
    recordingID?: string,
    startupSignal?: AbortSignal,
): Promise<RecordingRuntime> {
    artifactFields({ kind: 'audit', auditlog: source });
    if (signal.aborted) {
        throw new EvidenceError('cancelled');
    }
    let worker: Worker;
    try {
        worker = new Worker('/_bifroest/files/browser-evidence-worker.js', {
            type: 'module',
            credentials: 'omit',
            name: recordingID ? 'bifroest-recording-open' : 'bifroest-recording-verification',
        });
    } catch {
        throw new EvidenceError('worker');
    }
    let closed = false;
    let busy = false;
    const recoverable = (error: unknown) =>
        recordingID !== undefined &&
        error instanceof EvidenceError &&
        ['key', 'input', 'limit', 'verification'].includes(error.code);
    const failed = () => dispose();
    const observe = (event: MessageEvent) => {
        if (
            event.data?.kind === 'failed' &&
            (!busy || !recoverable(new EvidenceError(event.data.code)))
        ) {
            dispose();
        }
    };
    const dispose = () => {
        closed = true;
        worker.terminate();
        signal.removeEventListener('abort', dispose);
        worker.removeEventListener('error', failed);
        worker.removeEventListener('messageerror', failed);
        worker.removeEventListener('message', observe);
    };
    worker.addEventListener('error', failed);
    worker.addEventListener('messageerror', failed);
    worker.addEventListener('message', observe);
    signal.addEventListener('abort', dispose, { once: true });
    const initializing = startupSignal ? AbortSignal.any([signal, startupSignal]) : signal;
    try {
        await evidenceRPC(
            worker,
            'ready',
            AbortSignal.any([initializing, AbortSignal.timeout(20_000)]),
        );
        await evidenceRPC(
            worker,
            'batch-ready',
            initializing,
            recordingID
                ? { kind: 'recording-init', source, id: recordingID }
                : { kind: 'batch-init', source },
        );
        if (initializing.aborted) {
            throw new EvidenceError('cancelled');
        }
    } catch (error) {
        dispose();
        throw error;
    }
    const bound = (image: ReceivedArtifact) =>
        image?.request?.kind === 'recording' &&
        image.request.auditlog === source &&
        uuidEqual(image.request.id, recordingID);
    return {
        dispose,
        available: () => !closed && !signal.aborted,
        async open(image, key, operationSignal) {
            if (closed || signal.aborted || operationSignal.aborted) {
                throw new EvidenceError('cancelled');
            }
            if (!recordingID || !bound(image)) {
                dispose();
                throw new EvidenceError('input');
            }
            if (busy) {
                throw new EvidenceError('input');
            }
            busy = true;
            const stopped = AbortSignal.any([signal, operationSignal]);
            stopped.addEventListener('abort', dispose, { once: true });
            try {
                return await openRecordingWithWorker(image, key, stopped, worker);
            } catch (error) {
                if (!recoverable(error)) {
                    dispose();
                }
                throw error;
            } finally {
                stopped.removeEventListener('abort', dispose);
                busy = false;
            }
        },
        async receive(request, image) {
            if (closed || signal.aborted) {
                throw new EvidenceError('cancelled');
            }
            if (busy) {
                throw new EvidenceError('input');
            }
            busy = true;
            try {
                const selected = Object.freeze({ ...request }) as ArtifactRequest;
                artifactFields(selected);
                if (
                    recordingID !== undefined ||
                    selected.kind !== 'recording' ||
                    selected.auditlog !== source ||
                    image.status !== 200 ||
                    image.mediaType !== transferMediaType ||
                    !(image.bytes instanceof ArrayBuffer) ||
                    image.bytes.byteLength < 1 ||
                    image.bytes.byteLength > maximumTransferImageBytes
                ) {
                    throw new EvidenceError('input');
                }
                const reply = await evidenceRPC(
                    worker,
                    'received',
                    signal,
                    { kind: 'receive-source', request: selected, ...image },
                    [image.bytes],
                );
                const metadata = transferMetadata(selected, reply.metadata);
                const expected = expectedFiles(metadata);
                if (!Array.isArray(reply.files) || reply.files.length !== expected.length) {
                    throw new EvidenceError('protocol');
                }
                const files = reply.files.map((value, index) => {
                    const file = object(value, ['name', 'data']);
                    const wanted = expected[index];
                    if (
                        !wanted ||
                        file.name !== wanted.name ||
                        !(file.data instanceof Blob) ||
                        file.data.size !== wanted.size
                    ) {
                        throw new EvidenceError('protocol');
                    }
                    return Object.freeze({ name: wanted.name, data: file.data });
                });
                if (signal.aborted) {
                    throw new EvidenceError('cancelled');
                }
                return Object.freeze({
                    request: selected,
                    metadata,
                    files: Object.freeze(files),
                    transport: 'complete' as const,
                    evidence: 'unverified' as const,
                });
            } catch (error) {
                dispose();
                throw error;
            } finally {
                busy = false;
                if (image.bytes.byteLength) {
                    new Uint8Array(image.bytes).fill(0);
                }
            }
        },
        async verify(image, options, key, progress, operationSignal) {
            if (closed || signal.aborted) {
                throw new EvidenceError('cancelled');
            }
            if (recordingID && !bound(image)) {
                dispose();
                throw new EvidenceError('input');
            }
            if (busy) {
                throw new EvidenceError('input');
            }
            busy = true;
            const stopped = operationSignal ? AbortSignal.any([signal, operationSignal]) : signal;
            stopped.addEventListener('abort', dispose, { once: true });
            try {
                return await verifyArtifactImage(image, options, key, stopped, progress, {
                    worker,
                    source,
                    ...(recordingID ? { recordingID } : {}),
                });
            } catch (error) {
                if (!recoverable(error)) {
                    dispose();
                }
                throw error;
            } finally {
                stopped.removeEventListener('abort', dispose);
                busy = false;
            }
        },
    };
}

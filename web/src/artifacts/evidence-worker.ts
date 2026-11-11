import { object } from '../remember/http';
import { uuidEqual } from '../shared/uuid';
import { EvidenceError, evidenceMetadata, evidenceOptions } from './evidence-protocol';
import { expectedFiles, transferMetadata } from './metadata';
import { playbackMetadata, playbackOptions } from './playback-protocol';
import type { ArtifactRequest } from './protocol';
import {
    artifactFields,
    maximumBufferedArtifactBytes,
    maximumTransferImageBytes,
    transferMediaType,
} from './protocol';

type Runtime = {
    Go: new () => {
        importObject: WebAssembly.Imports;
        run(instance: WebAssembly.Instance): Promise<void>;
        exit: (code: number) => void;
    };
    bifroestEvidenceVerify: (...args: unknown[]) => unknown;
    bifroestEvidenceVerifyBatch: (...args: unknown[]) => unknown;
    bifroestEvidenceBeginBatch: (...args: unknown[]) => unknown;
    bifroestRecordingBegin: (...args: unknown[]) => unknown;
    bifroestRecordingSourceReceive: (...args: unknown[]) => unknown;
    bifroestEvidencePlayback: (...args: unknown[]) => unknown;
    bifroestRecordingOpen: (...args: unknown[]) => unknown;
};
const runtime = globalThis as unknown as Runtime;
const worker = globalThis as unknown as {
    postMessage(value: unknown, transfer?: Transferable[]): void;
    close(): void;
    onmessage: ((event: MessageEvent) => void) | null;
};
let used = false;
let busy = false;
let batchSource: string | null = null;
let recordingID: string | null = null;

function failed(code: EvidenceError['code'] = 'verification') {
    worker.postMessage({ kind: 'failed', code });
    if (recordingID === null || !['input', 'key', 'limit', 'verification'].includes(code)) {
        worker.close();
    }
}

worker.onmessage = (event) => {
    void process(event).catch(() => failed());
};

async function process(event: MessageEvent) {
    const buffers: Uint8Array<ArrayBuffer>[] = [];
    let ownsOperation = false;
    try {
        for (const name of ['privateKey', 'passphrase', 'bytes']) {
            const value = event.data?.[name];
            if (value instanceof ArrayBuffer) {
                buffers.push(new Uint8Array(value));
            }
        }
        if (busy || (used && batchSource === null)) {
            throw new EvidenceError('protocol');
        }
        busy = true;
        ownsOperation = true;
        used = true;
        if (event.data?.kind === 'batch-init') {
            const body = object(event.data, ['kind', 'source']);
            if (batchSource !== null || typeof body.source !== 'string') {
                throw new EvidenceError('input');
            }
            artifactFields({ kind: 'audit', auditlog: body.source });
            if (
                typeof runtime.bifroestEvidenceBeginBatch !== 'function' ||
                runtime.bifroestEvidenceBeginBatch(body.source) !== true
            ) {
                throw new EvidenceError('runtime');
            }
            batchSource = body.source;
            worker.postMessage({ kind: 'batch-ready' });
            return;
        }
        if (event.data?.kind === 'recording-init') {
            const body = object(event.data, ['kind', 'source', 'id']);
            if (
                batchSource !== null ||
                typeof body.source !== 'string' ||
                typeof body.id !== 'string'
            ) {
                throw new EvidenceError('protocol');
            }
            artifactFields({ kind: 'recording', auditlog: body.source, id: body.id });
            if (
                typeof runtime.bifroestRecordingBegin !== 'function' ||
                runtime.bifroestRecordingBegin(body.source, body.id) !== true
            ) {
                throw new EvidenceError('runtime');
            }
            batchSource = body.source;
            recordingID = body.id;
            worker.postMessage({ kind: 'batch-ready' });
            return;
        }
        if (event.data?.kind === 'receive-source') {
            const body = object(event.data, ['kind', 'request', 'bytes', 'mediaType', 'status']);
            const request = body.request as ArtifactRequest;
            artifactFields(request);
            if (
                batchSource === null ||
                recordingID !== null ||
                request.kind !== 'recording' ||
                request.auditlog !== batchSource ||
                !(body.bytes instanceof ArrayBuffer) ||
                body.bytes.byteLength < 1 ||
                body.bytes.byteLength > maximumTransferImageBytes ||
                body.mediaType !== transferMediaType ||
                body.status !== 200
            ) {
                throw new EvidenceError('input');
            }
            if (typeof runtime.bifroestRecordingSourceReceive !== 'function') {
                throw new EvidenceError('runtime');
            }
            const data = new Uint8Array(body.bytes);
            buffers.push(data);
            const raw = runtime.bifroestRecordingSourceReceive(
                batchSource,
                request.id,
                data,
                body.mediaType,
                body.status,
            );
            if (raw === null || typeof raw !== 'object') {
                throw new EvidenceError('protocol');
            }
            if ('ok' in raw && raw.ok === false) {
                const failure = object(raw, ['ok', 'code']);
                failed(failure.code === 'limit' ? 'limit' : 'input');
                return;
            }
            const result = object(raw, ['ok', 'metadata', 'files']);
            if (
                result.ok !== true ||
                typeof result.metadata !== 'string' ||
                !Array.isArray(result.files)
            ) {
                throw new EvidenceError('protocol');
            }
            const metadata = transferMetadata(request, JSON.parse(result.metadata));
            const expected = expectedFiles(metadata);
            if (result.files.length !== expected.length) {
                throw new EvidenceError('protocol');
            }
            const files = result.files.map((value, index) => {
                const file = object(value, ['name', 'data']);
                const wanted = expected[index];
                if (
                    !wanted ||
                    file.name !== wanted.name ||
                    !(file.data instanceof Uint8Array) ||
                    !(file.data.buffer instanceof ArrayBuffer) ||
                    file.data.byteOffset !== 0 ||
                    file.data.byteLength !== file.data.buffer.byteLength ||
                    file.data.byteLength !== wanted.size
                ) {
                    throw new EvidenceError('protocol');
                }
                const blob = new Blob([file.data.buffer], { type: 'application/octet-stream' });
                file.data.fill(0);
                return { name: wanted.name, data: blob };
            });
            worker.postMessage({ kind: 'received', metadata, files });
            return;
        }
        if (event.data?.kind === 'open-recording') {
            if (batchSource !== null && recordingID === null) {
                throw new EvidenceError('input');
            }
            if (typeof runtime.bifroestRecordingOpen !== 'function') {
                throw new EvidenceError('runtime');
            }
            const body = object(event.data, ['kind', 'id', 'data', 'privateKey', 'passphrase']);
            if (recordingID !== null && !uuidEqual(body.id, recordingID)) {
                throw new EvidenceError('protocol');
            }
            if (
                typeof body.id !== 'string' ||
                !(body.data instanceof Blob) ||
                body.data.size < 1 ||
                body.data.size > maximumBufferedArtifactBytes ||
                !(body.privateKey instanceof ArrayBuffer) ||
                body.privateKey.byteLength > 64 << 10 ||
                !(body.passphrase instanceof ArrayBuffer) ||
                body.passphrase.byteLength > 4096
            ) {
                throw new EvidenceError('input');
            }
            const data = new Uint8Array(await body.data.arrayBuffer());
            const key = new Uint8Array(body.privateKey);
            const password = new Uint8Array(body.passphrase);
            buffers.push(data, key, password);
            const raw = runtime.bifroestRecordingOpen(body.id, data, key, password);
            if (raw === null || typeof raw !== 'object') {
                throw new EvidenceError('input');
            }
            if ('ok' in raw && raw.ok === false) {
                const result = object(raw, ['ok', 'code']);
                failed(
                    ['input', 'key', 'limit'].includes(String(result.code))
                        ? (result.code as EvidenceError['code'])
                        : 'input',
                );
                return;
            }
            const result = object(raw, ['ok', 'metadata', 'output']);
            if (
                result.ok !== true ||
                typeof result.metadata !== 'string' ||
                !(result.output instanceof Uint8Array) ||
                !(result.output.buffer instanceof ArrayBuffer) ||
                result.output.byteOffset !== 0 ||
                result.output.byteLength !== result.output.buffer.byteLength ||
                result.output.byteLength > maximumBufferedArtifactBytes
            ) {
                throw new EvidenceError('input');
            }
            worker.postMessage(
                {
                    kind: 'opened',
                    metadata: JSON.parse(result.metadata),
                    output: result.output.buffer,
                },
                [result.output.buffer],
            );
            if (recordingID === null) {
                worker.close();
            }
            return;
        }
        if (event.data?.kind === 'playback') {
            if (batchSource !== null) {
                throw new EvidenceError('input');
            }
            const body = object(event.data, ['kind', 'options', 'data']);
            const options = playbackOptions(body.options);
            if (
                !(body.data instanceof Blob) ||
                body.data.size < 1 ||
                body.data.size > maximumBufferedArtifactBytes
            ) {
                throw new EvidenceError('limit');
            }
            const data = new Uint8Array(await body.data.arrayBuffer());
            buffers.push(data);
            const raw = runtime.bifroestEvidencePlayback(
                options.id,
                options.producer,
                options.allowUntrusted,
                data,
            );
            if (raw === null || typeof raw !== 'object') {
                throw new Error();
            }
            if ('ok' in raw && raw.ok === false) {
                const failure = object(raw, ['ok', 'code']);
                failed(
                    ['input', 'limit', 'verification'].includes(String(failure.code))
                        ? (failure.code as EvidenceError['code'])
                        : 'verification',
                );
                return;
            }
            const result = object(raw, ['ok', 'metadata', 'output']);
            if (
                result.ok !== true ||
                typeof result.metadata !== 'string' ||
                !(result.output instanceof Uint8Array) ||
                !(result.output.buffer instanceof ArrayBuffer) ||
                result.output.byteOffset !== 0 ||
                result.output.byteLength !== result.output.buffer.byteLength ||
                result.output.byteLength > maximumBufferedArtifactBytes
            ) {
                throw new Error();
            }
            const metadata = playbackMetadata(options, JSON.parse(result.metadata));
            worker.postMessage({ kind: 'prepared', metadata, output: result.output.buffer }, [
                result.output.buffer,
            ]);
            worker.close();
            return;
        }
        const body = object(event.data, [
            'kind',
            'request',
            'files',
            'options',
            'privateKey',
            'passphrase',
        ]);
        const request = body.request as ArtifactRequest;
        artifactFields(request);
        const options = evidenceOptions(request, body.options);
        if (
            batchSource !== null &&
            (request.kind !== 'recording' ||
                request.auditlog !== batchSource ||
                (recordingID !== null && !uuidEqual(request.id, recordingID)) ||
                (recordingID === null && options.export) ||
                options.sensitive ||
                options.auditScope !== '')
        ) {
            throw new EvidenceError(recordingID === null ? 'input' : 'protocol');
        }
        if (
            body.kind !== 'verify' ||
            !Array.isArray(body.files) ||
            body.files.length < 1 ||
            body.files.length > 65536 ||
            !(body.privateKey instanceof ArrayBuffer) ||
            !(body.passphrase instanceof ArrayBuffer) ||
            body.privateKey.byteLength > 64 << 10 ||
            body.passphrase.byteLength > 4096
        ) {
            throw new Error();
        }
        const privateKey = new Uint8Array(body.privateKey);
        const passphrase = new Uint8Array(body.passphrase);
        buffers.push(privateKey, passphrase);
        const files = [];
        const inputTotal = body.files.reduce((size: number, value: unknown) => {
            const file = object(value, ['name', 'data']);
            if (
                !(file.data instanceof Blob) ||
                file.data.size < 1 ||
                size + file.data.size > maximumBufferedArtifactBytes
            ) {
                throw new EvidenceError('limit');
            }
            return size + file.data.size;
        }, 0);
        let reportedAt = 0;
        let reportedPhase = '';
        const progress = (phase: string, completed: number, total: number) => {
            const now = performance.now();
            if (phase === reportedPhase && now - reportedAt < 100 && completed !== total) {
                return;
            }
            reportedAt = now;
            reportedPhase = phase;
            worker.postMessage({ kind: 'progress', phase, completed, total });
        };
        let total = 0;
        for (const item of body.files) {
            const file = object(item, ['name', 'data']);
            if (
                typeof file.name !== 'string' ||
                file.name.length > 255 ||
                !(file.data instanceof Blob) ||
                file.data.size < 1 ||
                total + file.data.size > maximumBufferedArtifactBytes
            ) {
                throw new Error();
            }
            total += file.data.size;
            const data = new Uint8Array(await file.data.arrayBuffer());
            buffers.push(data);
            files.push({ name: file.name, data });
            progress('reading', total, inputTotal);
        }
        progress('integrity', 0, -1);
        const verify =
            batchSource === null
                ? runtime.bifroestEvidenceVerify
                : runtime.bifroestEvidenceVerifyBatch;
        if (typeof verify !== 'function') {
            throw new EvidenceError('runtime');
        }
        const raw = verify(
            request.kind,
            request.auditlog,
            request.kind === 'recording' ? request.id : '',
            JSON.stringify(options),
            files,
            privateKey,
            passphrase,
            progress,
        );
        if (raw === null || typeof raw !== 'object') {
            throw new Error();
        }
        if ('ok' in raw && raw.ok === false) {
            const failure = object(raw, ['ok', 'code']);
            failed(
                ['input', 'key', 'limit', 'verification'].includes(String(failure.code))
                    ? (failure.code as EvidenceError['code'])
                    : 'verification',
            );
            return;
        }
        const result = object(raw, ['ok', 'metadata', 'output']);
        if (
            result.ok !== true ||
            typeof result.metadata !== 'string' ||
            !(result.output instanceof Uint8Array) ||
            !(result.output.buffer instanceof ArrayBuffer) ||
            result.output.byteOffset !== 0 ||
            result.output.byteLength !== result.output.buffer.byteLength ||
            result.output.byteLength > maximumBufferedArtifactBytes
        ) {
            throw new Error();
        }
        const metadata = evidenceMetadata(request, options, JSON.parse(result.metadata));
        buffers.push(new Uint8Array(result.output.buffer));
        if (!options.export && result.output.byteLength !== 0) {
            throw new Error();
        }
        worker.postMessage({
            kind: 'verified',
            metadata,
            output: new Blob([result.output.buffer], { type: 'application/octet-stream' }),
        });
        if (batchSource === null) {
            worker.close();
        }
    } catch (error) {
        failed(
            error instanceof EvidenceError
                ? error.code
                : event.data?.kind === 'open-recording'
                  ? 'protocol'
                  : 'verification',
        );
    } finally {
        for (const value of buffers) {
            value.fill(0);
        }
        if (ownsOperation) {
            busy = false;
        }
    }
}

async function readBounded(
    stream: ReadableStream<Uint8Array>,
    maximum: number,
): Promise<Uint8Array<ArrayBuffer>> {
    const reader = stream.getReader();
    const chunks = [];
    let size = 0;
    try {
        while (true) {
            const next = await reader.read();
            if (next.done) {
                break;
            }
            size += next.value.byteLength;
            if (size > maximum) {
                throw new Error();
            }
            chunks.push(next.value);
        }
    } finally {
        try {
            await reader.cancel();
        } finally {
            reader.releaseLock();
        }
    }
    const result = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return result;
}

let startup: EvidenceError['code'] = 'worker';
async function boot() {
    await import(/* @vite-ignore */ new URL('go-wasm-exec.js', location.href).href);
    startup = 'module-fetch';
    const url = new URL('browser-evidence.wasm.gz', location.href);
    const response = await fetch(url, {
        credentials: 'omit',
        mode: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(20_000),
    });
    if (
        response.status !== 200 ||
        response.redirected ||
        response.url !== url.href ||
        !['application/gzip', 'application/x-gzip'].includes(
            response.headers.get('Content-Type') ?? '',
        ) ||
        response.headers.has('Content-Encoding') ||
        response.body === null
    ) {
        throw new Error();
    }
    const compressed = await readBounded(response.body, 8 << 20);
    startup = 'module-decode';
    const bytes = await readBounded(
        new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip')),
        24 << 20,
    );
    const go = new runtime.Go();
    startup = 'runtime';
    go.exit = () => failed('runtime');
    const result = await WebAssembly.instantiate(bytes, go.importObject);
    void go.run(result.instance).catch(() => failed('runtime'));
}

void boot().catch(() => failed(startup));

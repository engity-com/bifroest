import type { ProgressListener } from '../management/progress';
import type { RecordingSourceImages } from '../management/source-transfer';
import type { ArtifactSessionSecrets } from './artifact-secrets';
import { EvidenceError } from './evidence-protocol';
import {
    type LocalRecordingIndex,
    RecordingIndexBuilder,
    recordingByteDigest,
} from './recording-index';
import {
    createRecordingVerificationBatch,
    type EvidenceKey,
    type RecordingVerificationBatch,
} from './verify';

export interface SourceVerificationResult {
    readonly checked: number;
    readonly full: number;
    readonly outer: number;
    readonly producer: string;
    readonly reported: boolean;
    readonly metadataLimited: boolean;
}
export interface SourceVerificationRequest {
    readonly source: string;
    readonly level: 'outer' | 'private';
    readonly producer: string;
    readonly reported: boolean;
    readonly key: EvidenceKey | null;
}
export interface SourceVerificationPorts {
    open(
        source: string,
        signal: AbortSignal,
        progress: ProgressListener,
    ): Promise<RecordingSourceImages>;
    readonly keys: Pick<ArtifactSessionSecrets, 'matching' | 'remember'>;
    current(): boolean;
    readonly signal: AbortSignal;
    readonly progress: ProgressListener;
    readonly createBatch?: typeof createRecordingVerificationBatch;
}

// Explicit whole-source verification. Ordinary list reads never enter here.
// Own the stream, worker and optional bounded display index in this use case.
export async function verifyRecordingSource(
    request: SourceVerificationRequest,
    ports: SourceVerificationPorts,
): Promise<{ result: SourceVerificationResult; index: LocalRecordingIndex | null }> {
    const { source, level, producer, reported } = request;
    const current = () => !ports.signal.aborted && ports.current();
    const requireCurrent = () => {
        if (!current()) {
            throw new EvidenceError('cancelled');
        }
    };
    const progress: ProgressListener = (value) => {
        if (current()) {
            ports.progress(value);
        }
    };
    let batch: RecordingVerificationBatch | undefined;
    let stream: RecordingSourceImages | undefined;
    let builder = level === 'private' ? new RecordingIndexBuilder(source, reported) : null;
    const result = { checked: 0, full: 0, outer: 0, producer, reported, metadataLimited: false };
    try {
        requireCurrent();
        stream = await ports.open(source, ports.signal, progress);
        for await (const row of stream) {
            requireCurrent();
            if (row.request.kind !== 'recording' || row.request.auditlog !== source) {
                throw new EvidenceError('input');
            }
            batch ??= await (ports.createBatch ?? createRecordingVerificationBatch)(
                source,
                ports.signal,
            );
            requireCurrent();
            const image = await batch.receive(row.request, row.image);
            requireCurrent();
            const key =
                level === 'private' && row.encrypted
                    ? (request.key ?? ports.keys.matching(row.recipient))
                    : null;
            if (level === 'private' && row.encrypted && !key) {
                throw new EvidenceError('key-required');
            }
            requireCurrent();
            const verified = await batch.verify(
                image,
                {
                    producer,
                    allowUntrusted: producer === '',
                    recipient: level === 'outer' ? row.recipient : '',
                    ...(key ? { recipientFromKey: true } : {}),
                    level,
                    export: false,
                    sensitive: false,
                    auditScope: '',
                    ...(builder ? { metadata: true } : {}),
                },
                key,
                progress,
            );
            requireCurrent();
            if (key) {
                ports.keys.remember(key, verified);
            }
            try {
                if (builder) {
                    const digest = await recordingByteDigest(image, ports.signal);
                    requireCurrent();
                    builder.add(image, verified, digest);
                }
            } catch (error) {
                if (!(error instanceof EvidenceError && error.code === 'limit')) {
                    throw error;
                }
                // Only the optional display index is abandoned. Every recording still
                // has to finish the originally requested verification.
                builder?.clear();
                builder = null;
                result.metadataLimited = true;
            }
            result.checked++;
            if (verified.metadata.validation === 'private') {
                result.full++;
            } else {
                result.outer++;
            }
            progress({ phase: 'verifying', completed: result.checked, total: row.total });
        }
        requireCurrent();
        return { result: Object.freeze(result), index: builder?.finish() ?? null };
    } finally {
        builder?.clear();
        batch?.dispose();
        await stream?.return?.();
    }
}

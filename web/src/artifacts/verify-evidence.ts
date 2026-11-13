import type { ProgressListener } from '../management/progress';
import { uuidEqual } from '../shared/uuid';
import type { AuditEventIndex } from './audit-events';
import { indexAuditEvents } from './audit-events';
import type { SigningExpectation } from './evidence-details';
import { EvidenceError, type EvidenceMetadata, evidenceOptions } from './evidence-protocol';
import type { ReceivedArtifact } from './protocol';
import { verifiedRecordingContext } from './recording-flow';
import { type EvidenceKey, type RecordingRuntime, verifyArtifact } from './verify';

export interface EvidenceVerificationOptions {
    readonly expectation: SigningExpectation;
    readonly level: 'outer' | 'private';
    readonly auditScope: 'complete' | 'captured-prefix';
    readonly sensitive: boolean;
    readonly indexAudit: boolean;
}
export interface EvidenceVerificationPorts {
    readonly signal: AbortSignal;
    current(): boolean;
    matches(): boolean;
    target(): { readonly flow?: string; readonly sessionId?: string } | null;
    recording(
        image: ReceivedArtifact,
        signal: AbortSignal,
    ): Promise<Pick<RecordingRuntime, 'verify'>>;
    readonly progress: ProgressListener;
    readonly audit?: typeof verifyArtifact;
}

// Verify immutable local bytes against an explicitly selected expectation.
// Neither transport admission, routing nor React state is available here.
export async function verifyEvidence(
    image: ReceivedArtifact,
    header: Pick<EvidenceMetadata, 'producer' | 'expectedRecipient'>,
    key: EvidenceKey | null,
    requested: EvidenceVerificationOptions,
    ports: EvidenceVerificationPorts,
) {
    const current = () => !ports.signal.aborted && ports.current();
    const requireCurrent = () => {
        if (!current() || !ports.matches()) {
            throw new EvidenceError('cancelled');
        }
    };
    const expectation = {
        ...requested.expectation,
        producer: requested.expectation.enabled ? requested.expectation.producer : '',
    };
    const options = evidenceOptions(image.request, {
        producer: expectation.producer,
        allowUntrusted: !expectation.enabled,
        recipient: requested.level === 'outer' ? header.expectedRecipient : '',
        ...(requested.level === 'private' && header.expectedRecipient !== ''
            ? { recipientFromKey: true }
            : {}),
        level: requested.level,
        export: requested.level === 'private',
        sensitive:
            requested.level === 'private' && image.request.kind === 'audit' && requested.sensitive,
        auditScope: image.request.kind === 'audit' ? requested.auditScope : '',
    });
    requireCurrent();
    const progress: ProgressListener = (value) => {
        if (current()) {
            ports.progress(value);
        }
    };
    const verified =
        image.request.kind === 'recording'
            ? await (await ports.recording(image, ports.signal)).verify(
                  image,
                  options,
                  key,
                  progress,
                  ports.signal,
              )
            : await (ports.audit ?? verifyArtifact)(image, options, key, ports.signal, progress);
    requireCurrent();
    const auditIndex: AuditEventIndex | null =
        requested.indexAudit &&
        image.request.kind === 'audit' &&
        verified.output &&
        verified.metadata.outputFormat === 'jsonl'
            ? await indexAuditEvents(verified.output, ports.signal, progress)
            : null;
    requireCurrent();
    const context = await verifiedRecordingContext(verified);
    requireCurrent();
    const target = ports.target();
    if (
        image.request.kind === 'recording' &&
        ((target?.flow && context.flow && target.flow !== context.flow) ||
            (verified.metadata.validation === 'private' &&
                target?.sessionId &&
                !uuidEqual(context.sessionId, target.sessionId)))
    ) {
        throw new EvidenceError('verification');
    }
    return { verified, auditIndex, context, expectation };
}

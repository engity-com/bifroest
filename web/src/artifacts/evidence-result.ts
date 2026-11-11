import type { AuditEventIndex } from './audit-events';
import type { SigningExpectation } from './evidence-details';
import type { VerifiedArtifact } from './evidence-protocol';

export interface EvidenceResult {
    readonly verified: VerifiedArtifact | null;
    readonly auditIndex: AuditEventIndex | null;
    readonly verifiedSensitive: boolean;
    readonly used: SigningExpectation | null;
    readonly recordingFlow: string;
    readonly recordingSession: string;
}
export const emptyEvidenceResult = (): EvidenceResult => ({
    verified: null,
    auditIndex: null,
    verifiedSensitive: false,
    used: null,
    recordingFlow: '',
    recordingSession: '',
});
export type EvidenceResultEvent =
    | { readonly type: 'clear' }
    | { readonly type: 'invalidate-verification' }
    | { readonly type: 'expectation'; readonly value: SigningExpectation }
    | { readonly type: 'relation'; readonly flow: string; readonly session: string }
    | {
          readonly type: 'verified';
          readonly value: VerifiedArtifact;
          readonly index: AuditEventIndex | null;
          readonly sensitive: boolean;
          readonly expectation: SigningExpectation;
          readonly flow: string;
          readonly session: string;
      };

// A verification receipt, its provenance and its derived identity are published
// atomically. An old index/private projection cannot survive invalidation.
export function evidenceResultTransition(
    previous: EvidenceResult,
    event: EvidenceResultEvent,
): EvidenceResult {
    switch (event.type) {
        case 'clear':
            return emptyEvidenceResult();
        case 'invalidate-verification':
            return {
                ...emptyEvidenceResult(),
                recordingFlow: previous.recordingFlow,
                recordingSession: previous.recordingSession,
            };
        case 'expectation':
            return { ...previous, used: event.value };
        case 'relation':
            return { ...previous, recordingFlow: event.flow, recordingSession: event.session };
        case 'verified':
            return {
                verified: event.value,
                auditIndex: event.index,
                verifiedSensitive: event.sensitive,
                used: event.expectation,
                recordingFlow: event.flow,
                recordingSession: event.session,
            };
    }
}

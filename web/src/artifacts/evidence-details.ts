import type { Message } from '../ui/messages';
import type { EvidenceMetadata } from './evidence-protocol';
import type { ArtifactPhase } from './evidence-view';
import type { RecordingInfo } from './open-recording';

export interface SigningExpectation {
  enabled: boolean;
  producer: string;
  source: 'reported' | 'user';
}
export interface EvidenceFailure {
  message: Message;
  code: string;
  stage: ArtifactPhase;
}
export interface EvidenceDetailsState {
  operationDetails: boolean;
  notice: Message | null;
  errorCode: string;
  failedStage: ArtifactPhase | null;
  phase: ArtifactPhase | null;
  verificationFailure: EvidenceFailure | null;
  success: boolean;
  metadata: EvidenceMetadata | undefined;
  protection: EvidenceMetadata | null;
  recordingInfo: RecordingInfo | null;
  used: SigningExpectation | null;
}

// Display projection only, never a verifier or a trust decision. In particular
// a user-selected signing ID without a successful check is not an established match.
export function evidenceDetails(state: EvidenceDetailsState) {
  const {
    operationDetails,
    notice,
    verificationFailure,
    success,
    metadata,
    protection,
    recordingInfo,
    used,
  } = state;
  const trust: Message =
    success && !verificationFailure && used?.enabled && used.source === 'user'
      ? 'artifactUserSelectedSigner'
      : used?.enabled && used.source === 'user'
        ? 'verificationMatchNotEstablished'
        : used?.enabled
          ? 'artifactServerSigner'
          : 'artifactSignerNotPinned';
  return {
    message: operationDetails
      ? notice
      : (verificationFailure?.message ?? (!success ? notice : null)),
    code: operationDetails
      ? state.errorCode || '—'
      : (verificationFailure?.code ?? (success ? '—' : state.errorCode || '—')),
    stage: operationDetails
      ? (state.failedStage ?? state.phase ?? 'complete')
      : (verificationFailure?.stage ??
        (success ? 'complete' : (state.failedStage ?? state.phase ?? 'complete'))),
    validation: metadata?.validation ?? protection?.validation ?? '—',
    producer: metadata?.producer ?? protection?.producer ?? recordingInfo?.producer ?? '—',
    expectedProducer: used?.enabled ? used.producer : null,
    trust,
    recipient:
      metadata?.expectedRecipient ||
      protection?.expectedRecipient ||
      recordingInfo?.recipient ||
      null,
    protectionKnown: !!(metadata || protection || recordingInfo),
    decryption: metadata?.decryption ?? recordingInfo?.decryption ?? 'not-checked',
    audit:
      metadata?.kind === 'audit'
        ? {
            records: metadata.records,
            privateRecords: metadata.privateRecords,
            scope: metadata.auditScope,
          }
        : null,
  };
}

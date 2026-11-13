// Standalone client-library composition root. Domain entry points stay narrow;
// this bundle deliberately assembles authentication and local evidence tools.

export type {
    EvidenceMetadata,
    EvidenceOptions,
    VerifiedArtifact,
} from './artifacts/evidence-protocol';
export { EvidenceError } from './artifacts/evidence-protocol';
export type { PlaybackMetadata, PlaybackOptions } from './artifacts/playback-protocol';
export { prepareRecordingPlayback } from './artifacts/prepare-playback';
export type { ArtifactRequest, ReceivedArtifact, ReceivedArtifactFile } from './artifacts/protocol';
export type { EvidenceKey } from './artifacts/verify';
export { createRecordingVerificationBatch, verifyArtifact } from './artifacts/verify';
export type { AuditlogSummary, Page, PageOptions, RecordingSummary } from './management/protocol';
export * from './remember';

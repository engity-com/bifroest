import { describe, expect, it } from 'vitest';
import { type EvidenceDetailsState, evidenceDetails } from '../src/artifacts/evidence-details';
import type { EvidenceMetadata } from '../src/artifacts/evidence-protocol';

function state(changes: Partial<EvidenceDetailsState> = {}): EvidenceDetailsState {
  return {
    operationDetails: false,
    notice: null,
    errorCode: '',
    failedStage: null,
    phase: null,
    verificationFailure: null,
    success: false,
    metadata: undefined,
    protection: null,
    recordingInfo: null,
    used: null,
    ...changes,
  };
}
function metadata(changes: Partial<EvidenceMetadata> = {}): EvidenceMetadata {
  return {
    kind: 'recording',
    validation: 'private',
    trust: 'pinned',
    producer: 'a'.repeat(64),
    expectedRecipient: '',
    decryption: 'not-encrypted',
    recordingId: '',
    auditScope: '',
    records: '0',
    privateRecords: '0',
    outputFormat: 'cast',
    ...changes,
  };
}
const user = { enabled: true, producer: 'a'.repeat(64), source: 'user' as const };

describe('evidence detail presentation', () => {
  it('distinguishes unknown protection and identity from confirmed unencrypted data', () => {
    const empty = evidenceDetails(state());
    expect(empty.protectionKnown).toBe(false);
    expect(empty.recipient).toBe(null);
    expect(empty.producer).toBe('—');
    expect(empty.trust).toBe('artifactSignerNotPinned');
    const header = evidenceDetails(state({ protection: metadata({ validation: 'outer' }) }));
    expect(header.protectionKnown).toBe(true);
    expect(header.validation).toBe('outer');
    expect(header.trust).toBe('artifactSignerNotPinned');
  });

  it('never presents a user-selected signer as matched before successful verification', () => {
    expect(evidenceDetails(state({ used: user, protection: metadata() })).trust).toBe(
      'verificationMatchNotEstablished',
    );
    expect(evidenceDetails(state({ used: user, metadata: metadata(), success: true })).trust).toBe(
      'artifactUserSelectedSigner',
    );
  });

  it('does not retain a successful match after a failed recheck', () => {
    const details = evidenceDetails(
      state({
        used: user,
        success: true,
        metadata: metadata(),
        verificationFailure: {
          message: 'artifactVerificationFailed',
          code: 'verification',
          stage: 'verifying',
        },
      }),
    );
    expect(details.trust).toBe('verificationMatchNotEstablished');
    expect(details.message).toBe('artifactVerificationFailed');
    expect(details.code).toBe('verification');
    expect(details.stage).toBe('verifying');
  });

  it('keeps operation diagnostics separate from the retained verification result', () => {
    const details = evidenceDetails(
      state({
        operationDetails: true,
        notice: 'artifactDownloadFailed',
        errorCode: 'unavailable',
        failedStage: 'downloading',
        metadata: metadata(),
        used: user,
        success: true,
      }),
    );
    expect(details.code).toBe('unavailable');
    expect(details.stage).toBe('downloading');
    expect(details.message).toBe('artifactDownloadFailed');
    expect(details.trust).toBe('artifactUserSelectedSigner');
  });

  it('preserves reported provenance and exact audit counts', () => {
    const details = evidenceDetails(
      state({
        success: true,
        used: { ...user, source: 'reported' },
        metadata: metadata({
          kind: 'audit',
          outputFormat: 'jsonl',
          records: '128',
          privateRecords: '7',
          auditScope: 'captured-prefix',
        }),
      }),
    );
    expect(details.trust).toBe('artifactServerSigner');
    expect(details.audit).toEqual({
      records: '128',
      privateRecords: '7',
      scope: 'captured-prefix',
    });
  });
});

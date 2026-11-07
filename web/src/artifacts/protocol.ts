import { RememberMeError } from '../remember/protocol';

export const maximumBufferedArtifactBytes = 64 << 20;
export const maximumTransferImageBytes = 72 << 20;
export const transferMediaType = 'application/vnd.bifroest.management-transfer.v1';

export type ArtifactRequest =
  | { readonly kind: 'recording'; readonly auditlog: string; readonly id: string }
  | { readonly kind: 'audit'; readonly auditlog: string };

export interface ReceivedArtifactFile {
  readonly name: string;
  readonly data: Blob;
}

export interface RecordingTransportMetadata {
  readonly Version: 1;
  readonly ID: string;
  readonly ProducerID: string;
  readonly Size: number;
  readonly SHA256: string;
}

export interface AuditTransportMetadata {
  readonly Version: 1;
  readonly Name: string;
  readonly Producer: string;
  readonly Recipient: string;
  readonly Files: readonly {
    readonly Name: string;
    readonly Size: number;
    readonly SHA256: string;
  }[];
}

// These are transport assertions only. Producer trust, signatures, private
// semantics and decryption must be checked independently by the evidence core.
export interface ReceivedArtifact {
  readonly request: ArtifactRequest;
  readonly transport: 'complete';
  readonly evidence: 'unverified';
  readonly metadata: RecordingTransportMetadata | AuditTransportMetadata;
  readonly files: readonly ReceivedArtifactFile[];
}

export function artifactFields(request: ArtifactRequest): Record<string, string> {
  if (
    request === null ||
    typeof request !== 'object' ||
    !['audit', 'recording'].includes(request.kind) ||
    Object.keys(request).sort().join(',') !==
      (request.kind === 'recording' ? 'auditlog,id,kind' : 'auditlog,kind') ||
    typeof request.auditlog !== 'string' ||
    !/^[A-Za-z0-9.-]{1,128}$/u.test(request.auditlog) ||
    request.auditlog === '.' ||
    request.auditlog === '..'
  ) {
    throw new RememberMeError('unavailable');
  }
  if (request.kind === 'recording') {
    if (
      typeof request.id !== 'string' ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(request.id) ||
      request.id === '00000000-0000-0000-0000-000000000000'
    ) {
      throw new RememberMeError('unavailable');
    }
    return { auditlog: request.auditlog, id: request.id };
  }
  return { auditlog: request.auditlog };
}

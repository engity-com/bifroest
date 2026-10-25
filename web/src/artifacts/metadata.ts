import { object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import type {
  ArtifactRequest,
  AuditTransportMetadata,
  RecordingTransportMetadata,
} from './protocol';
import { maximumBufferedArtifactBytes } from './protocol';

function size(value: unknown, maximum: number): value is number {
  return Number.isSafeInteger(value) && typeof value === 'number' && value > 0 && value <= maximum;
}

function digest(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
}

function producer(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/u.test(value);
}

// This validates the Go decoder's JS message shape, not CBOR, evidence
// signatures, producer trust or decryption. Every declared identity is untrusted.
export function transferMetadata(
  request: ArtifactRequest,
  value: unknown,
): RecordingTransportMetadata | AuditTransportMetadata {
  if (request.kind === 'recording') {
    const body = object(value, ['Version', 'ID', 'ProducerID', 'Size', 'SHA256']);
    if (
      body.Version !== 1 ||
      body.ID !== request.id ||
      !producer(body.ProducerID) ||
      !size(body.Size, maximumBufferedArtifactBytes) ||
      !digest(body.SHA256)
    ) {
      throw new RememberMeError('unavailable');
    }
    return Object.freeze({
      Version: 1,
      ID: request.id,
      ProducerID: body.ProducerID,
      Size: body.Size,
      SHA256: body.SHA256,
    });
  }
  const body = object(value, ['Version', 'Name', 'Producer', 'Recipient', 'Files']);
  if (
    body.Version !== 1 ||
    body.Name !== request.auditlog ||
    !producer(body.Producer) ||
    typeof body.Recipient !== 'string' ||
    (body.Recipient !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(body.Recipient)) ||
    !Array.isArray(body.Files) ||
    body.Files.length === 0
  ) {
    throw new RememberMeError('unavailable');
  }
  let total = 0;
  const names = new Set<string>();
  const files = body.Files.map((value) => {
    const entry = object(value, ['Name', 'Size', 'SHA256']);
    if (
      typeof entry.Name !== 'string' ||
      !/^[A-Za-z0-9.-]{1,255}$/u.test(entry.Name) ||
      names.has(entry.Name) ||
      !size(entry.Size, 17 << 20) ||
      !digest(entry.SHA256)
    ) {
      throw new RememberMeError('unavailable');
    }
    total += entry.Size;
    if (total > maximumBufferedArtifactBytes) {
      throw new RememberMeError('artifact-too-large');
    }
    names.add(entry.Name);
    return Object.freeze({ Name: entry.Name, Size: entry.Size, SHA256: entry.SHA256 });
  });
  if (!names.has('head.cbor')) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({
    Version: 1,
    Name: request.auditlog,
    Producer: body.Producer,
    Recipient: body.Recipient,
    Files: Object.freeze(files),
  });
}

export function expectedFiles(metadata: RecordingTransportMetadata | AuditTransportMetadata) {
  return 'Files' in metadata
    ? metadata.Files.map((entry) => ({ name: entry.Name, size: entry.Size }))
    : [{ name: 'recording', size: metadata.Size }];
}

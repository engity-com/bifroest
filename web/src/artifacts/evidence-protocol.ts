import { object } from '../remember/http';
import type { ArtifactRequest } from './protocol';

export class EvidenceError extends Error {
  constructor(
    readonly code: 'input' | 'key' | 'limit' | 'verification' | 'cancelled' | 'unavailable',
  ) {
    super(`Client evidence: ${code}`);
    this.name = 'EvidenceError';
  }
}

export interface EvidenceOptions {
  readonly producer: string;
  readonly allowUntrusted: boolean;
  readonly recipient: string;
  readonly level: 'outer' | 'private';
  readonly export: boolean;
  readonly sensitive: boolean;
  readonly auditScope: '' | 'complete' | 'captured-prefix';
}

export interface EvidenceMetadata {
  readonly kind: 'recording' | 'audit';
  readonly validation: 'outer' | 'private';
  readonly trust: 'pinned' | 'untrusted';
  readonly producer: string;
  readonly expectedRecipient: string;
  readonly decryption: 'not-checked' | 'not-encrypted' | 'authenticated' | 'no-private-records';
  readonly recordingId: string;
  readonly auditScope: '' | 'complete' | 'captured-prefix';
  readonly records: string;
  readonly privateRecords: string;
  readonly outputFormat: '' | 'cast' | 'jsonl';
}

export interface VerifiedArtifact {
  readonly request: ArtifactRequest;
  readonly provenance: 'bytes-only';
  readonly metadata: EvidenceMetadata;
  readonly output: Blob | null;
}

export function evidenceOptions(request: ArtifactRequest, value: unknown): EvidenceOptions {
  try {
    const body = object(value, [
      'producer',
      'allowUntrusted',
      'recipient',
      'level',
      'export',
      'sensitive',
      'auditScope',
    ]);
    if (
      typeof body.producer !== 'string' ||
      (body.producer !== '' &&
        (!/^[0-9a-f]{64}$/u.test(body.producer) || /^0+$/u.test(body.producer))) ||
      typeof body.allowUntrusted !== 'boolean' ||
      (body.producer === '' && !body.allowUntrusted) ||
      typeof body.recipient !== 'string' ||
      (body.recipient !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(body.recipient)) ||
      (body.level !== 'outer' && body.level !== 'private') ||
      typeof body.export !== 'boolean' ||
      typeof body.sensitive !== 'boolean' ||
      ((body.export || body.sensitive) && body.level !== 'private') ||
      (request.kind === 'recording' && (body.sensitive || body.auditScope !== '')) ||
      (request.kind === 'audit' &&
        body.auditScope !== 'complete' &&
        body.auditScope !== 'captured-prefix')
    ) {
      throw new Error();
    }
    return Object.freeze({ ...body }) as unknown as EvidenceOptions;
  } catch {
    throw new EvidenceError('input');
  }
}

export function evidenceMetadata(
  request: ArtifactRequest,
  options: EvidenceOptions,
  value: unknown,
): EvidenceMetadata {
  try {
    const body = object(value, [
      'kind',
      'validation',
      'trust',
      'producer',
      'expectedRecipient',
      'decryption',
      'recordingId',
      'auditScope',
      'records',
      'privateRecords',
      'outputFormat',
    ]);
    if (
      body.kind !== request.kind ||
      (body.validation !== 'outer' && body.validation !== 'private') ||
      (options.level === 'private' && body.validation !== 'private') ||
      (body.trust !== 'pinned' && body.trust !== 'untrusted') ||
      typeof body.producer !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(body.producer) ||
      (options.producer !== '' &&
        (body.producer !== options.producer || body.trust !== 'pinned')) ||
      (options.producer === '' && body.trust !== 'untrusted') ||
      body.expectedRecipient !== options.recipient ||
      typeof body.decryption !== 'string' ||
      !['not-checked', 'not-encrypted', 'authenticated', 'no-private-records'].includes(
        body.decryption,
      ) ||
      body.recordingId !== (request.kind === 'recording' ? request.id : '') ||
      body.auditScope !== options.auditScope ||
      typeof body.records !== 'string' ||
      !/^(0|[1-9][0-9]{0,19})$/u.test(body.records) ||
      typeof body.privateRecords !== 'string' ||
      !/^(0|[1-9][0-9]{0,19})$/u.test(body.privateRecords) ||
      BigInt(body.privateRecords) > BigInt(body.records) ||
      body.outputFormat !==
        (options.export ? (request.kind === 'recording' ? 'cast' : 'jsonl') : '') ||
      (body.decryption === 'authenticated' &&
        (options.level !== 'private' || options.recipient === '')) ||
      (body.decryption === 'not-encrypted' && options.recipient !== '')
    ) {
      throw new Error();
    }
    return Object.freeze({ ...body }) as unknown as EvidenceMetadata;
  } catch {
    throw new EvidenceError('verification');
  }
}

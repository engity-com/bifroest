import {
  type GridFilterItem,
  getGridDateOperators,
  getGridNumericOperators,
  getGridSingleSelectOperators,
  getGridStringOperators,
} from '@mui/x-data-grid';
import type { ColumnFilter, Page, RecordingSummary } from '../management/protocol';
import { uuidClassic, uuidEqual } from '../shared/uuid';
import { readLocalBytes } from '../wasm/local-file';
import { EvidenceError, type VerifiedArtifact } from './evidence-protocol';
import type { ReceivedArtifact } from './protocol';
import { maximumBufferedArtifactBytes } from './protocol';

// Metadata only: no recording plaintext, keys, persistence or exports. Both
// aggregate UTF-8 size and object count are bounded before a source is published.
export const maximumLocalRecordings = 25_000;
export const maximumRecordingMetadataBytes = 16 << 20;
interface IndexedRecording {
  readonly row: RecordingSummary;
  readonly order: string;
  readonly idOrder: string;
  readonly proof: {
    readonly sha256: string;
    readonly metadata: VerifiedArtifact['metadata'];
    readonly reported: boolean;
  } | null;
}
export interface LocalRecordingIndex {
  readonly source: string;
  readonly entries: readonly IndexedRecording[];
}
const localMetadata = Symbol('completed-local-recording-verification');
const completedIndexes = new WeakSet<LocalRecordingIndex>();
const byteDigests = new WeakMap<ReceivedArtifact, string>();

// Measure the immutable Blob itself, independently of transport/server claims.
// The temporary buffer is bounded, abortable and never retained in the index.
export async function recordingByteDigest(
  image: ReceivedArtifact,
  signal: AbortSignal,
): Promise<string> {
  if (signal.aborted) {
    throw new EvidenceError('cancelled');
  }
  const cached = byteDigests.get(image);
  if (cached) {
    return cached;
  }
  const file = image.files[0];
  if (
    image.request.kind !== 'recording' ||
    image.files.length !== 1 ||
    file?.name !== 'recording' ||
    file.data.size < 1 ||
    file.data.size > maximumBufferedArtifactBytes
  ) {
    throw new EvidenceError('input');
  }
  const bytes = await readLocalBytes(file.data, signal);
  try {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    if (signal.aborted) {
      throw new EvidenceError('cancelled');
    }
    const text = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
    if (Object.isFrozen(image) && Object.isFrozen(image.files) && Object.isFrozen(file)) {
      byteDigests.set(image, text);
    }
    return text;
  } finally {
    new Uint8Array(bytes).fill(0);
  }
}
export function isLocalRecordingMetadata(row: RecordingSummary | null | undefined): boolean {
  return !!row && (row as RecordingSummary & { [localMetadata]?: boolean })[localMetadata] === true;
}
export class RecordingIndexBuilder {
  #entries: IndexedRecording[] = [];
  #bytes = 0;
  #ids = new Set<string>();
  #closed = false;
  constructor(
    readonly source: string,
    readonly reported = true,
  ) {}
  add(image: ReceivedArtifact, verified: VerifiedArtifact, measuredDigest?: string): void {
    if (this.#closed) {
      throw new EvidenceError('verification');
    }
    const metadata = verified.metadata;
    const context = metadata.recordingContext;
    if (
      image.request.kind !== 'recording' ||
      image.request.auditlog !== this.source ||
      verified.request.kind !== 'recording' ||
      verified.request.auditlog !== this.source ||
      !uuidEqual(image.request.id, verified.request.id) ||
      verified.provenance !== 'bytes-only' ||
      metadata.validation !== 'private' ||
      metadata.kind !== 'recording' ||
      !['authenticated', 'not-encrypted'].includes(metadata.decryption) ||
      !uuidEqual(metadata.recordingId, verified.request.id) ||
      !context ||
      !('Size' in image.metadata)
    ) {
      this.clear();
      throw new EvidenceError('verification');
    }
    const key = uuidClassic(verified.request.id);
    if (this.#ids.has(key)) {
      this.clear();
      throw new EvidenceError('verification');
    }
    const encrypted = metadata.decryption === 'authenticated';
    const row: RecordingSummary = Object.freeze({
      [localMetadata]: true,
      auditlog: this.source,
      id: verified.request.id,
      producerId: metadata.producer,
      format: encrypted ? 'becast-cbor/v1' : 'bcast/v1',
      status: context.status,
      startedAt: context.startedAt,
      endedAt: context.endedAt,
      containerBytes: image.metadata.Size,
      chunkCount: context.chunkCount,
      encrypted,
      verificationScope: encrypted ? 'outer' : 'full',
      ...(encrypted ? { recipientFingerprint: metadata.expectedRecipient } : {}),
      flow: context.flow,
      sessionId: context.sessionId,
      ...(context.user ? { user: context.user } : {}),
    });
    const proof =
      measuredDigest && /^[0-9a-f]{64}$/u.test(measuredDigest)
        ? Object.freeze({ sha256: measuredDigest, metadata, reported: this.reported })
        : null;
    const time = `${row.startedAt.slice(0, 19)}.${row.startedAt.slice(19, -1).replace('.', '').padEnd(9, '0')}`;
    const entry = Object.freeze({ row, order: time, idOrder: key, proof });
    const bytes = new TextEncoder().encode(JSON.stringify(entry)).byteLength;
    if (
      this.#entries.length >= maximumLocalRecordings ||
      bytes > maximumRecordingMetadataBytes - this.#bytes
    ) {
      this.clear();
      throw new EvidenceError('limit');
    }
    this.#bytes += bytes;
    this.#ids.add(key);
    this.#entries.push(entry);
  }
  finish(): LocalRecordingIndex {
    if (this.#closed) {
      throw new EvidenceError('verification');
    }
    const entries = this.#entries.splice(0);
    this.clear();
    const index = Object.freeze({ source: this.source, entries: Object.freeze(entries) });
    completedIndexes.add(index);
    return index;
  }
  clear(): void {
    this.#closed = true;
    this.#entries = [];
    this.#ids.clear();
    this.#bytes = 0;
  }
}

// Reuse only a completed actor/source-owned index AND an identical, completely
// received byte image. IDs, names, filters or a server's status alone are not proof.
export async function recordingVerificationFromIndex(
  index: LocalRecordingIndex | null,
  image: ReceivedArtifact,
  signal: AbortSignal,
): Promise<{ verified: VerifiedArtifact; reported: boolean } | null> {
  if (
    !index ||
    !completedIndexes.has(index) ||
    image.request.kind !== 'recording' ||
    image.request.auditlog !== index.source ||
    !('SHA256' in image.metadata)
  ) {
    return null;
  }
  const item = index.entries.find(({ row }) =>
    uuidEqual(row.id, image.request.kind === 'recording' ? image.request.id : ''),
  );
  if (
    !item?.proof ||
    item.proof.sha256 !== image.metadata.SHA256 ||
    item.row.containerBytes !== image.metadata.Size ||
    item.row.producerId !== image.metadata.ProducerID ||
    image.files.length !== 1 ||
    image.files[0]?.name !== 'recording' ||
    image.files[0].data.size !== image.metadata.Size
  ) {
    return null;
  }
  if ((await recordingByteDigest(image, signal)) !== item.proof.sha256) {
    return null;
  }
  return {
    reported: item.proof.reported,
    verified: Object.freeze({
      request: image.request,
      provenance: 'bytes-only',
      output: null,
      metadata: item.proof.metadata,
    }),
  };
}

export function localRecordingPage(
  index: LocalRecordingIndex,
  page: number,
  query: string,
  filter: ColumnFilter | null,
  descending: boolean,
  sensitive: boolean,
  flow?: string,
  session?: string,
): Page<RecordingSummary> {
  if (!Number.isSafeInteger(page) || page < 0) {
    throw new EvidenceError('input');
  }
  const privateFields = ['user', 'flow', 'sessionId', 'target'];
  const field = filter?.field;
  const definitions = {
    id: 'string',
    user: 'string',
    flow: 'string',
    sessionId: 'string',
    target: 'string',
    status: 'singleSelect',
    startedAt: 'dateTime',
    duration: 'number',
    containerBytes: 'number',
  } as const;
  let predicate: (row: RecordingSummary) => boolean = () => true;
  if (filter) {
    if (!Object.hasOwn(definitions, filter.field)) {
      throw new EvidenceError('input');
    }
    const type = definitions[filter.field as keyof typeof definitions];
    const operators =
      type === 'dateTime'
        ? getGridDateOperators(true)
        : type === 'number'
          ? getGridNumericOperators()
          : type === 'singleSelect'
            ? getGridSingleSelectOperators()
            : getGridStringOperators();
    const operator = operators.find((value) => value.value === filter.operator);
    if (!operator) {
      throw new EvidenceError('input');
    }
    const item: GridFilterItem = {
      field: filter.field,
      operator: filter.operator,
      value: filter.operator === 'isAnyOf' ? JSON.parse(filter.value) : filter.value,
    };
    const apply = operator.getApplyFilterFn(item, {
      field: filter.field,
      type,
      ...(type === 'singleSelect' ? { valueOptions: ['completed', 'failed', 'incomplete'] } : {}),
    }) as ((value: unknown) => boolean) | null;
    if (!apply) {
      throw new EvidenceError('input');
    }
    predicate = (row) => {
      const value =
        field === 'startedAt'
          ? new Date(row.startedAt)
          : field === 'duration'
            ? Math.max(0, (Date.parse(row.endedAt) - Date.parse(row.startedAt)) / 1000)
            : row[field as keyof RecordingSummary];
      // Missing legacy requesting users and unrecorded targets are unknown,
      // not evidence for an empty or negative private-field predicate.
      if (value === undefined || value === null) {
        return false;
      }
      if (field === 'id' || field === 'sessionId') {
        if (filter.operator === 'equals') {
          return uuidEqual(value, filter.value);
        }
        if (filter.operator === 'doesNotEqual') {
          return !uuidEqual(value, filter.value);
        }
        if (filter.operator === 'isAnyOf') {
          return (item.value as string[]).some((choice) => uuidEqual(value, choice));
        }
      }
      return apply(value);
    };
  }
  const selected = index.entries
    .filter(({ row }) => {
      if (!sensitive && (flow || session || (field && privateFields.includes(field)))) {
        return false;
      }
      if ((flow && row.flow !== flow) || (session && !uuidEqual(row.sessionId, session))) {
        return false;
      }
      if (
        query &&
        !`${row.id} ${row.status} ${sensitive ? `${row.user ?? ''} ${row.flow ?? ''} ${row.sessionId ?? ''}` : ''}`
          .toLowerCase()
          .includes(query.toLowerCase())
      ) {
        return false;
      }
      return predicate(row);
    })
    .sort((a, b) => {
      if (a.order === b.order) {
        return a.idOrder < b.idOrder ? -1 : a.idOrder > b.idOrder ? 1 : 0;
      }
      const order = a.order < b.order ? -1 : a.order > b.order ? 1 : 0;
      return descending ? -order : order;
    });
  const items = selected.slice(page * 20, page * 20 + 20).map(({ row }) =>
    sensitive
      ? row
      : Object.freeze({
          [localMetadata]: true,
          auditlog: row.auditlog,
          id: row.id,
          producerId: row.producerId,
          format: row.format,
          status: row.status,
          startedAt: row.startedAt,
          endedAt: row.endedAt,
          containerBytes: row.containerBytes,
          chunkCount: row.chunkCount,
          encrypted: row.encrypted,
          verificationScope: row.verificationScope,
          ...(row.recipientFingerprint ? { recipientFingerprint: row.recipientFingerprint } : {}),
          metadataUnavailable: true as const,
        }),
  );
  return Object.freeze({
    items: Object.freeze(items),
    next: page * 20 + 20 < selected.length ? 'local-next' : '',
    skipped: 0,
    total: selected.length,
  });
}

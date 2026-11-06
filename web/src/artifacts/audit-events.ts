import {
  type GridFilterItem,
  getGridDateOperators,
  getGridStringOperators,
} from '@mui/x-data-grid';
import type { ColumnFilter } from '../management/protocol';
import { EvidenceError } from './evidence-protocol';
import { maximumBufferedArtifactBytes } from './protocol';

const maximumRecords = 250000;
const maximumLineBytes = 1 << 20;
export interface AuditEventRow {
  id: string;
  recordedAt: Date;
  name: string;
  outcome: string;
  flow: string;
  reason: string;
  sessionId: string;
  record: Record<string, unknown>;
}
export interface AuditEventIndex {
  readonly source: Blob;
  readonly offsets: Uint32Array;
  readonly lengths: Uint32Array;
  readonly times: Float64Array;
  readonly count: number;
}
const text = (value: unknown) => (typeof value === 'string' ? value : '');
function rowFor(value: unknown, index: number): AuditEventRow {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new EvidenceError('verification');
  }
  const record = value as Record<string, unknown>;
  const event = record.event;
  if (event === null || typeof event !== 'object' || Array.isArray(event)) {
    throw new EvidenceError('verification');
  }
  const fields = event as Record<string, unknown>;
  const recordedAt = new Date(text(record.recordedAt));
  if (!Number.isFinite(recordedAt.getTime()) || text(fields.name) === '') {
    throw new EvidenceError('verification');
  }
  return {
    id: `${index}:${text(record.id)}`,
    recordedAt,
    name: text(fields.name),
    outcome: text(fields.outcome),
    flow: text(fields.flow),
    reason: text(fields.reason),
    sessionId: text(fields.sessionId),
    record,
  };
}
async function* lines(source: Blob, signal: AbortSignal) {
  if (source.size > maximumBufferedArtifactBytes) {
    throw new EvidenceError('limit');
  }
  const reader = source.stream().getReader();
  const pending = new Uint8Array(maximumLineBytes);
  let used = 0;
  let offset = 0;
  let start = 0;
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) {
        throw new EvidenceError('cancelled');
      }
      const part = await reader.read();
      if (part.done) {
        break;
      }
      for (let begin = 0; begin < part.value.byteLength; ) {
        const end = part.value.indexOf(10, begin);
        const until = end < 0 ? part.value.byteLength : end;
        const length = until - begin;
        if (length > pending.byteLength - used) {
          throw new EvidenceError('limit');
        }
        pending.set(part.value.subarray(begin, until), used);
        used += length;
        offset += length;
        begin = until;
        if (end >= 0) {
          if (used > 0) {
            yield {
              offset: start,
              length: used,
              text: new TextDecoder('utf-8', { fatal: true }).decode(pending.subarray(0, used)),
            };
          }
          begin++;
          offset++;
          start = offset;
          pending.fill(0, 0, used);
          used = 0;
        }
      }
    }
    if (used > 0) {
      yield {
        offset: start,
        length: used,
        text: new TextDecoder('utf-8', { fatal: true }).decode(pending.subarray(0, used)),
      };
    }
  } finally {
    signal.removeEventListener('abort', cancel);
    pending.fill(0);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export async function indexAuditEvents(
  source: Blob,
  signal: AbortSignal,
): Promise<AuditEventIndex> {
  const offsets = new Uint32Array(maximumRecords);
  const lengths = new Uint32Array(maximumRecords);
  const times = new Float64Array(maximumRecords);
  let count = 0;
  for await (const line of lines(source, signal)) {
    if (count >= maximumRecords) {
      throw new EvidenceError('limit');
    }
    const row = rowFor(JSON.parse(line.text) as unknown, count);
    offsets[count] = line.offset;
    lengths[count] = line.length;
    times[count] = row.recordedAt.getTime();
    count++;
    if (count % 4096 === 0) {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    }
  }
  if (signal.aborted) {
    throw new EvidenceError('cancelled');
  }
  return { source, offsets, lengths, times, count };
}
function predicate(filter: ColumnFilter | null): (row: AuditEventRow) => boolean {
  if (filter === null) {
    return () => true;
  }
  const fields = ['recordedAt', 'name', 'outcome', 'flow', 'reason', 'sessionId'];
  if (!fields.includes(filter.field)) {
    throw new EvidenceError('input');
  }
  const operators =
    filter.field === 'recordedAt' ? getGridDateOperators(true) : getGridStringOperators();
  const item: GridFilterItem = {
    field: filter.field,
    operator: filter.operator,
    value: filter.operator === 'isAnyOf' ? (JSON.parse(filter.value) as string[]) : filter.value,
  };
  const operator = operators.find((value) => value.value === item.operator);
  if (!operator) {
    throw new EvidenceError('input');
  }
  // These public built-ins operate only on their primitive column value; no
  // custom callback, row retention or application API is supplied to them.
  const apply = operator.getApplyFilterFn(item, {
    field: filter.field,
    type: filter.field === 'recordedAt' ? 'dateTime' : 'string',
  }) as ((value: unknown) => boolean) | null;
  return (row) => apply === null || apply(row[filter.field as keyof AuditEventRow]);
}
export async function auditEventPage(
  index: AuditEventIndex,
  page: number,
  query: string,
  filter: ColumnFilter | null,
  descending: boolean,
  signal: AbortSignal,
  exactFlow?: string,
): Promise<{ items: AuditEventRow[]; next: string; skipped: number }> {
  if (
    !Number.isSafeInteger(page) ||
    page < 0 ||
    page >= maximumRecords / 20 ||
    query.length > 256
  ) {
    throw new EvidenceError('input');
  }
  const matched = new Uint32Array(index.count);
  let count = 0;
  const accepts = predicate(filter);
  const tokens = query.toLowerCase().split(/\s+/u).filter(Boolean);
  if (filter === null && tokens.length === 0 && exactFlow === undefined) {
    for (let row = 0; row < index.count; row++) {
      matched[count++] = row;
    }
  } else {
    let number = 0;
    for await (const line of lines(index.source, signal)) {
      const row = rowFor(JSON.parse(line.text) as unknown, number);
      const search = [row.name, row.outcome, row.flow, row.reason, row.sessionId]
        .join(' ')
        .toLowerCase();
      if (
        (exactFlow === undefined ||
          (exactFlow === '-' ? row.flow === '' : row.flow === exactFlow)) &&
        accepts(row) &&
        tokens.every((token) => search.includes(token))
      ) {
        matched[count++] = number;
      }
      number++;
      if (number % 4096 === 0) {
        await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      }
    }
  }
  const selected = matched.subarray(0, count);
  selected.sort(
    (a, b) => ((index.times[a] ?? 0) - (index.times[b] ?? 0)) * (descending ? -1 : 1) || a - b,
  );
  const items: AuditEventRow[] = [];
  for (const number of selected.subarray(page * 20, page * 20 + 20)) {
    if (signal.aborted) {
      throw new EvidenceError('cancelled');
    }
    const from = index.offsets[number] ?? 0;
    const length = index.lengths[number] ?? 0;
    const raw = await index.source.slice(from, from + length).text();
    items.push(rowFor(JSON.parse(raw) as unknown, number));
  }
  if (signal.aborted) {
    throw new EvidenceError('cancelled');
  }
  return { items, next: (page + 1) * 20 < count ? 'next' : '', skipped: 0 };
}

export async function auditEventByID(
  index: AuditEventIndex,
  id: string,
  signal: AbortSignal,
  flow?: string,
): Promise<AuditEventRow | null> {
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(id)) {
    throw new EvidenceError('input');
  }
  let number = 0;
  let found: AuditEventRow | null = null;
  for await (const line of lines(index.source, signal)) {
    if (number >= index.count) {
      throw new EvidenceError('verification');
    }
    const row = rowFor(JSON.parse(line.text) as unknown, number);
    if (
      row.record.id === id &&
      (flow === undefined || (flow === '-' ? row.flow === '' : row.flow === flow))
    ) {
      if (found !== null) {
        throw new EvidenceError('verification');
      }
      found = row;
    }
    number++;
    if (number % 4096 === 0) {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    }
  }
  if (signal.aborted) {
    throw new EvidenceError('cancelled');
  }
  return found;
}

import { object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import { resourceID, uuidEqual } from '../shared/uuid';
import {
  auditlogName,
  type Page,
  type PageOptions,
  pageFields,
  recordingTime,
  sessionID,
} from './protocol';

export interface AuditEventOptions extends PageOptions {
  readonly flow?: string;
  readonly sessionId?: string;
  readonly id?: string;
  readonly sensitive?: boolean;
}
export interface AuditEventItem {
  readonly key: string;
  readonly id: string;
  readonly recordedAt: string;
  readonly event: Readonly<Record<string, string | number | boolean>>;
}
export interface AuditOverviewPage extends Page<AuditEventItem> {
  readonly source: {
    readonly auditlog: string;
    readonly encrypted: boolean;
    readonly sensitive: boolean;
    readonly verification: 'server-overview';
    readonly producerId?: string;
  };
}
export interface CatalogVerification {
  readonly auditlog: string;
  readonly checked: number;
  readonly full: number;
  readonly outer: number;
  readonly independent: false;
}
const idPattern = { test: resourceID };
export function auditEventFields(
  auditlog: string,
  options: AuditEventOptions,
): Record<string, string> {
  const after = options.after ?? '';
  if (
    typeof after !== 'string' ||
    after.length > 4096 ||
    (after !== '' && !/^bae1\.[A-Za-z0-9_-]+$/u.test(after))
  ) {
    throw new RememberMeError('unavailable');
  }
  const fields = pageFields({ ...options, after: '' }, ['recorded-asc', 'recorded-desc']);
  fields.after = after;
  fields.auditlog = auditlogName(auditlog);
  fields.sort = options.sort ?? 'recorded-desc';
  if (options.sessionId !== undefined) {
    fields.sessionId = sessionID(options.sessionId);
  }
  if (options.flow !== undefined) {
    if (
      !/^[A-Za-z0-9.-]{1,255}$/u.test(options.flow) ||
      options.flow === '.' ||
      options.flow === '..'
    ) {
      throw new RememberMeError('unavailable');
    }
    fields.flow = options.flow;
  }
  if (options.id) {
    if (!idPattern.test(options.id) || after !== '') {
      throw new RememberMeError('unavailable');
    }
    fields.id = options.id;
  }
  if (options.sensitive !== undefined && typeof options.sensitive !== 'boolean') {
    throw new RememberMeError('unavailable');
  }
  fields.sensitive = String(options.sensitive ?? false);
  return fields;
}
export function auditOverviewPage(
  value: unknown,
  fields: Record<string, string>,
): AuditOverviewPage {
  const envelope = object(value, ['version', 'operation', 'auditEvents', 'auditEventSource']);
  if (envelope.version !== 1 || envelope.operation !== 'audit-events.list') {
    throw new RememberMeError('unavailable');
  }
  const source = object(envelope.auditEventSource, [
    'auditlog',
    'encrypted',
    'sensitive',
    'verification',
    ...(envelope.auditEventSource !== null &&
    typeof envelope.auditEventSource === 'object' &&
    Object.hasOwn(envelope.auditEventSource, 'producerId')
      ? ['producerId']
      : []),
  ]);
  if (
    source.auditlog !== fields.auditlog ||
    typeof source.encrypted !== 'boolean' ||
    source.sensitive !== (fields.sensitive === 'true') ||
    source.verification !== 'server-overview' ||
    (source.encrypted && source.sensitive) ||
    (source.producerId !== undefined &&
      (typeof source.producerId !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(source.producerId) ||
        /^0+$/u.test(source.producerId)))
  ) {
    throw new RememberMeError('unavailable');
  }
  const page = object(envelope.auditEvents, ['items', 'next', 'skipped']);
  if (
    !Array.isArray(page.items) ||
    page.items.length > Number(fields.limit) ||
    typeof page.next !== 'string' ||
    page.next.length > 4096 ||
    (page.next !== '' && !/^bae1\.[A-Za-z0-9_-]+$/u.test(page.next)) ||
    !Number.isSafeInteger(page.skipped) ||
    Number(page.skipped) < 0
  ) {
    throw new RememberMeError('unavailable');
  }
  const allowed = [
    'name',
    'domain',
    'outcome',
    'flow',
    'connectionId',
    'sessionId',
    'operationId',
    'recordingId',
    'recordingDigest',
    'target',
    'authenticationMethod',
    'authenticationPhase',
    'authorizationKind',
    'sessionTask',
    'sessionSubsystem',
    'reason',
    'errorCategory',
    'exitCode',
    'bytesRead',
    'bytesWritten',
    'durationMillis',
    'count',
    'pty',
    'agentForwarding',
    'forcedCommand',
  ];
  const items = page.items.map((raw) => {
    const row = object(raw, ['key', 'id', 'recordedAt', 'event']);
    if (
      typeof row.key !== 'string' ||
      row.key.length > 128 ||
      !/^[0-9]+:[0-9]+:/u.test(row.key) ||
      typeof row.id !== 'string' ||
      !idPattern.test(row.id) ||
      row.id === '00000000-0000-0000-0000-000000000000' ||
      !row.key.endsWith(`:${row.id}`) ||
      (fields.id && !uuidEqual(row.id, fields.id)) ||
      row.event === null ||
      typeof row.event !== 'object' ||
      Array.isArray(row.event)
    ) {
      throw new RememberMeError('unavailable');
    }
    const event = row.event as Record<string, unknown>;
    for (const [name, item] of Object.entries(event)) {
      if (
        !allowed.includes(name) ||
        (!source.sensitive && !['name', 'domain', 'outcome'].includes(name)) ||
        !['string', 'number', 'boolean'].includes(typeof item) ||
        (typeof item === 'string' &&
          (!item.isWellFormed() || new TextEncoder().encode(item).byteLength > 4096)) ||
        (typeof item === 'number' && !Number.isSafeInteger(item))
      ) {
        throw new RememberMeError('unavailable');
      }
    }
    if (typeof event.name !== 'string' || event.name === '') {
      throw new RememberMeError('unavailable');
    }
    if (fields.sessionId && source.sensitive && !uuidEqual(event.sessionId, fields.sessionId)) {
      throw new RememberMeError('unavailable');
    }
    if (
      fields.flow &&
      source.sensitive &&
      (fields.flow === '-'
        ? event.flow !== undefined && event.flow !== ''
        : event.flow !== fields.flow)
    ) {
      throw new RememberMeError('unavailable');
    }
    return Object.freeze({
      key: row.key,
      id: row.id,
      recordedAt: recordingTime(row.recordedAt),
      event: Object.freeze(event as Record<string, string | number | boolean>),
    });
  });
  if (
    new Set(items.map((row) => row.key)).size !== items.length ||
    (fields.id && items.length > 1) ||
    (page.next !== '' && (items.length === 0 || page.next === fields.after))
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({
    items: Object.freeze(items),
    next: page.next,
    skipped: Number(page.skipped),
    source: Object.freeze(source as AuditOverviewPage['source']),
  });
}
export function catalogVerification(value: unknown, source: string): CatalogVerification {
  const envelope = object(value, ['version', 'operation', 'verification']);
  const result = object(envelope.verification, [
    'auditlog',
    'checked',
    'full',
    'outer',
    'independent',
  ]);
  if (
    envelope.version !== 1 ||
    envelope.operation !== 'recordings.verify' ||
    result.auditlog !== source ||
    result.independent !== false ||
    ![result.checked, result.full, result.outer].every(
      (value) => Number.isSafeInteger(value) && Number(value) >= 0,
    ) ||
    Number(result.full) + Number(result.outer) !== result.checked
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze(result as unknown as CatalogVerification);
}

import { object, time } from '../remember/http';
import { RememberMeError } from '../remember/protocol';

export interface PageOptions {
  readonly limit?: number;
  readonly after?: string;
}
export interface SessionOptions extends PageOptions {
  readonly flow?: string;
  readonly user?: string;
  readonly state?: 'active' | 'all' | 'new' | 'authorized' | 'disposed';
}
export interface FlowSummary {
  readonly name: string;
  readonly auditlog: string;
  readonly authorization: string;
  readonly environment: string;
}
export interface VersionInfo {
  readonly detail: 'long' | 'short';
  readonly text: string;
}

export function versionInfo(value: unknown, long: boolean): VersionInfo {
  const envelope = object(value, ['version', 'operation', 'versionInfo']);
  const result = object(envelope.versionInfo, ['detail', 'text']);
  if (
    envelope.version !== 1 ||
    envelope.operation !== 'version.show' ||
    result.detail !== (long ? 'long' : 'short') ||
    typeof result.text !== 'string' ||
    !result.text.isWellFormed() ||
    result.text.length === 0 ||
    new TextEncoder().encode(result.text).length > 64 << 10 ||
    /[\p{Cc}]/u.test(result.text.replace(/[\n\t]/gu, ''))
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({ detail: result.detail as VersionInfo['detail'], text: result.text });
}
// Server metadata only, never independent browser evidence or trust pins.
export interface AuditlogSummary {
  readonly name: string;
  readonly enabled: boolean;
  readonly recordingEnabled: boolean;
  readonly encrypted: boolean;
}
export interface RecordingSummary {
  readonly auditlog: string;
  readonly id: string;
  readonly producerId: string;
  readonly format: 'bcast/v1' | 'becast-cbor/v1';
  readonly status: 'completed' | 'failed' | 'incomplete';
  readonly startedAt: string;
  readonly endedAt: string;
  readonly containerBytes: number;
  readonly chunkCount: number;
  readonly encrypted: boolean;
  readonly recipientFingerprint?: string;
  readonly verificationScope: 'outer' | 'full';
}
export interface SessionItem {
  readonly id: string;
  readonly flow: string;
  readonly state: string;
  readonly user: string;
  readonly remote: string;
  readonly createdAt: string;
  readonly lastAccessed?: string;
  readonly validUntil?: string;
  readonly owner: { readonly issuer: string; readonly subject: string } | null;
  readonly policyLimited?: boolean;
}
export interface Page<T> {
  readonly items: readonly T[];
  readonly next: string;
  readonly skipped: number;
}

function text(value: unknown, maximum: number): string {
  if (
    typeof value !== 'string' ||
    !value.isWellFormed() ||
    new TextEncoder().encode(value).length > maximum ||
    /[\p{Cc}]/u.test(value)
  ) {
    throw new RememberMeError('unavailable');
  }
  return value;
}
export function pageFields(options: PageOptions): Record<string, string> {
  const limit = options.limit ?? 20;
  const after = options.after ?? '';
  if (
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 20 ||
    typeof after !== 'string' ||
    after.length > 4096 ||
    (after !== '' && !/^bmp1\.[A-Za-z0-9_-]+$/u.test(after))
  ) {
    throw new RememberMeError('unavailable');
  }
  return { limit: String(limit), after };
}
export function sessionFields(options: SessionOptions): Record<string, string> {
  const state = options.state ?? 'active';
  if (!['active', 'all', 'new', 'authorized', 'disposed'].includes(state)) {
    throw new RememberMeError('unavailable');
  }
  return {
    ...pageFields(options),
    flow: text(options.flow ?? '', 255),
    user: text(options.user ?? '', 256),
    state,
  };
}
export function auditlogName(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9.-]{1,128}$/u.test(value) ||
    value === '.' ||
    value === '..'
  ) {
    throw new RememberMeError('unavailable');
  }
  return value;
}
function auditlog(value: unknown): AuditlogSummary {
  const row = object(value, ['name', 'enabled', 'recordingEnabled', 'encrypted']);
  if (
    typeof row.enabled !== 'boolean' ||
    typeof row.recordingEnabled !== 'boolean' ||
    typeof row.encrypted !== 'boolean'
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({
    name: auditlogName(row.name),
    enabled: row.enabled,
    recordingEnabled: row.recordingEnabled,
    encrypted: row.encrypted,
  });
}
function recording(value: unknown): RecordingSummary {
  const optional =
    value !== null && typeof value === 'object' && Object.hasOwn(value, 'recipientFingerprint')
      ? ['recipientFingerprint']
      : [];
  const row = object(value, [
    'auditlog',
    'id',
    'producerId',
    'format',
    'status',
    'startedAt',
    'endedAt',
    'containerBytes',
    'chunkCount',
    'encrypted',
    'verificationScope',
    ...optional,
  ]);
  if (
    typeof row.id !== 'string' ||
    !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(row.id) ||
    /^0{8}-(?:0{4}-){3}0{12}$/u.test(row.id) ||
    typeof row.producerId !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(row.producerId) ||
    /^0+$/u.test(row.producerId) ||
    typeof row.status !== 'string' ||
    !['completed', 'failed', 'incomplete'].includes(row.status) ||
    typeof row.encrypted !== 'boolean' ||
    row.format !== (row.encrypted ? 'becast-cbor/v1' : 'bcast/v1') ||
    row.verificationScope !== (row.encrypted ? 'outer' : 'full') ||
    !Number.isSafeInteger(row.containerBytes) ||
    (row.containerBytes as number) < 1 ||
    (row.containerBytes as number) > 32 * 2 ** 30 ||
    !Number.isSafeInteger(row.chunkCount) ||
    (row.chunkCount as number) < 1 ||
    (row.encrypted &&
      (typeof row.recipientFingerprint !== 'string' ||
        !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(row.recipientFingerprint))) ||
    (!row.encrypted && row.recipientFingerprint !== undefined)
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({
    auditlog: auditlogName(row.auditlog),
    id: row.id,
    producerId: row.producerId,
    format: row.format as RecordingSummary['format'],
    status: row.status as RecordingSummary['status'],
    startedAt: time(row.startedAt),
    endedAt: time(row.endedAt),
    containerBytes: row.containerBytes as number,
    chunkCount: row.chunkCount as number,
    encrypted: row.encrypted,
    verificationScope: row.verificationScope as RecordingSummary['verificationScope'],
    ...(row.recipientFingerprint === undefined
      ? {}
      : { recipientFingerprint: row.recipientFingerprint as string }),
  });
}
function flow(value: unknown): FlowSummary {
  const row = object(value, ['name', 'auditlog', 'authorization', 'environment']);
  return Object.freeze({
    name: text(row.name, 255),
    auditlog: text(row.auditlog, 255),
    authorization: text(row.authorization, 255),
    environment: text(row.environment, 255),
  });
}
export function session(value: unknown): SessionItem {
  const optional = ['lastAccessed', 'validUntil', 'policyLimited'].filter(
    (field) => value !== null && typeof value === 'object' && Object.hasOwn(value, field),
  );
  const row = object(value, [
    'id',
    'flow',
    'state',
    'user',
    'remote',
    'createdAt',
    'owner',
    ...optional,
  ]);
  if (
    typeof row.id !== 'string' ||
    !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(row.id) ||
    !['new', 'authorized', 'disposed'].includes(row.state as string)
  ) {
    throw new RememberMeError('unavailable');
  }
  let owner: SessionItem['owner'] = null;
  if (row.policyLimited !== undefined && row.policyLimited !== true) {
    throw new RememberMeError('unavailable');
  }
  if (row.policyLimited === true && row.owner !== null) {
    throw new RememberMeError('unavailable');
  }
  if (row.owner !== null) {
    const selected = object(row.owner, ['issuer', 'subject']);
    owner = Object.freeze({
      issuer: text(selected.issuer, 1024),
      subject: text(selected.subject, 1024),
    });
    if (owner.issuer === '' || owner.subject === '') {
      throw new RememberMeError('unavailable');
    }
  }
  return Object.freeze({
    id: row.id,
    flow: text(row.flow, 255),
    state: row.state as string,
    user: text(row.user, 8192),
    remote: text(row.remote, 8192),
    createdAt: time(row.createdAt),
    owner,
    ...(row.lastAccessed === undefined ? {} : { lastAccessed: time(row.lastAccessed) }),
    ...(row.validUntil === undefined ? {} : { validUntil: time(row.validUntil) }),
    ...(row.policyLimited === true ? { policyLimited: true } : {}),
  });
}
export function page<T>(
  value: unknown,
  kind: 'flows' | 'sessions' | 'auditlogs' | 'recordings',
  maximum: number,
): Page<T> {
  const envelope = object(value, ['version', 'operation', kind]);
  if (envelope.version !== 1 || envelope.operation !== `${kind}.list`) {
    throw new RememberMeError('unavailable');
  }
  const result = object(envelope[kind], ['items', 'next', 'skipped']);
  if (
    !Array.isArray(result.items) ||
    result.items.length > maximum ||
    typeof result.next !== 'string' ||
    result.next.length > 4096 ||
    (result.next !== '' && !/^bmp1\.[A-Za-z0-9_-]+$/u.test(result.next)) ||
    !Number.isSafeInteger(result.skipped) ||
    (result.skipped as number) < 0
  ) {
    throw new RememberMeError('unavailable');
  }
  const items = Object.freeze(
    result.items.map((value) =>
      kind === 'flows'
        ? flow(value)
        : kind === 'sessions'
          ? session(value)
          : kind === 'auditlogs'
            ? auditlog(value)
            : recording(value),
    ),
  ) as readonly T[];
  return Object.freeze({ items, next: result.next, skipped: result.skipped as number });
}
export function detail(value: unknown): SessionItem {
  const result = object(value, ['version', 'operation', 'session']);
  if (result.version !== 1 || result.operation !== 'sessions.show') {
    throw new RememberMeError('unavailable');
  }
  return session(result.session);
}

import { object, time } from '../remember/http';
import { RememberMeError } from '../remember/protocol';

export interface PageOptions { readonly limit?: number; readonly after?: string; }
export interface SessionOptions extends PageOptions { readonly flow?: string; readonly user?: string; readonly state?: 'active' | 'all' | 'new' | 'authorized' | 'disposed'; }
export interface FlowSummary { readonly name: string; readonly auditlog: string; readonly authorization: string; readonly environment: string; }
export interface SessionItem {
  readonly id: string; readonly flow: string; readonly state: string; readonly user: string; readonly remote: string;
  readonly createdAt: string; readonly lastAccessed?: string; readonly validUntil?: string;
  readonly owner: { readonly issuer: string; readonly subject: string } | null;
  readonly policyLimited?: boolean;
}
export interface Page<T> { readonly items: readonly T[]; readonly next: string; readonly skipped: number; }

function text(value: unknown, maximum: number): string {
  if (typeof value !== 'string' || !value.isWellFormed() || new TextEncoder().encode(value).length > maximum || /[\p{Cc}]/u.test(value)) throw new RememberMeError('unavailable');
  return value;
}
export function pageFields(options: PageOptions): Record<string, string> {
  const limit = options.limit ?? 20, after = options.after ?? '';
  if (!Number.isInteger(limit) || limit < 1 || limit > 20 || typeof after !== 'string' || after.length > 4096 || after !== '' && !/^bmp1\.[A-Za-z0-9_-]+$/u.test(after)) throw new RememberMeError('unavailable');
  return { limit: String(limit), after };
}
export function sessionFields(options: SessionOptions): Record<string, string> {
  const state = options.state ?? 'active';
  if (!['active', 'all', 'new', 'authorized', 'disposed'].includes(state)) throw new RememberMeError('unavailable');
  return { ...pageFields(options), flow: text(options.flow ?? '', 255), user: text(options.user ?? '', 256), state };
}
function flow(value: unknown): FlowSummary {
  const row = object(value, ['name', 'auditlog', 'authorization', 'environment']);
  return Object.freeze({ name: text(row.name, 255), auditlog: text(row.auditlog, 255), authorization: text(row.authorization, 255), environment: text(row.environment, 255) });
}
export function session(value: unknown): SessionItem {
  const optional = ['lastAccessed', 'validUntil', 'policyLimited'].filter(field => value !== null && typeof value === 'object' && Object.hasOwn(value, field));
  const row = object(value, ['id', 'flow', 'state', 'user', 'remote', 'createdAt', 'owner', ...optional]);
  if (typeof row.id !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(row.id) || !['new', 'authorized', 'disposed'].includes(row.state as string)) throw new RememberMeError('unavailable');
  let owner: SessionItem['owner'] = null;
  if (row.policyLimited !== undefined && row.policyLimited !== true) throw new RememberMeError('unavailable');
  if (row.policyLimited === true && row.owner !== null) throw new RememberMeError('unavailable');
  if (row.owner !== null) { const selected = object(row.owner, ['issuer', 'subject']); owner = Object.freeze({ issuer: text(selected.issuer, 1024), subject: text(selected.subject, 1024) }); if (owner.issuer === '' || owner.subject === '') throw new RememberMeError('unavailable'); }
  return Object.freeze({ id: row.id, flow: text(row.flow, 255), state: row.state as string, user: text(row.user, 8192), remote: text(row.remote, 8192), createdAt: time(row.createdAt), owner,
    ...(row.lastAccessed === undefined ? {} : { lastAccessed: time(row.lastAccessed) }), ...(row.validUntil === undefined ? {} : { validUntil: time(row.validUntil) }), ...(row.policyLimited === true ? { policyLimited: true } : {}) });
}
export function page<T>(value: unknown, kind: 'flows' | 'sessions', maximum: number): Page<T> {
  const envelope = object(value, ['version', 'operation', kind]);
  if (envelope.version !== 1 || envelope.operation !== `${kind}.list`) throw new RememberMeError('unavailable');
  const result = object(envelope[kind], ['items', 'next', 'skipped']);
  if (!Array.isArray(result.items) || result.items.length > maximum || typeof result.next !== 'string' || result.next.length > 4096 || result.next !== '' && !/^bmp1\.[A-Za-z0-9_-]+$/u.test(result.next) || !Number.isSafeInteger(result.skipped) || (result.skipped as number) < 0) throw new RememberMeError('unavailable');
  const items = Object.freeze(result.items.map(value => kind === 'flows' ? flow(value) : session(value))) as readonly T[];
  return Object.freeze({ items, next: result.next, skipped: result.skipped as number });
}
export function detail(value: unknown): SessionItem {
  const result = object(value, ['version', 'operation', 'session']);
  if (result.version !== 1 || result.operation !== 'sessions.show') throw new RememberMeError('unavailable');
  return session(result.session);
}

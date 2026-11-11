import type { Scope } from '../remember/protocol';
import { validateScope } from '../remember/protocol';
import { resourceID, uuidBytes } from '../shared/uuid';

export type ManagementPage = 'server' | 'sessions' | 'recordings' | 'auditlogs' | 'version';
export interface ManagementLocation {
  readonly managementFlow: string;
  readonly page: ManagementPage;
  readonly flow?: string;
  readonly id?: string;
  readonly auditlog?: string;
  readonly auditlogHint?: string;
  readonly eventHint?: string;
  readonly recordingHint?: string;
  readonly sessionId?: string;
}
const name = (value: string) =>
  /^[A-Za-z0-9.-]{1,255}$/u.test(value) && value !== '.' && value !== '..';
const log = (value: string) =>
  /^[A-Za-z0-9._-]{1,128}$/u.test(value) && value !== '.' && value !== '..';
const id = (value: string) => uuidBytes(value) !== null;
export function parseManagementLocation(
  scope: Scope,
  current: { pathname: string; search: string; hash: string },
): ManagementLocation | null {
  try {
    validateScope(scope);
  } catch {
    return null;
  }
  if (
    current.hash !== '' ||
    current.search.length > 512 ||
    current.search === '?' ||
    current.pathname.length > 2048 ||
    current.pathname.includes('%') ||
    current.pathname.includes('\\')
  ) {
    return null;
  }
  const prefix = `/${scope.slug ? `${scope.slug}/` : ''}`;
  if (!current.pathname.startsWith(prefix)) {
    return null;
  }
  const parts = current.pathname.slice(prefix.length).split('/');
  const managementFlow = parts.shift();
  if (!managementFlow || !name(managementFlow) || parts.some((part) => part === '')) {
    return null;
  }
  const section = parts.shift();
  let result: ManagementLocation;
  if (section === undefined) {
    result = { managementFlow, page: 'server' };
  } else if (section === 'version' && parts.length === 0) {
    result = { managementFlow, page: 'version' };
  } else if ((section === 'sessions' || section === 'recordings') && parts.length <= 2) {
    const [flow, entry] = parts;
    if ((flow !== undefined && !name(flow)) || (entry !== undefined && !id(entry))) {
      return null;
    }
    result = {
      managementFlow,
      page: section,
      ...(flow ? { flow } : {}),
      ...(entry ? { id: entry } : {}),
    };
  } else if (
    section === 'auditlogs' &&
    parts.length >= 2 &&
    parts.length <= 3 &&
    (parts[1] === 'events' || parts[1] === 'recordings')
  ) {
    const [source, collection, entry] = parts;
    if (!source || !log(source) || (entry !== undefined && !id(entry))) {
      return null;
    }
    result = {
      managementFlow,
      page: collection === 'events' ? 'auditlogs' : 'recordings',
      ...(collection === 'events' ? { auditlog: source } : { auditlogHint: source }),
      ...(entry ? { id: entry } : {}),
    };
  } else if (section === 'auditlogs' && parts.length <= 3) {
    const [auditlog, flow, event] = parts;
    if (
      (auditlog !== undefined && !log(auditlog)) ||
      (flow !== undefined && !name(flow)) ||
      (event !== undefined && !id(event))
    ) {
      return null;
    }
    result = {
      managementFlow,
      page: 'auditlogs',
      ...(auditlog ? { auditlog } : {}),
      ...(flow ? { flow } : {}),
      ...(event ? { id: event } : {}),
    };
  } else {
    return null;
  }
  const query = new URLSearchParams(current.search);
  if (current.search !== '' && !current.search.startsWith('?')) {
    return null;
  }
  const seen = new Set<string>();
  for (const [key, value] of query) {
    if (seen.has(key)) {
      return null;
    }
    seen.add(key);
    if (
      key === 'sessionId' &&
      (result.page === 'recordings' || result.page === 'auditlogs') &&
      resourceID(value)
    ) {
      result = { ...result, sessionId: value };
    } else if (
      key === 'flow' &&
      (result.page === 'auditlogs' || result.page === 'recordings') &&
      result.flow === undefined &&
      name(value)
    ) {
      result = { ...result, flow: value };
    } else if (
      key === 'auditlog' &&
      result.page === 'recordings' &&
      result.auditlogHint === undefined &&
      log(value)
    ) {
      result = { ...result, auditlogHint: value };
    } else if (
      key === 'event' &&
      result.page === 'auditlogs' &&
      result.auditlog &&
      result.id === undefined &&
      id(value)
    ) {
      result = { ...result, eventHint: value };
    } else if (
      key === 'recording' &&
      result.page === 'recordings' &&
      result.id === undefined &&
      id(value)
    ) {
      result = { ...result, recordingHint: value };
    } else {
      return null;
    }
  }
  return result;
}
export function managementPath(scope: Scope, route: ManagementLocation): string {
  let path = `/${scope.slug ? `${scope.slug}/` : ''}${route.managementFlow}`;
  const source =
    route.page === 'auditlogs'
      ? route.auditlog
      : route.page === 'recordings'
        ? route.auditlogHint
        : undefined;
  const collection = !!source && (route.page === 'auditlogs' || route.page === 'recordings');
  if (collection) {
    path += `/auditlogs/${source}/${route.page === 'auditlogs' ? 'events' : 'recordings'}`;
    if (route.id) {
      path += `/${route.id}`;
    }
  } else if (route.page !== 'server') {
    path += `/${route.page}`;
  }
  if (!collection && route.page !== 'auditlogs' && route.flow) {
    path += `/${route.flow}`;
    if (route.id) {
      path += `/${route.id}`;
    }
  }
  const query = new URLSearchParams();
  if (route.auditlogHint && !collection) {
    query.set('auditlog', route.auditlogHint);
  }
  if ((collection || route.page === 'auditlogs') && route.flow) {
    query.set('flow', route.flow);
  }
  if (route.eventHint) {
    query.set('event', route.eventHint);
  }
  if (route.recordingHint) {
    query.set('recording', route.recordingHint);
  }
  if (route.sessionId) {
    query.set('sessionId', route.sessionId);
  }
  const search = query.size ? `?${query}` : '';
  const parsed = parseManagementLocation(scope, { pathname: path, search, hash: '' });
  if (!parsed || JSON.stringify(parsed) !== JSON.stringify(route)) {
    // Compare canonical properties, independent of caller object insertion order.
    if (
      !parsed ||
      Object.keys(parsed).length !== Object.keys(route).length ||
      Object.entries(parsed).some(
        ([key, value]) => route[key as keyof ManagementLocation] !== value,
      )
    ) {
      throw new Error('Invalid management location');
    }
  }
  return path + search;
}

export function exactFlow(
  filter: { field: string; operator: string; value: string } | null,
): string | undefined {
  return filter?.field === 'flow' && filter.operator === 'equals' && name(filter.value)
    ? filter.value
    : undefined;
}

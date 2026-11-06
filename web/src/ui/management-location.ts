import type { Scope } from '../remember/protocol';
import { validateScope } from '../remember/protocol';

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
}
const name = (value: string) =>
  /^[A-Za-z0-9.-]{1,255}$/u.test(value) && value !== '.' && value !== '..';
const log = (value: string) =>
  /^[A-Za-z0-9._-]{1,128}$/u.test(value) && value !== '.' && value !== '..';
const id = (value: string) => /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(value);
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
    if (key === 'auditlog' && result.page === 'recordings' && log(value)) {
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
  if (route.page !== 'server') {
    path += `/${route.page}`;
  }
  if (route.page === 'auditlogs') {
    if (route.auditlog) {
      path += `/${route.auditlog}`;
      if (route.flow) {
        path += `/${route.flow}`;
        if (route.id) {
          path += `/${route.id}`;
        }
      }
    }
  } else if (route.flow) {
    path += `/${route.flow}`;
    if (route.id) {
      path += `/${route.id}`;
    }
  }
  const query = new URLSearchParams();
  if (route.auditlogHint) {
    query.set('auditlog', route.auditlogHint);
  }
  if (route.eventHint) {
    query.set('event', route.eventHint);
  }
  if (route.recordingHint) {
    query.set('recording', route.recordingHint);
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

import { type Scope, validateScope } from '../remember/protocol';
import { resourceID, uuidText } from '../shared/uuid';
import {
  type ManagementLocation,
  managementPath,
  parseManagementLocation,
} from './management-location';

export interface HashTarget {
  readonly scope: Scope;
  readonly connection: string | null;
  readonly management: ManagementLocation | null;
}
const dummyFlow = 'management';
const uuidFields = ['id', 'recordingHint', 'eventHint', 'sessionId'] as const;
function ids(route: ManagementLocation, format: (value: string) => string): ManagementLocation {
  const result = { ...route };
  for (const key of uuidFields) {
    const value = route[key];
    if (value !== undefined) {
      Object.assign(result, { [key]: format(value) });
    }
  }
  return result;
}

// The entire fragment is public navigation intent, never a credential or grant.
// A nested slug is ONE encoded component; an empty first component is root.
export function parseHashTarget(origin: string, hash: string): HashTarget | null {
  if (!hash.startsWith('#') || hash.length > 4096 || hash.includes('\\')) {
    return null;
  }
  const input = hash.slice(1);
  const slash = input.indexOf('/');
  const encoded = slash < 0 ? input : input.slice(0, slash);
  let slug: string;
  try {
    slug = decodeURIComponent(encoded);
    validateScope({ origin, slug });
  } catch {
    return null;
  }
  if (encodeURIComponent(slug) !== encoded) {
    return null;
  }
  const scope = { origin, slug };
  if (slash < 0) {
    return { scope, connection: null, management: null };
  }
  const rest = input.slice(slash + 1);
  const end = rest.indexOf('/');
  const connectionText = end < 0 ? rest : rest.slice(0, end);
  if (connectionText !== '-' && !resourceID(connectionText)) {
    return null;
  }
  const connection = connectionText === '-' ? '-' : uuidText(connectionText);
  if (end < 0) {
    return { scope, connection, management: null };
  }
  const resource = rest.slice(end);
  const question = resource.indexOf('?');
  const path = question < 0 ? resource : resource.slice(0, question);
  const search = question < 0 ? '' : resource.slice(question);
  const parsed = parseManagementLocation(
    { origin, slug: '' },
    { pathname: `/${dummyFlow}${path}`, search, hash: '' },
  );
  if (!parsed) {
    return null;
  }
  return { scope, connection, management: { ...ids(parsed, uuidText), managementFlow: '' } };
}

export function hashPath(
  scope: Scope,
  connection: string | null,
  management?: ManagementLocation,
): string {
  validateScope(scope);
  if (connection !== null && connection !== '-' && !resourceID(connection)) {
    throw new Error('Invalid UI connection ID');
  }
  let hash = `#${encodeURIComponent(scope.slug)}`;
  if (connection === null) {
    if (management) {
      throw new Error('A target needs a connection or placeholder');
    }
    return `/${hash}`;
  }
  hash += `/${connection === '-' ? '-' : uuidText(connection)}`;
  if (management) {
    const route = ids({ ...management, managementFlow: dummyFlow }, uuidText);
    const legacy = managementPath({ origin: scope.origin, slug: '' }, route);
    if (management.page !== 'server') {
      hash += legacy.slice(dummyFlow.length + 1);
    }
  }
  const parsed = parseHashTarget(scope.origin, hash);
  if (!parsed) {
    throw new Error('Invalid hash navigation target');
  }
  return `/${hash}`;
}

export function bookmarkPath(scope: Scope, management?: ManagementLocation): string {
  return hashPath(scope, '-', management);
}

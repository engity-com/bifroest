import {
    type ManagementLocation,
    managementPath,
    parseManagementLocation,
} from '../application/management-location';
import { type Scope, validateScope } from '../remember/protocol';
import { publicPath } from '../shared/upstream';
import { resourceID, uuidText } from '../shared/uuid';

export interface HashTarget {
    readonly scope: Scope;
    readonly user: string | null;
    readonly connection: string | null;
    readonly management: ManagementLocation | null;
}
const dummyFlow = 'management';
const uuidFields = ['id', 'recordingHint', 'eventHint', 'sessionId'] as const;
function validUser(user: string): boolean {
    return user.length > 0 && user.length <= 256 && !/[\p{Cc}\p{Cs}]/u.test(user);
}
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
    const head = slash < 0 ? input : input.slice(0, slash);
    const at = head.indexOf('@');
    const encoded = at < 0 ? head : head.slice(at + 1);
    let user: string | null = null;
    let slug: string;
    try {
        if (at >= 0) {
            const encodedUser = head.slice(0, at);
            user = decodeURIComponent(encodedUser);
            if (!validUser(user) || encodeURIComponent(user) !== encodedUser) {
                return null;
            }
        }
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
        return { scope, user, connection: null, management: null };
    }
    const rest = input.slice(slash + 1);
    const end = rest.indexOf('/');
    const connectionText = end < 0 ? rest : rest.slice(0, end);
    if (connectionText !== '-' && !resourceID(connectionText)) {
        return null;
    }
    const connection = connectionText === '-' ? '-' : uuidText(connectionText);
    if (end < 0) {
        return { scope, user, connection, management: null };
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
    return {
        scope,
        user,
        connection,
        management: { ...ids(parsed, uuidText), managementFlow: '' },
    };
}

export function hashPath(
    scope: Scope,
    connection: string | null,
    management?: ManagementLocation,
    user?: string | null,
): string {
    validateScope(scope);
    if (connection !== null && connection !== '-' && !resourceID(connection)) {
        throw new Error('Invalid UI connection ID');
    }
    if (user && !validUser(user)) {
        throw new Error('Invalid login user');
    }
    let hash = `#${user ? `${encodeURIComponent(user)}@` : ''}${encodeURIComponent(scope.slug)}`;
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

export function bookmarkPath(
    scope: Scope,
    management?: ManagementLocation,
    user?: string | null,
): string {
    return publicPath(hashPath(scope, '-', management, user));
}

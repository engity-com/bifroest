import { type ReactNode, useCallback, useEffect, useLayoutEffect, useMemo, useRef } from 'react';
import {
    type BlockerFunction,
    createBrowserRouter,
    type DataRouter,
    type Location,
    useBlocker,
    useLocation,
    useNavigate,
} from 'react-router';
import { type Scope, validateScope } from '../remember/protocol';
import { newViewID } from '../shared/uuid';
import type { ConnectionView } from '../workspace/model';
import { hashPath, parseHashTarget } from './hash-route';
import { type ManagementLocation, parseManagementLocation } from './management-location';

export interface SlugRoute {
    readonly scope: Scope | null;
    readonly key: string;
    readonly view: number | null;
    readonly management: ManagementLocation | null;
    readonly canonicalizing: boolean;
    navigate(slug: string, replace?: boolean): Promise<void>;
    activate(
        slug: string,
        view: number,
        replace?: boolean,
        management?: ManagementLocation,
        routeId?: string,
    ): Promise<void>;
}

interface ViewIntent {
    readonly generation: string;
    readonly view: number;
}

function viewIntent(state: unknown): ViewIntent | null {
    if (state === null || typeof state !== 'object' || Array.isArray(state)) {
        return null;
    }
    const value = state as Record<string, unknown>;
    return Object.keys(value).sort().join(',') === 'generation,view' &&
        typeof value.generation === 'string' &&
        typeof value.view === 'number' &&
        Number.isSafeInteger(value.view) &&
        value.view > 0
        ? (value as unknown as ViewIntent)
        : null;
}

// Keep the workspace mounted: routing owns URLs/history, not discovery or access.
export function createSlugRouter(element: ReactNode): DataRouter {
    return createBrowserRouter([{ id: 'workspace', path: '*', element }]);
}

export function scopeFromSlugLocation(
    origin: string,
    current: Pick<Location, 'pathname' | 'search' | 'hash'>,
): Scope | null {
    if (
        !current.pathname.startsWith('/') ||
        current.pathname === '/api' ||
        current.pathname.startsWith('/api/') ||
        current.search !== '' ||
        current.hash !== ''
    ) {
        return null;
    }
    const scope = {
        origin,
        slug: current.pathname === '/' ? '' : current.pathname.slice(1),
    };
    try {
        // Validate the original path without decoding or normalizing aliases.
        validateScope(scope);
        return scope;
    } catch {
        return null;
    }
}

export function useSlugRoute(
    blocked: boolean,
    onBlocked: () => void,
    slugs: readonly string[] = [],
    connections: readonly ConnectionView[] = [],
): SlugRoute {
    const incoming = useLocation();
    const accepted = useRef(incoming);
    const repairing = useRef(false);
    const blockedChange =
        blocked &&
        (incoming.pathname !== accepted.current.pathname ||
            incoming.search !== accepted.current.search ||
            incoming.hash !== accepted.current.hash ||
            JSON.stringify(viewIntent(incoming.state)) !==
                JSON.stringify(viewIntent(accepted.current.state)));
    // Browser-created fragment history entries need not have React Router's idx.
    // Even when its POP blocker cannot stop them, never apply them to an owner
    // while an operation is locked; restore only the last committed location.
    const current = blockedChange ? accepted.current : incoming;
    useLayoutEffect(() => {
        if (!blockedChange) {
            accepted.current = incoming;
        }
    }, [incoming, blockedChange]);
    const activation = useRef<{ key: string; slug: string; view: number; path: string } | null>(
        null,
    );
    useLayoutEffect(() => {
        if (activation.current?.key !== current.key) {
            activation.current = null;
        }
    }, [current.key]);
    const blockedNow = useRef(blocked);
    useLayoutEffect(() => {
        // React Router registers blocker functions in a passive effect. Child
        // workspace effects may select a newly authorized view before that update;
        // always consult the latest committed boundary, not the preceding login.
        blockedNow.current = blocked;
    }, [blocked]);
    // Never persist this generation. A reload must turn even a valid old view ID
    // into a fresh login intent, not reconnect or recover a grant.
    const generation = useRef(newViewID());
    const publicIds = useRef(new Map<number, string>());
    for (const connection of connections) {
        if (connection.routeId) {
            publicIds.current.set(connection.id, connection.routeId);
        }
    }
    const intent = viewIntent(current.state);
    const legacyView = intent?.generation === generation.current ? intent.view : null;
    const routerNavigate = useNavigate();
    useLayoutEffect(() => {
        if (blockedChange) {
            const previous = accepted.current;
            repairing.current = true;
            onBlocked();
            void Promise.resolve(
                routerNavigate(previous.pathname + previous.search + previous.hash, {
                    replace: true,
                    state: previous.state,
                }),
            ).finally(() => {
                repairing.current = false;
            });
        }
    }, [blockedChange, routerNavigate, onBlocked]);
    const origin = window.location.origin;
    const { pathname, search, hash } = current;
    const fragment = useMemo(
        () => (hash === '' ? null : search === '' ? parseHashTarget(origin, hash) : null),
        [origin, hash, search],
    );
    const hashOwner =
        fragment?.connection && fragment.connection !== '-'
            ? connections.find(
                  (value) =>
                      publicIds.current.get(value.id) === fragment.connection &&
                      value.scope.origin === fragment.scope.origin &&
                      value.scope.slug === fragment.scope.slug,
              )
            : undefined;
    const view = hash !== '' ? (hashOwner?.id ?? null) : legacyView;
    const choices = JSON.stringify([...new Set(slugs)]);
    const resolved = useMemo(() => {
        if (hash !== '') {
            const parsed = search === '' ? parseHashTarget(origin, hash) : null;
            return parsed
                ? { scope: parsed.scope, management: parsed.management }
                : { scope: null, management: null };
        }
        const candidates = (JSON.parse(choices) as string[])
            .map((slug) => ({
                scope: { origin, slug },
                management: parseManagementLocation({ origin, slug }, { pathname, search, hash }),
            }))
            .filter((value) => value.management !== null);
        // Preserve exact access-link selection when its public metadata identifies
        // that slug. Do not decode or infer aliases from an unrelated active grant.
        const legacy = scopeFromSlugLocation(origin, { pathname, search, hash });
        if (legacy && (JSON.parse(choices) as string[]).includes(legacy.slug)) {
            return { scope: legacy, management: null };
        }
        if (candidates.length === 1) {
            return candidates[0] ?? { scope: null, management: null };
        }
        return { scope: candidates.length === 0 ? legacy : null, management: null };
    }, [origin, pathname, search, hash, choices]);
    const scope = resolved.scope;
    const ownerFlow = hashOwner?.access.snapshot().flow?.name ?? 'management';
    const previousTarget = current.state as {
        legacyHash?: unknown;
        legacyManagementFlow?: unknown;
    } | null;
    const legacyExpectedFlow =
        previousTarget?.legacyHash === hash &&
        typeof previousTarget.legacyManagementFlow === 'string' &&
        /^[A-Za-z0-9.-]{1,255}$/u.test(previousTarget.legacyManagementFlow)
            ? previousTarget.legacyManagementFlow
            : null;
    const management = useMemo(
        () =>
            resolved.management && hashOwner
                ? {
                      ...resolved.management,
                      managementFlow: ownerFlow,
                  }
                : resolved.management && legacyExpectedFlow
                  ? { ...resolved.management, managementFlow: legacyExpectedFlow }
                  : hashOwner?.access.snapshot().environment === 'management'
                    ? { managementFlow: ownerFlow, page: 'server' as const }
                    : resolved.management,
        [resolved.management, hashOwner, ownerFlow, legacyExpectedFlow],
    );
    const missingConnection = !!fragment?.connection && fragment.connection !== '-' && !hashOwner;
    const canonicalizing =
        !blocked &&
        ((missingConnection && activation.current?.key !== current.key) ||
            (!!fragment && pathname !== '/') ||
            (hash === '' && !!scope && (pathname !== '/' || search !== '')));
    useLayoutEffect(() => {
        if (blocked) {
            return;
        }
        if (missingConnection && fragment && activation.current?.key !== current.key) {
            void routerNavigate(hashPath(fragment.scope, '-', fragment.management ?? undefined), {
                replace: true,
                state: null,
            });
        } else if (fragment && pathname !== '/') {
            void routerNavigate(
                hashPath(fragment.scope, fragment.connection, fragment.management ?? undefined),
                { replace: true, state: current.state },
            );
        } else if (hash === '' && scope && (pathname !== '/' || search !== '')) {
            const path = hashPath(
                scope,
                resolved.management ? '-' : null,
                resolved.management ?? undefined,
            );
            void routerNavigate(path, {
                replace: true,
                state: resolved.management
                    ? {
                          legacyHash: path.slice(1),
                          legacyManagementFlow: resolved.management.managementFlow,
                      }
                    : null,
            });
        }
    }, [
        missingConnection,
        blocked,
        fragment,
        routerNavigate,
        pathname,
        search,
        hash,
        scope,
        resolved.management,
        current.state,
        current.key,
    ]);
    const shouldBlock = useCallback<BlockerFunction>(
        ({ currentLocation, nextLocation }) =>
            !(
                repairing.current &&
                nextLocation.pathname === accepted.current.pathname &&
                nextLocation.search === accepted.current.search &&
                nextLocation.hash === accepted.current.hash &&
                JSON.stringify(viewIntent(nextLocation.state)) ===
                    JSON.stringify(viewIntent(accepted.current.state))
            ) &&
            blockedNow.current &&
            (currentLocation.pathname !== nextLocation.pathname ||
                currentLocation.search !== nextLocation.search ||
                currentLocation.hash !== nextLocation.hash ||
                JSON.stringify(viewIntent(currentLocation.state)) !==
                    JSON.stringify(viewIntent(nextLocation.state))),
        [],
    );
    const blocker = useBlocker(shouldBlock);
    useEffect(() => {
        if (blocker.state === 'blocked') {
            try {
                onBlocked();
            } finally {
                activation.current = null;
                blocker.reset();
            }
        }
    }, [blocker, onBlocked]);

    const navigate = useCallback(
        async (slug: string, replace = false): Promise<void> => {
            validateScope({ origin, slug });
            const next = hashPath({ origin, slug }, null);
            if (pathname + search + hash === next && current.state === null) {
                return;
            }
            activation.current = null;
            await routerNavigate(next, { replace, state: null });
        },
        [origin, pathname, search, hash, current.state, routerNavigate],
    );
    const activate = useCallback(
        async (
            slug: string,
            nextView: number,
            replace = false,
            target?: ManagementLocation,
            routeId?: string,
        ): Promise<void> => {
            validateScope({ origin, slug });
            if (!Number.isSafeInteger(nextView) || nextView < 1) {
                throw new Error('Invalid local view ID');
            }
            const publicId = routeId ?? publicIds.current.get(nextView) ?? newViewID();
            publicIds.current.set(nextView, publicId);
            const path = hashPath({ origin, slug }, publicId, target);
            if (pathname + search + hash === path && view === nextView) {
                return;
            }
            // Native pointer focus and click can request the same tab before React
            // commits the first location. Keep that intent until commit or rejection,
            // not merely until navigate() resolves, or Back lands on a duplicate tab.
            if (
                activation.current?.key === current.key &&
                activation.current.slug === slug &&
                activation.current.view === nextView &&
                activation.current.path === path
            ) {
                return;
            }
            const requested = { key: current.key, slug, view: nextView, path };
            activation.current = requested;
            try {
                await routerNavigate(path, {
                    replace,
                    state: { generation: generation.current, view: nextView } satisfies ViewIntent,
                });
            } catch (error) {
                if (activation.current === requested) {
                    activation.current = null;
                }
                throw error;
            }
        },
        [origin, pathname, search, hash, view, current.key, routerNavigate],
    );
    // Native fragment navigation can reuse history.state/key (or "default").
    // Location.key alone would miss a second manually edited hash and keep the
    // preceding actor/view active. This key is volatile navigation identity only.
    const key = JSON.stringify([current.key, pathname, search, hash]);
    return { scope, key, view, management, canonicalizing, navigate, activate };
}

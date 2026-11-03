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

export interface SlugRoute {
  readonly scope: Scope | null;
  readonly key: string;
  readonly view: number | null;
  navigate(slug: string, replace?: boolean): Promise<void>;
  activate(slug: string, view: number, replace?: boolean): Promise<void>;
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
  if (!current.pathname.startsWith('/') || current.search !== '' || current.hash !== '') {
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

export function useSlugRoute(blocked: boolean, onBlocked: () => void): SlugRoute {
  const current = useLocation();
  const activation = useRef<{ key: string; slug: string; view: number } | null>(null);
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
  const generation = useRef(crypto.randomUUID());
  const intent = viewIntent(current.state);
  const view = intent?.generation === generation.current ? intent.view : null;
  const routerNavigate = useNavigate();
  const origin = window.location.origin;
  const { pathname, search, hash } = current;
  const scope = useMemo(
    () => scopeFromSlugLocation(origin, { pathname, search, hash }),
    [origin, pathname, search, hash],
  );
  const shouldBlock = useCallback<BlockerFunction>(
    ({ currentLocation, nextLocation }) =>
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
      const next = `/${slug}`;
      if (pathname === next && search === '' && hash === '' && current.state === null) {
        return;
      }
      activation.current = null;
      await routerNavigate(next, { replace, state: null });
    },
    [origin, pathname, search, hash, current.state, routerNavigate],
  );
  const activate = useCallback(
    async (slug: string, nextView: number, replace = false): Promise<void> => {
      validateScope({ origin, slug });
      if (!Number.isSafeInteger(nextView) || nextView < 1) {
        throw new Error('Invalid local view ID');
      }
      if (pathname === `/${slug}` && search === '' && hash === '' && view === nextView) {
        return;
      }
      // Native pointer focus and click can request the same tab before React
      // commits the first location. Keep that intent until commit or rejection,
      // not merely until navigate() resolves, or Back lands on a duplicate tab.
      if (
        activation.current?.key === current.key &&
        activation.current.slug === slug &&
        activation.current.view === nextView
      ) {
        return;
      }
      const requested = { key: current.key, slug, view: nextView };
      activation.current = requested;
      try {
        await routerNavigate(`/${slug}`, {
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
  return { scope, key: current.key, view, navigate, activate };
}

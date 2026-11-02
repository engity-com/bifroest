import { type ReactNode, useCallback, useEffect, useMemo } from 'react';
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
  navigate(slug: string, replace?: boolean): Promise<void>;
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
  const routerNavigate = useNavigate();
  const origin = window.location.origin;
  const { pathname, search, hash } = current;
  const scope = useMemo(
    () => scopeFromSlugLocation(origin, { pathname, search, hash }),
    [origin, pathname, search, hash],
  );
  const shouldBlock = useCallback<BlockerFunction>(
    ({ currentLocation, nextLocation }) =>
      blocked &&
      (currentLocation.pathname !== nextLocation.pathname ||
        currentLocation.search !== nextLocation.search ||
        currentLocation.hash !== nextLocation.hash),
    [blocked],
  );
  const blocker = useBlocker(shouldBlock);
  useEffect(() => {
    if (blocker.state === 'blocked') {
      try {
        onBlocked();
      } finally {
        blocker.reset();
      }
    }
  }, [blocker, onBlocked]);

  const navigate = useCallback(
    async (slug: string, replace = false): Promise<void> => {
      validateScope({ origin, slug });
      const next = `/${slug}`;
      if (pathname === next && search === '' && hash === '') {
        return;
      }
      await routerNavigate(next, { replace, state: null });
    },
    [origin, pathname, search, hash, routerNavigate],
  );
  return { scope, key: current.key, navigate };
}

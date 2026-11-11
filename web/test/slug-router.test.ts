import { act, createElement, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter, type Location } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { validateScope } from '../src/remember/protocol';
import { newViewID } from '../src/shared/uuid';
import { type SlugRoute, scopeFromSlugLocation, useSlugRoute } from '../src/ui/slug-router';
import type { ConnectionView } from '../src/workspace/model';

vi.mock('../src/remember/protocol', { spy: true });
const protocol = await vi.importActual<typeof import('../src/remember/protocol')>(
  '../src/remember/protocol',
);
const origin = 'https://app.example.org:8443';
const cleanups: (() => void)[] = [];

afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
      cleanup();
    }
  });
  vi.mocked(validateScope).mockRestore();
  vi.unstubAllGlobals();
});

describe('exact slug location parsing', () => {
  it.each([
    '',
    'Work',
    'bla-bla',
    'Work/TeAm',
    'a'.repeat(64),
    `${'A'.repeat(64)}/${'b'.repeat(64)}`,
  ])('preserves root, case, segment bounds and the exact origin port', (slug) => {
    expect(scopeFromSlugLocation(origin, { pathname: `/${slug}`, search: '', hash: '' })).toEqual({
      origin,
      slug,
    });
  });

  it.each([
    '',
    'Work',
    '//other.example.org/Work',
    'https://other.example.org/Work',
    '/Work/',
    '/Work//Team',
    '/Work/Team/Extra',
    '/./Work',
    '/Work/../Team',
    '/Work.',
    '/%57ork',
    '/Work%2fTeam',
    '/Work%252fTeam',
    '/_bifroest',
    '/api',
    '/api/v1/access',
    '/api/unknown',
    '/assets/app.js',
    '/Work_Team',
    '/Wörk',
    '/Work Team',
    '/Work?extra',
    '/Work#extra',
    '/Work\\Team',
    `/${'a'.repeat(65)}`,
    `/Work/${'b'.repeat(65)}`,
  ])('rejects aliases, foreign URLs, reserved characters and invalid paths', (pathname) => {
    expect(scopeFromSlugLocation(origin, { pathname, search: '', hash: '' })).toBeNull();
  });

  it.each([
    { search: '?mode=extra', hash: '' },
    { search: '?', hash: '' },
    { search: '', hash: '#extra' },
    { search: '', hash: '#' },
    { search: '?mode=extra', hash: '#extra' },
  ])('rejects query and fragment data instead of interpreting it as scope', (extra) => {
    expect(scopeFromSlugLocation(origin, { pathname: '/Work', ...extra })).toBeNull();
  });

  it.each([
    'http://app.example.org:8443',
    'https://App.example.org:8443',
    'https://app.example.org:443',
    'https://app.example.org.',
    'https://app.example.org/Work',
    'https://app.example.org?mode=extra',
    'https://app.example.org#extra',
    'not-an-origin',
  ])('rejects insecure, noncanonical and non-origin inputs', (invalidOrigin) => {
    expect(
      scopeFromSlugLocation(invalidOrigin, { pathname: '/Work', search: '', hash: '' }),
    ).toBeNull();
  });
});

interface RouteProbe {
  current?: SlugRoute;
  updateBlocked: (blocked: boolean) => void;
  onBlocked: () => void;
  mounted: () => void;
  unmounted: () => void;
}

function RouteWorkspace({
  probe,
  initiallyBlocked,
}: {
  probe: RouteProbe;
  initiallyBlocked: boolean;
}) {
  const [blocked, setBlocked] = useState(initiallyBlocked);
  const [connections, setConnections] = useState<readonly ConnectionView[]>([]);
  const pending = useRef(new Map<number, ConnectionView>());
  probe.updateBlocked = setBlocked;
  const route = useSlugRoute(blocked, probe.onBlocked, [], connections);
  probe.current = {
    ...route,
    activate: async (slug, id, replace, target) => {
      const connection =
        connections.find((value) => value.id === id) ??
        pending.current.get(id) ??
        ({
          id,
          routeId: newViewID(),
          scope: { origin: location.origin, slug },
          access: { snapshot: () => ({ environment: 'management', flow: { name: 'management' } }) },
        } as ConnectionView);
      pending.current.set(id, connection);
      setConnections((values) =>
        values.some((value) => value.id === id) ? values : [...values, connection],
      );
      return route.activate(slug, id, replace, target, connection.routeId);
    },
  };
  useEffect(() => {
    probe.mounted();
    return () => {
      probe.unmounted();
    };
  }, [probe]);
  return null;
}

async function mountRoute(
  initialEntries: (string | Partial<Location>)[] = ['/', '/Work'],
  initiallyBlocked = false,
) {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  // Vitest serves its browser on HTTP. Adapt only that test origin; the real
  // validator still checks every slug, and parser tests use it unmodified.
  if (location.protocol !== 'https:') {
    vi.mocked(validateScope).mockImplementation((scope) => {
      protocol.validateScope(scope.origin === location.origin ? { ...scope, origin } : scope);
    });
  }
  const onBlocked = vi.fn();
  const mounted = vi.fn();
  const unmounted = vi.fn();
  const probe: RouteProbe = {
    updateBlocked: () => {
      throw new Error('Route is not mounted');
    },
    onBlocked,
    mounted,
    unmounted,
  };
  const router = createMemoryRouter(
    [
      {
        id: 'workspace',
        path: '*',
        element: createElement(RouteWorkspace, { probe, initiallyBlocked }),
      },
    ],
    { initialEntries, initialIndex: initialEntries.length - 1 },
  );
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  cleanups.push(() => {
    root.unmount();
    router.dispose();
    container.remove();
  });
  await act(async () => {
    root.render(createElement(RouterProvider, { router }));
  });
  return {
    router,
    onBlocked,
    mounted,
    unmounted,
    route(): SlugRoute {
      if (probe.current === undefined) {
        throw new Error('Route is not mounted');
      }
      return probe.current;
    },
    async setBlocked(blocked: boolean) {
      await act(async () => {
        probe.updateBlocked(blocked);
      });
    },
  };
}

describe('data-router slug navigation', () => {
  it('coalesces focus and click activation before the first location commit', async () => {
    const view = await mountRoute(['/Work']);
    await act(async () => {
      await view.route().activate('Work', 1, true);
    });
    const originalKey = view.route().key;
    await act(async () => {
      const route = view.route();
      await Promise.all([route.activate('bla-bla', 2), route.activate('bla-bla', 2)]);
    });
    expect(view.route().view).toBe(2);
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().view).toBe(1);
    expect(view.route().scope?.slug).toBe('Work');
    expect(view.route().key).toBe(originalKey);
  });

  it('allows a previously blocked activation after the operation is resolved', async () => {
    const view = await mountRoute(['/Work']);
    await act(async () => {
      await view.route().activate('Work', 1, true);
    });
    await view.setBlocked(true);
    await act(async () => {
      await view.route().activate('bla-bla', 2);
    });
    expect(view.route().view).toBe(1);
    expect(view.onBlocked).toHaveBeenCalledTimes(1);
    await view.setBlocked(false);
    await act(async () => {
      await view.route().activate('bla-bla', 2);
    });
    expect(view.route().view).toBe(2);
    expect(view.route().scope?.slug).toBe('bla-bla');
  });

  it('pushes distinct local views even on the same alias, and replaces successful-login entries', async () => {
    const view = await mountRoute(['/bla-bla']);
    await act(async () => {
      await view.route().activate('bla-bla', 1, true);
    });
    const first = view.router.state.location;
    const firstRouteKey = view.route().key;
    expect(view.route().view).toBe(1);
    expect(first.state).toEqual({ generation: expect.any(String), view: 1 });
    await act(async () => {
      await view.route().activate('bla-bla', 2);
    });
    expect(view.route().view).toBe(2);
    expect(view.route().scope?.slug).toBe('bla-bla');
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().view).toBe(1);
    expect(view.route().key).toBe(firstRouteKey);
    await act(async () => {
      await view.router.navigate(1);
    });
    expect(view.route().view).toBe(2);
    await act(async () => {
      await view.route().navigate('bla-bla');
    });
    expect(view.route().view).toBeNull();
    expect(view.router.state.location.state).toBeNull();
    expect(view.mounted).toHaveBeenCalledTimes(1);
  });

  it('treats history view IDs from a previous app generation as fresh login intents', async () => {
    const original = await mountRoute(['/bla-bla']);
    await act(async () => {
      await original.route().activate('bla-bla', 1, true);
    });
    const reloaded = await mountRoute([original.router.state.location]);
    expect(reloaded.route().scope?.slug).toBe('bla-bla');
    expect(reloaded.route().view).toBeNull();
    const foreign = await mountRoute([
      { pathname: '/Work', state: { generation: 'old', view: 1, token: 'ignored' } },
    ]);
    expect(foreign.route().view).toBeNull();
  });

  it('blocks same-URL view activation and login intents atomically, including POP', async () => {
    const view = await mountRoute(['/Work']);
    await act(async () => {
      await view.route().activate('Work', 1, true);
    });
    await act(async () => {
      await view.route().activate('Work', 2);
    });
    await view.setBlocked(true);
    const key = view.route().key;
    for (const action of [
      () => view.route().activate('Work', 1),
      () => view.route().navigate('Work'),
      () => view.router.navigate(-1),
    ]) {
      await act(async () => {
        await action();
      });
      expect(view.route().key).toBe(key);
      expect(view.route().view).toBe(2);
    }
    expect(view.onBlocked).toHaveBeenCalledTimes(3);
    await view.setBlocked(false);
    expect(view.route().view).toBe(2);
  });

  it('updates push/back/forward scope and key without remounting the workspace', async () => {
    const view = await mountRoute();
    const firstKey = view.route().key;
    expect(view.route().scope).toEqual({ origin: location.origin, slug: 'Work' });
    await act(async () => {
      await view.route().navigate('Team/TeSt');
    });
    const nextKey = view.route().key;
    expect(nextKey).not.toBe(firstKey);
    expect(view.route().scope).toEqual({ origin: location.origin, slug: 'Team/TeSt' });
    expect(view.router.state.location.state).toBeNull();
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().key).toBe(firstKey);
    expect(view.route().scope?.slug).toBe('Work');
    await act(async () => {
      await view.router.navigate(1);
    });
    expect(view.route().key).toBe(nextKey);
    expect(view.route().scope?.slug).toBe('Team/TeSt');
    expect(view.mounted).toHaveBeenCalledTimes(1);
    expect(view.unmounted).not.toHaveBeenCalled();
  });

  it('skips duplicate URLs and replaces an entry only when requested', async () => {
    const view = await mountRoute();
    const firstKey = view.route().key;
    await act(async () => {
      await view.route().navigate('Work');
    });
    expect(view.route().key).toBe(firstKey);
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().scope?.slug).toBe('');
    await act(async () => {
      await view.router.navigate(1);
      await view.route().navigate('Other', true);
    });
    expect(view.route().scope?.slug).toBe('Other');
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().scope?.slug).toBe('');
    await act(async () => {
      await view.router.navigate(1);
    });
    expect(view.route().scope?.slug).toBe('Other');
    expect(view.router.state.location.state).toBeNull();
  });

  it('returns null on invalid routes and clears query/hash on validated navigation', async () => {
    const view = await mountRoute(['/Work?mode=extra#extra']);
    const firstKey = view.route().key;
    expect(view.route().scope).toBeNull();
    await act(async () => {
      await view.route().navigate('Work');
    });
    expect(view.route().scope?.slug).toBe('Work');
    expect(view.route().key).not.toBe(firstKey);
    expect(view.router.state.location.search).toBe('');
    expect(view.router.state.location.hash).toBe('#Work');
    await act(async () => {
      await view.router.navigate('/%57ork');
    });
    expect(view.route().scope).toBeNull();
  });

  it('rejects invalid and foreign navigation before changing history', async () => {
    const view = await mountRoute();
    const firstKey = view.route().key;
    for (const slug of ['../Other', 'Work/', '%57ork', 'https://other.example.org', 'Work?extra']) {
      await expect(view.route().navigate(slug)).rejects.toMatchObject({ code: 'unavailable' });
    }
    expect(view.route().key).toBe(firstKey);
    expect(view.route().scope?.slug).toBe('Work');
  });

  it('resets blocked push/query/hash, allows the same URL and never replays intent', async () => {
    const view = await mountRoute(undefined, true);
    const firstKey = view.route().key;
    for (const pathname of ['/Other', '/Work?mode=extra', '/Work#extra']) {
      await act(async () => {
        await view.router.navigate(pathname);
      });
      expect(view.route().key).toBe(firstKey);
      expect(view.route().scope?.slug).toBe('Work');
    }
    expect(view.onBlocked).toHaveBeenCalledTimes(3);
    await act(async () => {
      await view.router.navigate('/Work');
    });
    expect(view.onBlocked).toHaveBeenCalledTimes(3);
    await view.setBlocked(false);
    expect(view.route().scope?.slug).toBe('Work');
    await act(async () => {
      await view.route().navigate('Allowed');
    });
    expect(view.route().scope?.slug).toBe('Allowed');
    expect(view.onBlocked).toHaveBeenCalledTimes(3);
    expect(view.unmounted).not.toHaveBeenCalled();
  });

  it('resets blocked POP navigation and preserves both route and callback behavior', async () => {
    const view = await mountRoute(undefined, true);
    const firstKey = view.route().key;
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().key).toBe(firstKey);
    expect(view.route().scope?.slug).toBe('Work');
    expect(view.onBlocked).toHaveBeenCalledTimes(1);
    await view.setBlocked(false);
    expect(view.route().scope?.slug).toBe('Work');
    await act(async () => {
      await view.router.navigate(-1);
    });
    expect(view.route().scope?.slug).toBe('');
    expect(view.onBlocked).toHaveBeenCalledTimes(1);
  });
});

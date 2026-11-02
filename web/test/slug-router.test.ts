import { act, createElement, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { validateScope } from '../src/remember/protocol';
import { type SlugRoute, scopeFromSlugLocation, useSlugRoute } from '../src/ui/slug-router';

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
  it.each(['', 'Work', 'Work/TeAm', 'a'.repeat(64), `${'A'.repeat(64)}/${'b'.repeat(64)}`])(
    'preserves root, case, segment bounds and the exact origin port',
    (slug) => {
      expect(scopeFromSlugLocation(origin, { pathname: `/${slug}`, search: '', hash: '' })).toEqual(
        { origin, slug },
      );
    },
  );

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
    '/assets/app.js',
    '/Work-Team',
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
  probe.updateBlocked = setBlocked;
  probe.current = useSlugRoute(blocked, probe.onBlocked);
  useEffect(() => {
    probe.mounted();
    return () => {
      probe.unmounted();
    };
  }, [probe]);
  return null;
}

async function mountRoute(initialEntries = ['/', '/Work'], initiallyBlocked = false) {
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
    expect(view.router.state.location.hash).toBe('');
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

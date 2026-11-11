import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter, type Location } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ManagementConnection } from '../src/management/channel';
import { BrowserBinding, BrowserClient } from '../src/remember';
import { WebAccess } from '../src/remember/client';
import { validateScope } from '../src/remember/protocol';
import { uuidText } from '../src/shared/uuid';
import type { TerminalState } from '../src/terminal/socket';
import { App } from '../src/ui/App';
import { parseHashTarget } from '../src/ui/hash-route';
import type { LinkMetadata } from '../src/ui/link-metadata';

vi.mock('../src/remember/protocol', { spy: true });
const protocol = await vi.importActual<typeof import('../src/remember/protocol')>(
  '../src/remember/protocol',
);
const panels = vi.hoisted(() => ({
  mounted: [] as number[],
  unmounted: [] as number[],
  signals: new Map<number, AbortSignal>(),
  pending: new Set<number>(),
  states: new Map<number, (state: TerminalState) => void>(),
}));
vi.mock('../src/terminal/TerminalPanel', async () => {
  const { createElement, useEffect } = await import('react');
  return {
    terminalStatus: () => 'terminalConnected',
    TerminalPanel: ({
      id,
      signal,
      onState,
    }: {
      id: number;
      signal: AbortSignal;
      onState: (id: number, state: TerminalState) => void;
    }) => {
      useEffect(() => {
        panels.mounted.push(id);
        panels.states.set(id, (state) => onState(id, state));
        panels.signals.set(id, signal);
        if (!panels.pending.has(id)) {
          onState(id, { phase: 'connected' });
        }
        return () => {
          panels.unmounted.push(id);
        };
      }, [id, signal, onState]);
      return createElement('span', null, `Owned execution ${id}`);
    },
  };
});

const cleanups: (() => void)[] = [];
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.mocked(validateScope).mockImplementation((scope) => {
    protocol.validateScope(
      scope.origin === location.origin ? { ...scope, origin: 'https://app.example.org' } : scope,
    );
  });
  vi.spyOn(BrowserBinding, 'load').mockResolvedValue(null);
  vi.spyOn(BrowserClient.prototype, 'resume');
  // Route/owner retention uses the standalone mock HTTP protocol here. Real
  // channel admission, expiry and isolation have separate transport tests.
  vi.spyOn(WebAccess.prototype, 'openManagement').mockReturnValue({
    disconnect() {},
  } as ManagementConnection);
  panels.mounted.length = 0;
  panels.unmounted.length = 0;
  panels.signals.clear();
  panels.pending.clear();
  panels.states.clear();
});
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
      cleanup();
    }
  });
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function metadata(
  slug: string,
  rootAvailable = false,
  publishedSlugs: readonly string[] = ['docker', 'Other', 'Work'],
): LinkMetadata {
  return {
    scope: { origin: location.origin, slug },
    rootAvailable,
    loginOptions:
      slug === '' && !rootAvailable
        ? []
        : [{ method: 'password', requestUser: false, certificateRequired: false }],
    publishedSlugs,
  };
}

async function mountApp(
  initial: string | Partial<Location> = '/bla-bla',
  rootAvailable = false,
  management = false,
  scenario: {
    publishedSlugs?: readonly string[];
    precedingPath?: string;
    failDiscovery?: boolean;
    entrySlug?: string;
    flow?: { name: string; title: string };
  } = {},
) {
  const requests: {
    path: string;
    options: RequestInit | undefined;
    fields: Record<string, string> | undefined;
  }[] = [];
  let holdLogin: (() => Promise<void>) | null = null;
  let holdLogout: (() => Promise<void>) | null = null;
  let grants = 0;
  let failDiscovery = scenario.failDiscovery ?? false;
  const transport = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    const fields = options?.body
      ? (JSON.parse(String(options.body)) as Record<string, string>)
      : undefined;
    requests.push({ path, options, fields });
    if (options?.method !== 'POST') {
      return new Response(
        JSON.stringify(metadata(path.slice(1), rootAvailable, scenario.publishedSlugs)),
        {
          status: failDiscovery ? 503 : 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }
    if (path.endsWith('/login/password')) {
      await holdLogin?.();
      const first = ++grants === 1;
      return new Response(
        JSON.stringify({
          status: 'authorized',
          accessToken: `bwa1.${'A'.repeat(42)}${first ? 'A' : 'E'}`,
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
          scope: { origin: location.origin, slug: fields?.slug },
          principal: first ? 'alice' : 'bob',
          environment: management ? 'management' : 'terminal',
          terminalAvailable: !management,
          keepAlive: { interval: '15s', locked: false },
          ...(scenario.flow ? { flow: scenario.flow } : {}),
        }),
        { headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (path.endsWith('/logout')) {
      await holdLogout?.();
      return new Response(null, { status: 204 });
    }
    if (path.endsWith('/management/version/show')) {
      return new Response(
        JSON.stringify({
          version: 1,
          operation: 'version.show',
          versionInfo: {
            detail: fields?.long === 'false' ? 'short' : 'long',
            text: 'Retained owner version',
          },
        }),
        { headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (path.endsWith('/management/sessions/list') || path.endsWith('/management/flows/list')) {
      const kind = path.endsWith('/sessions/list') ? 'sessions' : 'flows';
      return new Response(
        JSON.stringify({
          version: 1,
          operation: `${kind}.list`,
          [kind]: { items: [], next: '', skipped: 0 },
        }),
        { headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (path.endsWith('/management/sessions/show')) {
      return new Response(
        JSON.stringify({
          version: 1,
          operation: 'sessions.show',
          session: {
            flow: fields?.flow,
            id: fields?.id,
            state: 'authorized',
            user: 'alice',
            remote: 'alice@127.0.0.1',
            createdAt: '2026-01-01T00:00:00Z',
            owner: null,
          },
        }),
        { headers: { 'Content-Type': 'application/json' } },
      );
    }
    throw new Error(`Unexpected authentication request ${path}`);
  });
  vi.stubGlobal('fetch', transport);
  const slug =
    scenario.entrySlug ??
    parseHashTarget(
      location.origin,
      typeof initial === 'string' ? new URL(initial, location.origin).hash : (initial.hash ?? ''),
    )?.scope.slug ??
    (typeof initial === 'string' ? initial : (initial.pathname ?? '/')).slice(1);
  const router = createMemoryRouter(
    [
      {
        path: '*',
        element: createElement(App, {
          metadata: metadata(slug, rootAvailable, scenario.publishedSlugs),
          scheme: 'auto',
          onScheme: () => {},
        }),
      },
    ],
    { initialEntries: scenario.precedingPath ? [scenario.precedingPath, initial] : [initial] },
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
    requests,
    transport,
    holdLogin: (hold: () => Promise<void>) => {
      holdLogin = hold;
    },
    holdLogout: (hold: () => Promise<void>) => {
      holdLogout = hold;
    },
    failDiscovery: () => {
      failDiscovery = true;
    },
  };
}

function dialog(): HTMLElement {
  const element = document.querySelector<HTMLElement>('.login-dialog[role="dialog"]');
  if (!element) {
    throw new Error('Missing login dialog');
  }
  return element;
}
async function click(element: HTMLElement | null) {
  if (!element) {
    throw new Error('Missing element');
  }
  await act(async () => {
    element.click();
  });
}
function button(name: string, parent: ParentNode = document): HTMLButtonElement {
  const element = [...parent.querySelectorAll<HTMLButtonElement>('button,a[href]')].find(
    (node) => node.getAttribute('aria-label') === name || node.textContent === name,
  );
  if (!element) {
    throw new Error(`Missing button ${name}`);
  }
  return element;
}
async function signIn() {
  const form = dialog().querySelector('form');
  if (!form) {
    throw new Error('Missing login form');
  }
  const password = form.querySelector<HTMLInputElement>('input[name="password"]');
  if (password) {
    password.value = 'must-not-enter-history';
  }
  await act(async () => {
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
}
async function chooseSlug(slug: string) {
  await act(async () => {
    dialog()
      .querySelector('[role="combobox"]')
      ?.dispatchEvent(new MouseEvent('mousedown', { button: 0, bubbles: true }));
  });
  const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
    (node) => node.textContent === (slug || '/'),
  );
  await click(option ?? null);
}
function selectedID(): string | null {
  return document.querySelector('[data-connection-active="true"]')?.id ?? null;
}
function fragmentScope(value: Location): string {
  expect(value.pathname).toBe('/');
  expect(value.search).toBe('');
  if (value.hash === '') {
    return '';
  }
  const parsed = parseHashTarget(location.origin, value.hash);
  expect(parsed).not.toBeNull();
  return parsed?.scope.slug ?? '';
}

describe('owned workspace view routing with the real router and workspace', () => {
  it('does not expose the new login form before its route commits and resets the password field', async () => {
    const app = await mountApp('/Work');
    await signIn();
    await vi.waitFor(() => {
      expect(app.router.state.location.state).toMatchObject({ view: 1 });
      expect(document.querySelector('.login-dialog[role="dialog"]')).toBeNull();
    });
    const requests = app.requests.length;
    const navigate = app.router.navigate.bind(app.router);
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.spyOn(app.router, 'navigate').mockImplementationOnce(async (to, options) => {
      await pending;
      if (typeof to === 'number') {
        await navigate(to);
      } else {
        await navigate(to, options);
      }
    });
    await click(button('New connection'));
    try {
      expect(document.querySelector('.login-dialog[role="dialog"]')).toBeNull();
      expect(app.requests).toHaveLength(requests);
    } finally {
      await act(async () => {
        release();
        await pending;
      });
    }
    expect(dialog().querySelector('form')).not.toBeNull();
    expect(app.router.state.location.state).toBeNull();
    await signIn();
    expect(selectedID()).toBe('terminal-pane-2');
    expect(app.requests.filter((request) => request.path.endsWith('/login/password'))).toHaveLength(
      2,
    );
  });

  it('replaces a directory-only root with its single choice without authenticating or resuming saved access', async () => {
    vi.mocked(BrowserBinding.load).mockResolvedValue({ binding: {} } as unknown as BrowserBinding);
    const app = await mountApp('/', false, false, {
      publishedSlugs: ['foo'],
      precedingPath: '/before',
    });
    expect(fragmentScope(app.router.state.location)).toBe('foo');
    expect(app.router.state.historyAction).toBe('REPLACE');
    expect(dialog().querySelector('[role="combobox"]')).toBeNull();
    expect(dialog().querySelector('form')).not.toBeNull();
    expect(app.requests.map((request) => request.path)).toEqual(['/foo']);
    expect(app.requests[0]?.options).toMatchObject({
      credentials: 'omit',
      cache: 'no-store',
      mode: 'same-origin',
      redirect: 'error',
    });
    expect(app.requests.filter((request) => request.options?.method === 'POST')).toHaveLength(0);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    expect(panels.mounted).toEqual([]);
    await act(async () => {
      await app.router.navigate(-1);
    });
    expect(fragmentScope(app.router.state.location)).toBe('before');
  });

  it('retains the root choice when it is an actual login alongside the single published slug', async () => {
    const app = await mountApp('/', true, false, { publishedSlugs: ['foo'] });
    expect(app.router.state.location.pathname).toBe('/');
    expect(dialog().querySelector('[role="combobox"]')).not.toBeNull();
    expect(app.requests).toEqual([]);
  });

  it.each(['/foo', '/bla-bla'])(
    'never redirects the explicitly entered scope %s to its published name',
    async (initial) => {
      const app = await mountApp(initial, false, false, { publishedSlugs: ['foo'] });
      expect(fragmentScope(app.router.state.location)).toBe(initial.slice(1));
      expect(Boolean(dialog().querySelector('[role="combobox"]'))).toBe(initial !== '/foo');
      expect(app.requests).toEqual([]);
      expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    },
  );

  it('does not skip a known alias tab when returning to a directory with one published slug', async () => {
    const app = await mountApp('/bla-bla', false, false, { publishedSlugs: ['foo'] });
    await signIn();
    const posts = app.requests.filter((request) => request.options?.method === 'POST').length;
    await act(async () => {
      await app.router.navigate('/');
    });
    expect(app.router.state.location.pathname).toBe('/');
    expect(dialog().querySelector('[role="combobox"]')).not.toBeNull();
    expect(dialog().querySelector('form')).toBeNull();
    expect(app.requests.filter((request) => request.options?.method === 'POST')).toHaveLength(
      posts,
    );
    expect(panels.unmounted).toEqual([]);
    expect(panels.signals.get(1)?.aborted).toBe(false);
  });

  it('leaves a failed automatic metadata load at the selected slug without retrying or authenticating', async () => {
    const app = await mountApp('/', false, false, { publishedSlugs: ['foo'], failDiscovery: true });
    expect(fragmentScope(app.router.state.location)).toBe('foo');
    expect(app.requests.map((request) => request.path)).toEqual(['/foo']);
    expect(dialog().querySelector('[role="combobox"]')).toBeNull();
    expect(button('Retry loading options')).toBeDefined();
    expect(app.requests.filter((request) => request.options?.method === 'POST')).toHaveLength(0);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
  });

  it('retains management results across login and view navigation without changing the owning access', async () => {
    const app = await mountApp('/bla-bla', false, true);
    await signIn();
    await vi.waitFor(async () => {
      await act(async () => {});
      expect(
        app.requests
          .filter((request) => request.path.includes('/management/'))
          .map((request) => request.path.split('/management/')[1]),
      ).toEqual(['flows/list']);
    });
    await click(button('Sessions'));
    // The first active view now reads its metadata once. Join those exact
    // requests before testing that pure tab/history activation does not reread.
    await vi.waitFor(async () => {
      await act(async () => {});
      expect(
        app.requests
          .filter((request) => request.path.includes('/management/'))
          .map((request) => request.path.split('/management/')[1]),
      ).toEqual(['flows/list', 'sessions/list']);
    });
    await click(button('Version'));
    expect(app.router.state.location.hash).toMatch(
      /^#bla-bla\/[1-9A-HJ-NP-Za-km-z]{16,22}\/version$/u,
    );
    await vi.waitFor(() =>
      expect(
        app.requests.filter((request) => request.path.endsWith('/management/version/show')),
      ).toHaveLength(2),
    );
    const owned = document.getElementById('terminal-pane-1');
    expect(owned?.querySelector('[aria-label="Server version"]')?.textContent).toContain(
      'Retained owner version',
    );
    await click(button('New connection'));
    await chooseSlug('Work');
    await signIn();
    expect(selectedID()).toBe('terminal-pane-2');
    const secondPane = document.getElementById('terminal-pane-2');
    if (!secondPane) {
      throw new Error('Missing second management owner');
    }
    await click(button('Version', secondPane));
    await vi.waitFor(() =>
      expect(
        document.getElementById('terminal-pane-2')?.querySelector('[aria-label="Server version"]')
          ?.textContent,
      ).toContain('Retained owner version'),
    );
    await vi.waitFor(() =>
      expect(
        app.requests.filter((request) => request.path.endsWith('/management/flows/list')),
      ).toHaveLength(2),
    );
    const versionReads = app.requests.filter((request) =>
      request.path.endsWith('/management/version/show'),
    );
    expect(
      new Headers(versionReads[0]?.options?.headers).get('Authorization') !==
        new Headers(versionReads[2]?.options?.headers).get('Authorization'),
    ).toBe(true);
    const requests = app.requests.length;
    const reads = vi.mocked(BrowserBinding.load).mock.calls.length;
    await click(document.getElementById('terminal-tab-1'));
    expect(selectedID()).toBe('terminal-pane-1');
    expect(fragmentScope(app.router.state.location)).toBe('bla-bla');
    expect(owned?.querySelector('[aria-label="Server version"]')?.textContent).toContain(
      'Retained owner version',
    );
    expect(app.requests).toHaveLength(requests);
    expect(BrowserBinding.load).toHaveBeenCalledTimes(reads);
    expect(
      app.requests.filter((request) => request.path.endsWith('/management/version/show')),
    ).toHaveLength(4);
  });

  it('closing a background tab does not select it through its close control focus', async () => {
    const app = await mountApp();
    await signIn();
    await click(button('New connection'));
    await chooseSlug('Work');
    await signIn();
    await click(document.getElementById('terminal-tab-1'));
    const selected = app.router.state.location;
    const requests = app.requests.length;
    const close = document.querySelector<HTMLElement>('[aria-label="Close terminal 2"]');
    expect(close).not.toBeNull();
    await act(async () => {
      close?.focus();
    });
    expect(app.router.state.location.key).toBe(selected.key);
    expect(selectedID()).toBe('terminal-pane-1');
    await click(close);
    expect(app.router.state.location.key).toBe(selected.key);
    expect(selectedID()).toBe('terminal-pane-1');
    await click(button('Close terminal'));
    expect(document.getElementById('terminal-pane-2')).toBeNull();
    expect(app.router.state.location.key).toBe(selected.key);
    expect(panels.unmounted).toEqual([2]);
    expect(panels.signals.get(1)?.aborted).toBe(false);
    expect(app.requests).toHaveLength(requests);
  });

  it('preserves aliases, connecting executions, duplicate scopes and history without discovery/auth/saved reads', async () => {
    const app = await mountApp();
    await signIn();
    expect(selectedID()).toBe('terminal-pane-1');
    const aliasEntry = app.router.state.location;
    expect(fragmentScope(aliasEntry)).toBe('bla-bla');
    expect(aliasEntry.state).toEqual({ generation: expect.any(String), view: 1 });
    await click(button('New connection'));
    await chooseSlug('docker');
    panels.pending.add(2);
    await signIn();
    expect(selectedID()).toBe('terminal-pane-2');
    const requestCount = app.requests.length;
    const savedReads = vi.mocked(BrowserBinding.load).mock.calls.length;
    await click(document.getElementById('terminal-tab-1'));
    expect(fragmentScope(app.router.state.location)).toBe('bla-bla');
    expect(selectedID()).toBe('terminal-pane-1');
    expect(panels.signals.get(2)?.aborted).toBe(false);
    await act(async () => {
      await app.router.navigate(-1);
    });
    expect(fragmentScope(app.router.state.location)).toBe('docker');
    expect(selectedID()).toBe('terminal-pane-2');
    await act(async () => {
      await app.router.navigate(1);
    });
    expect(selectedID()).toBe('terminal-pane-1');
    expect(app.requests).toHaveLength(requestCount);
    expect(BrowserBinding.load).toHaveBeenCalledTimes(savedReads);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    expect(panels.mounted).toEqual([1, 2]);
    expect(panels.unmounted).toEqual([]);
    await act(async () => {
      document
        .getElementById('terminal-tab-1')
        ?.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    });
    const duplicate = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
      (node) => node.textContent === 'Duplicate',
    );
    await click(duplicate ?? null);
    expect(selectedID()).toBe('terminal-pane-3');
    expect(fragmentScope(app.router.state.location)).toBe('bla-bla');
    expect(document.getElementById('terminal-pane-3')?.getAttribute('data-connection-scope')).toBe(
      'bla-bla',
    );
    expect(app.requests).toHaveLength(requestCount);
    expect(JSON.stringify(app.router.state.location.state)).not.toMatch(
      /actor|token|grant|password|must-not/,
    );
    // An explicit new login, unlike tab activation, loads that alias's metadata.
    await click(button('New connection'));
    expect(
      dialog().querySelector('[data-login-scope="bla-bla"][data-login-ready="true"]'),
    ).not.toBeNull();
    expect(app.requests.at(-1)?.path).toBe('/bla-bla');
  });

  it('does not revive closed IDs or IDs from a reload, and never automatically authenticates', async () => {
    const app = await mountApp();
    await signIn();
    const old = app.router.state.location;
    await act(async () => {
      document
        .getElementById('terminal-tab-1')
        ?.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    });
    const close = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
      (node) => node.textContent === 'Close',
    );
    await click(close ?? null);
    await click(button('Close terminal'));
    expect(document.getElementById('terminal-pane-1')).toBeNull();
    const posts = app.requests.filter((request) => request.options?.method === 'POST').length;
    await act(async () => {
      await app.router.navigate('/bla-bla', { state: old.state });
    });
    expect(dialog().querySelector('form')).not.toBeNull();
    expect(selectedID()).toBeNull();
    expect(app.requests.filter((request) => request.options?.method === 'POST')).toHaveLength(
      posts,
    );
    await signIn();
    expect(document.getElementById('terminal-pane-1')).toBeNull();
    expect(selectedID()).toBe('terminal-pane-2');
    const reloaded = await mountApp(old);
    expect(reloaded.requests).toEqual([]);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    expect(panels.mounted).toEqual([1, 2]);
  });

  it.each([false, true])(
    'keeps the exact logout receipt through last-tab rediscovery after another login scope: %s',
    async (changedScope) => {
      const app = await mountApp('/#Work');
      await signIn();
      if (changedScope) {
        await click(button('New connection'));
        await chooseSlug('Other');
        await click(button('Close', dialog()));
        expect(fragmentScope(app.router.state.location)).toBe('Work');
      }
      await act(async () => {
        document
          .getElementById('terminal-tab-1')
          ?.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
      });
      const logout = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
        (node) => node.textContent === 'Log out',
      );
      await click(logout ?? null);
      await vi.waitFor(() => expect(document.getElementById('terminal-pane-1')).toBeNull());
      expect(app.router.state.location.hash).toBe('#Work/-');
      expect(dialog().querySelector('form')).not.toBeNull();
      await click(button('Notification details', dialog()));
      const notice = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find(
        (node) =>
          node.getAttribute('aria-labelledby') &&
          node.textContent?.includes('Logout confirmed.') &&
          node.textContent?.includes('Notification details'),
      );
      expect(notice?.checkVisibility({ visibilityProperty: true })).toBe(true);
      if (!notice) {
        throw new Error('Missing contextual logout result');
      }
      await click(button('Close', notice));
      expect(dialog().querySelector('form')).not.toBeNull();
      expect(app.requests.filter((request) => request.path.endsWith('/logout'))).toHaveLength(1);
      expect(
        app.requests.filter((request) => request.path.endsWith('/login/password')),
      ).toHaveLength(1);
      expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    },
  );

  it('keeps an explicitly opened pending logout notice above the last-tab sign-in until its exact completion is acknowledged', async () => {
    const app = await mountApp('/#Work');
    await signIn();
    let release!: () => void;
    app.holdLogout(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await act(async () => {
      document
        .getElementById('terminal-tab-1')
        ?.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    });
    await click(
      [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
        (node) => node.textContent === 'Log out',
      ) ?? null,
    );
    await click(button('Notification details'));
    const notice = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
      node.textContent?.includes(
        'New actions in this tab are blocked while logout is being confirmed.',
      ),
    );
    expect(notice?.checkVisibility({ visibilityProperty: true })).toBe(true);
    await act(async () => release());
    await vi.waitFor(() => expect(notice?.textContent).toContain('Logout confirmed.'));
    expect(notice?.checkVisibility({ visibilityProperty: true })).toBe(true);
    await vi.waitFor(() =>
      expect(
        document.querySelector('.login-dialog')?.checkVisibility({ visibilityProperty: true }) ??
          false,
      ).toBe(false),
    );
    if (!notice) {
      throw new Error('Missing owned logout receipt');
    }
    await click(button('Close', notice));
    await vi.waitFor(() =>
      expect(dialog().checkVisibility({ visibilityProperty: true })).toBe(true),
    );
    expect(app.requests.filter((request) => request.path.endsWith('/logout'))).toHaveLength(1);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
  });

  it('blocks view POP during authentication without changing the selected view or disposing its execution', async () => {
    const app = await mountApp();
    await signIn();
    await click(button('New connection'));
    await chooseSlug('Other');
    let release!: () => void;
    app.holdLogin(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await signIn();
    const key = app.router.state.location.key;
    await act(async () => {
      await app.router.navigate(-1);
    });
    expect(app.router.state.location.key).toBe(key);
    expect(fragmentScope(app.router.state.location)).toBe('Other');
    expect(selectedID()).toBe('terminal-pane-1');
    expect(panels.signals.get(1)?.aborted).toBe(false);
    expect(panels.unmounted).toEqual([]);
    await act(async () => {
      release();
    });
  });

  it('atomically blocks a same-Slug POP between different actors during targeted logout, without losing its completion', async () => {
    const app = await mountApp();
    await signIn();
    const aliceEntry = app.router.state.location;
    await click(button('New connection'));
    await signIn();
    const bobEntry = app.router.state.location;
    expect(fragmentScope(aliceEntry)).toBe('bla-bla');
    expect(fragmentScope(bobEntry)).toBe(fragmentScope(aliceEntry));
    expect(bobEntry.hash).not.toBe(aliceEntry.hash);
    expect(aliceEntry.state.view).toBe(1);
    expect(bobEntry.state.view).toBe(2);
    expect(
      document.getElementById('terminal-pane-1')?.getAttribute('data-connection-principal'),
    ).toBe('alice');
    expect(
      document.getElementById('terminal-pane-2')?.getAttribute('data-connection-principal'),
    ).toBe('bob');
    let release!: () => void;
    app.holdLogout(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await act(async () => {
      document
        .getElementById('terminal-tab-2')
        ?.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    });
    const logout = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
      (node) => node.textContent === 'Log out',
    );
    await click(logout ?? null);
    const requests = app.requests.length;
    await act(async () => {
      await app.router.navigate(-1);
    });
    expect(app.router.state.location.key).toBe(bobEntry.key);
    expect(app.router.state.location.state.view).toBe(2);
    expect(selectedID()).toBe('terminal-pane-2');
    expect(panels.unmounted).toEqual([]);
    expect(panels.signals.get(1)?.aborted).toBe(false);
    expect(panels.signals.get(2)?.aborted).toBe(false);
    expect(app.requests).toHaveLength(requests);
    const targeted = app.requests.at(-1);
    expect(targeted?.path).toBe('/api/v1/logout');
    expect(targeted?.fields?.slug).toBe('bla-bla');
    expect(new Headers(targeted?.options?.headers).get('Authorization')).toBe(
      `Bearer bwa1.${'A'.repeat(42)}E`,
    );
    await act(async () => {
      release();
    });
    expect(document.getElementById('terminal-pane-2')).toBeNull();
    expect(document.getElementById('terminal-pane-1')).not.toBeNull();
    expect(selectedID()).toBe('terminal-pane-1');
    expect(app.router.state.location.state.view).toBe(1);
    expect(panels.unmounted).toEqual([2]);
    expect(panels.signals.get(1)?.aborted).toBe(false);
  });

  it.each([false, true])(
    'renders root directory options using rootAvailable=%s, never a phantom root entry',
    async (rootAvailable) => {
      const app = await mountApp('/', rootAvailable);
      const select = dialog().querySelector<HTMLElement>('[role="combobox"]');
      expect(select).not.toBeNull();
      expect(select?.textContent?.replaceAll('\u200b', '')).toBe(rootAvailable ? '/' : '');
      await act(async () => {
        select?.dispatchEvent(new MouseEvent('mousedown', { button: 0, bubbles: true }));
      });
      const labels = [...document.querySelectorAll('[role="option"]')].map(
        (node) => node.textContent,
      );
      expect(labels.includes('/')).toBe(rootAvailable);
      expect(labels).toContain('docker');
      expect(app.requests).toEqual([]);
      expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    },
  );

  it('selects a pasted known hash without reads and treats the same ID under another slug as an explicit login intent', async () => {
    const app = await mountApp('/#bla-bla');
    await signIn();
    const first = app.router.state.location;
    const target = parseHashTarget(location.origin, first.hash);
    expect(target?.connection).toBeTruthy();
    await click(button('New connection'));
    await signIn();
    expect(selectedID()).toBe('terminal-pane-2');
    const requests = app.requests.length;
    const saved = vi.mocked(BrowserBinding.load).mock.calls.length;
    await act(async () => {
      await app.router.navigate(`/${first.hash}`, { state: null });
    });
    expect(selectedID()).toBe('terminal-pane-1');
    expect(app.requests).toHaveLength(requests);
    expect(BrowserBinding.load).toHaveBeenCalledTimes(saved);
    await act(async () => {
      await app.router.navigate(`/#Other/${target?.connection}`);
    });
    expect(app.router.state.location.pathname + app.router.state.location.hash).toBe('/#Other/-');
    expect(
      dialog().querySelector('[data-login-scope="Other"][data-login-ready="true"]'),
    ).not.toBeNull();
    expect(app.requests.slice(requests).map((request) => request.path)).toEqual(['/Other']);
    expect(app.requests.filter((request) => request.options?.method === 'POST')).toHaveLength(2);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    expect(panels.mounted).toEqual([1, 2]);
    expect(panels.unmounted).toEqual([]);
    await signIn();
    expect(selectedID()).toBe('terminal-pane-3');
    expect(fragmentScope(app.router.state.location)).toBe('Other');
    expect(parseHashTarget(location.origin, app.router.state.location.hash)?.connection).not.toBe(
      target?.connection,
    );
  });

  it('keeps a stale hash target behind sign-in and replaces only its tab placeholder after explicit authorization', async () => {
    const stale = uuidText('34e34ab8-7457-4d88-a5e4-c57791775c3a');
    const app = await mountApp(`/#Work/${stale}/version`, false, true, {
      flow: { name: 'admin', title: 'Administration' },
    });
    expect(app.router.state.location.pathname + app.router.state.location.hash).toBe(
      '/#Work/-/version',
    );
    expect(app.requests).toEqual([]);
    expect(dialog().querySelector('form')).not.toBeNull();
    await signIn();
    await vi.waitFor(() =>
      expect(document.getElementById('terminal-tab-1')?.textContent).toBe('Version'),
    );
    const target = parseHashTarget(location.origin, app.router.state.location.hash);
    expect(target?.scope.slug).toBe('Work');
    expect(target?.management?.page).toBe('version');
    expect(target?.connection).not.toBe('-');
    expect(target?.connection).not.toBe(stale);
    expect(app.requests.filter((request) => request.path.endsWith('/login/password'))).toHaveLength(
      1,
    );
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
  });

  it('cycles owned tabs with delivered Ctrl+Tab and closes zero-status terminals without logout or confirmation', async () => {
    const app = await mountApp('/#Work');
    await signIn();
    await click(button('New connection'));
    await signIn();
    const requests = app.requests.length;
    await vi.waitFor(() =>
      expect(
        document
          .querySelector<HTMLElement>('.login-dialog[role="dialog"]')
          ?.checkVisibility({ visibilityProperty: true }) ?? false,
      ).toBe(false),
    );
    const key = async (shiftKey = false) => {
      const event = new KeyboardEvent('keydown', {
        key: 'Tab',
        ctrlKey: true,
        shiftKey,
        bubbles: true,
        cancelable: true,
      });
      await act(async () => {
        document.dispatchEvent(event);
      });
      expect(event.defaultPrevented).toBe(true);
    };
    await key();
    expect(selectedID()).toBe('terminal-pane-1');
    await key(true);
    expect(selectedID()).toBe('terminal-pane-2');
    await act(async () => panels.states.get(2)?.({ phase: 'exited', status: 0 }));
    expect(document.getElementById('terminal-pane-2')).toBeNull();
    expect(selectedID()).toBe('terminal-pane-1');
    await act(async () => panels.states.get(1)?.({ phase: 'exited', status: 0 }));
    expect(document.getElementById('terminal-pane-1')).toBeNull();
    expect(dialog().querySelector('form')).not.toBeNull();
    expect(app.requests).toHaveLength(requests);
  });

  it('retains a nonzero terminal result without an external exit-status text block', async () => {
    const app = await mountApp('/#Work');
    await signIn();
    await vi.waitFor(() =>
      expect(app.router.state.location.hash).toMatch(/^#Work\/[1-9A-HJ-NP-Za-km-z]{16,22}$/u),
    );
    await act(async () => panels.states.get(1)?.({ phase: 'exited', status: 7 }));
    expect(
      document.getElementById('terminal-pane-1')?.getAttribute('data-terminal-exit-status'),
    ).toBe('7');
    expect(document.querySelector('.terminal-state')).toBeNull();
    await vi.waitFor(() =>
      expect(
        document
          .querySelector<HTMLElement>('.login-dialog[role="dialog"]')
          ?.checkVisibility({ visibilityProperty: true }) ?? false,
      ).toBe(false),
    );
  });

  it('closes only the active management tab on Ctrl+D and does not close it behind sign-in', async () => {
    const app = await mountApp('/#Work', false, true);
    await signIn();
    const posts = app.requests.filter((request) => request.options?.method === 'POST').length;
    await click(button('New connection'));
    await act(async () =>
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'd', ctrlKey: true, bubbles: true, cancelable: true }),
      ),
    );
    expect(document.getElementById('terminal-pane-1')).not.toBeNull();
    await click(button('Close', dialog()));
    await vi.waitFor(() =>
      expect(
        document
          .querySelector<HTMLElement>('.login-dialog[role="dialog"]')
          ?.checkVisibility({ visibilityProperty: true }) ?? false,
      ).toBe(false),
    );
    for (const editable of ['', 'plaintext-only']) {
      const editor = document.createElement('div');
      editor.setAttribute('contenteditable', editable);
      document.getElementById('terminal-pane-1')?.append(editor);
      await act(async () =>
        editor.dispatchEvent(
          new KeyboardEvent('keydown', {
            key: 'd',
            ctrlKey: true,
            bubbles: true,
            cancelable: true,
          }),
        ),
      );
      expect(document.getElementById('terminal-pane-1')).not.toBeNull();
      editor.remove();
    }
    await act(async () =>
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'd', ctrlKey: true, bubbles: true, cancelable: true }),
      ),
    );
    expect(document.getElementById('terminal-pane-1')).toBeNull();
    expect(dialog().querySelector('form')).not.toBeNull();
    expect(app.requests.filter((request) => request.path.endsWith('/logout'))).toHaveLength(0);
    expect(app.requests.filter((request) => request.options?.method === 'POST')).toHaveLength(
      posts,
    );
  });

  it('does not log in on failed root discovery or explicit retry', async () => {
    const app = await mountApp();
    app.failDiscovery();
    await act(async () => {
      await app.router.navigate('/');
    });
    expect(dialog().querySelector('form')).toBeNull();
    await click(button('Retry loading options', dialog()));
    expect(app.requests.map((request) => request.path)).toEqual(['/', '/']);
    expect(app.requests.every((request) => request.options?.method !== 'POST')).toBe(true);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
  });

  it('preserves a cold management suffix through explicit login and uses fresh local history ownership', async () => {
    const app = await mountApp('/Work/admin/version', false, true, {
      entrySlug: 'Work',
      flow: { name: 'admin', title: 'Administration' },
    });
    expect(app.requests).toEqual([]);
    expect(dialog().querySelector('form')).not.toBeNull();
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
    await signIn();
    await vi.waitFor(() =>
      expect(document.getElementById('terminal-tab-1')?.textContent).toBe('Version'),
    );
    expect(fragmentScope(app.router.state.location)).toBe('Work');
    expect(app.router.state.location.hash).toMatch(
      /^#Work\/[1-9A-HJ-NP-Za-km-z]{16,22}\/version$/u,
    );
    expect(app.router.state.location.state.view).toBe(1);
    expect(
      app.requests
        .filter((request) => request.path.includes('/management/'))
        .map((request) => request.path.split('/management/')[1]),
    ).toEqual(['version/show', 'version/show']);
    expect(
      app.requests
        .filter((request) => request.path.includes('/management/'))
        .map((request) => request.fields?.long),
    ).toEqual(['false', 'true']);
    const cold = await mountApp(app.router.state.location, false, true, {
      entrySlug: 'Work',
      flow: { name: 'admin', title: 'Administration' },
    });
    expect(cold.requests).toEqual([]);
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
  });
  it('rejects a successful login to the wrong actual management flow without opening or reading the requested view', async () => {
    const app = await mountApp('/Work/expected/version', false, true, {
      entrySlug: 'Work',
      flow: { name: 'different', title: 'Administration' },
    });
    await signIn();
    expect(document.querySelector('[role="tab"]')).toBeNull();
    expect(app.router.state.location.pathname + app.router.state.location.hash).toBe(
      '/#Work/-/version',
    );
    expect(app.requests.map((request) => request.path)).toEqual(['/api/v1/login/password']);
    expect(dialog().textContent).toContain('does not match this management link');
  });
  it('returns side navigation to the page root instead of restoring an earlier entity depth', async () => {
    const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
    const path = `/Work/admin/sessions/Docker/${id}`;
    const app = await mountApp(path, false, true, {
      entrySlug: 'Work',
      flow: { name: 'admin', title: 'Administration' },
    });
    await signIn();
    await vi.waitFor(() => expect(document.querySelector('.session-details')).not.toBeNull());
    await click(button('Version'));
    await vi.waitFor(() =>
      expect(app.router.state.location.hash).toMatch(
        /^#Work\/[1-9A-HJ-NP-Za-km-z]{16,22}\/version$/u,
      ),
    );
    await click(button('Sessions'));
    await vi.waitFor(() =>
      expect(app.router.state.location.hash).toMatch(
        /^#Work\/[1-9A-HJ-NP-Za-km-z]{16,22}\/sessions$/u,
      ),
    );
    expect(document.querySelector('.session-details')).toBeNull();
    expect(app.requests.filter((request) => request.path.endsWith('/sessions/show'))).toHaveLength(
      1,
    );
  });
  it('confirms close-all once, cancels the owned connections like X, and does not log out, revoke, dispose, or forget settings', async () => {
    const app = await mountApp();
    await signIn();
    await click(button('New connection'));
    await signIn();
    const requests = app.requests.length;
    localStorage.setItem('bifroest-ui-v1:theme', 'dark');
    const menuItem = () =>
      [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
        (node) => node.textContent === 'Close all sessions',
      ) ?? null;
    await click(button('Application menu'));
    await click(menuItem());
    expect(panels.unmounted).toEqual([]);
    await click(button('Cancel'));
    expect(panels.unmounted).toEqual([]);
    await click(button('Application menu'));
    await click(menuItem());
    await click(button('Confirm'));
    await vi.waitFor(() => expect(document.querySelector('[role="tab"]')).toBeNull());
    expect([...panels.signals.values()].every((signal) => signal.aborted)).toBe(true);
    expect(panels.unmounted).toEqual([1, 2]);
    expect(app.requests).toHaveLength(requests);
    expect(localStorage.getItem('bifroest-ui-v1:theme')).toBe('dark');
    localStorage.removeItem('bifroest-ui-v1:theme');
  });
  it('runs the central confirmed reset for all owned accesses, closes their tabs and clears origin preferences', async () => {
    const app = await mountApp();
    await signIn();
    await click(button('New connection'));
    await signIn();
    const before = app.requests.length;
    const clears = vi.spyOn(BrowserBinding, 'clearForReset').mockResolvedValue(0);
    vi.spyOn(BrowserBinding, 'selectionsForReset').mockResolvedValue({
      handles: [],
      unconfirmed: 0,
    });
    localStorage.setItem('bifroest-ui-v1:theme', 'dark');
    localStorage.setItem('unrelated-app-key', 'untouched');
    try {
      await click(button('Application menu'));
      await click(
        [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
          (node) => node.textContent === 'Reset all settings and credentials',
        ) ?? null,
      );
      expect(clears).not.toHaveBeenCalled();
      expect(panels.unmounted).toEqual([]);
      await click(button('Confirm'));
      await vi.waitFor(() => expect(document.querySelector('[role="tab"]')).toBeNull());
      await vi.waitFor(() =>
        expect(document.querySelector('[role="dialog"]')?.textContent).toContain(
          'requested remote logouts and revocations were confirmed',
        ),
      );
      expect(app.requests.slice(before).map((request) => request.path)).toEqual([
        '/api/v1/logout',
        '/api/v1/logout',
      ]);
      expect(panels.unmounted).toEqual([1, 2]);
      expect(localStorage.getItem('bifroest-ui-v1:theme')).toBeNull();
      expect(localStorage.getItem('unrelated-app-key')).toBe('untouched');
      expect(clears).toHaveBeenCalledTimes(2);
    } finally {
      localStorage.removeItem('bifroest-ui-v1:theme');
      localStorage.removeItem('unrelated-app-key');
    }
  });
});

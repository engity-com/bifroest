import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter, type Location } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ManagementConnection } from '../src/management/channel';
import { BrowserBinding, BrowserClient } from '../src/remember';
import { WebAccess } from '../src/remember/client';
import { validateScope } from '../src/remember/protocol';
import { App } from '../src/ui/App';
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
      onState: (id: number, state: { phase: 'connected' }) => void;
    }) => {
      useEffect(() => {
        panels.mounted.push(id);
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
    throw new Error(`Unexpected authentication request ${path}`);
  });
  vi.stubGlobal('fetch', transport);
  const slug = (typeof initial === 'string' ? initial : (initial.pathname ?? '/')).slice(1);
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
  const element = [...parent.querySelectorAll('button')].find(
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
    expect(app.router.state.location.pathname).toBe('/foo');
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
    expect(app.router.state.location.pathname).toBe('/before');
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
      expect(app.router.state.location.pathname).toBe(initial);
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
    expect(app.router.state.location.pathname).toBe('/foo');
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
      ).toEqual(['version/show', 'flows/list']);
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
      ).toEqual(['version/show', 'flows/list', 'sessions/list']);
    });
    await click(button('Bifröst'));
    const owned = document.getElementById('terminal-pane-1');
    expect(owned?.querySelector('[aria-label="Server version"]')?.textContent).toContain(
      'Retained owner version',
    );
    await click(button('New connection'));
    await chooseSlug('Work');
    await signIn();
    expect(selectedID()).toBe('terminal-pane-2');
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
        new Headers(versionReads[1]?.options?.headers).get('Authorization'),
    ).toBe(true);
    const requests = app.requests.length;
    const reads = vi.mocked(BrowserBinding.load).mock.calls.length;
    await click(document.getElementById('terminal-tab-1'));
    expect(selectedID()).toBe('terminal-pane-1');
    expect(app.router.state.location.pathname).toBe('/bla-bla');
    expect(owned?.querySelector('[aria-label="Server version"]')?.textContent).toContain(
      'Retained owner version',
    );
    expect(app.requests).toHaveLength(requests);
    expect(BrowserBinding.load).toHaveBeenCalledTimes(reads);
    expect(
      app.requests.filter((request) => request.path.endsWith('/management/version/show')),
    ).toHaveLength(2);
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
    expect(aliasEntry.pathname).toBe('/bla-bla');
    expect(aliasEntry.state).toEqual({ generation: expect.any(String), view: 1 });
    await click(button('New connection'));
    await chooseSlug('docker');
    panels.pending.add(2);
    await signIn();
    expect(selectedID()).toBe('terminal-pane-2');
    const requestCount = app.requests.length;
    const savedReads = vi.mocked(BrowserBinding.load).mock.calls.length;
    await click(document.getElementById('terminal-tab-1'));
    expect(app.router.state.location.pathname).toBe('/bla-bla');
    expect(selectedID()).toBe('terminal-pane-1');
    expect(panels.signals.get(2)?.aborted).toBe(false);
    await act(async () => {
      await app.router.navigate(-1);
    });
    expect(app.router.state.location.pathname).toBe('/docker');
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
    expect(app.router.state.location.pathname).toBe('/bla-bla');
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
    expect(app.router.state.location.pathname).toBe('/Other');
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
    expect(aliceEntry.pathname).toBe('/bla-bla');
    expect(bobEntry.pathname).toBe(aliceEntry.pathname);
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
    expect(targeted?.path).toBe('/_bifroest/api/v1/logout');
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
});

import { act, createElement, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SessionActionConfirmation } from '../src/management/action';
import { ManagementPanel } from '../src/management/ManagementPanel';
import type { Page, SessionItem, SessionOptions } from '../src/management/protocol';
import { RememberMeError, type WebAccess } from '../src/remember';
import { closeNativeFilter, nativeColumnFilter } from './native-grid-filter-ui';
import { openSessionTarget, sessionTargetAction } from './session-target-ui';
import '../src/ui/app.css';

const item: SessionItem = {
  id: '9c77b24c-62f4-44c2-aea3-771c75e5a107',
  flow: 'work',
  state: 'authorized',
  user: 'alice',
  remote: 'alice@127.0.0.1',
  createdAt: '2026-01-01T00:00:00Z',
  owner: { issuer: 'verified-issuer', subject: 'verified-subject' },
};
const page: Page<SessionItem> = { items: [item], next: '', skipped: 0 };
const cleanups: (() => void)[] = [];
beforeEach(() => vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true));
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
      cleanup();
    }
  });
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function fixture() {
  const confirm = vi.fn(async () => ({ action: 'dispose' as const, flow: item.flow, id: item.id }));
  const cancel = vi.fn(async () => {});
  const preview = {
    action: 'dispose' as const,
    target: { flow: item.flow, id: item.id, details: item },
    expiresAt: '2026-12-01T00:00:00Z',
  };
  const api = {
    snapshot: () => ({
      scope: { origin: 'https://app.example.org', slug: 'Manage' },
      principal: 'manager',
    }),
    managementSessions: vi.fn(async (_options: SessionOptions, _signal?: AbortSignal) => page),
    managementSession: vi.fn(async () => item),
    managementVersion: vi.fn(async (long: boolean) => ({
      detail: long ? ('long' as const) : ('short' as const),
      text: long ? 'Version: test\nGo: test' : 'Bifröst test',
    })),
    managementFlows: vi.fn(async () => ({
      items: [{ name: 'work', authorization: 'simple', environment: 'local', auditlog: 'default' }],
      next: '',
      skipped: 0,
    })),
    prepareSessionAction: vi.fn(
      async () => new SessionActionConfirmation(preview, confirm, cancel),
    ),
  };
  return { api, access: api as unknown as WebAccess, confirm, cancel };
}
async function mount(
  access: WebAccess,
  initial: Partial<Parameters<typeof ManagementPanel>[0]> = {},
  strict = false,
) {
  const container = document.createElement('div');
  container.style.width = '1200px';
  document.body.append(container);
  const root = createRoot(container);
  const lock = vi.fn();
  let props = {
    access,
    active: true,
    disabled: false,
    view: 'sessions' as const,
    onActionLock: lock,
    ...initial,
  };
  cleanups.push(() => {
    root.unmount();
    container.remove();
  });
  async function render(next: Partial<Parameters<typeof ManagementPanel>[0]> = {}) {
    props = { ...props, ...next };
    await act(async () => {
      const content = createElement(ManagementPanel, props);
      root.render(strict ? createElement(StrictMode, null, content) : content);
    });
  }
  await render();
  return { container, lock, render };
}
function button(name: string, parent: ParentNode = document) {
  const found = [...parent.querySelectorAll<HTMLButtonElement>('button,a[href]')].find(
    (node) =>
      !node.closest('[hidden]') &&
      (node.textContent === name || node.getAttribute('aria-label') === name),
  );
  if (!found) {
    throw new Error(`Missing button: ${name}`);
  }
  return found;
}
async function click(element: HTMLElement) {
  await act(async () => element.click());
}
async function fill(label: string, value: string, parent: ParentNode = document) {
  const field = [...parent.querySelectorAll<HTMLInputElement>('input')].find(
    (node) => node.labels?.[0]?.textContent?.replace(/\s*\*$/, '') === label,
  );
  if (!field) {
    throw new Error(`Missing field: ${label}`);
  }
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

describe('management view read intent and retained ownership', () => {
  it('renders a missing entity as a management page, while an empty grid selection stays an unadorned empty grid', async () => {
    const { api, access } = fixture();
    api.managementSession.mockRejectedValue(new RememberMeError('not-found'));
    const { container, render } = await mount(access);
    await click(button(`Session details ${item.id}`, container));
    expect(container.querySelector('.management-not-found')?.textContent).toBe('Page not found');
    expect(container.querySelector('[role="alert"]')).toBeNull();
    const next = fixture();
    next.api.managementSessions.mockResolvedValue({ items: [], next: '', skipped: 0 });
    await render({ access: next.access });
    expect(container.querySelector('[role="grid"]')).not.toBeNull();
    expect(container.querySelector('.management-not-found')).toBeNull();
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });
  it.each(['sessions', 'server', 'version'] as const)(
    'does not duplicate the first %s read during StrictMode effect replay',
    async (view) => {
      const { api, access } = fixture();
      await mount(access, { view }, true);
      expect(api.managementSessions).toHaveBeenCalledTimes(view === 'sessions' ? 1 : 0);
      expect(api.managementVersion).toHaveBeenCalledTimes(view === 'version' ? 2 : 0);
      expect(api.managementFlows).toHaveBeenCalledTimes(view === 'server' ? 1 : 0);
      expect(api.prepareSessionAction).not.toHaveBeenCalled();
    },
  );
  it('loads sessions once only after its first active, enabled view; no background server reads', async () => {
    const { api, access } = fixture();
    const { render } = await mount(access, { active: false });
    expect(api.managementSessions).not.toHaveBeenCalled();
    expect(api.managementVersion).not.toHaveBeenCalled();
    expect(api.managementFlows).not.toHaveBeenCalled();
    await render({ active: true, disabled: true });
    expect(api.managementSessions).not.toHaveBeenCalled();
    await render({ disabled: false });
    expect(api.managementSessions).toHaveBeenCalledExactlyOnceWith(
      { state: 'all' },
      expect.any(AbortSignal),
    );
    await render({ active: false });
    await render({ active: true });
    expect(api.managementSessions).toHaveBeenCalledTimes(1);
    expect(api.managementVersion).not.toHaveBeenCalled();
    expect(api.managementFlows).not.toHaveBeenCalled();
    await click(button('Refresh sessions'));
    expect(api.managementSessions).toHaveBeenCalledTimes(2);
  });

  it('automatically serializes short and full version only in its own Version page, never in Overview', async () => {
    const { api, access } = fixture();
    const version = Promise.withResolvers<{ detail: 'short'; text: string }>();
    api.managementVersion.mockReturnValueOnce(version.promise);
    const { render, container } = await mount(access, { view: 'version', active: false });
    expect(api.managementVersion).not.toHaveBeenCalled();
    await render({ active: true });
    expect(api.managementSessions).not.toHaveBeenCalled();
    expect(api.managementVersion).toHaveBeenCalledExactlyOnceWith(false, expect.any(AbortSignal));
    expect(api.managementFlows).not.toHaveBeenCalled();
    await act(async () => version.resolve({ detail: 'short', text: 'Bifröst test' }));
    expect(api.managementFlows).not.toHaveBeenCalled();
    expect(api.managementVersion).toHaveBeenLastCalledWith(true, expect.any(AbortSignal));
    expect(container.textContent).toContain('Go: test');
    expect(container.querySelector('.build-details')).toBeNull();
    await render({ view: 'sessions' });
    await render({ view: 'server' });
    expect(api.managementVersion).toHaveBeenCalledTimes(2);
    expect(api.managementFlows).toHaveBeenCalledTimes(1);
    await render({ view: 'version' });
    expect(api.managementVersion).toHaveBeenCalledTimes(2);
    expect(container.textContent).toContain('Go: test');
  });

  it('does not retry a denied first read on activation, navigation or unrelated renders', async () => {
    const { api, access } = fixture();
    api.managementSessions.mockRejectedValue(new RememberMeError('denied'));
    const { render } = await mount(access);
    expect(api.managementSessions).toHaveBeenCalledTimes(1);
    await render({ active: false });
    await render({ active: true });
    await render({ view: 'server' });
    await render({ view: 'sessions' });
    await render({ disabled: true });
    await render({ disabled: false });
    await render();
    expect(api.managementSessions).toHaveBeenCalledTimes(1);
    await click(button('Refresh sessions'));
    expect(api.managementSessions).toHaveBeenCalledTimes(2);
  });

  it('does not continue the initial version read sequence while the page is inactive', async () => {
    const { api, access } = fixture();
    const version = Promise.withResolvers<{ detail: 'short'; text: string }>();
    api.managementVersion.mockReturnValueOnce(version.promise);
    const { render } = await mount(access, { view: 'version' });
    await render({ active: false });
    await act(async () => version.resolve({ detail: 'short', text: 'Bifröst test' }));
    expect(api.managementFlows).not.toHaveBeenCalled();
    expect(api.managementVersion).toHaveBeenCalledTimes(1);
    await render({ active: true });
    expect(api.managementVersion).toHaveBeenCalledTimes(2);
    expect(api.managementFlows).not.toHaveBeenCalled();
  });

  it('does not retry denied version reads or conflate them with the independently selected Overview page', async () => {
    const { api, access } = fixture();
    api.managementVersion.mockRejectedValue(new RememberMeError('denied'));
    const { render } = await mount(access, { view: 'version' });
    expect(api.managementVersion).toHaveBeenCalledTimes(2);
    expect(api.managementFlows).not.toHaveBeenCalled();
    await render({ active: false });
    await render({ active: true });
    expect(api.managementVersion).toHaveBeenCalledTimes(2);
    await render({ view: 'server' });
    expect(api.managementFlows).toHaveBeenCalledTimes(1);
  });

  it('retains selected details, version and target fields through view changes; resets for a new actor', async () => {
    const { api, access } = fixture();
    const { container, render } = await mount(access);
    await openSessionTarget(container);
    await fill('Target flow', 'retained-flow');
    await fill('Target session ID', item.id);
    await click(button('Open by ID', container));
    await click(button(`Session details ${item.id}`, container));
    const details = container.querySelector('.session-details');
    expect(document.activeElement).toBe(details);
    expect(container.querySelector('.session-details h3')).toBeNull();
    expect(container.querySelector('.session-actions')).toBeNull();
    expect(container.querySelector('.session-details .metadata-grid')?.textContent).toContain(
      'Disconnect connections',
    );
    await render({ active: false });
    await render({ active: true, view: 'server' });
    await render({ view: 'sessions' });
    expect(container.querySelector('.session-details')).toBe(details);
    expect(api.managementSession).toHaveBeenCalledTimes(1);
    expect(api.managementSessions).toHaveBeenCalledTimes(1);
    expect(container.querySelector('.session-details button[aria-label="Close"]')).toBeNull();
    await click(button('Sessions', container));
    await openSessionTarget(container);
    expect(document.querySelector<HTMLInputElement>('[role="dialog"] input')?.value).toBe(
      'retained-flow',
    );
    const next = fixture();
    next.api.managementSessions.mockResolvedValue({ items: [], next: '', skipped: 0 });
    await render({ access: next.access });
    expect(container.querySelector('.session-details')).toBeNull();
    expect(container.textContent).not.toContain('verified-issuer');
    expect(container.textContent).not.toContain('Bifröst test');
    expect(document.querySelector('[role="dialog"] input')).toBeNull();
    await openSessionTarget(container);
    expect(document.querySelector<HTMLInputElement>('[role="dialog"] input')?.value).toBe('');
    expect(next.api.managementSessions).toHaveBeenCalledTimes(1);
  });

  it('never focuses hidden details when a read finishes after leaving the sessions view', async () => {
    const { api, access } = fixture();
    const pending = Promise.withResolvers<SessionItem>();
    api.managementSession.mockReturnValueOnce(pending.promise);
    const { container, render } = await mount(access);
    await click(button(`Session details ${item.id}`, container));
    await render({ view: 'server' });
    await act(async () => pending.resolve(item));
    expect(document.activeElement).not.toBe(container.querySelector('.session-details'));
    await render({ view: 'sessions' });
    expect(api.managementSession).toHaveBeenCalledTimes(1);
  });

  it('aborts old actor reads and rejects their late results without reading for a disabled new actor', async () => {
    const old = fixture();
    const pending = Promise.withResolvers<Page<SessionItem>>();
    old.api.managementSessions.mockReturnValueOnce(pending.promise);
    const { container, render } = await mount(old.access);
    const signal = old.api.managementSessions.mock.calls[0]?.[1];
    const next = fixture();
    await render({ access: next.access, disabled: true });
    expect(signal?.aborted).toBe(true);
    expect(next.api.managementSessions).not.toHaveBeenCalled();
    await act(async () => pending.resolve(page));
    expect(container.querySelector('[role="grid"]')).not.toBeNull();
    expect(container.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    expect(container.textContent).not.toContain('alice');
    await render({ disabled: false });
    expect(next.api.managementSessions).toHaveBeenCalledTimes(1);
  });

  it('keeps the native column predicate bound to its server cursor across pages', async () => {
    const { api, access } = fixture();
    api.managementSessions.mockResolvedValueOnce({ ...page, next: 'bmp1.REAL' });
    const { container } = await mount(access);
    await vi.waitFor(() => expect(button('Refresh sessions', container).disabled).toBe(false));
    expect(button('Go to next page', container).disabled).toBe(false);
    api.managementSessions.mockResolvedValueOnce({ ...page, next: 'bmp1.FILTERED' });
    await nativeColumnFilter(container, 'Requesting user', 'alice');
    await vi.waitFor(() =>
      expect(api.managementSessions).toHaveBeenLastCalledWith(
        {
          state: 'all',
          query: '',
          filter: { field: 'user', operator: 'contains', value: 'alice' },
          sort: 'flow-asc',
        },
        expect.any(AbortSignal),
      ),
    );
    await closeNativeFilter(container);
    await click(button('Go to next page', container));
    expect(api.managementSessions.mock.calls.map(([filters]) => filters.after ?? '')).toEqual([
      '',
      '',
      'bmp1.FILTERED',
    ]);
    expect(api.managementSessions).toHaveBeenLastCalledWith(
      {
        state: 'all',
        query: '',
        filter: { field: 'user', operator: 'contains', value: 'alice' },
        sort: 'flow-asc',
        after: 'bmp1.FILTERED',
      },
      expect.any(AbortSignal),
    );
    expect(container.textContent).toContain('alice');
  });

  it('shows policy withholding instead of fabricated identity or lifetime, with no row actions', async () => {
    const { api, access } = fixture();
    const limited = { ...item, owner: null, remote: '', policyLimited: true };
    api.managementSessions.mockResolvedValue({ items: [limited], next: '', skipped: 1 });
    api.managementSession.mockResolvedValue(limited);
    const { container } = await mount(access);
    expect(container.textContent).toContain('Not returned under this forced-command policy');
    expect(container.textContent).toContain('must not be treated as a complete snapshot');
    await click(button(`Session details ${item.id}`, container));
    expect(button('End session', container).disabled).toBe(true);
    expect(button('Disconnect connections', container).disabled).toBe(true);
    expect(container.textContent).not.toContain('No fixed limit reported');
    expect(container.textContent).not.toContain('No verified association available');
  });

  it('allows explicit ID preparation despite a denied list read, without requiring target metadata', async () => {
    const { api, access, confirm, cancel } = fixture();
    api.managementSessions.mockRejectedValue(new RememberMeError('denied'));
    api.prepareSessionAction.mockResolvedValueOnce(
      new SessionActionConfirmation(
        {
          action: 'disconnect',
          target: { flow: item.flow, id: item.id },
          expiresAt: '2026-12-01T00:00:00Z',
        },
        confirm,
        cancel,
      ),
    );
    const { container } = await mount(access);
    const target = await openSessionTarget(container);
    await fill('Target flow', item.flow, target);
    await fill('Target session ID', item.id, target);
    await sessionTargetAction(target, 'Disconnect connections');
    await click(button('Go', target));
    expect(api.prepareSessionAction).toHaveBeenCalledExactlyOnceWith(
      'disconnect',
      item.flow,
      item.id,
      expect.any(AbortSignal),
    );
    expect(api.managementSessions).toHaveBeenCalledTimes(1);
    expect(api.managementSession).not.toHaveBeenCalled();
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain(
      'Session details are not returned under this action-only policy.',
    );
    expect(confirm).not.toHaveBeenCalled();
    await click(button('Cancel'));
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('keeps exact typing, preparation cancellation and the unknown outcome lock without replay', async () => {
    const { access, api, confirm, cancel } = fixture();
    confirm.mockRejectedValue(new RememberMeError('management-unknown'));
    const { container, lock, render } = await mount(access);
    await click(button(`Session details ${item.id}`, container));
    await click(button('End session', container));
    await render({ active: false });
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(confirm).not.toHaveBeenCalled();
    await render({ active: true });
    await click(button('End session', container));
    expect(button('Confirm session action').disabled).toBe(true);
    await fill('Type the exact flow/session ID shown above', 'wrong');
    expect(button('Confirm session action').disabled).toBe(true);
    await fill('Type the exact flow/session ID shown above', `${item.flow}/${item.id}`);
    await click(button('Confirm session action'));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(lock).toHaveBeenLastCalledWith(true);
    expect(container.textContent).toContain('The session action result is unknown.');
    expect(button('Open by ID', container).disabled).toBe(true);
    await render({ active: false });
    await render({ active: true });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(api.managementSessions).toHaveBeenCalledTimes(1);
    expect(lock).toHaveBeenLastCalledWith(true);
    await click(button('Dismiss local warning (does not confirm result)', container));
    expect(lock).toHaveBeenLastCalledWith(false);
    expect(confirm).toHaveBeenCalledTimes(1);
  });
});

import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import { AdminDataGrid } from '../src/ui/AdminDataGrid';
import {
  detailPreferenceKey,
  setDetailedView,
  useDetailRefresh,
} from '../src/ui/detail-preference';
import { t } from '../src/ui/messages';
import '../src/ui/app.css';

const rows = [{ id: 'row1', name: 'Core field', extra: 'Additional metadata' }];

it('keeps the source-switch action in place while search expands and read cancellation becomes available', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const host = document.createElement('div');
  host.style.width = '1200px';
  document.body.append(host);
  const root = createRoot(host);
  const switchSource = vi.fn();
  const render = async (busy = false) =>
    act(async () =>
      root.render(
        createElement(AdminDataGrid, {
          label: 'Stable toolbar',
          rows,
          columns: [{ field: 'name', headerName: 'Name', flex: 1 }],
          busy,
          disabled: false,
          page: 0,
          hasNext: false,
          query: '',
          sortField: 'name',
          sortDirection: 'asc',
          onPage: vi.fn(),
          onQuery: vi.fn(),
          onSort: vi.fn(),
          onSearch: vi.fn(),
          onRefresh: vi.fn(),
          onCancelRead: vi.fn(),
          work: { mode: 'server', onClick: switchSource },
        }),
      ),
    );
  const button = (label: string) => {
    const node = host.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
    if (!node) {
      throw new Error(`Missing ${label}`);
    }
    return node;
  };
  try {
    await render();
    const action = button(t('directServerData'));
    const before = Math.round(action.getBoundingClientRect().x);
    await act(async () => button('Search').click());
    await vi.waitFor(() =>
      expect(host.querySelector('input[placeholder="Search…"]')?.getClientRects().length).toBe(1),
    );
    expect(Math.round(action.getBoundingClientRect().x)).toBe(before);
    await render(true);
    expect(host.querySelector(`button[aria-label="${t('directServerData')}"]`)).toBe(action);
    expect(Math.round(action.getBoundingClientRect().x)).toBe(before);
    await render(false);
    expect(Math.round(action.getBoundingClientRect().x)).toBe(before);
    await act(async () => action.click());
    expect(switchSource).toHaveBeenCalledOnce();
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  }
});
it('retains the same grid while loading, disables refresh, and opens rows or the final non-hideable Actions icon exactly once', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const host = document.createElement('div');
  host.style.width = '1100px';
  document.body.append(host);
  const root = createRoot(host);
  const refresh = vi.fn();
  const open = vi.fn();
  const render = async (busy = false) =>
    act(async () =>
      root.render(
        createElement(AdminDataGrid, {
          label: 'Owned grid',
          rows: busy ? [] : rows,
          columns: [{ field: 'name', headerName: 'Name', flex: 1 }],
          busy,
          disabled: false,
          page: 0,
          hasNext: false,
          query: '',
          sortField: 'name',
          sortDirection: 'asc',
          onPage: vi.fn(),
          onQuery: vi.fn(),
          onSort: vi.fn(),
          onOpen: open,
          onRefresh: refresh,
        }),
      ),
    );
  const button = (label: string) => {
    const node = host.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
    if (!node) {
      throw new Error(`Missing ${label}`);
    }
    return node;
  };
  try {
    await render();
    const grid = host.querySelector('[role="grid"]');
    expect([...host.querySelectorAll('[role="columnheader"]')].at(-1)?.textContent).toBe('Actions');
    await act(async () =>
      host.querySelector<HTMLElement>('[role="gridcell"][data-field="name"]')?.click(),
    );
    expect(open).toHaveBeenCalledTimes(1);
    await act(async () => button('Show details').click());
    expect(open).toHaveBeenCalledTimes(2);
    await act(async () => button('Refresh').click());
    expect(refresh).toHaveBeenCalledOnce();
    await render(true);
    expect(host.querySelector('[role="grid"]')).toBe(grid);
    expect(button('Refresh').disabled).toBe(true);
    expect(grid?.getAttribute('aria-busy')).toBe('true');
    await vi.waitFor(() =>
      expect(
        host.querySelector('[data-testid="GridLoadingOverlay"]')?.closest('[role="grid"]'),
      ).toBe(grid),
    );
    expect(host.querySelector('[data-testid="VisibilityOffIcon"]')).not.toBeNull();
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  }
});
function DetailFixture({ reload }: { reload: () => void }) {
  const detailed = useDetailRefresh(true, false, false, reload);
  return createElement(AdminDataGrid, {
    label: 'Detail grid',
    rows,
    columns: [
      { field: 'name', headerName: 'Name', width: 250 },
      { field: 'extra', headerName: 'Extra', width: 250 },
    ],
    busy: false,
    disabled: false,
    page: 0,
    hasNext: false,
    query: '',
    sortField: 'name',
    sortDirection: 'asc',
    onPage: vi.fn(),
    onQuery: vi.fn(),
    onSort: vi.fn(),
    detailsAvailable: true,
    detailed,
    detailFields: ['extra'],
  });
}
it('defaults to full details and persists the eye for the origin, reloading and hiding supplemental columns without replacing the grid', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  localStorage.removeItem(detailPreferenceKey);
  const reload = vi.fn();
  const host = document.createElement('div');
  host.style.width = '1100px';
  document.body.append(host);
  const root = createRoot(host);
  try {
    await act(async () => root.render(createElement(DetailFixture, { reload })));
    const grid = host.querySelector('[role="grid"]');
    expect(host.textContent).toContain('Additional metadata');
    const eye = host.querySelector<HTMLButtonElement>(
      'button[aria-label="Show all available details"]',
    );
    if (!eye) {
      throw new Error('Missing eye');
    }
    expect(eye.getAttribute('aria-pressed')).toBe('true');
    await act(async () => eye.click());
    expect(localStorage.getItem(detailPreferenceKey)).toBe('compact');
    expect(reload).toHaveBeenCalledOnce();
    expect(host.textContent).not.toContain('Additional metadata');
    expect(host.querySelector('[role="grid"]')).toBe(grid);
  } finally {
    await act(async () => root.unmount());
    host.remove();
    localStorage.removeItem(detailPreferenceKey);
    vi.unstubAllGlobals();
  }
});
it('still switches the display in memory when browser preference storage is unavailable', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  localStorage.removeItem(detailPreferenceKey);
  const host = document.createElement('div');
  host.style.width = '1100px';
  document.body.append(host);
  const root = createRoot(host);
  const reload = vi.fn();
  const blocked = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new DOMException('blocked', 'SecurityError');
  });
  try {
    await act(async () => root.render(createElement(DetailFixture, { reload })));
    const eye = host.querySelector<HTMLButtonElement>(
      'button[aria-label="Show all available details"]',
    );
    if (!eye) {
      throw new Error('Missing eye');
    }
    await act(async () => eye.click());
    expect(eye.getAttribute('aria-pressed')).toBe('false');
    expect(host.textContent).not.toContain('Additional metadata');
    expect(reload).toHaveBeenCalledOnce();
  } finally {
    await act(async () => root.unmount());
    host.remove();
    blocked.mockRestore();
    setDetailedView(true);
    localStorage.removeItem(detailPreferenceKey);
    vi.unstubAllGlobals();
  }
});

import { act, createElement, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, expect, it, vi } from 'vitest';
import type { ColumnFilter } from '../src/management/protocol';
import { AdminDataGrid } from '../src/ui/AdminDataGrid';
import '../src/ui/app.css';

const cleanups: (() => void)[] = [];
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });
  vi.unstubAllGlobals();
});

function Fixture({
  requests,
  active = true,
}: {
  requests: (kind: string, value: unknown) => void;
  active?: boolean;
}) {
  const rows = Array.from({ length: 20 }, (_, index) => ({
    id: `row-${index}`,
    name: `Name ${index}`,
  }));
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ColumnFilter | null>(null);
  const [page, setPage] = useState(0);
  const [direction, setDirection] = useState<'asc' | 'desc'>('asc');
  return createElement(AdminDataGrid, {
    label: 'Fixture inventory',
    rows,
    columns: [{ field: 'name', headerName: 'Name', flex: 1 }],
    busy: false,
    disabled: false,
    page,
    hasNext: true,
    query,
    active,
    columnFilter: filter,
    onSearch: (query, filter) => {
      requests(filter ? 'filter' : 'query', filter ?? query);
      setQuery(query);
      setFilter(filter);
      setPage(0);
    },
    sortField: 'name',
    sortDirection: direction,
    onPage: (next) => {
      requests('page', next);
      setPage(next);
    },
    onQuery: (next) => {
      requests('query', next);
      setQuery(next);
      setPage(0);
    },
    onSort: (next) => {
      requests('sort', next);
      setDirection(next);
      setPage(0);
    },
  });
}

it('uses native grid pagination and column sorting as server intents, without quick search', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const host = document.createElement('div');
  host.style.width = '1000px';
  document.body.append(host);
  const root = createRoot(host);
  cleanups.push(() => {
    root.unmount();
    host.remove();
  });
  const requests = vi.fn();
  await act(async () => root.render(createElement(Fixture, { requests })));
  const button = (label: string) => {
    const result = [...host.querySelectorAll<HTMLButtonElement>('button')].find(
      (node) => node.getAttribute('aria-label') === label,
    );
    if (!result) {
      throw new Error(`Missing native grid button ${label}`);
    }
    return result;
  };
  await act(async () => button('Go to next page').click());
  expect(requests).toHaveBeenLastCalledWith('page', 1);
  await act(async () => button('Go to previous page').click());
  expect(requests).toHaveBeenLastCalledWith('page', 0);
  const header = host.querySelector<HTMLElement>('[role="columnheader"][data-field="name"]');
  if (!header) {
    throw new Error('Missing sortable grid header');
  }
  await act(async () => header.click());
  expect(requests).toHaveBeenLastCalledWith('sort', 'desc');
  expect(host.querySelector('button[aria-label="Search"]')).toBeNull();
  expect(host.querySelector('input[placeholder="Search…"]')).toBeNull();
  // The server has deliberately not replaced this fixture page yet. A local
  // filter/sort would remove/reorder these rows, misrepresenting the inventory.
  expect(host.querySelector('[role="gridcell"][data-field="name"]')?.textContent).toBe('Name 0');
  expect(host.querySelector('[aria-label="Export"]')).toBeNull();
});

it('opens the built-in filter panel, submits its real column predicate, and retires its portal on deactivation', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const host = document.createElement('div');
  host.style.width = '1000px';
  document.body.append(host);
  const root = createRoot(host);
  cleanups.push(() => {
    root.unmount();
    host.remove();
  });
  const requests = vi.fn();
  await act(async () => root.render(createElement(Fixture, { requests })));
  const trigger = [...host.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) => node.getAttribute('aria-label') === 'Filters',
  );
  if (!trigger) {
    throw new Error('Missing native Data Grid Filters control');
  }
  await act(async () => trigger.click());
  const input = document.querySelector<HTMLInputElement>('input[placeholder="Filter value"]');
  if (!input) {
    throw new Error('Missing native column filter input');
  }
  expect(requests).not.toHaveBeenCalled();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
      input,
      'Name 1',
    );
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await vi.waitFor(() =>
    expect(requests).toHaveBeenLastCalledWith('filter', {
      field: 'name',
      operator: 'contains',
      value: 'Name 1',
    }),
  );
  expect(host.querySelector('[role="gridcell"][data-field="name"]')?.textContent).toBe('Name 0');
  const count = requests.mock.calls.length;
  await act(async () => root.render(createElement(Fixture, { requests, active: false })));
  await vi.waitFor(() =>
    expect(
      [...document.querySelectorAll<HTMLElement>('.MuiDataGrid-filterForm')].every(
        (node) => node.getClientRects().length === 0,
      ),
    ).toBe(true),
  );
  expect(requests).toHaveBeenCalledTimes(count);
});

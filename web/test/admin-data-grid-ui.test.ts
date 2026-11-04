import { act, createElement, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, expect, it, vi } from 'vitest';
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

function Fixture({ requests }: { requests: (kind: string, value: string | number) => void }) {
  const rows = Array.from({ length: 20 }, (_, index) => ({
    id: `row-${index}`,
    name: `Name ${index}`,
  }));
  const [query, setQuery] = useState('');
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

it('uses native grid pagination, column sorting and quick search as server intents, not local page transformations', async () => {
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
  await act(async () => button('Search').click());
  const input = host.querySelector<HTMLInputElement>('input[placeholder="Search…"]');
  if (!input) {
    throw new Error('Missing native quick search');
  }
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
      input,
      'not-a-local-row',
    );
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await vi.waitFor(() => expect(requests).toHaveBeenLastCalledWith('query', 'not-a-local-row'));
  // The server has deliberately not replaced this fixture page yet. A local
  // filter/sort would remove/reorder these rows, misrepresenting the inventory.
  expect(host.querySelector('[role="gridcell"][data-field="name"]')?.textContent).toBe('Name 0');
  expect(host.querySelector('[aria-label="Export"]')).toBeNull();
});

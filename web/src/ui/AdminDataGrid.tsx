import {
  DataGrid,
  type GridColDef,
  type GridFilterModel,
  type GridSortModel,
  type GridValidRowModel,
} from '@mui/x-data-grid';
import { useEffect, useMemo, useRef, useState } from 'react';

// Native grid controls, but authoritative filtering/order/pagination stay on the
// server. Never pretend that sorting one loaded page sorts the whole inventory.
export function AdminDataGrid<R extends GridValidRowModel>({
  label,
  rows,
  columns,
  getRowId,
  busy,
  disabled,
  page,
  hasNext,
  query,
  sortField,
  sortDirection,
  onPage,
  onQuery,
  onSort,
  actionField,
}: {
  label: string;
  rows: readonly R[];
  columns: readonly GridColDef<R>[];
  getRowId?: (row: R) => string;
  busy: boolean;
  disabled: boolean;
  page: number;
  hasNext: boolean;
  query: string;
  sortField: string;
  sortDirection: 'asc' | 'desc';
  onPage(page: number): void;
  onQuery(query: string): void;
  onSort(direction: 'asc' | 'desc'): void;
  actionField?: string;
}) {
  const [draft, setDraft] = useState(query);
  const pending = useRef<string | null>(null);
  const send = useRef(onQuery);
  send.current = onQuery;
  useEffect(() => {
    if (pending.current === null) {
      setDraft(query);
    }
  }, [query]);
  useEffect(() => {
    if (!busy && !disabled && pending.current !== null) {
      const next = pending.current;
      pending.current = null;
      send.current(next);
    }
  }, [busy, disabled]);
  const filters: GridFilterModel = useMemo(
    () => ({
      items: [],
      quickFilterValues: draft.split(/\s+/u).filter(Boolean),
    }),
    [draft],
  );
  const order: GridSortModel = useMemo(
    () => [{ field: sortField, sort: sortDirection }],
    [sortField, sortDirection],
  );
  const paginationModel = useMemo(() => ({ page, pageSize: 20 }), [page]);
  return (
    <div className="admin-data-grid">
      <DataGrid<R>
        nonce={
          document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? ''
        }
        label={label}
        rows={rows}
        columns={columns
          .toSorted((a, b) => Number(b.field === actionField) - Number(a.field === actionField))
          .map((column) => ({
            ...column,
            filterable: false,
            sortable: column.field === sortField,
          }))}
        {...(getRowId ? { getRowId } : {})}
        loading={busy}
        disableRowSelectionOnClick
        disableColumnSelector
        disableDensitySelector
        showToolbar
        slotProps={{
          toolbar: {
            csvOptions: { disableToolbarButton: true },
            printOptions: { disableToolbarButton: true },
          },
        }}
        pagination
        paginationMode="server"
        sortingMode="server"
        filterMode="server"
        filterDebounceMs={350}
        paginationModel={paginationModel}
        // Supply an exact count only once the server cursor ends. Combining a
        // newly closed cursor with paginationMeta lets x-data-grid infer the
        // count from the PREVIOUS controlled page before applying the new one.
        rowCount={hasNext ? -1 : page * 20 + rows.length}
        pageSizeOptions={[20]}
        onPaginationModelChange={(model) => {
          if (!disabled && !busy && model.page !== page) {
            onPage(model.page);
          }
        }}
        filterModel={filters}
        onFilterModelChange={(model) => {
          const next = (model.quickFilterValues ?? []).join(' ').slice(0, 256);
          if (!disabled && next !== draft) {
            setDraft(next);
            if (busy) {
              pending.current = next;
            } else {
              onQuery(next);
            }
          }
        }}
        sortModel={order}
        sortingOrder={['asc', 'desc']}
        onSortModelChange={(model) => {
          const next = model[0]?.sort;
          if (!disabled && !busy && (next === 'asc' || next === 'desc') && next !== sortDirection) {
            onSort(next);
          }
        }}
        disableColumnFilter
        hideFooterSelectedRowCount
        sx={{
          border: 0,
          '& .MuiDataGrid-cell': { alignItems: 'center', display: 'flex' },
          '& .MuiDataGrid-toolbar': { gap: 1 },
        }}
      />
    </div>
  );
}

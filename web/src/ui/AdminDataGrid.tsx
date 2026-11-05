import {
  DataGrid,
  type GridColDef,
  type GridFilterModel,
  type GridSortModel,
  type GridValidRowModel,
  useGridApiRef,
} from '@mui/x-data-grid';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ColumnFilter } from '../management/protocol';
import { type GridSearch, gridModel, gridSearch } from './grid-filter';
import { t } from './messages';

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
  columnFilter = null,
  onSearch,
  active = true,
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
  columnFilter?: ColumnFilter | null;
  onSearch?: (query: string, filter: ColumnFilter | null) => void;
  active?: boolean;
}) {
  const apiRef = useGridApiRef();
  useLayoutEffect(() => {
    if (!active || disabled) {
      pending.current = null;
      apiRef.current?.hideFilterPanel?.();
      apiRef.current?.hideColumnMenu?.();
    }
  }, [active, disabled, apiRef]);
  const [model, setModel] = useState<GridFilterModel>(() => gridModel(query, columnFilter));
  const [filterInvalid, setFilterInvalid] = useState(false);
  const currentColumns = useRef(columns);
  currentColumns.current = columns;
  const pending = useRef<GridSearch | null>(null);
  const send = useRef((value: GridSearch) =>
    onSearch ? onSearch(value.query, value.filter) : onQuery(value.query),
  );
  send.current = (value) => (onSearch ? onSearch(value.query, value.filter) : onQuery(value.query));
  const sent = useRef(JSON.stringify({ query, filter: columnFilter }));
  useEffect(() => {
    if (pending.current === null) {
      sent.current = JSON.stringify({ query, filter: columnFilter });
      setModel((current) => {
        try {
          return JSON.stringify(gridSearch(current, currentColumns.current)) === sent.current
            ? current
            : gridModel(query, columnFilter);
        } catch {
          return current;
        }
      });
    }
  }, [query, columnFilter]);
  useEffect(() => {
    if (!busy && !disabled && active && pending.current !== null) {
      const next = pending.current;
      pending.current = null;
      send.current(next);
    }
  }, [busy, disabled, active]);
  const order: GridSortModel = useMemo(
    () => [{ field: sortField, sort: sortDirection }],
    [sortField, sortDirection],
  );
  const paginationModel = useMemo(() => ({ page, pageSize: 20 }), [page]);
  return (
    <div className="admin-data-grid">
      <DataGrid<R>
        apiRef={apiRef}
        nonce={
          document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? ''
        }
        label={label}
        rows={rows}
        columns={columns
          .toSorted((a, b) => Number(b.field === actionField) - Number(a.field === actionField))
          .map((column) => ({
            ...column,
            filterable: !!onSearch && column.field !== actionField && column.filterable !== false,
            sortable: column.field === sortField,
          }))}
        {...(getRowId ? { getRowId } : {})}
        loading={busy}
        disableRowSelectionOnClick
        disableColumnSelector
        disableDensitySelector
        showToolbar
        slotProps={{
          filterPanel: {
            filterFormProps: {
              valueInputProps: {
                InputComponentProps: {
                  error: filterInvalid,
                  helperText: filterInvalid ? t('adminFilterLimit') : '',
                },
              },
            },
          },
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
          if (active && !disabled && !busy && model.page !== page) {
            onPage(model.page);
          }
        }}
        filterModel={model}
        onFilterModelChange={(nextModel) => {
          if (disabled || !active) {
            return;
          }
          setModel(nextModel);
          let next: GridSearch;
          try {
            next = gridSearch(nextModel, columns);
            setFilterInvalid(false);
          } catch {
            setFilterInvalid(true);
            return;
          }
          const key = JSON.stringify(next);
          if (key !== sent.current) {
            sent.current = key;
            if (busy) {
              pending.current = next;
            } else {
              send.current(next);
            }
          }
        }}
        sortModel={order}
        sortingOrder={['asc', 'desc']}
        onSortModelChange={(model) => {
          const next = model[0]?.sort;
          if (
            active &&
            !disabled &&
            !busy &&
            (next === 'asc' || next === 'desc') &&
            next !== sortDirection
          ) {
            onSort(next);
          }
        }}
        disableColumnFilter={!onSearch}
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

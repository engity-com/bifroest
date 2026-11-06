import SearchIcon from '@mui/icons-material/Search';
import { IconButton, Tooltip } from '@mui/material';
import {
  DataGrid,
  type GridColDef,
  type GridFilterModel,
  type GridSortModel,
  type GridValidRowModel,
  useGridApiRef,
} from '@mui/x-data-grid';
import type { ReactNode } from 'react';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ColumnFilter } from '../management/protocol';
import { AdminGridControlsContext, AdminGridToolbar } from './AdminGridToolbar';
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
  total,
  resultAvailable = true,
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
  onRefresh,
  refreshLabel,
  onOpen,
  canOpen,
  openLabel,
  openByID,
  detailFields = [],
  detailed = true,
  detailsAvailable = false,
  rowActions,
}: {
  label: string;
  rows: readonly R[];
  columns: readonly GridColDef<R>[];
  getRowId?: (row: R) => string;
  busy: boolean;
  disabled: boolean;
  page: number;
  hasNext: boolean;
  total?: number | undefined;
  resultAvailable?: boolean;
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
  onRefresh?: () => void;
  refreshLabel?: string;
  onOpen?: (row: R) => void;
  canOpen?: (row: R) => boolean;
  openLabel?: (row: R) => string;
  openByID?: ReactNode;
  detailFields?: readonly string[];
  detailed?: boolean;
  detailsAvailable?: boolean;
  rowActions?: (row: R) => ReactNode;
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
    <AdminGridControlsContext.Provider
      value={{
        active,
        disabled,
        busy,
        filterable: !!onSearch,
        onRefresh,
        refreshLabel,
        detailsAvailable,
        openByID,
      }}
    >
      <div className="admin-data-grid">
        <DataGrid<R>
          apiRef={apiRef}
          nonce={
            document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? ''
          }
          aria-label={label}
          aria-busy={busy}
          rows={rows}
          columns={[
            ...columns.filter(
              (column) =>
                column.field !== actionField && (detailed || !detailFields.includes(column.field)),
            ),
            ...(onOpen || rowActions
              ? [
                  {
                    field: 'actions',
                    type: 'actions' as const,
                    headerName: t('adminGridActions'),
                    width: rowActions ? 144 : 90,
                    hideable: false,
                    disableColumnMenu: true,
                    filterable: false,
                    sortable: false,
                    renderCell: (params: { row: R }) =>
                      rowActions ? (
                        rowActions(params.row)
                      ) : (
                        <Tooltip title={openLabel?.(params.row) ?? t('adminGridOpen')}>
                          <span>
                            <IconButton
                              size="small"
                              aria-label={openLabel?.(params.row) ?? t('adminGridOpen')}
                              disabled={
                                disabled || busy || !active || canOpen?.(params.row) === false
                              }
                              onClick={(event) => {
                                event.stopPropagation();
                                onOpen?.(params.row);
                              }}
                            >
                              <SearchIcon fontSize="small" />
                            </IconButton>
                          </span>
                        </Tooltip>
                      ),
                  },
                ]
              : []),
          ].map((column) => ({
            ...column,
            filterable: !!onSearch && column.field !== 'actions' && column.filterable !== false,
            sortable: column.field === sortField,
          }))}
          {...(getRowId ? { getRowId } : {})}
          loading={busy}
          localeText={resultAvailable ? {} : { noRowsLabel: t('scanNoResult') }}
          hideFooterPagination={!resultAvailable}
          onRowClick={(params, event) => {
            if (
              !disabled &&
              !busy &&
              active &&
              canOpen?.(params.row) !== false &&
              !(event.target as Element).closest('button,a,input,[role="button"]')
            ) {
              onOpen?.(params.row);
            }
          }}
          onCellKeyDown={(params, event) => {
            if (
              (event.key === 'Enter' || event.key === ' ') &&
              params.field !== 'actions' &&
              onOpen &&
              !disabled &&
              !busy &&
              active &&
              canOpen?.(params.row) !== false
            ) {
              event.preventDefault();
              onOpen(params.row);
            }
          }}
          disableRowSelectionOnClick
          disableColumnSelector
          disableDensitySelector
          showToolbar
          slots={{ toolbar: AdminGridToolbar }}
          slotProps={{
            main: { 'aria-busy': busy },
            loadingOverlay: { variant: 'skeleton', noRowsVariant: 'skeleton' },
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
          // Streaming counts become authority for this view only with a
          // completed matching page. Legacy cursors still infer an exact count
          // only when they end. Combining a
          // newly closed cursor with paginationMeta lets x-data-grid infer the
          // count from the PREVIOUS controlled page before applying the new one.
          rowCount={
            busy || !resultAvailable ? -1 : (total ?? (hasNext ? -1 : page * 20 + rows.length))
          }
          pageSizeOptions={[20]}
          onPaginationModelChange={(model) => {
            if (active && !disabled && !busy && resultAvailable && model.page !== page) {
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
            '& .MuiDataGrid-row': { cursor: onOpen ? 'pointer' : undefined },
          }}
        />
      </div>
    </AdminGridControlsContext.Provider>
  );
}

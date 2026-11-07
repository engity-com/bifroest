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
import { useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ReadProgress } from '../management/progress';
import type { ColumnFilter } from '../management/protocol';
import { AdminGridControlsContext, AdminGridToolbar } from './AdminGridToolbar';
import {
  type GridDetails,
  GridLoadingOverlay,
  GridProgressContext,
  type GridWork,
  GridWorkContext,
} from './GridWork';
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
  hiddenFields = [],
  detailed = true,
  detailsAvailable = false,
  rowActions,
  work,
  readProgress,
  onCancelRead,
  detailToggle,
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
  hiddenFields?: readonly string[];
  detailed?: boolean;
  detailsAvailable?: boolean;
  rowActions?: (row: R) => ReactNode;
  work?: GridWork | undefined;
  readProgress?: ReadProgress | null | undefined;
  onCancelRead?: (() => void) | undefined;
  detailToggle?: GridDetails | undefined;
}) {
  const inheritedWork = useContext(GridWorkContext);
  const gridWork = work ?? inheritedWork;
  const loading = busy || gridWork?.mode === 'cancel';
  const container = useRef<HTMLDivElement>(null);
  const apiRef = useGridApiRef();
  useLayoutEffect(() => {
    if (!active || disabled || loading) {
      apiRef.current?.hideFilterPanel?.();
      apiRef.current?.hideColumnMenu?.();
    }
    const main = container.current?.querySelector<HTMLElement>('.MuiDataGrid-main');
    if (main) {
      main.inert = disabled || !active;
    }
    // Leave the progress live region accessible. Only the data, headers,
    // scrollbars and footer become inert during an owned operation.
    for (const element of container.current?.querySelectorAll<HTMLElement>(
      '.MuiDataGrid-columnHeaders, .MuiDataGrid-virtualScrollerRenderZone, .MuiDataGrid-footerContainer, .MuiDataGrid-scrollbar',
    ) ?? []) {
      element.inert = loading || disabled || !active;
    }
  }, [active, disabled, loading, apiRef]);
  const [model, setModel] = useState<GridFilterModel>(() => gridModel(query, columnFilter));
  const [filterInvalid, setFilterInvalid] = useState(false);
  const currentColumns = useRef(columns);
  currentColumns.current = columns;
  const sent = useRef(JSON.stringify({ query, filter: columnFilter }));
  useEffect(() => {
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
  }, [query, columnFilter]);
  const order: GridSortModel = useMemo(
    () => [{ field: sortField, sort: sortDirection }],
    [sortField, sortDirection],
  );
  const paginationModel = useMemo(() => ({ page, pageSize: 20 }), [page]);
  return (
    <GridProgressContext.Provider
      value={{
        visible: busy || gridWork?.mode === 'cancel',
        value: gridWork?.mode === 'cancel' ? (gridWork.progress ?? null) : (readProgress ?? null),
      }}
    >
      <AdminGridControlsContext.Provider
        value={{
          active,
          disabled,
          busy: loading,
          filterable: !!onSearch,
          onRefresh,
          refreshLabel,
          detailsAvailable,
          openByID,
          work: gridWork,
          detailToggle,
          onCancelRead,
        }}
      >
        <div className="admin-data-grid" ref={container}>
          <DataGrid<R>
            apiRef={apiRef}
            nonce={
              document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? ''
            }
            aria-label={label}
            aria-busy={loading}
            rows={rows}
            columns={[
              ...columns.filter((column) => column.field !== actionField),
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
                      renderCell: (params: { row: R }) => (
                        <div className="actions">
                          {rowActions?.(params.row)}
                          {onOpen && (
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
                          )}
                        </div>
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
            loading={loading}
            localeText={resultAvailable ? {} : { noRowsLabel: t('scanNoResult') }}
            hideFooterPagination={!resultAvailable}
            onRowClick={(params, event) => {
              if (
                !disabled &&
                !loading &&
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
                !loading &&
                active &&
                canOpen?.(params.row) !== false
              ) {
                event.preventDefault();
                onOpen(params.row);
              }
            }}
            disableRowSelectionOnClick
            disableColumnSelector
            columnVisibilityModel={Object.fromEntries([
              ...detailFields.map((field) => [field, detailed || columnFilter?.field === field]),
              ...hiddenFields.map((field) => [field, columnFilter?.field === field]),
            ])}
            disableDensitySelector
            showToolbar
            slots={{ toolbar: AdminGridToolbar, loadingOverlay: GridLoadingOverlay }}
            slotProps={{
              basePagination: { disabled: loading || disabled || !active },
              main: { 'aria-busy': loading },
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
              if (active && !disabled && !loading && resultAvailable && model.page !== page) {
                onPage(model.page);
              }
            }}
            filterModel={model}
            onFilterModelChange={(nextModel) => {
              if (disabled || !active || loading) {
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
                if (onSearch) {
                  onSearch(next.query, next.filter);
                } else {
                  onQuery(next.query);
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
                !loading &&
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
              '& .MuiDataGrid-overlayWrapper': { pointerEvents: 'none' },
              '& .MuiDataGrid-cell': { alignItems: 'center', display: 'flex' },
              '& .MuiDataGrid-toolbar': { gap: 1 },
              '& .MuiDataGrid-row': { cursor: onOpen ? 'pointer' : undefined },
            }}
          />
        </div>
      </AdminGridControlsContext.Provider>
    </GridProgressContext.Provider>
  );
}

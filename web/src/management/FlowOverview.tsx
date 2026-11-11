import FactCheckIcon from '@mui/icons-material/FactCheck';
import PeopleOutlineIcon from '@mui/icons-material/PeopleOutlineOutlined';
import ScreenshotMonitorIcon from '@mui/icons-material/ScreenshotMonitor';
import { IconButton, Link, Tooltip } from '@mui/material';
import type { Scope } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { bookmarkPath } from '../ui/hash-route';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert } from '../ui/material';
import { t } from '../ui/messages';
import { m } from './messages';
import type { ColumnFilter, FlowSummary, Page } from './protocol';

export function FlowOverview({
  scope,
  rows,
  active,
  busy,
  locked,
  disabled,
  pagination,
  actions,
}: {
  scope: Scope;
  rows: Page<FlowSummary> | null;
  active: boolean;
  busy: boolean;
  locked: boolean;
  disabled: boolean;
  pagination: {
    index: number;
    query: string;
    direction: 'asc' | 'desc';
    filter: ColumnFilter | null;
  };
  actions: {
    refresh(): void;
    search(query: string, filter: ColumnFilter | null): void;
    page(index: number): void;
    query(value: string): void;
    sort(direction: 'asc' | 'desc'): void;
  };
}) {
  const navigation = useManagementNavigation();
  return (
    <>
      {(rows?.skipped ?? 0) > 0 && (
        <Alert color="yellow">
          {t('managementPartial')} ({rows?.skipped})
        </Alert>
      )}
      <AdminDataGrid<FlowSummary>
        active={active}
        label={t('managementFlowsCaption')}
        rows={rows?.items ?? []}
        onRefresh={actions.refresh}
        refreshLabel={m('flowsRefresh')}
        getRowId={(item) => item.name}
        columns={[
          { field: 'name', headerName: t('managementFlow'), minWidth: 170, flex: 1 },
          {
            field: 'authorization',
            headerName: t('managementAuthorization'),
            minWidth: 170,
            flex: 1,
          },
          { field: 'environment', headerName: t('managementEnvironment'), minWidth: 170, flex: 1 },
          {
            field: 'auditlog',
            headerName: t('managementAuditlog'),
            minWidth: 170,
            flex: 1,
            renderCell: (params) =>
              params.row.auditlog && navigation ? (
                <Link
                  href={
                    locked
                      ? undefined
                      : bookmarkPath(scope, {
                          managementFlow: navigation.location.managementFlow,
                          page: 'auditlogs',
                          auditlog: params.row.auditlog,
                        })
                  }
                  aria-disabled={locked}
                  onClick={(event) => {
                    event.stopPropagation();
                    if (locked) {
                      event.preventDefault();
                      return;
                    }
                    if (
                      event.button !== 0 ||
                      event.ctrlKey ||
                      event.metaKey ||
                      event.shiftKey ||
                      event.altKey
                    ) {
                      return;
                    }
                    event.preventDefault();
                    navigation.navigate({
                      managementFlow: navigation.location.managementFlow,
                      page: 'auditlogs',
                      auditlog: params.row.auditlog,
                    });
                  }}
                >
                  {params.row.auditlog}
                </Link>
              ) : (
                params.row.auditlog
              ),
          },
        ]}
        rowActions={(row) => (
          <div className="actions">
            <Tooltip title={t('workspaceSessions')}>
              <IconButton
                size="small"
                disabled={locked || !navigation}
                aria-label={`${t('workspaceSessions')} ${row.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  navigation?.navigate({
                    managementFlow: navigation.location.managementFlow,
                    page: 'sessions',
                    flow: row.name,
                  });
                }}
              >
                <PeopleOutlineIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('workspaceRecordings')}>
              <IconButton
                size="small"
                disabled={locked || !navigation || !row.auditlog}
                aria-label={`${t('workspaceRecordings')} ${row.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  navigation?.navigate({
                    managementFlow: navigation.location.managementFlow,
                    page: 'recordings',
                    flow: row.name,
                    auditlogHint: row.auditlog,
                  });
                }}
              >
                <ScreenshotMonitorIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('workspaceAuditlogs')}>
              <IconButton
                size="small"
                disabled={locked || !navigation || !row.auditlog}
                aria-label={`${t('workspaceAuditlogs')} ${row.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  navigation?.navigate({
                    managementFlow: navigation.location.managementFlow,
                    page: 'auditlogs',
                    auditlog: row.auditlog,
                    flow: row.name,
                  });
                }}
              >
                <FactCheckIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </div>
        )}
        busy={busy}
        disabled={disabled}
        page={pagination.index}
        hasNext={(rows?.next ?? '') !== ''}
        query={pagination.query}
        columnFilter={pagination.filter}
        onSearch={actions.search}
        sortField="name"
        sortDirection={pagination.direction}
        onPage={actions.page}
        onQuery={actions.query}
        onSort={actions.sort}
      />
    </>
  );
}

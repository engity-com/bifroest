import CloseIcon from '@mui/icons-material/Close';
import { IconButton } from '@mui/material';
import { Fragment, useEffect, useEffectEvent, useRef, useState } from 'react';
import type { AuditEventItem, AuditOverviewPage } from '../management/audit-overview';
import type { ReadProgress as Progress } from '../management/progress';
import type { ColumnFilter } from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailRefresh } from '../ui/detail-preference';
import { exactFlow, type ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button, Checkbox, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import { ReadProgress } from '../ui/ReadProgress';

const routeFilter = (flow: string | undefined): ColumnFilter | null =>
  flow
    ? {
        field: 'flow',
        operator: flow === '-' ? 'isEmpty' : 'equals',
        value: flow === '-' ? '' : flow,
      }
    : null;
export function AuditOverview({
  access,
  source,
  active,
  disabled,
}: {
  access: WebAccess;
  source: string;
  active: boolean;
  disabled: boolean;
}) {
  const navigation = useManagementNavigation();
  const route = navigation?.location;
  const flow = route?.flow;
  const target = route?.id ?? route?.eventHint;
  const [rows, setRows] = useState<AuditOverviewPage | null>(null);
  const [detail, setDetail] = useState<AuditEventItem | null>(null);
  const [sourceInfo, setSourceInfo] = useState<AuditOverviewPage['source'] | null>(null);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ColumnFilter | null>(() => routeFilter(flow));
  const [sort, setSort] = useState<'asc' | 'desc'>('desc');
  const [sensitive, setSensitive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [failed, setFailed] = useState(false);
  const [denied, setDenied] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [eventInput, setEventInput] = useState('');
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const attempted = useRef('');
  const scope = useRef(flow);
  const cursors = useRef(['']);
  const cached = useRef<{ key: string; result: AuditOverviewPage } | null>(null);
  const native = useRef<{
    flow: string | undefined;
    query: string;
    filter: ColumnFilter | null;
  } | null>(null);
  const returnRoute = useRef<ManagementLocation | null>(null);
  const current = useRef({ flow, target, active });
  current.current = { flow, target, active };
  useEffect(
    () => () => {
      generation.current++;
      request.current?.abort();
    },
    [],
  );
  const reconcile = useEffectEvent(() => {
    if (!active || disabled) {
      request.current?.abort();
      return;
    }
    const changed = !target && scope.current !== flow;
    const intent = changed && native.current?.flow === flow ? native.current : null;
    const selectedPage = target ? 0 : changed ? 0 : page;
    const selectedQuery = target ? '' : changed ? (intent?.query ?? '') : query;
    const selectedFilter = target ? null : changed ? (intent?.filter ?? routeFilter(flow)) : filter;
    const key = JSON.stringify([
      source,
      flow,
      target,
      sensitive,
      selectedPage,
      selectedQuery,
      selectedFilter,
      sort,
      refresh,
    ]);
    if (attempted.current === key) {
      return;
    }
    if (changed) {
      scope.current = flow;
      native.current = null;
      cursors.current = [''];
      setPage(0);
      setQuery(selectedQuery);
      setFilter(selectedFilter);
    }
    const token = ++generation.current;
    request.current?.abort();
    request.current = null;
    attempted.current = key;
    if (!target && cached.current?.key === key) {
      setRows(cached.current.result);
      setDetail(null);
      setBusy(false);
      setFailed(false);
      setCancelled(false);
      return;
    }
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setProgress(null);
    setFailed(false);
    setDenied(false);
    setCancelled(false);
    setDetail(null);
    if (!target) {
      setRows(null);
    }
    void (async () => {
      try {
        const result = await access.managementAuditEvents(
          source,
          {
            limit: target ? 1 : 20,
            after: target || selectedPage === 0 ? '' : (cursors.current[selectedPage] ?? ''),
            query: selectedQuery,
            filter: selectedFilter,
            sort: sort === 'desc' ? 'recorded-desc' : 'recorded-asc',
            sensitive,
            ...(flow ? { flow } : {}),
            ...(target ? { id: target } : {}),
          },
          controller.signal,
          (value) => {
            if (token === generation.current && !controller.signal.aborted) {
              setProgress(value);
            }
          },
        );
        if (
          token !== generation.current ||
          controller.signal.aborted ||
          flow !== current.current.flow ||
          target !== current.current.target
        ) {
          return;
        }
        setSourceInfo(result.source);
        if (target) {
          setDetail(result.items[0] ?? null);
          if (result.items.length === 0) {
            setFailed(true);
          }
        } else {
          if (selectedPage === 0) {
            cursors.current = [''];
          }
          cursors.current[selectedPage + 1] = result.next;
          cached.current = { key, result };
          setRows(result);
          setPage(selectedPage);
        }
      } catch (error) {
        if (token === generation.current) {
          setDenied(
            !controller.signal.aborted &&
              error instanceof RememberMeError &&
              error.code === 'denied',
          );
          setFailed(!controller.signal.aborted);
          setCancelled(controller.signal.aborted);
          if (!target) {
            setRows(null);
            cursors.current = [''];
          }
        }
      } finally {
        if (request.current === controller) {
          request.current = null;
        }
        if (token === generation.current) {
          setBusy(false);
          if (controller.signal.aborted) {
            setCancelled(true);
          }
        }
      }
    })();
  });
  // biome-ignore lint/correctness/useExhaustiveDependencies: Effect-event reconciliation must run for each explicit route/filter/page intent, without making its internal state updates retry an RPC.
  useEffect(() => {
    reconcile();
  }, [active, disabled, source, flow, target, sensitive, page, query, filter, sort, refresh]);
  const detailed = useDetailRefresh(active && !target, disabled, busy, () => {
    cached.current = null;
    setRefresh((value) => value + 1);
  });
  const field = (row: AuditEventItem, name: string) =>
    typeof row.event[name] === 'string' ? String(row.event[name]) : '';
  function open(row: AuditEventItem) {
    if (navigation && route) {
      returnRoute.current = route;
      const { id: _id, eventHint: _event, ...parent } = route;
      navigation.navigate({ ...parent, eventHint: row.id });
    }
  }
  function back() {
    if (navigation && route) {
      const { id: _id, eventHint: _event, ...parent } = route;
      navigation.navigate(returnRoute.current ?? parent);
    }
  }
  return (
    <section className="stack" aria-label={t('auditOverview')}>
      <Alert color="blue">{t('auditOverviewWarning')}</Alert>
      {sourceInfo?.encrypted && <Alert color="blue">{t('auditOverviewEncrypted')}</Alert>}
      <Checkbox
        label={t('auditOverviewPrivate')}
        checked={sensitive}
        disabled={disabled || busy || sourceInfo === null || sourceInfo.encrypted}
        onChange={(event) => {
          cached.current = null;
          cursors.current = [''];
          setPage(0);
          setRows(null);
          setDetail(null);
          setSensitive(event.currentTarget.checked);
        }}
      />
      {busy && <ReadProgress value={progress} onCancel={() => request.current?.abort()} />}
      {failed && (
        <Alert color="red" role="status">
          {t(denied ? 'artifactDownloadDenied' : 'auditOverviewFailed')}
        </Alert>
      )}
      {cancelled && (
        <Alert color="blue" role="status">
          {t('artifactCatalogCancelled')}
        </Alert>
      )}
      <div hidden={!!target}>
        <AdminDataGrid<AuditEventItem>
          active={active && !target}
          label={t('auditEvents')}
          rows={scope.current === flow ? (rows?.items ?? []) : []}
          resultAvailable={rows !== null && scope.current === flow}
          getRowId={(row) => row.key}
          busy={busy}
          disabled={disabled}
          page={page}
          hasNext={(rows?.next ?? '') !== ''}
          total={rows?.total}
          query={query}
          columnFilter={filter}
          sortField="recordedAt"
          sortDirection={sort}
          detailsAvailable
          detailed={detailed}
          detailFields={['reason', 'sessionId']}
          onOpen={open}
          openLabel={(row) => `${t('auditEventDetails')} ${row.id}`}
          refreshLabel={t('auditRefreshEvents')}
          onRefresh={() => {
            cached.current = null;
            cursors.current = [''];
            setPage(0);
            setRows(null);
            setRefresh((value) => value + 1);
          }}
          openByID={
            <form
              className="actions"
              method="dialog"
              onSubmit={(event) => {
                event.preventDefault();
                if (navigation && route) {
                  returnRoute.current = route;
                  const { id: _id, eventHint: _event, ...parent } = route;
                  navigation.navigate({ ...parent, eventHint: eventInput });
                }
              }}
            >
              <TextInput
                label={t('artifactEventID')}
                value={eventInput}
                onChange={(event) => setEventInput(event.currentTarget.value)}
                required
                maxLength={36}
                pattern="[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"
              />
              <Button type="submit" disabled={disabled || busy || !active}>
                Go
              </Button>
            </form>
          }
          columns={[
            {
              field: 'recordedAt',
              headerName: t('auditRecordedAt'),
              type: 'dateTime',
              minWidth: 190,
              valueGetter: (_value, row) => new Date(row.recordedAt),
              valueFormatter: (value) =>
                new Intl.DateTimeFormat(undefined, {
                  dateStyle: 'medium',
                  timeStyle: 'medium',
                }).format(value as Date),
            },
            {
              field: 'name',
              headerName: t('auditEventName'),
              minWidth: 240,
              flex: 1,
              valueGetter: (_value, row) => field(row, 'name'),
            },
            {
              field: 'outcome',
              headerName: t('auditEventOutcome'),
              minWidth: 120,
              valueGetter: (_value, row) => field(row, 'outcome'),
            },
            {
              field: 'flow',
              headerName: t('recordingFilterFlow'),
              minWidth: 130,
              valueGetter: (_value, row) => field(row, 'flow'),
              renderCell: (params) =>
                rows?.source.sensitive
                  ? field(params.row, 'flow') || '—'
                  : t('recordingMetadataProtected'),
            },
            {
              field: 'reason',
              headerName: t('auditEventReason'),
              minWidth: 160,
              valueGetter: (_value, row) => field(row, 'reason'),
            },
            {
              field: 'sessionId',
              headerName: t('auditEventSession'),
              minWidth: 280,
              valueGetter: (_value, row) => field(row, 'sessionId'),
            },
          ]}
          onPage={(index) => {
            if (index <= page + 1 && cursors.current[index] !== undefined) {
              setRows(null);
              setPage(index);
            }
          }}
          onQuery={(value) => {
            cached.current = null;
            setRows(null);
            setPage(0);
            setQuery(value);
          }}
          onSearch={(value, predicate) => {
            cached.current = null;
            setRows(null);
            setPage(0);
            setQuery(value);
            setFilter(predicate);
            const selected =
              predicate?.field === 'flow' && predicate.operator === 'isEmpty'
                ? '-'
                : exactFlow(predicate);
            if (navigation && route && selected !== flow) {
              native.current = { flow: selected, query: value, filter: predicate };
              const { flow: _flow, id: _id, eventHint: _event, ...parent } = route;
              navigation.navigate({ ...parent, ...(selected ? { flow: selected } : {}) });
            }
          }}
          onSort={(value) => {
            cached.current = null;
            setRows(null);
            setPage(0);
            setSort(value);
          }}
        />
      </div>
      {target && (
        <section className="stack" aria-label={t('auditEventDetails')}>
          <div className="section-heading">
            <IconButton aria-label={t('auditOverviewBack')} onClick={back}>
              <CloseIcon />
            </IconButton>
            <strong>{t('auditOverviewDetails')}</strong>
          </div>
          {detail && (
            <dl className="metadata-grid">
              <dt>{t('artifactEventID')}</dt>
              <dd>{detail.id}</dd>
              <dt>{t('auditRecordedAt')}</dt>
              <dd>{new Date(detail.recordedAt).toLocaleString()}</dd>
              {Object.entries(detail.event).map(([name, value]) => (
                <Fragment key={name}>
                  <dt>{name}</dt>
                  <dd>{String(value)}</dd>
                </Fragment>
              ))}
            </dl>
          )}
          <Button
            variant="default"
            disabled={disabled || busy}
            onClick={() => setRefresh((value) => value + 1)}
          >
            {t('auditRefreshEvents')}
          </Button>
        </section>
      )}
    </section>
  );
}

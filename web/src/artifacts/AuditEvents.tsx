import CloseIcon from '@mui/icons-material/Close';
import { IconButton } from '@mui/material';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ColumnFilter } from '../management/protocol';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailRefresh } from '../ui/detail-preference';
import { exactFlow, type ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import {
  type AuditEventIndex,
  type AuditEventRow,
  auditEventByID,
  auditEventPage,
  indexAuditEvents,
} from './audit-events';

export function AuditEvents({
  source,
  active,
  selected: controlled,
  onSelect,
}: {
  source: Blob;
  active: boolean;
  selected?: AuditEventRow | null;
  onSelect?: (row: AuditEventRow | null) => void;
}) {
  const navigation = useManagementNavigation();
  const route = navigation?.location.page === 'auditlogs' ? navigation.location : null;
  const routeKey = JSON.stringify(route);
  const navigateRef = useRef(navigation);
  navigateRef.current = navigation;
  const returnRoute = useRef<ManagementLocation | null>(null);
  const cachedEvent = useRef<{ source: Blob; key: string; row: AuditEventRow } | null>(null);
  const [eventInput, setEventInput] = useState('');
  const nativeFilterIntent = useRef<{
    flow: string | undefined;
    query: string;
    filter: ColumnFilter | null;
  } | null>(null);
  const [rows, setRows] = useState<AuditEventRow[]>([]);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ColumnFilter | null>(null);
  const [sort, setSort] = useState<'asc' | 'desc'>('desc');
  const [next, setNext] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [ownSelected, setOwnSelected] = useState<AuditEventRow | null>(null);
  const [refresh, setRefresh] = useState(0);
  const rawSelected = controlled === undefined ? ownSelected : controlled;
  const requestedID = route?.id ?? route?.eventHint;
  const detailIntent = !!requestedID;
  const selected =
    navigation && route
      ? rawSelected &&
        rawSelected.record.id === requestedID &&
        (!route.flow ||
          (route.flow === '-' ? rawSelected.flow === '' : rawSelected.flow === route.flow))
        ? rawSelected
        : null
      : rawSelected;
  const shownFilter: ColumnFilter | null =
    route && !detailIntent
      ? route.flow
        ? {
            field: 'flow',
            operator: route.flow === '-' ? 'isEmpty' : 'equals',
            value: route.flow === '-' ? '' : route.flow,
          }
        : exactFlow(filter) || (filter?.field === 'flow' && filter.operator === 'isEmpty')
          ? null
          : filter
      : filter;
  const choose = useCallback(
    (row: AuditEventRow | null) => {
      setOwnSelected(row);
      onSelect?.(row);
    },
    [onSelect],
  );
  const detailed = useDetailRefresh(
    active && selected === null && !detailIntent,
    false,
    busy,
    () => {
      setFilter(null);
      setPage(0);
      setRefresh((value) => value + 1);
    },
  );
  const index = useRef<AuditEventIndex | null>(null);
  const generation = useRef(0);
  const indexedRevision = useRef(0);
  const listScope = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (index.current?.source === source) {
      return;
    }
    index.current = null;
    cachedEvent.current = null;
    returnRoute.current = null;
    listScope.current = undefined;
    setRows([]);
    setPage(0);
    setQuery('');
    setFilter(null);
    choose(null);
  }, [source, choose]);
  useEffect(() => {
    const controller = new AbortController();
    const current = ++generation.current;
    if (!active) {
      return;
    }
    setBusy(true);
    setFailed(false);
    void (async () => {
      try {
        const ownedIndex =
          index.current?.source === source && indexedRevision.current === refresh
            ? index.current
            : await indexAuditEvents(source, controller.signal);
        if (current !== generation.current || controller.signal.aborted) {
          return;
        }
        index.current = ownedIndex;
        indexedRevision.current = refresh;
        const target = JSON.parse(routeKey) as ManagementLocation | null;
        if (target && (target.id || target.eventHint)) {
          const id = target.id ?? target.eventHint ?? '';
          const key = JSON.stringify([target.auditlog, target.flow, target.id, target.eventHint]);
          const cached = cachedEvent.current;
          if (cached?.source === source && cached.key === key) {
            choose(cached.row);
            return;
          }
          choose(null);
          const row = await auditEventByID(ownedIndex, id, controller.signal, target.flow);
          if (current !== generation.current || controller.signal.aborted) {
            return;
          }
          if (!row || !target.auditlog || row.flow === '-') {
            setFailed(true);
            return;
          }
          const canonical: ManagementLocation = {
            managementFlow: target.managementFlow,
            page: 'auditlogs',
            auditlog: target.auditlog,
            flow: row.flow || '-',
            id,
          };
          cachedEvent.current = {
            source,
            key: JSON.stringify([
              canonical.auditlog,
              canonical.flow,
              canonical.id,
              canonical.eventHint,
            ]),
            row,
          };
          choose(row);
          if (target.eventHint) {
            navigateRef.current?.navigate(canonical, true);
          }
          return;
        }
        if (navigateRef.current) {
          choose(null);
        }
        const requestedFilter: ColumnFilter | null = target?.flow
          ? {
              field: 'flow',
              operator: target.flow === '-' ? 'isEmpty' : 'equals',
              value: target.flow === '-' ? '' : target.flow,
            }
          : target &&
              (exactFlow(filter) || (filter?.field === 'flow' && filter.operator === 'isEmpty'))
            ? null
            : filter;
        const scopeChanged = target?.flow !== listScope.current;
        const native =
          nativeFilterIntent.current?.flow === target?.flow ? nativeFilterIntent.current : null;
        const result = await auditEventPage(
          ownedIndex,
          scopeChanged ? 0 : page,
          scopeChanged ? (native?.query ?? '') : query,
          requestedFilter,
          sort === 'desc',
          controller.signal,
          target?.flow,
        );
        if (current === generation.current && !controller.signal.aborted) {
          listScope.current = target?.flow;
          if (scopeChanged) {
            setPage(0);
            setQuery(native?.query ?? '');
          }
          nativeFilterIntent.current = null;
          setRows(result.items);
          setNext(result.next !== '');
        }
      } catch {
        if (current === generation.current && !controller.signal.aborted) {
          setRows([]);
          setFailed(true);
        }
      } finally {
        if (current === generation.current) {
          setBusy(false);
        }
      }
    })();
    return () => controller.abort();
  }, [source, active, page, query, filter, sort, refresh, routeKey, choose]);
  function openRow(row: AuditEventRow) {
    if (navigation && route?.auditlog && typeof row.record.id === 'string') {
      returnRoute.current = route;
      navigation.navigate({
        managementFlow: route.managementFlow,
        page: 'auditlogs',
        auditlog: route.auditlog,
        flow: row.flow || '-',
        id: row.record.id,
      });
    } else {
      choose(row);
    }
  }
  function close() {
    if (navigation && route) {
      const { id: _id, eventHint: _hint, ...parent } = route;
      navigation.navigate(returnRoute.current ?? parent);
    } else {
      choose(null);
    }
  }
  const event = selected?.record.event;
  const fields =
    event !== null && typeof event === 'object' && !Array.isArray(event)
      ? (event as Record<string, unknown>)
      : {};
  const display = (value: unknown) =>
    typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return (
    <section className="stack" aria-label={t('auditEvents')}>
      {failed && <Alert color="red">{t('auditEventsFailed')}</Alert>}
      {busy && detailIntent && selected === null && <p role="status">{t('auditEventLoading')}</p>}
      <div hidden={selected !== null || detailIntent}>
        <AdminDataGrid<AuditEventRow>
          active={active && selected === null && !detailIntent}
          label={t('auditEvents')}
          rows={!route || listScope.current === route.flow ? rows : []}
          onOpen={openRow}
          openByID={
            <form
              method="dialog"
              className="actions"
              onSubmit={(event) => {
                event.preventDefault();
                if (navigation && route?.auditlog) {
                  returnRoute.current = route;
                  navigation.navigate({
                    managementFlow: route.managementFlow,
                    page: 'auditlogs',
                    auditlog: route.auditlog,
                    eventHint: eventInput,
                  });
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
              <Button type="submit" disabled={busy || !active || !navigation}>
                Go
              </Button>
            </form>
          }
          openLabel={(row) => `${t('auditEventDetails')} ${row.id}`}
          detailsAvailable
          detailed={detailed}
          detailFields={['reason', 'sessionId']}
          onRefresh={() => setRefresh((value) => value + 1)}
          refreshLabel={t('auditRefreshEvents')}
          columns={[
            {
              field: 'recordedAt',
              headerName: t('auditRecordedAt'),
              type: 'dateTime',
              minWidth: 190,
              valueFormatter: (value) =>
                new Intl.DateTimeFormat(undefined, {
                  dateStyle: 'medium',
                  timeStyle: 'medium',
                }).format(value as Date),
            },
            { field: 'name', headerName: t('auditEventName'), minWidth: 260, flex: 1 },
            { field: 'outcome', headerName: t('auditEventOutcome'), minWidth: 120 },
            { field: 'flow', headerName: t('recordingFilterFlow'), minWidth: 130 },
            { field: 'reason', headerName: t('auditEventReason'), minWidth: 180 },
            { field: 'sessionId', headerName: t('auditEventSession'), minWidth: 280 },
          ]}
          busy={busy}
          disabled={!active}
          page={page}
          hasNext={next}
          query={query}
          columnFilter={shownFilter}
          sortField="recordedAt"
          sortDirection={sort}
          onPage={setPage}
          onQuery={(value) => {
            setQuery(value);
            setPage(0);
          }}
          onSearch={(query, filter) => {
            setQuery(query);
            setFilter(filter);
            setPage(0);
            const flow =
              filter?.field === 'flow' && filter.operator === 'isEmpty' ? '-' : exactFlow(filter);
            if (navigation && route && flow !== route.flow) {
              nativeFilterIntent.current = { flow, query, filter };
              const { flow: _flow, id: _id, eventHint: _hint, ...parent } = route;
              navigation.navigate({ ...parent, ...(flow ? { flow } : {}) });
            }
          }}
          onSort={(value) => {
            setSort(value);
            setPage(0);
          }}
        />
      </div>
      {selected && (
        <section
          className="stack record-card audit-event-details"
          aria-label={t('auditEventDetails')}
          tabIndex={-1}
        >
          <div className="section-heading">
            <IconButton aria-label={t('close')} onClick={close}>
              <CloseIcon />
            </IconButton>
          </div>
          <dl className="metadata-grid">
            <dt>{t('auditRecordedAt')}</dt>
            <dd>{selected.recordedAt.toLocaleString()}</dd>
            <dt>{t('auditEventName')}</dt>
            <dd>{selected.name}</dd>
            <dt>{t('auditEventOutcome')}</dt>
            <dd>{selected.outcome}</dd>
            <dt>{t('recordingFilterFlow')}</dt>
            <dd>{selected.flow || '—'}</dd>
            {detailed &&
              Object.entries(selected.record)
                .filter(([key]) => key !== 'event' && key !== 'recordedAt')
                .map(([key, value]) => (
                  <div className="metadata-pair" key={key}>
                    <dt>{key}</dt>
                    <dd className="identifier">{display(value)}</dd>
                  </div>
                ))}
            {detailed &&
              Object.entries(fields)
                .filter(([key]) => !['name', 'outcome', 'flow'].includes(key))
                .map(([key, value]) => (
                  <div className="metadata-pair" key={key}>
                    <dt>{key}</dt>
                    <dd className="identifier">{display(value)}</dd>
                  </div>
                ))}
          </dl>
        </section>
      )}
    </section>
  );
}

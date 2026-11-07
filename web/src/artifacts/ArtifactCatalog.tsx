import type { ReactNode } from 'react';
import { useEffect, useEffectEvent, useRef, useState } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { ColumnFilter, RecordingOptions } from '../management/protocol';
import type { AuditlogSummary, Page, RecordingSummary, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailRefresh } from '../ui/detail-preference';
import { reportUiError } from '../ui/error-report';
import { ManagementJump, relationID, sessionRelation } from '../ui/ManagementJump';
import { exactFlow } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button, Select } from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import type { ArtifactRequest } from './protocol';
import { useRecordingVerification } from './RecordingVerification';

const when = (value: Date) =>
  new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(value);
function duration(seconds: number): string {
  const rounded = Math.round(seconds);
  if (rounded >= 3600) {
    return `${Math.floor(rounded / 3600)} h ${Math.floor(rounded / 60) % 60} min`;
  }
  if (rounded >= 60) {
    return `${Math.floor(rounded / 60)} min ${rounded % 60} s`;
  }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(seconds)} s`;
}
function bytes(size: number): string {
  const unit = size >= 1024 ** 2 ? 'MiB' : size >= 1024 ? 'KiB' : 'B';
  const divisor = unit === 'MiB' ? 1024 ** 2 : unit === 'KiB' ? 1024 : 1;
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(size / divisor)} ${unit}`;
}

export function ArtifactCatalog({
  access,
  disabled,
  active = true,
  ownerActive,
  onSelect,
  openByID,
  onSource,
}: {
  access: WebAccess;
  disabled: boolean;
  active?: boolean;
  ownerActive?: boolean;
  selected?: ArtifactRequest | null;
  onSelect(request: ArtifactRequest, summary?: RecordingSummary): void;
  openByID?: ReactNode;
  onSource?: (name: string) => void;
}) {
  const navigation = useManagementNavigation();
  const route = navigation?.location.page === 'recordings' ? navigation.location : null;
  const routeKey = JSON.stringify([
    route?.flow,
    route?.auditlogHint,
    route?.id,
    route?.recordingHint,
    route?.sessionId,
  ]);
  const currentRoute = useRef(routeKey);
  currentRoute.current = routeKey;
  const consumedRoute = useRef<string | null>(null);
  const loadedScope = useRef<string | null>(null);
  const nativeFilterIntent = useRef<{
    key: string;
    query: string;
    filter: ColumnFilter | null;
  } | null>(null);
  const [sources, setSources] = useState<Page<AuditlogSummary> | null>(null);
  const [source, setSource] = useState('');
  const verification = useRecordingVerification({
    access,
    source,
    active: ownerActive ?? active,
    disabled,
  });
  const [rows, setRows] = useState<Page<RecordingSummary> | null>(null);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<'asc' | 'desc'>('desc');
  const [filter, setFilter] = useState<ColumnFilter | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [failed, setFailed] = useState<Message | null>(null);
  const failedRoute = useRef<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const attempted = useRef(false);
  const cursors = useRef(['']);
  const available = useRef(active && !disabled);
  available.current = active && !disabled;
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset at the actor boundary, never retain another access's metadata.
  useEffect(() => {
    generation.current++;
    attempted.current = false;
    consumedRoute.current = null;
    loadedScope.current = null;
    nativeFilterIntent.current = null;
    cursors.current = [''];
    setSources(null);
    setSource('');
    setRows(null);
    setPage(0);
    setQuery('');
    setSort('desc');
    setFilter(null);
    setBusy(false);
    setFailed(null);
    failedRoute.current = null;
    return () => {
      generation.current++;
      request.current?.abort();
      request.current = null;
    };
  }, [access]);
  useEffect(() => {
    if (disabled || !active) {
      request.current?.abort();
    }
  }, [disabled, active]);
  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (!active || disabled || request.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
    setProgress(null);
    setFailed(null);
    failedRoute.current = null;
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (current === generation.current) {
        loadedScope.current = null;
        setRows(null);
        setPage(0);
        cursors.current = [''];
        if (!controller.signal.aborted) {
          reportUiError('artifact-catalog', error);
        }
        failedRoute.current = routeKey;
        setFailed(
          controller.signal.aborted ||
            (error instanceof RememberMeError && error.code === 'cancelled')
            ? 'artifactCatalogCancelled'
            : error instanceof RememberMeError && error.code === 'denied'
              ? 'recordingReadDenied'
              : 'recordingReadFailed',
        );
      }
    } finally {
      if (current === generation.current && controller.signal.aborted) {
        loadedScope.current = null;
        setRows(null);
        setPage(0);
        cursors.current = [''];
        failedRoute.current = routeKey;
        setFailed('artifactCatalogCancelled');
      }
      if (request.current === controller) {
        request.current = null;
        setBusy(false);
      }
    }
  }
  function options(
    index = 0,
    search = query,
    direction = sort,
    predicate = filter,
  ): RecordingOptions {
    return {
      after: index === 0 ? '' : (cursors.current[index] ?? ''),
      query: search,
      sort: direction === 'asc' ? 'started-asc' : 'started-desc',
      filter: predicate,
      ...(route?.flow ? { flow: route.flow } : {}),
      ...(route?.sessionId ? { sessionId: route.sessionId } : {}),
    };
  }
  async function load(
    name = source,
    index = 0,
    search = query,
    direction = sort,
    predicate = filter,
  ) {
    await run(async (signal, current) => {
      const selected = options(index, search, direction, predicate);
      consumedRoute.current = routeKey;
      loadedScope.current = null;
      setRows(null);
      setSource(name);
      setQuery(search);
      setSort(direction);
      setFilter(predicate);
      const result = await access.managementRecordings(name, selected, signal, (value) => {
        if (
          current === generation.current &&
          !signal.aborted &&
          routeKey === currentRoute.current
        ) {
          setProgress(value);
        }
      });
      if (current !== generation.current || signal.aborted || routeKey !== currentRoute.current) {
        if (routeKey !== currentRoute.current && consumedRoute.current === routeKey) {
          consumedRoute.current = null;
        }
        return;
      }
      if (index === 0) {
        cursors.current = [''];
      }
      cursors.current[index + 1] = result.next;
      setSource(name);
      loadedScope.current = JSON.stringify([route?.flow, name, route?.sessionId]);
      setRows(result);
      setPage(index);
      setQuery(search);
      setSort(direction);
      setFilter(predicate);
      consumedRoute.current = routeKey;
    });
  }
  async function loadSources(after = '') {
    await run(async (signal, current) => {
      const report = (value: Progress) => {
        if (
          current === generation.current &&
          !signal.aborted &&
          routeKey === currentRoute.current
        ) {
          setProgress(value);
        }
      };
      const result = await access.managementAuditlogs({ after }, signal, report);
      if (current !== generation.current || signal.aborted) {
        return;
      }
      const items = after === '' ? result.items : [...(sources?.items ?? []), ...result.items];
      setSources({ ...result, items });
      const enabled = items.filter((row) => row.enabled && row.recordingEnabled);
      if (source === '' && (route?.auditlogHint || (enabled.length === 1 && result.next === ''))) {
        const name = route?.auditlogHint ?? enabled[0]?.name;
        if (name === undefined) {
          return;
        }
        setSource(name);
        if (routeKey !== currentRoute.current) {
          return;
        }
        if (route?.id || route?.recordingHint) {
          onSource?.(name);
          return;
        }
        const predicate = route?.sessionId
          ? { field: 'sessionId', operator: 'equals', value: route.sessionId }
          : route?.flow
            ? { field: 'flow', operator: 'equals', value: route.flow }
            : null;
        consumedRoute.current = routeKey;
        // A source response can complete between a navigation render and its
        // passive abort effect. Do not start a new scan for an inactive page.
        if (!available.current) {
          request.current?.abort();
          return;
        }
        loadedScope.current = null;
        setRows(null);
        setQuery('');
        setSort('desc');
        setFilter(predicate);
        const result = await access.managementRecordings(
          name,
          options(0, '', 'desc', predicate),
          signal,
          report,
        );
        if (current !== generation.current || signal.aborted || routeKey !== currentRoute.current) {
          return;
        }
        cursors.current = ['', result.next];
        loadedScope.current = JSON.stringify([route?.flow, name, route?.sessionId]);
        setRows(result);
        setPage(0);
        setQuery('');
        setSort('desc');
        setFilter(predicate);
        consumedRoute.current = routeKey;
      }
    });
  }
  useEffect(() => {
    if (available.current && !attempted.current) {
      const current = generation.current;
      queueMicrotask(() => {
        if (current === generation.current && available.current && !attempted.current) {
          attempted.current = true;
          void loadSources();
        }
      });
    }
  });
  const readRoute = useEffectEvent(() => {
    if (
      !route ||
      !active ||
      disabled ||
      busy ||
      request.current !== null ||
      (source === '' && !route.auditlogHint) ||
      consumedRoute.current === routeKey ||
      route.id ||
      route.recordingHint
    ) {
      return;
    }
    const name = route.auditlogHint ?? source;
    const native = nativeFilterIntent.current?.key === routeKey ? nativeFilterIntent.current : null;
    nativeFilterIntent.current = null;
    consumedRoute.current = routeKey;
    // A row/detail URL makes an automatically selected sole source explicit.
    // That spelling change is not a different dataset and must not replay its
    // retained list read after playback. A genuinely different flow/source or
    // pending native filter intent still requires an authoritative new read.
    if (
      !native &&
      rows !== null &&
      loadedScope.current === JSON.stringify([route.flow, name, route.sessionId])
    ) {
      setFailed(null);
      return;
    }
    setRows(null);
    setPage(0);
    setSource(name);
    cursors.current = [''];
    void load(
      name,
      0,
      native?.query ?? '',
      sort,
      native
        ? native.filter
        : route.sessionId
          ? { field: 'sessionId', operator: 'equals', value: route.sessionId }
          : route.flow
            ? { field: 'flow', operator: 'equals', value: route.flow }
            : exactFlow(filter)
              ? null
              : filter,
    );
  });
  useEffect(() => {
    if (
      request.current !== null &&
      consumedRoute.current !== null &&
      consumedRoute.current !== routeKey
    ) {
      request.current.abort();
    }
    if (active && !disabled && !busy && consumedRoute.current !== routeKey) {
      readRoute();
    }
  }, [active, disabled, busy, routeKey]);
  const locked = disabled || busy;
  const detailed = useDetailRefresh(active, disabled, busy, () => {
    void (source === '' ? loadSources() : load(source, 0, query, sort, null));
  });
  const enabled = sources?.items.filter((row) => row.enabled && row.recordingEnabled) ?? [];
  const identity = (row: RecordingSummary) =>
    row.encrypted || row.metadataUnavailable ? null : row;
  const visibleFailure = failedRoute.current === routeKey ? failed : null;
  return (
    <section className="stack" aria-label={t('artifactCatalog')}>
      {verification.dialog}
      {visibleFailure && (
        <Alert role="status" color="red">
          {t(visibleFailure)}
        </Alert>
      )}
      {((sources?.skipped ?? 0) > 0 || (rows?.skipped ?? 0) > 0) && (
        <Alert color="yellow">{t('managementPartial')}</Alert>
      )}
      {enabled.length > 0 &&
        (enabled.length > 1 || (sources?.next ?? '') !== '' || source === '') && (
          <Select
            label={t('recordingSource')}
            value={source}
            placeholder={t('recordingChooseSource')}
            disabled={locked}
            data={[
              ...enabled.map((row) => ({ value: row.name, label: row.name })),
              ...(source && !enabled.some((row) => row.name === source)
                ? [{ value: source, label: source }]
                : []),
            ]}
            onChange={(name) => {
              if (name !== null) {
                if (navigation && route) {
                  navigation.navigate({ ...route, auditlogHint: name });
                  onSource?.(name);
                } else {
                  void load(name, 0, '', 'desc', null);
                }
              }
            }}
          />
        )}
      {sources?.next && (
        <Button
          variant="subtle"
          disabled={locked}
          onClick={() => {
            void loadSources(sources.next);
          }}
        >
          {t('recordingSourcesMore')}
        </Button>
      )}
      {sources && sources.next === '' && enabled.length === 0 && !busy && (
        <p className="empty-state">{t('recordingNoSources')}</p>
      )}
      <AdminDataGrid<RecordingSummary>
        work={verification.work}
        readProgress={progress}
        onCancelRead={() => request.current?.abort()}
        active={active}
        actionField="open"
        label={`${t('recordingList')} · ${source}`}
        resultAvailable={
          rows !== null &&
          (!route ||
            loadedScope.current ===
              JSON.stringify([route.flow, route.auditlogHint ?? source, route.sessionId]))
        }
        rows={
          !route ||
          loadedScope.current ===
            JSON.stringify([route.flow, route.auditlogHint ?? source, route.sessionId])
            ? (rows?.items ?? [])
            : []
        }
        onRefresh={() => {
          void (source === '' ? loadSources() : load(source, page));
        }}
        refreshLabel={t('recordingRefresh')}
        openByID={openByID}
        detailsAvailable
        detailed={detailed}
        detailFields={['user', 'duration', 'containerBytes']}
        hiddenFields={['sessionId']}
        onOpen={(row) => onSelect({ kind: 'recording', auditlog: row.auditlog, id: row.id }, row)}
        openLabel={(row) => `${t('recordingOpen')} ${row.id}`}
        rowActions={(row) =>
          navigation &&
          identity(row) && (
            <ManagementJump
              scope={access.snapshot().scope}
              target={sessionRelation(navigation.location.managementFlow, row.flow, row.sessionId)}
              label="showSession"
              compact
              disabled={locked}
            />
          )
        }
        columns={[
          { field: 'id', headerName: t('artifactRecordingID'), minWidth: 270 },
          {
            field: 'sessionId',
            headerName: t('managementSessionId'),
            minWidth: 280,
            valueGetter: (_value, row) => identity(row)?.sessionId ?? '',
          },
          {
            field: 'startedAt',
            headerName: t('recordingStarted'),
            minWidth: 190,
            flex: 1,
            type: 'dateTime',
            valueGetter: (_value, row) => new Date(row.startedAt),
            valueFormatter: (value) => when(value as Date),
          },
          {
            field: 'user',
            headerName: t('recordingIdentity'),
            minWidth: 170,
            flex: 1,
            valueGetter: (_value, row) => identity(row)?.user ?? '',
            renderCell: (params) => (
              <span>
                {identity(params.row)?.user ||
                  t(
                    params.row.encrypted
                      ? 'recordingMetadataProtected'
                      : 'recordingMetadataUnknown',
                  )}
                {identity(params.row)?.target && (
                  <small>
                    {' '}
                    · {t('recordingFilterTarget')}: {identity(params.row)?.target}
                  </small>
                )}
              </span>
            ),
          },
          {
            field: 'flow',
            headerName: t('recordingFilterFlow'),
            minWidth: 130,
            valueGetter: (_value, row) => identity(row)?.flow ?? '',
          },
          {
            field: 'status',
            headerName: t('recordingFilterStatus'),
            minWidth: 130,
            type: 'singleSelect',
            valueOptions: [
              { value: 'completed', label: t('artifactCatalogCompleted') },
              { value: 'failed', label: t('artifactCatalogFailedStatus') },
              { value: 'incomplete', label: t('artifactCatalogIncomplete') },
            ],
          },
          {
            field: 'duration',
            headerName: t('recordingDuration'),
            minWidth: 120,
            type: 'number',
            valueGetter: (_value, row) =>
              Math.max(0, (Date.parse(row.endedAt) - Date.parse(row.startedAt)) / 1000),
            valueFormatter: (value) => duration(Number(value)),
          },
          {
            field: 'containerBytes',
            headerName: t('recordingSize'),
            minWidth: 100,
            type: 'number',
            valueFormatter: (value) => bytes(Number(value)),
          },
        ]}
        busy={busy || !attempted.current}
        disabled={disabled}
        page={page}
        hasNext={(rows?.next ?? '') !== ''}
        total={rows?.total}
        query={query}
        columnFilter={filter}
        sortField="startedAt"
        sortDirection={sort}
        onPage={(index) => {
          if (index <= page + 1 && cursors.current[index] !== undefined) {
            void load(source, index);
          }
        }}
        onQuery={(value) => {
          void load(source, 0, value);
        }}
        onSearch={(search, predicate) => {
          const flow =
            route?.sessionId && predicate?.field !== 'flow' ? route.flow : exactFlow(predicate);
          const sessionId =
            predicate?.field === 'sessionId'
              ? predicate.operator === 'equals' && relationID(predicate.value)
                ? predicate.value
                : undefined
              : predicate === null && filter?.field === 'sessionId'
                ? undefined
                : route?.sessionId;
          if (navigation && route && (flow !== route.flow || sessionId !== route.sessionId)) {
            setQuery(search);
            setFilter(predicate);
            const {
              flow: _flow,
              id: _id,
              recordingHint: _recording,
              sessionId: _session,
              ...parent
            } = route;
            const next = {
              ...parent,
              ...(flow ? { flow } : {}),
              ...(sessionId ? { sessionId } : {}),
            };
            nativeFilterIntent.current = {
              key: JSON.stringify([
                next.flow,
                next.auditlogHint,
                undefined,
                undefined,
                next.sessionId,
              ]),
              query: search,
              filter: predicate,
            };
            navigation.navigate(next);
            return;
          }
          void load(source, 0, search, sort, predicate);
        }}
        onSort={(direction) => {
          void load(source, 0, query, direction);
        }}
      />
    </section>
  );
}

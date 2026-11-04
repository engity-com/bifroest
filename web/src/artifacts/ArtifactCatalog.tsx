import { useEffect, useRef, useState } from 'react';
import type { RecordingOptions } from '../management/protocol';
import type { AuditlogSummary, Page, RecordingSummary, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Select, TextInput } from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import type { ArtifactRequest } from './protocol';

interface Filters {
  flow: string;
  user: string;
  from: string;
  until: string;
  status: string;
}
const emptyFilters: Filters = { flow: '', user: '', from: '', until: '', status: '' };
const when = (value: string) =>
  new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(value),
  );
function duration(row: RecordingSummary): string {
  const seconds = Math.max(0, (Date.parse(row.endedAt) - Date.parse(row.startedAt)) / 1000);
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
  selected,
  onSelect,
}: {
  access: WebAccess;
  disabled: boolean;
  active?: boolean;
  selected?: ArtifactRequest | null;
  onSelect: (request: ArtifactRequest, summary?: RecordingSummary) => void;
}) {
  const [auditlogs, setAuditlogs] = useState<Page<AuditlogSummary> | null>(null);
  const [auditRows, setAuditRows] = useState<Page<AuditlogSummary> | null>(null);
  const [auditPage, setAuditPage] = useState(0);
  const [auditQuery, setAuditQuery] = useState('');
  const [auditSort, setAuditSort] = useState<'asc' | 'desc'>('asc');
  const auditCursors = useRef<string[]>(['']);
  const [source, setSource] = useState('');
  const [recordings, setRecordings] = useState<Page<RecordingSummary> | null>(null);
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [applied, setApplied] = useState<Filters>(emptyFilters);
  const [pageIndex, setPageIndex] = useState(0);
  const [gridQuery, setGridQuery] = useState('');
  const [gridSort, setGridSort] = useState<'asc' | 'desc'>('desc');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<Message | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const initialAttempt = useRef(false);
  const cursors = useRef<string[]>(['']);
  const selectionHeading = useRef<HTMLHeadingElement | null>(null);
  const availableNow = useRef(active && !disabled);
  availableNow.current = active && !disabled;

  // An immutable access owns its results. Merely hiding/reopening this view does
  // not reread metadata or turn server labels into verification expectations.
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset only at the actor/access boundary.
  useEffect(() => {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    initialAttempt.current = false;
    cursors.current = [''];
    setAuditlogs(null);
    setAuditRows(null);
    setAuditPage(0);
    setAuditQuery('');
    setAuditSort('asc');
    auditCursors.current = [''];
    setSource('');
    setRecordings(null);
    setFilters(emptyFilters);
    setApplied(emptyFilters);
    setPageIndex(0);
    setGridQuery('');
    setGridSort('desc');
    setBusy(false);
    setFailed(null);
    setCancelled(false);
    return () => {
      generation.current++;
      operation.current?.abort();
      operation.current = null;
    };
  }, [access]);
  useEffect(() => {
    if (disabled) {
      operation.current?.abort();
    }
  }, [disabled]);

  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (disabled || operation.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    operation.current = controller;
    setBusy(true);
    setFailed(null);
    setCancelled(false);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (current === generation.current && !controller.signal.aborted) {
        if (!(error instanceof RememberMeError && error.code === 'cancelled')) {
          reportUiError('artifact-catalog', error);
          setFailed(
            error instanceof RememberMeError && error.code === 'denied'
              ? 'recordingReadDenied'
              : 'recordingReadFailed',
          );
        }
      }
    } finally {
      if (operation.current === controller) {
        operation.current = null;
        setBusy(false);
      }
    }
  }
  function query(
    values: Filters,
    after = '',
    search = gridQuery,
    direction = gridSort,
  ): RecordingOptions {
    return {
      after,
      sort: direction === 'asc' ? 'started-asc' : 'started-desc',
      query: search,
      flow: values.flow,
      user: values.user,
      target: '',
      startedFrom: values.from === '' ? '' : new Date(values.from).toISOString(),
      startedUntil: values.until === '' ? '' : new Date(values.until).toISOString(),
      status:
        values.status === '' ? 'all' : (values.status as NonNullable<RecordingOptions['status']>),
    };
  }
  async function loadRecordings(
    name: string,
    values = filters,
    index = 0,
    search = gridQuery,
    direction = gridSort,
  ) {
    await run(async (signal, current) => {
      const result = await access.managementRecordings(
        name,
        query(values, cursors.current[index] ?? '', search, direction),
        signal,
      );
      if (current === generation.current && !signal.aborted) {
        setSource(name);
        setRecordings(result);
        setApplied({ ...values });
        setPageIndex(index);
        setGridQuery(search);
        setGridSort(direction);
        if (index === 0) {
          cursors.current = [''];
        }
        cursors.current[index + 1] = result.next;
      }
    });
  }
  async function loadSources(after = '') {
    await run(async (signal, current) => {
      const result = await access.managementAuditlogs({ after }, signal);
      if (current !== generation.current || signal.aborted) {
        return;
      }
      const items = after === '' ? result.items : [...(auditlogs?.items ?? []), ...result.items];
      setAuditlogs({ ...result, items });
      if (after === '') {
        setAuditRows(result);
        setAuditPage(0);
        setAuditQuery('');
        setAuditSort('asc');
        auditCursors.current = ['', result.next];
      }
      const available = items.filter((row) => row.enabled && row.recordingEnabled);
      // A sole source is established only after the complete source inventory,
      // including later pages. Keep its identity even if its read is denied.
      if (source === '' && available.length === 1 && result.next === '') {
        const name = available[0]?.name;
        if (name === undefined) {
          return;
        }
        setSource(name);
        const rows = await access.managementRecordings(name, query(emptyFilters), signal);
        if (current !== generation.current || signal.aborted) {
          return;
        }
        cursors.current = ['', rows.next];
        setPageIndex(0);
        setSource(name);
        setRecordings(rows);
        setFilters(emptyFilters);
        setApplied(emptyFilters);
      }
    });
  }
  useEffect(() => {
    if (active && !disabled && !initialAttempt.current) {
      const current = generation.current;
      queueMicrotask(() => {
        if (current === generation.current && availableNow.current && !initialAttempt.current) {
          initialAttempt.current = true;
          void loadSources();
        }
      });
    }
  });
  async function loadAuditRows(index: number, search = auditQuery, direction = auditSort) {
    await run(async (signal, current) => {
      const rows = await access.managementAuditlogs(
        {
          after: index === 0 ? '' : (auditCursors.current[index] ?? ''),
          query: search,
          ...(direction === 'desc' ? { sort: 'name-desc' } : {}),
        },
        signal,
      );
      if (current !== generation.current || signal.aborted) {
        return;
      }
      setAuditRows(rows);
      setAuditPage(index);
      setAuditQuery(search);
      setAuditSort(direction);
      if (index === 0) {
        auditCursors.current = [''];
      }
      auditCursors.current[index + 1] = rows.next;
    });
  }
  function cancel() {
    generation.current++;
    operation.current?.abort();
    setCancelled(true);
  }
  const locked = disabled || busy;
  const sources = auditlogs?.items.filter((row) => row.enabled && row.recordingEnabled) ?? [];
  const selectionMatches = (row: RecordingSummary) =>
    selected?.kind === 'recording' && selected.auditlog === row.auditlog && selected.id === row.id;
  const patch = (key: keyof Filters, value: string) =>
    setFilters((current) => ({ ...current, [key]: value }));
  const choose = (row: RecordingSummary) => {
    if (!locked) {
      onSelect({ kind: 'recording', auditlog: row.auditlog, id: row.id }, row);
    }
  };
  const identity = (row: RecordingSummary) =>
    row.encrypted || row.metadataUnavailable ? null : row;
  return (
    <section className="stack" aria-label={t('artifactCatalog')}>
      <div className="section-heading">
        <div>
          <h3 ref={selectionHeading} className="recording-heading">
            {t('recordingList')}
          </h3>
          <span className="caption subtle">{t('recordingSort')}</span>
        </div>
        <div className="actions">
          <Button
            variant="default"
            disabled={locked}
            onClick={() => {
              void (source === '' ? loadSources() : loadRecordings(source, applied));
            }}
          >
            {t('recordingRefresh')}
          </Button>
          {busy && (
            <Button variant="default" onClick={cancel}>
              {t('artifactCatalogCancel')}
            </Button>
          )}
        </div>
      </div>
      {busy && <p role="status">{t('recordingLoading')}</p>}
      {failed !== null && (
        <Alert role="status" color="red">
          {t(failed)}
        </Alert>
      )}
      {cancelled && (
        <Alert role="status" color="yellow">
          {t('artifactCatalogCancelled')}
        </Alert>
      )}
      {((auditlogs?.skipped ?? 0) > 0 || (recordings?.skipped ?? 0) > 0) && (
        <Alert color="yellow">{t('managementPartial')}</Alert>
      )}
      {sources.length > 0 &&
        (sources.length > 1 || (auditlogs?.next ?? '') !== '' || source === '') && (
          <Select
            label={t('recordingSource')}
            value={source}
            placeholder={t('recordingChooseSource')}
            disabled={locked}
            data={sources.map((row) => ({ value: row.name, label: row.name }))}
            onChange={(name) => {
              if (name !== null) {
                void loadRecordings(name);
              }
            }}
          />
        )}
      {auditlogs !== null && auditlogs.next === '' && sources.length === 0 && !busy && (
        <p className="empty-state">{t('recordingNoSources')}</p>
      )}
      {auditlogs?.next && (
        <Button
          variant="subtle"
          disabled={locked}
          onClick={() => {
            void loadSources(auditlogs.next);
          }}
        >
          {t('recordingSourcesMore')}
        </Button>
      )}
      {source !== '' && (
        <>
          <details className="recording-filters">
            <summary>{t('recordingFilters')}</summary>
            <form
              className="admin-filter-grid"
              method="dialog"
              onSubmit={(event) => {
                event.preventDefault();
                void loadRecordings(source);
              }}
            >
              <TextInput
                label={t('recordingFilterUser')}
                value={filters.user}
                disabled={locked}
                maxLength={256}
                onChange={(event) => patch('user', event.currentTarget.value)}
              />
              <TextInput
                label={t('recordingFilterFlow')}
                value={filters.flow}
                disabled={locked}
                maxLength={255}
                onChange={(event) => patch('flow', event.currentTarget.value)}
              />
              <Select
                label={t('recordingFilterStatus')}
                value={filters.status}
                disabled={locked}
                data={[
                  { value: '', label: t('recordingFilterAll') },
                  { value: 'completed', label: t('artifactCatalogCompleted') },
                  { value: 'incomplete', label: t('artifactCatalogIncomplete') },
                  { value: 'failed', label: t('artifactCatalogFailedStatus') },
                ]}
                onChange={(value) => patch('status', value ?? '')}
              />
              <TextInput
                type="datetime-local"
                label={t('recordingFilterFrom')}
                value={filters.from}
                disabled={locked}
                onChange={(event) => patch('from', event.currentTarget.value)}
              />
              <TextInput
                type="datetime-local"
                label={t('recordingFilterUntil')}
                value={filters.until}
                disabled={locked}
                onChange={(event) => patch('until', event.currentTarget.value)}
              />
              <Button type="submit" disabled={locked}>
                {t('recordingFilterApply')}
              </Button>
            </form>
          </details>
          {JSON.stringify(filters) !== JSON.stringify(applied) && (
            <p className="caption subtle">{t('recordingFiltersPending')}</p>
          )}
          {(filters.user !== '' || filters.flow !== '') && (
            <p className="caption subtle">{t('recordingIdentityFilterHint')}</p>
          )}
        </>
      )}
      {recordings !== null && (
        <AdminDataGrid<RecordingSummary>
          actionField="open"
          label={`${t('recordingList')} · ${source}`}
          rows={recordings.items}
          columns={[
            {
              field: 'startedAt',
              headerName: t('recordingStarted'),
              minWidth: 190,
              flex: 1,
              valueFormatter: (value) => when(value as string),
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
              valueGetter: (_value, row) => identity(row)?.flow || '—',
            },
            {
              field: 'status',
              headerName: t('recordingFilterStatus'),
              minWidth: 130,
              valueFormatter: (value) =>
                t(
                  value === 'completed'
                    ? 'artifactCatalogCompleted'
                    : value === 'failed'
                      ? 'artifactCatalogFailedStatus'
                      : 'artifactCatalogIncomplete',
                ),
            },
            {
              field: 'duration',
              headerName: t('recordingDuration'),
              minWidth: 120,
              valueGetter: (_value, row) => duration(row),
            },
            {
              field: 'containerBytes',
              headerName: t('recordingSize'),
              minWidth: 100,
              valueFormatter: (value) => bytes(value as number),
            },
            {
              field: 'open',
              headerName: t('recordingOpen'),
              minWidth: 170,
              renderCell: (params) => (
                <Button
                  disabled={locked}
                  aria-current={selectionMatches(params.row) ? 'true' : undefined}
                  aria-label={`${t('recordingOpen')} ${params.row.id}`}
                  onClick={() => choose(params.row)}
                >
                  {t('recordingOpen')}
                </Button>
              ),
            },
          ]}
          busy={busy}
          disabled={disabled}
          page={pageIndex}
          hasNext={recordings.next !== ''}
          query={gridQuery}
          sortField="startedAt"
          sortDirection={gridSort}
          onPage={(index) => {
            if (index <= pageIndex + 1 && cursors.current[index] !== undefined) {
              void loadRecordings(source, applied, index);
            }
          }}
          onQuery={(search) => {
            void loadRecordings(source, applied, 0, search, gridSort);
          }}
          onSort={(direction) => {
            void loadRecordings(source, applied, 0, gridQuery, direction);
          }}
        />
      )}
      <details className="context-help">
        <summary>{t('recordingAuditExports')}</summary>
        <div className="stack">
          <p>{t('recordingServerMetadata')}</p>
          {auditRows !== null && (
            <AdminDataGrid<AuditlogSummary>
              actionField="open"
              label={t('artifactAuditlogCaption')}
              rows={auditRows.items}
              getRowId={(row) => row.name}
              columns={[
                { field: 'name', headerName: t('artifactAuditlog'), minWidth: 190, flex: 1 },
                {
                  field: 'configuration',
                  headerName: t('artifactCatalogConfiguration'),
                  minWidth: 300,
                  flex: 1,
                  valueGetter: (_value, row) =>
                    `${t(row.recordingEnabled ? 'artifactCatalogRecordingOn' : 'artifactCatalogRecordingOff')} · ${t(row.encrypted ? 'artifactCatalogEncrypted' : 'artifactCatalogClear')}`,
                },
                {
                  field: 'open',
                  headerName: t('recordingOpenAudit'),
                  minWidth: 170,
                  renderCell: (params) => (
                    <Button
                      disabled={locked || !params.row.enabled}
                      aria-label={`${t('recordingOpenAudit')} ${params.row.name}`}
                      onClick={() => {
                        if (!locked && params.row.enabled) {
                          onSelect({ kind: 'audit', auditlog: params.row.name });
                        }
                      }}
                    >
                      {t('recordingOpenAudit')}
                    </Button>
                  ),
                },
              ]}
              busy={busy}
              disabled={disabled}
              page={auditPage}
              hasNext={auditRows.next !== ''}
              query={auditQuery}
              sortField="name"
              sortDirection={auditSort}
              onPage={(index) => {
                if (index <= auditPage + 1 && auditCursors.current[index] !== undefined) {
                  void loadAuditRows(index);
                }
              }}
              onQuery={(search) => {
                void loadAuditRows(0, search, auditSort);
              }}
              onSort={(direction) => {
                void loadAuditRows(0, auditQuery, direction);
              }}
            />
          )}
          <p>{t('artifactCatalogWarning')}</p>
        </div>
      </details>
    </section>
  );
}

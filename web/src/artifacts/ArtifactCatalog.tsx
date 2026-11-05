import type { ReactNode } from 'react';
import { useEffect, useRef, useState } from 'react';
import type { ColumnFilter, RecordingOptions } from '../management/protocol';
import type { AuditlogSummary, Page, RecordingSummary, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailRefresh } from '../ui/detail-preference';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Select } from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import type { ArtifactRequest } from './protocol';

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
  onSelect,
  openByID,
}: {
  access: WebAccess;
  disabled: boolean;
  active?: boolean;
  selected?: ArtifactRequest | null;
  onSelect(request: ArtifactRequest, summary?: RecordingSummary): void;
  openByID?: ReactNode;
}) {
  const [sources, setSources] = useState<Page<AuditlogSummary> | null>(null);
  const [source, setSource] = useState('');
  const [rows, setRows] = useState<Page<RecordingSummary> | null>(null);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<'asc' | 'desc'>('desc');
  const [filter, setFilter] = useState<ColumnFilter | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<Message | null>(null);
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
    return () => {
      generation.current++;
      request.current?.abort();
      request.current = null;
    };
  }, [access]);
  useEffect(() => {
    if (disabled) {
      request.current?.abort();
    }
  }, [disabled]);
  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (disabled || request.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
    setFailed(null);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (
        current === generation.current &&
        !controller.signal.aborted &&
        !(error instanceof RememberMeError && error.code === 'cancelled')
      ) {
        reportUiError('artifact-catalog', error);
        setFailed(
          error instanceof RememberMeError && error.code === 'denied'
            ? 'recordingReadDenied'
            : 'recordingReadFailed',
        );
      }
    } finally {
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
      const result = await access.managementRecordings(
        name,
        options(index, search, direction, predicate),
        signal,
      );
      if (current !== generation.current || signal.aborted) {
        return;
      }
      if (index === 0) {
        cursors.current = [''];
      }
      cursors.current[index + 1] = result.next;
      setSource(name);
      setRows(result);
      setPage(index);
      setQuery(search);
      setSort(direction);
      setFilter(predicate);
    });
  }
  async function loadSources(after = '') {
    await run(async (signal, current) => {
      const result = await access.managementAuditlogs({ after }, signal);
      if (current !== generation.current || signal.aborted) {
        return;
      }
      const items = after === '' ? result.items : [...(sources?.items ?? []), ...result.items];
      setSources({ ...result, items });
      const enabled = items.filter((row) => row.enabled && row.recordingEnabled);
      if (source === '' && enabled.length === 1 && result.next === '') {
        const name = enabled[0]?.name;
        if (name === undefined) {
          return;
        }
        setSource(name);
        const result = await access.managementRecordings(
          name,
          options(0, '', 'desc', null),
          signal,
        );
        if (current !== generation.current || signal.aborted) {
          return;
        }
        cursors.current = ['', result.next];
        setRows(result);
        setPage(0);
        setQuery('');
        setSort('desc');
        setFilter(null);
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
  const locked = disabled || busy;
  const detailed = useDetailRefresh(active, disabled, busy, () => {
    void (source === '' ? loadSources() : load(source, 0, query, sort, null));
  });
  const enabled = sources?.items.filter((row) => row.enabled && row.recordingEnabled) ?? [];
  const identity = (row: RecordingSummary) =>
    row.encrypted || row.metadataUnavailable ? null : row;
  return (
    <section className="stack" aria-label={t('artifactCatalog')}>
      {failed && (
        <Alert role="status" color="red">
          {t(failed)}
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
            data={enabled.map((row) => ({ value: row.name, label: row.name }))}
            onChange={(name) => {
              if (name !== null) {
                void load(name, 0, '', 'desc', null);
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
        active={active}
        actionField="open"
        label={`${t('recordingList')} · ${source}`}
        rows={rows?.items ?? []}
        onRefresh={() => {
          void (source === '' ? loadSources() : load(source, page));
        }}
        refreshLabel={t('recordingRefresh')}
        openByID={openByID}
        detailsAvailable
        detailed={detailed}
        detailFields={['user', 'duration', 'containerBytes']}
        onOpen={(row) => onSelect({ kind: 'recording', auditlog: row.auditlog, id: row.id }, row)}
        openLabel={(row) => `${t('recordingOpen')} ${row.id}`}
        columns={[
          { field: 'id', headerName: t('artifactRecordingID'), minWidth: 270 },
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
          void load(source, 0, search, sort, predicate);
        }}
        onSort={(direction) => {
          void load(source, 0, query, direction);
        }}
      />
    </section>
  );
}

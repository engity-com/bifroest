import { useEffect, useRef, useState } from 'react';
import type { RecordingOptions } from '../management/protocol';
import type { AuditlogSummary, Page, RecordingSummary, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Select, Table, TextInput } from '../ui/material';
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
  const [source, setSource] = useState('');
  const [recordings, setRecordings] = useState<Page<RecordingSummary> | null>(null);
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [applied, setApplied] = useState<Filters>(emptyFilters);
  const [pageIndex, setPageIndex] = useState(0);
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
    setSource('');
    setRecordings(null);
    setFilters(emptyFilters);
    setApplied(emptyFilters);
    setPageIndex(0);
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
  function query(values: Filters, after = ''): RecordingOptions {
    return {
      after,
      sort: 'started-desc',
      flow: values.flow,
      user: values.user,
      target: '',
      startedFrom: values.from === '' ? '' : new Date(values.from).toISOString(),
      startedUntil: values.until === '' ? '' : new Date(values.until).toISOString(),
      status:
        values.status === '' ? 'all' : (values.status as NonNullable<RecordingOptions['status']>),
    };
  }
  async function loadRecordings(name: string, values = filters, index = 0) {
    await run(async (signal, current) => {
      const result = await access.managementRecordings(
        name,
        query(values, cursors.current[index] ?? ''),
        signal,
      );
      if (current === generation.current && !signal.aborted) {
        setSource(name);
        setRecordings(result);
        setApplied({ ...values });
        setPageIndex(index);
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
        <>
          <div className="table-scroll desktop-recordings">
            <Table captionSide="top" className="recording-table">
              <caption>
                {t('recordingList')} · {source}
              </caption>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('recordingStarted')}</Table.Th>
                  <Table.Th>{t('recordingIdentity')}</Table.Th>
                  <Table.Th>{t('recordingFilterFlow')}</Table.Th>
                  <Table.Th>{t('recordingFilterStatus')}</Table.Th>
                  <Table.Th>{t('recordingDuration')}</Table.Th>
                  <Table.Th>{t('recordingSize')}</Table.Th>
                  <Table.Th>{t('recordingOpen')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {recordings.items.map((row) => (
                  <Table.Tr
                    key={row.id}
                    className={selectionMatches(row) ? 'selected-row' : undefined}
                    aria-current={selectionMatches(row) ? 'true' : undefined}
                  >
                    <Table.Td>{when(row.startedAt)}</Table.Td>
                    <Table.Td>
                      {identity(row) ? (
                        <>
                          <strong>{identity(row)?.user || t('recordingMetadataUnknown')}</strong>
                          {identity(row)?.target && (
                            <>
                              <br />
                              <span className="caption subtle">
                                {t('recordingFilterTarget')}: {identity(row)?.target}
                              </span>
                            </>
                          )}
                        </>
                      ) : (
                        <span className="caption subtle">
                          {t(
                            row.encrypted
                              ? 'recordingMetadataProtected'
                              : 'recordingMetadataUnknown',
                          )}
                        </span>
                      )}
                    </Table.Td>
                    <Table.Td>{identity(row)?.flow || '—'}</Table.Td>
                    <Table.Td>
                      {t(
                        row.status === 'completed'
                          ? 'artifactCatalogCompleted'
                          : row.status === 'failed'
                            ? 'artifactCatalogFailedStatus'
                            : 'artifactCatalogIncomplete',
                      )}
                    </Table.Td>
                    <Table.Td>{duration(row)}</Table.Td>
                    <Table.Td>{bytes(row.containerBytes)}</Table.Td>
                    <Table.Td>
                      <Button
                        disabled={locked}
                        aria-label={`${t('recordingOpen')} ${row.id}`}
                        onClick={() => choose(row)}
                      >
                        {t('recordingOpen')}
                      </Button>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          <div className="mobile-recordings stack">
            {recordings.items.map((row) => (
              <article
                key={row.id}
                className={`recording-card stack${selectionMatches(row) ? ' selected-row' : ''}`}
              >
                <div className="section-heading">
                  <strong>{when(row.startedAt)}</strong>
                  <span>
                    {t(
                      row.status === 'completed'
                        ? 'artifactCatalogCompleted'
                        : row.status === 'failed'
                          ? 'artifactCatalogFailedStatus'
                          : 'artifactCatalogIncomplete',
                    )}
                  </span>
                </div>
                <p>
                  {identity(row)?.user ||
                    t(row.encrypted ? 'recordingMetadataProtected' : 'recordingMetadataUnknown')}
                </p>
                <p className="caption subtle">
                  {identity(row)?.flow || '—'} ·{' '}
                  {identity(row)?.target
                    ? `${t('recordingFilterTarget')}: ${identity(row)?.target} · `
                    : ''}
                  {duration(row)} · {bytes(row.containerBytes)}
                </p>
                <Button
                  disabled={locked}
                  aria-label={`${t('recordingOpen')} ${row.id}`}
                  onClick={() => choose(row)}
                >
                  {t('recordingOpen')}
                </Button>
              </article>
            ))}
          </div>
          {recordings.items.length === 0 && (
            <p className="empty-state">{t('recordingNoMatches')}</p>
          )}
          <div className="actions">
            {pageIndex > 0 && (
              <Button
                variant="default"
                disabled={locked}
                onClick={() => {
                  void loadRecordings(source, applied, pageIndex - 1);
                }}
              >
                {t('recordingPrevious')}
              </Button>
            )}
            <span className="caption subtle">
              {t('recordingPage')} {pageIndex + 1}
            </span>
            {recordings.next !== '' && (
              <Button
                variant="default"
                disabled={locked}
                onClick={() => {
                  void loadRecordings(source, applied, pageIndex + 1);
                }}
              >
                {t('recordingMore')}
              </Button>
            )}
          </div>
        </>
      )}
      <details className="context-help">
        <summary>{t('recordingAuditExports')}</summary>
        <div className="stack">
          <p>{t('recordingServerMetadata')}</p>
          {auditlogs !== null && (
            <div className="table-scroll">
              <Table captionSide="top">
                <caption>{t('artifactAuditlogCaption')}</caption>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('artifactAuditlog')}</Table.Th>
                    <Table.Th>{t('artifactCatalogConfiguration')}</Table.Th>
                    <Table.Th>{t('recordingOpenAudit')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {auditlogs.items.map((row) => (
                    <Table.Tr key={row.name}>
                      <Table.Td>{row.name}</Table.Td>
                      <Table.Td>
                        {t(
                          row.recordingEnabled
                            ? 'artifactCatalogRecordingOn'
                            : 'artifactCatalogRecordingOff',
                        )}{' '}
                        · {t(row.encrypted ? 'artifactCatalogEncrypted' : 'artifactCatalogClear')}
                      </Table.Td>
                      <Table.Td>
                        <Button
                          disabled={locked || !row.enabled}
                          aria-label={`${t('recordingOpenAudit')} ${row.name}`}
                          onClick={() => {
                            if (!locked && row.enabled) {
                              onSelect({ kind: 'audit', auditlog: row.name });
                            }
                          }}
                        >
                          {t('recordingOpenAudit')}
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
          )}
          <p>{t('artifactCatalogWarning')}</p>
        </div>
      </details>
    </section>
  );
}

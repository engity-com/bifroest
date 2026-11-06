import type { ReactNode } from 'react';
import { useEffect, useRef, useState } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { ColumnFilter } from '../management/protocol';
import type { AuditlogSummary, Page, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailRefresh } from '../ui/detail-preference';
import { reportUiError } from '../ui/error-report';
import { Alert } from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import { ReadProgress } from '../ui/ReadProgress';
import type { ArtifactRequest } from './protocol';

// Independent page/selection per actor. Visiting audit logs never queries or
// downloads recordings, nor silently borrows the recording page's results.
export function AuditCatalog({
  access,
  active,
  disabled,
  onSelect,
  openByID,
}: {
  access: WebAccess;
  active: boolean;
  disabled: boolean;
  onSelect(request: ArtifactRequest): void;
  openByID?: ReactNode;
}) {
  const [rows, setRows] = useState<Page<AuditlogSummary> | null>(null);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<'asc' | 'desc'>('asc');
  const [filter, setFilter] = useState<ColumnFilter | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
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
    setRows(null);
    setPage(0);
    setQuery('');
    setSort('asc');
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
    if (disabled || !active) {
      request.current?.abort();
    }
  }, [disabled, active]);
  async function load(index = page, search = query, direction = sort, predicate = filter) {
    if (!active || disabled || request.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
    setRows(null);
    setProgress(null);
    setFailed(null);
    try {
      const result = await access.managementAuditlogs(
        {
          after: index === 0 ? '' : (cursors.current[index] ?? ''),
          query: search,
          filter: predicate,
          ...(direction === 'desc' ? { sort: 'name-desc' } : {}),
        },
        controller.signal,
        (value) => {
          if (current === generation.current && !controller.signal.aborted) {
            setProgress(value);
          }
        },
      );
      if (current !== generation.current || controller.signal.aborted) {
        return;
      }
      if (index === 0) {
        cursors.current = [''];
      }
      cursors.current[index + 1] = result.next;
      setRows(result);
      setPage(index);
      setQuery(search);
      setSort(direction);
      setFilter(predicate);
    } catch (error) {
      if (current === generation.current) {
        if (!controller.signal.aborted) {
          reportUiError('artifact-catalog', error);
        }
        setRows(null);
        setPage(0);
        cursors.current = [''];
        setFailed(
          controller.signal.aborted
            ? 'artifactCatalogCancelled'
            : error instanceof RememberMeError && error.code === 'denied'
              ? 'recordingReadDenied'
              : 'recordingReadFailed',
        );
      }
    } finally {
      if (current === generation.current && controller.signal.aborted) {
        setRows(null);
        setPage(0);
        cursors.current = [''];
        setFailed('artifactCatalogCancelled');
      }
      if (request.current === controller) {
        request.current = null;
        setBusy(false);
      }
    }
  }
  useEffect(() => {
    if (available.current && !attempted.current) {
      const current = generation.current;
      queueMicrotask(() => {
        if (current === generation.current && available.current && !attempted.current) {
          attempted.current = true;
          void load(0);
        }
      });
    }
  });
  const detailed = useDetailRefresh(active, disabled, busy, () => {
    void load(0, query, sort, null);
  });
  return (
    <section className="stack" aria-label={t('artifactAuditlogCaption')}>
      {busy && <ReadProgress value={progress} onCancel={() => request.current?.abort()} />}
      {failed && (
        <Alert role="status" color="yellow">
          {t(failed)}
        </Alert>
      )}
      {(rows?.skipped ?? 0) > 0 && <Alert color="yellow">{t('managementPartial')}</Alert>}
      <AdminDataGrid<AuditlogSummary>
        active={active}
        label={t('artifactAuditlogCaption')}
        resultAvailable={rows !== null}
        rows={rows?.items ?? []}
        onRefresh={() => {
          void load();
        }}
        refreshLabel={t('auditRefresh')}
        openByID={openByID}
        detailsAvailable
        detailed={detailed}
        detailFields={['recordingEnabled']}
        canOpen={(row) => row.enabled}
        onOpen={(row) => onSelect({ kind: 'audit', auditlog: row.name })}
        openLabel={(row) => `${t('recordingOpenAudit')} ${row.name}`}
        getRowId={(row) => row.name}
        actionField="open"
        columns={[
          { field: 'name', headerName: t('artifactAuditlog'), minWidth: 190, flex: 1 },
          {
            field: 'recordingEnabled',
            headerName: t('artifactCatalogConfiguration'),
            type: 'boolean',
            minWidth: 200,
            valueFormatter: (value) =>
              t(value ? 'artifactCatalogRecordingOn' : 'artifactCatalogRecordingOff'),
          },
          {
            field: 'encrypted',
            headerName: t('artifactDetectedEncryption'),
            type: 'boolean',
            minWidth: 200,
            valueFormatter: (value) =>
              t(value ? 'artifactCatalogEncrypted' : 'artifactCatalogClear'),
          },
        ]}
        busy={busy || !attempted.current}
        disabled={disabled}
        page={page}
        hasNext={(rows?.next ?? '') !== ''}
        total={rows?.total}
        query={query}
        columnFilter={filter}
        onSearch={(query, filter) => {
          void load(0, query, sort, filter);
        }}
        sortField="name"
        sortDirection={sort}
        onPage={(index) => {
          if (index <= page + 1 && cursors.current[index] !== undefined) {
            void load(index);
          }
        }}
        onQuery={(value) => {
          void load(0, value);
        }}
        onSort={(value) => {
          void load(0, query, value);
        }}
      />
    </section>
  );
}

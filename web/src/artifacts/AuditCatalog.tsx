import { useEffect, useRef, useState } from 'react';
import type { ColumnFilter } from '../management/protocol';
import type { AuditlogSummary, Page, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { reportUiError } from '../ui/error-report';
import { Alert, Button } from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import type { ArtifactRequest } from './protocol';

// Independent page/selection per actor. Visiting audit logs never queries or
// downloads recordings, nor silently borrows the recording page's results.
export function AuditCatalog({
  access,
  active,
  disabled,
  onSelect,
}: {
  access: WebAccess;
  active: boolean;
  disabled: boolean;
  onSelect(request: ArtifactRequest): void;
}) {
  const [rows, setRows] = useState<Page<AuditlogSummary> | null>(null);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<'asc' | 'desc'>('asc');
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
    if (disabled) {
      request.current?.abort();
    }
  }, [disabled]);
  async function load(index = page, search = query, direction = sort, predicate = filter) {
    if (disabled || request.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
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
      if (current === generation.current && !controller.signal.aborted) {
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
  return (
    <section className="stack" aria-label={t('artifactAuditlogCaption')}>
      <div className="actions">
        <Button
          variant="default"
          disabled={disabled || busy}
          onClick={() => {
            void load();
          }}
        >
          {t('recordingRefresh')}
        </Button>
        {busy && (
          <Button
            onClick={() => {
              request.current?.abort();
              setFailed('artifactCatalogCancelled');
            }}
          >
            {t('artifactCatalogCancel')}
          </Button>
        )}
      </div>
      {failed && (
        <Alert role="status" color="yellow">
          {t(failed)}
        </Alert>
      )}
      {(rows?.skipped ?? 0) > 0 && <Alert color="yellow">{t('managementPartial')}</Alert>}
      {rows && (
        <AdminDataGrid<AuditlogSummary>
          active={active}
          label={t('artifactAuditlogCaption')}
          rows={rows.items}
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
            {
              field: 'open',
              headerName: t('recordingOpenAudit'),
              minWidth: 170,
              renderCell: (params) => (
                <Button
                  disabled={disabled || busy || !params.row.enabled}
                  aria-label={`${t('recordingOpenAudit')} ${params.row.name}`}
                  onClick={() => onSelect({ kind: 'audit', auditlog: params.row.name })}
                >
                  {t('recordingOpenAudit')}
                </Button>
              ),
            },
          ]}
          busy={busy}
          disabled={disabled}
          page={page}
          hasNext={rows.next !== ''}
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
      )}
    </section>
  );
}

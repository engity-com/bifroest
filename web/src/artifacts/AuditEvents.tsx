import CloseIcon from '@mui/icons-material/Close';
import { IconButton } from '@mui/material';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ColumnFilter } from '../management/protocol';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailRefresh } from '../ui/detail-preference';
import { Alert } from '../ui/material';
import { t } from '../ui/messages';
import {
  type AuditEventIndex,
  type AuditEventRow,
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
  const selected = controlled === undefined ? ownSelected : controlled;
  const choose = useCallback(
    (row: AuditEventRow | null) => {
      setOwnSelected(row);
      onSelect?.(row);
    },
    [onSelect],
  );
  const detailed = useDetailRefresh(active && selected === null, false, busy, () => {
    setFilter(null);
    setPage(0);
    setRefresh((value) => value + 1);
  });
  const index = useRef<AuditEventIndex | null>(null);
  const generation = useRef(0);
  const indexedRevision = useRef(0);
  useEffect(() => {
    if (index.current?.source === source) {
      return;
    }
    index.current = null;
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
        const result = await auditEventPage(
          ownedIndex,
          page,
          query,
          filter,
          sort === 'desc',
          controller.signal,
        );
        if (current === generation.current && !controller.signal.aborted) {
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
  }, [source, active, page, query, filter, sort, refresh]);
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
      <div hidden={selected !== null}>
        <AdminDataGrid<AuditEventRow>
          active={active && selected === null}
          label={t('auditEvents')}
          rows={rows}
          onOpen={choose}
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
          columnFilter={filter}
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
            <IconButton aria-label={t('close')} onClick={() => choose(null)}>
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

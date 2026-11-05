import { useEffect, useRef, useState } from 'react';
import type { ColumnFilter } from '../management/protocol';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { Alert, Button, Modal } from '../ui/material';
import { t } from '../ui/messages';
import {
  type AuditEventIndex,
  type AuditEventRow,
  auditEventPage,
  indexAuditEvents,
} from './audit-events';

export function AuditEvents({ source, active }: { source: Blob; active: boolean }) {
  const [rows, setRows] = useState<AuditEventRow[]>([]);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<ColumnFilter | null>(null);
  const [sort, setSort] = useState<'asc' | 'desc'>('desc');
  const [next, setNext] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [selected, setSelected] = useState<AuditEventRow | null>(null);
  const index = useRef<AuditEventIndex | null>(null);
  const generation = useRef(0);
  useEffect(() => {
    if (index.current?.source === source) {
      return;
    }
    index.current = null;
    setRows([]);
    setPage(0);
    setQuery('');
    setFilter(null);
    setSelected(null);
  }, [source]);
  useEffect(() => {
    const controller = new AbortController();
    const current = ++generation.current;
    if (!active) {
      setSelected(null);
      return;
    }
    setBusy(true);
    setFailed(false);
    void (async () => {
      try {
        const ownedIndex =
          index.current?.source === source
            ? index.current
            : await indexAuditEvents(source, controller.signal);
        if (current !== generation.current || controller.signal.aborted) {
          return;
        }
        index.current = ownedIndex;
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
  }, [source, active, page, query, filter, sort]);
  return (
    <section className="stack" aria-label={t('auditEvents')}>
      {failed && <Alert color="red">{t('auditEventsFailed')}</Alert>}
      <AdminDataGrid<AuditEventRow>
        active={active}
        label={t('auditEvents')}
        rows={rows}
        actionField="details"
        columns={[
          {
            field: 'details',
            headerName: t('auditOpenDetails'),
            minWidth: 100,
            filterable: false,
            renderCell: (params) => (
              <Button variant="subtle" onClick={() => setSelected(params.row)}>
                {t('auditOpenDetails')}
              </Button>
            ),
          },
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
      <Modal
        opened={active && selected !== null}
        onClose={() => setSelected(null)}
        title={t('auditEventDetails')}
      >
        <pre className="identifier">{selected ? JSON.stringify(selected.record, null, 2) : ''}</pre>
      </Modal>
    </section>
  );
}

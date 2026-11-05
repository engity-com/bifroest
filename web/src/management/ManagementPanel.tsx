import CloseIcon from '@mui/icons-material/Close';
import { IconButton } from '@mui/material';
import { useEffect, useEffectEvent, useId, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useAdminDetail } from '../ui/admin-navigation';
import { useDetailRefresh } from '../ui/detail-preference';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Modal, Select, TextInput, Title } from '../ui/material';
import { t } from '../ui/messages';
import type { ActionPreview, SessionAction, SessionActionConfirmation } from './action';
import { m, sessionStateLabel } from './messages';
import type {
  ColumnFilter,
  FlowSummary,
  Page,
  SessionItem,
  SessionOptions,
  VersionInfo,
} from './protocol';
import { VersionDetails } from './VersionDetails';

export function ManagementPanel({
  access,
  active,
  disabled,
  onActionLock,
  view,
}: {
  access: WebAccess;
  active: boolean;
  disabled: boolean;
  onActionLock: (locked: boolean) => void;
  view: 'sessions' | 'server' | 'version';
}) {
  const [flows, setFlows] = useState<Page<FlowSummary> | null>(null);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [buildVersion, setBuildVersion] = useState<VersionInfo | null>(null);
  const [sessions, setSessions] = useState<Page<SessionItem> | null>(null);
  const [selected, setSelected] = useState<SessionItem | null>(null);
  const [sessionFilter, setSessionFilter] = useState<ColumnFilter | null>(null);
  const [flowFilter, setFlowFilter] = useState<ColumnFilter | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<'denied' | 'unavailable' | null>(null);
  const [readCompletion, setReadCompletion] = useState(0);
  const [loading, setLoading] = useState<
    'sessions' | 'flows' | 'version' | 'build' | 'details' | null
  >(null);
  const [sessionPage, setSessionPage] = useState(1);
  const [sessionQuery, setSessionQuery] = useState('');
  const [sessionSort, setSessionSort] = useState<'asc' | 'desc'>('asc');
  const sessionCursors = useRef<string[]>(['']);
  const [flowPage, setFlowPage] = useState(1);
  const [flowQuery, setFlowQuery] = useState('');
  const [flowSort, setFlowSort] = useState<'asc' | 'desc'>('asc');
  const flowCursors = useRef<string[]>(['']);
  const [versionFailed, setVersionFailed] = useState(false);
  const attempted = useRef({ sessions: false, version: false, flows: false, build: false });
  const detailElement = useRef<HTMLElement | null>(null);
  const listElement = useRef<HTMLDivElement | null>(null);
  const returningToList = useRef(false);
  const detailID = useId();
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const lastFilter = useRef<SessionOptions>({});
  const confirmation = useRef<SessionActionConfirmation | null>(null);
  const sending = useRef(false);
  const preparing = useRef<number | null>(null);
  const isActive = useRef(active);
  isActive.current = active;
  const [preview, setPreview] = useState<ActionPreview | null>(null);
  const [typed, setTyped] = useState('');
  const [actionFlow, setActionFlow] = useState('');
  const [actionID, setActionID] = useState('');
  const [actionKind, setActionKind] = useState<SessionAction>('disconnect');
  const [notice, setNotice] = useState<{
    kind: 'confirmed' | 'unknown';
    preview: ActionPreview;
  } | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: An access change must reset all actor-owned results, even though the effect does not read the access itself.
  useEffect(() => {
    generation.current++;
    request.current?.abort();
    request.current = null;
    setFlows(null);
    setVersion(null);
    setBuildVersion(null);
    setSessions(null);
    setSelected(null);
    setBusy(false);
    setError(null);
    setLoading(null);
    setSessionPage(1);
    setSessionQuery('');
    setSessionSort('asc');
    sessionCursors.current = [''];
    setFlowPage(1);
    setFlowQuery('');
    setFlowSort('asc');
    flowCursors.current = [''];
    setVersionFailed(false);
    attempted.current = { sessions: false, version: false, flows: false, build: false };
    lastFilter.current = {};
    setSessionFilter(null);
    setFlowFilter(null);
    preparing.current = null;
    sending.current = false;
    setPreview(null);
    setTyped('');
    setActionFlow('');
    setActionID('');
    setActionKind('disconnect');
    setNotice(null);
    onActionLock(false);
    return () => {
      generation.current++;
      request.current?.abort();
      request.current = null;
      void confirmation.current?.cancel();
      confirmation.current = null;
      onActionLock(false);
    };
  }, [access, onActionLock]);
  useEffect(() => {
    if (
      active ||
      sending.current ||
      (preparing.current === null && confirmation.current === null)
    ) {
      return;
    }
    generation.current++;
    request.current?.abort();
    request.current = null;
    preparing.current = null;
    const handle = confirmation.current;
    confirmation.current = null;
    setPreview(null);
    setTyped('');
    setBusy(false);
    void handle?.cancel(); // Retire only an unused preparation, never a mutation.
  }, [active]);
  // Read intent belongs to the first active, enabled view of this access, not to
  // mounting a background tab. Mark attempts before dispatch: failures, view
  // changes and cleared mutation results must never cause an automatic retry.
  const readInitialView = useEffectEvent(() => {
    if (!active || disabled || busy || request.current !== null || notice?.kind === 'unknown') {
      return;
    }
    if (view === 'sessions' && !attempted.current.sessions) {
      attempted.current.sessions = true;
      void loadSessions(false, { state: 'all' });
    } else if (view === 'version' && !attempted.current.version) {
      attempted.current.version = true;
      void loadVersion();
    } else if (view === 'version' && !attempted.current.build) {
      attempted.current.build = true;
      void loadVersion(true);
    } else if (view === 'server' && !attempted.current.flows) {
      attempted.current.flows = true;
      void loadFlows();
    }
  });
  // biome-ignore lint/correctness/useExhaustiveDependencies: Access/view are read intents. The completion counter also advances the serialized initial server reads when React batches busy=true/false.
  useEffect(() => {
    if (active && !disabled && !busy) {
      const current = generation.current;
      // Commit ownership before dispatch. StrictMode's setup/cleanup replay
      // retires the first lease without sending a duplicate server request.
      queueMicrotask(() => {
        if (current === generation.current) {
          readInitialView();
        }
      });
    }
  }, [access, active, disabled, busy, view, readCompletion]);
  const focusDetails = useEffectEvent(() => {
    if (active && view === 'sessions') {
      detailElement.current?.focus({ preventScroll: true });
    }
  });
  useEffect(() => {
    if (selected !== null) {
      focusDetails();
    } else if (returningToList.current) {
      returningToList.current = false;
      if (isActive.current) {
        const target =
          listElement.current?.querySelector<HTMLElement>('[role="gridcell"][tabindex="0"]') ??
          listElement.current?.querySelector<HTMLElement>('button:not([disabled])');
        target?.focus({ preventScroll: true });
      }
    }
  }, [selected]);
  function returnToSessions() {
    returningToList.current = true;
    setSelected(null);
  }
  function cancel() {
    if (sending.current && preview !== null) {
      reportUiError(
        'management-mutation',
        new RememberMeError('management-unknown'),
        'mutation-unknown',
      );
      setNotice({ kind: 'unknown', preview });
      setPreview(null);
      confirmation.current = null;
      setSessions(null);
      setSelected(null);
    }
    generation.current++;
    request.current?.abort();
    request.current = null;
    sending.current = false;
    setBusy(false);
    setLoading(null);
  }
  async function run(
    action: (signal: AbortSignal, current: number) => Promise<void>,
    resource: typeof loading = null,
  ) {
    if (disabled || request.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
    setLoading(resource);
    setError(null);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (
        current === generation.current &&
        !(error instanceof RememberMeError && error.code === 'cancelled')
      ) {
        reportUiError('management-read', error);
        setError(
          error instanceof RememberMeError && error.code === 'denied' ? 'denied' : 'unavailable',
        );
        if (resource === 'version') {
          setVersionFailed(true);
        }
      }
    } finally {
      if (current === generation.current) {
        request.current = null;
        setBusy(false);
        setLoading(null);
        setReadCompletion((value) => value + 1);
      }
    }
  }
  async function loadFlows(
    after = '',
    index = 0,
    query = flowQuery,
    direction = flowSort,
    filter = flowFilter,
  ) {
    attempted.current.flows = true;
    await run(async (signal, current) => {
      const result = await access.managementFlows(
        { after, query, filter, ...(direction === 'desc' ? { sort: 'name-desc' } : {}) },
        signal,
      );
      if (current === generation.current) {
        setFlows(result);
        setFlowPage(index + 1);
        setFlowQuery(query);
        setFlowSort(direction);
        setFlowFilter(filter);
        if (index === 0) {
          flowCursors.current = [''];
        }
        flowCursors.current[index + 1] = result.next;
      }
    }, 'flows');
  }
  async function loadVersion(long = false) {
    if (!long) {
      attempted.current.version = true;
    }
    await run(
      async (signal, current) => {
        const result = await access.managementVersion(long, signal);
        if (current === generation.current) {
          if (long) {
            setBuildVersion(result);
          } else {
            setVersion(result);
            setVersionFailed(false);
          }
        }
      },
      long ? 'build' : 'version',
    );
  }
  async function refreshSessions() {
    await loadSessions(false, {
      ...lastFilter.current,
      after: '',
      flow: lastFilter.current.flow ?? '',
      user: lastFilter.current.user ?? '',
      state: lastFilter.current.state ?? 'all',
    });
  }
  async function loadSessions(next = false, initial?: SessionOptions, index?: number) {
    attempted.current.sessions = true;
    const filters: SessionOptions =
      initial ??
      (next
        ? { ...lastFilter.current, after: sessions?.next ?? '' }
        : {
            state: 'all',
            filter: sessionFilter,
            query: sessionQuery,
            sort: sessionSort === 'asc' ? 'flow-asc' : 'flow-desc',
          });
    const pageIndex = index ?? (next ? sessionPage : 0);
    await run(async (signal, current) => {
      const result = await access.managementSessions(filters, signal);
      if (current === generation.current) {
        lastFilter.current = filters;
        setSessions(result);
        setSelected(null);
        setSessionPage(pageIndex + 1);
        if (pageIndex === 0) {
          sessionCursors.current = [''];
        }
        sessionCursors.current[pageIndex + 1] = result.next;
        setSessionQuery(filters.query ?? '');
        setSessionSort(filters.sort === 'flow-desc' ? 'desc' : 'asc');
        setSessionFilter(filters.filter ?? null);
      }
    }, 'sessions');
  }
  async function show(item: SessionItem) {
    await run(async (signal, current) => {
      const result = await access.managementSession(item.flow, item.id, signal);
      if (current === generation.current) {
        setSelected(result);
      }
    }, 'details');
  }
  async function prepare(
    action: SessionAction,
    item: { readonly flow: string; readonly id: string },
  ) {
    if (!isActive.current || notice?.kind === 'unknown') {
      return;
    }
    await run(async (signal, current) => {
      preparing.current = current;
      try {
        const handle = await access.prepareSessionAction(action, item.flow, item.id, signal);
        if (current !== generation.current || !isActive.current) {
          await handle.cancel();
          return;
        }
        confirmation.current = handle;
        setPreview(handle.snapshot());
        setTyped('');
      } finally {
        if (preparing.current === current) {
          preparing.current = null;
        }
      }
    });
  }
  function closeConfirmation() {
    if (sending.current) {
      return;
    }
    const handle = confirmation.current;
    confirmation.current = null;
    setPreview(null);
    setTyped('');
    void handle?.cancel(); // Preparation cancellation, never undo/logout/disposal.
  }
  async function confirmAction() {
    const handle = confirmation.current;
    const pinned = preview;
    if (
      disabled ||
      !isActive.current ||
      request.current !== null ||
      handle === null ||
      pinned === null ||
      typed !== `${pinned.target.flow}/${pinned.target.id}`
    ) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    sending.current = true;
    setBusy(true);
    setError(null);
    onActionLock(true);
    try {
      await handle.confirm(controller.signal);
      if (current === generation.current) {
        setNotice({ kind: 'confirmed', preview: pinned });
        onActionLock(false);
      }
    } catch (error) {
      if (current === generation.current) {
        reportUiError('management-mutation', error, 'mutation-unknown');
        setNotice({ kind: 'unknown', preview: pinned });
      }
    } finally {
      if (current === generation.current) {
        request.current = null;
        sending.current = false;
        confirmation.current = null;
        setPreview(null);
        setTyped('');
        setBusy(false);
        setSessions(null);
        setSelected(null);
      }
    }
  }
  const locked = disabled || busy;
  const detailed = useDetailRefresh(
    active && view !== 'version' && selected === null,
    disabled,
    busy,
    () => {
      if (view === 'sessions') {
        void loadSessions(false, { ...lastFilter.current, filter: null, after: '' }, 0);
      } else if (view === 'server') {
        void loadFlows('', 0, flowQuery, flowSort, null);
      }
    },
  );
  const when = (value: string) =>
    new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(
      new Date(value),
    );
  const ownerLabel = (item: SessionItem) =>
    item.owner === null
      ? t(item.policyLimited ? 'managementWithheldOwner' : 'managementUnknownOwner')
      : `${item.owner.issuer} / ${item.owner.subject}`;
  const field = (item: SessionItem, value: string) =>
    value || m(item.policyLimited ? 'withheld' : 'notReported');
  const integratedNavigation = useAdminDetail(
    'sessions',
    selected?.id ?? null,
    returnToSessions,
    selected ? [selected.flow] : [],
  );
  return (
    <section className="stack" aria-label={t('managementTitle')}>
      {!integratedNavigation && (
        <AdminBreadcrumbs
          items={
            view === 'server'
              ? [{ label: t('workspaceBifroest') }]
              : [
                  { label: t('workspaceBifroest') },
                  {
                    label: t('workspaceSessions'),
                    ...(selected ? { onClick: returnToSessions, disabled: locked } : {}),
                  },
                  ...(selected ? [{ label: selected.flow }, { label: selected.id }] : []),
                ]
          }
        />
      )}
      <section hidden={view !== 'version'} className="stack">
        <div className="section-heading admin-toolbar">
          <Title order={3}>{t('managementVersionTitle')}</Title>
          <Button
            variant="default"
            disabled={locked}
            onClick={() => {
              void loadVersion(buildVersion !== null);
            }}
          >
            {m('versionRefresh')}
          </Button>
        </div>
        {loading === 'version' && <p role="status">{m('versionLoading')}</p>}
        {version === null && loading !== 'version' && (
          <p className="empty-state">
            {m(versionFailed ? 'versionUnavailable' : 'versionPending')}
          </p>
        )}
        {(buildVersion ?? version) !== null && (
          <section aria-label={t('managementVersionTitle')}>
            <VersionDetails info={(buildVersion ?? version) as VersionInfo} />
          </section>
        )}
      </section>
      {notice !== null && (
        <Alert role="status" color={notice.kind === 'confirmed' ? 'green' : 'yellow'}>
          <p>
            {t(
              notice.kind === 'confirmed' ? 'managementActionConfirmed' : 'managementActionUnknown',
            )}
          </p>
          <p>
            {m(notice.preview.action === 'dispose' ? 'end' : 'disconnect')}:{' '}
            {notice.preview.target.flow}/{notice.preview.target.id}
          </p>
          {notice.kind === 'unknown' && (
            <Button
              variant="default"
              onClick={() => {
                setNotice(null);
                onActionLock(false);
              }}
            >
              {t('managementDismissUnknown')}
            </Button>
          )}
        </Alert>
      )}
      {error && (
        <Alert role="status" color="red">
          <p>{m(error === 'denied' ? 'readDenied' : 'readUnavailable')}</p>
          {error !== 'denied' && <p>{m('readNext')}</p>}
        </Alert>
      )}
      <div hidden={view !== 'server'} className="stack">
        {(flows?.skipped ?? 0) > 0 && (
          <Alert color="yellow">
            {t('managementPartial')} ({flows?.skipped})
          </Alert>
        )}
        <AdminDataGrid<FlowSummary>
          active={active && view === 'server'}
          label={t('managementFlowsCaption')}
          rows={flows?.items ?? []}
          onRefresh={() => {
            void loadFlows();
          }}
          refreshLabel={m('flowsRefresh')}
          getRowId={(item) => item.name}
          columns={[
            { field: 'name', headerName: t('managementFlow'), minWidth: 170, flex: 1 },
            {
              field: 'authorization',
              headerName: t('managementAuthorization'),
              minWidth: 170,
              flex: 1,
            },
            {
              field: 'environment',
              headerName: t('managementEnvironment'),
              minWidth: 170,
              flex: 1,
            },
            { field: 'auditlog', headerName: t('managementAuditlog'), minWidth: 170, flex: 1 },
          ]}
          busy={busy || !attempted.current.flows}
          disabled={disabled || notice?.kind === 'unknown'}
          page={flowPage - 1}
          hasNext={(flows?.next ?? '') !== ''}
          query={flowQuery}
          columnFilter={flowFilter}
          onSearch={(query, filter) => {
            void loadFlows('', 0, query, flowSort, filter);
          }}
          sortField="name"
          sortDirection={flowSort}
          onPage={(index) => {
            const cursor = flowCursors.current[index];
            if (cursor !== undefined && index <= flowPage) {
              void loadFlows(cursor, index);
            }
          }}
          onQuery={(query) => {
            void loadFlows('', 0, query, flowSort);
          }}
          onSort={(direction) => {
            void loadFlows('', 0, flowQuery, direction);
          }}
        />
      </div>
      {busy && sending.current && (
        <Button variant="default" onClick={cancel}>
          {t(sending.current ? 'managementStopWaiting' : 'managementCancel')}
        </Button>
      )}
      <section hidden={view !== 'sessions'} className="stack">
        <div hidden={selected !== null} className="stack" ref={listElement}>
          {(sessions?.skipped ?? 0) > 0 && (
            <Alert color="yellow">
              {t('managementPartial')} ({sessions?.skipped})
            </Alert>
          )}
          <AdminDataGrid<SessionItem>
            active={active && view === 'sessions' && selected === null}
            actionField="details"
            label={t('managementSessionsCaption')}
            rows={sessions?.items ?? []}
            onRefresh={() => {
              void refreshSessions();
            }}
            refreshLabel={m('refreshSessions')}
            detailsAvailable
            detailed={detailed}
            detailFields={['user', 'remote']}
            onOpen={(item) => {
              void show(item);
            }}
            openLabel={(item) => `${t('managementDetails')} ${item.id}`}
            getRowId={(item) => `${item.flow}/${item.id}`}
            columns={[
              {
                field: 'user',
                headerName: m('user'),
                minWidth: 170,
                flex: 1,
                valueGetter: (_value, item) => field(item, item.user),
              },
              { field: 'flow', headerName: t('managementFlow'), minWidth: 150 },
              {
                field: 'state',
                headerName: m('status'),
                minWidth: 130,
                type: 'singleSelect',
                valueOptions: ['new', 'authorized', 'disposed'].map((value) => ({
                  value,
                  label: sessionStateLabel(value),
                })),
              },
              {
                field: 'createdAt',
                headerName: m('started'),
                minWidth: 190,
                type: 'dateTime',
                valueGetter: (_value, item) => new Date(item.createdAt),
                valueFormatter: (value) => when((value as Date).toISOString()),
              },
              {
                field: 'remote',
                headerName: m('origin'),
                minWidth: 180,
                flex: 1,
                valueGetter: (_value, item) => field(item, item.remote),
              },
            ]}
            busy={busy || !attempted.current.sessions}
            disabled={disabled || notice?.kind === 'unknown'}
            page={sessionPage - 1}
            hasNext={(sessions?.next ?? '') !== ''}
            query={sessionQuery}
            columnFilter={sessionFilter}
            onSearch={(query, filter) => {
              void loadSessions(
                false,
                {
                  state: 'all',
                  query,
                  filter,
                  sort: sessionSort === 'asc' ? 'flow-asc' : 'flow-desc',
                },
                0,
              );
            }}
            sortField="flow"
            sortDirection={sessionSort}
            onPage={(index) => {
              const cursor = sessionCursors.current[index];
              if (cursor !== undefined && index <= sessionPage) {
                void loadSessions(false, { ...lastFilter.current, after: cursor }, index);
              }
            }}
            onQuery={(query) => {
              void loadSessions(false, { ...lastFilter.current, after: '', query }, 0);
            }}
            onSort={(direction) => {
              void loadSessions(
                false,
                {
                  ...lastFilter.current,
                  after: '',
                  sort: direction === 'asc' ? 'flow-asc' : 'flow-desc',
                },
                0,
              );
            }}
          />
        </div>
        {selected !== null && (
          <section
            ref={detailElement}
            id={detailID}
            tabIndex={-1}
            aria-label={m('detailsTitle')}
            className="stack session-details record-card"
          >
            <div className="section-heading">
              <IconButton aria-label={t('close')} disabled={locked} onClick={returnToSessions}>
                <CloseIcon />
              </IconButton>
            </div>
            <dl className="metadata-grid">
              {detailed && (
                <>
                  <dt>{m('user')}</dt>
                  <dd>{field(selected, selected.user)}</dd>
                </>
              )}
              <dt>{t('managementFlow')}</dt>
              <dd>{selected.flow}</dd>
              <dt>{m('status')}</dt>
              <dd>{sessionStateLabel(selected.state)}</dd>
              <dt>{m('started')}</dt>
              <dd>{when(selected.createdAt)}</dd>
              {detailed && (
                <>
                  <dt>{m('origin')}</dt>
                  <dd>{field(selected, selected.remote)}</dd>
                </>
              )}
              <dt>{t('managementSessionId')}</dt>
              <dd className="identifier">{selected.id}</dd>
              {detailed &&
                (selected.owner === null ? (
                  <>
                    <dt>{t('managementOwner')}</dt>
                    <dd>{ownerLabel(selected)}</dd>
                  </>
                ) : (
                  <>
                    <dt>{m('issuer')}</dt>
                    <dd>{selected.owner.issuer}</dd>
                    <dt>{m('subject')}</dt>
                    <dd>{selected.owner.subject}</dd>
                  </>
                ))}
              {detailed && selected.lastAccessed !== undefined && (
                <>
                  <dt>{m('lastAccessed')}</dt>
                  <dd>{when(selected.lastAccessed)}</dd>
                </>
              )}
              <dt>{t('managementValidUntil')}</dt>
              <dd>
                {selected.validUntil === undefined
                  ? t(selected.policyLimited ? 'managementWithheldOwner' : 'managementNoLimit')
                  : when(selected.validUntil)}
              </dd>
              <dt>{t('adminGridActions')}</dt>
              <dd className="actions">
                <Button
                  disabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
                  color="orange"
                  onClick={() => {
                    void prepare('disconnect', selected);
                  }}
                >
                  {m('disconnect')}
                </Button>
                <Button
                  disabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
                  color="red"
                  onClick={() => {
                    void prepare('dispose', selected);
                  }}
                >
                  {m('end')}
                </Button>
              </dd>
            </dl>
          </section>
        )}
        <details className="advanced-action" hidden={selected !== null}>
          <summary>{m('direct')}</summary>
          <section aria-label={m('direct')} className="stack">
            <p className="caption subtle">{t('managementDirectActionHint')}</p>
            <form
              method="dialog"
              className="session-filters"
              onSubmit={(event) => {
                event.preventDefault();
                void prepare(actionKind, { flow: actionFlow, id: actionID });
              }}
            >
              <TextInput
                label={t('managementActionFlow')}
                value={actionFlow}
                onChange={(event) => setActionFlow(event.currentTarget.value)}
                disabled={locked}
                maxLength={255}
                required
              />
              <TextInput
                label={t('managementActionID')}
                value={actionID}
                onChange={(event) => setActionID(event.currentTarget.value)}
                disabled={locked}
                maxLength={36}
                required
                pattern="[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"
              />
              <Select
                label={t('managementActionKind')}
                value={actionKind}
                onChange={(value) => setActionKind(value === 'dispose' ? 'dispose' : 'disconnect')}
                data={[
                  { value: 'disconnect', label: m('disconnect') },
                  { value: 'dispose', label: m('end') },
                ]}
                disabled={locked}
              />
              <p className="caption subtle">
                {m(actionKind === 'dispose' ? 'endHint' : 'disconnectHint')}
              </p>
              <Button type="submit" disabled={locked || notice?.kind === 'unknown'}>
                {t('managementPrepareAction')}
              </Button>
            </form>
          </section>
        </details>
      </section>
      <Modal
        classNames={{ content: 'confirmation-dialog' }}
        lockScroll={false}
        opened={active && preview !== null}
        onClose={closeConfirmation}
        closeOnClickOutside={false}
        closeOnEscape={!sending.current}
        withCloseButton={!sending.current}
        title={t('managementConfirmTitle')}
      >
        {preview !== null && (
          <form
            method="dialog"
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void confirmAction();
            }}
          >
            <p>
              {access.snapshot().scope.slug || '/'} · {access.snapshot().principal}
            </p>
            <Alert color={preview.action === 'dispose' ? 'red' : 'yellow'}>
              {t(
                preview.action === 'dispose'
                  ? 'managementDisposeWarning'
                  : 'managementDisconnectWarning',
              )}
            </Alert>
            <p>
              {preview.target.flow}/{preview.target.id}
            </p>
            {preview.target.details === undefined ? (
              <Alert color="yellow">{t('managementActionNoDetails')}</Alert>
            ) : (
              <>
                <p>{ownerLabel(preview.target.details)}</p>
                <p>
                  {t('managementCreated')}: {when(preview.target.details.createdAt)}
                </p>
              </>
            )}
            <p>
              {t('managementConfirmationExpires')}: {when(preview.expiresAt)}
            </p>
            <TextInput
              label={t('managementConfirmTarget')}
              value={typed}
              onChange={(event) => setTyped(event.currentTarget.value)}
              disabled={busy}
              autoComplete="off"
            />
            <div className="actions">
              <Button
                type="submit"
                color="red"
                disabled={
                  disabled || busy || typed !== `${preview.target.flow}/${preview.target.id}`
                }
              >
                {t('managementConfirmAction')}
              </Button>
              {busy ? (
                <Button type="button" variant="default" onClick={cancel}>
                  {t('managementStopWaiting')}
                </Button>
              ) : (
                <Button type="button" variant="default" onClick={closeConfirmation}>
                  {t('cancel')}
                </Button>
              )}
            </div>
          </form>
        )}
      </Modal>
    </section>
  );
}

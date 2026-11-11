import { CircularProgress } from '@mui/material';
import { useEffect, useEffectEvent, useId, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { uuidEqual, uuidText } from '../shared/uuid';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useAdminDetail } from '../ui/admin-navigation';
import { useDetailRefresh } from '../ui/detail-preference';
import { reportUiError } from '../ui/error-report';
import { bookmarkPath as managementPath } from '../ui/hash-route';
import { ManagementNotFound } from '../ui/ManagementNotFound';
import { exactFlow, type ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button } from '../ui/material';
import { t } from '../ui/messages';
import { profileResetEvent } from '../ui/profile-reset';
import type { ActionPreview, SessionAction, SessionActionConfirmation } from './action';
import { FlowOverview } from './FlowOverview';
import { m, sessionStateLabel } from './messages';
import type {
  ColumnFilter,
  FlowSummary,
  Page,
  SessionItem,
  SessionOptions,
  VersionInfo,
} from './protocol';
import { SessionActionDialog } from './SessionActionDialog';
import { SessionArtifactLinks } from './SessionArtifactLinks';
import { SessionDetails } from './SessionDetails';
import { SessionTarget, type SessionTargetValue } from './SessionTarget';
import { sessionField as field, sessionTime as when } from './session-display';
import { VersionPage } from './VersionPage';

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
  const [target, setTarget] = useState<SessionTargetValue>({ flow: '', id: '', action: 'details' });
  useEffect(() => {
    const reset = () => setTarget({ flow: '', id: '', action: 'details' });
    window.addEventListener(profileResetEvent, reset);
    return () => window.removeEventListener(profileResetEvent, reset);
  }, []);
  const navigation = useManagementNavigation();
  const route = navigation?.location.page === 'sessions' ? navigation.location : null;
  const routeKey = JSON.stringify(route);
  const routeNow = useRef(route);
  routeNow.current = route;
  const nativeFilterIntent = useRef<{
    key: string;
    query: string;
    filter: ColumnFilter | null;
  } | null>(null);
  const mutationRoute = useRef<ManagementLocation | null>(null);
  const consumedRoute = useRef<string | null>(null);
  const loadedFlow = useRef<string | null>(null);
  const returnRoute = useRef<ManagementLocation | null>(null);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [buildVersion, setBuildVersion] = useState<VersionInfo | null>(null);
  const [sessions, setSessions] = useState<Page<SessionItem> | null>(null);
  const [selected, setSelected] = useState<SessionItem | null>(null);
  const [sessionFilter, setSessionFilter] = useState<ColumnFilter | null>(null);
  const [flowFilter, setFlowFilter] = useState<ColumnFilter | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<'denied' | 'unavailable' | 'not-found' | null>(null);
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
    setTarget({ flow: '', id: '', action: 'details' });
    consumedRoute.current = null;
    mutationRoute.current = null;
    nativeFilterIntent.current = null;
    loadedFlow.current = null;
    returnRoute.current = null;
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
    if (view === 'sessions' && !route && !attempted.current.sessions) {
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
  const readRoute = useEffectEvent(() => {
    if (
      !active ||
      disabled ||
      busy ||
      request.current !== null ||
      !route ||
      consumedRoute.current === routeKey
    ) {
      return;
    }
    consumedRoute.current = routeKey;
    setError(null);
    if (route.id && route.flow) {
      if (!uuidEqual(selected?.id, route.id) || selected?.flow !== route.flow) {
        setSelected(null);
        void show({ flow: route.flow, id: route.id });
      }
      return;
    }
    setSelected(null);
    if (loadedFlow.current === (route.flow ?? '') && sessions !== null) {
      return;
    }
    const native = nativeFilterIntent.current?.key === routeKey ? nativeFilterIntent.current : null;
    nativeFilterIntent.current = null;
    const filter = native
      ? native.filter
      : route.flow
        ? { field: 'flow', operator: 'equals', value: route.flow }
        : exactFlow(sessionFilter)
          ? null
          : sessionFilter;
    setSessions(null);
    setSessionPage(1);
    sessionCursors.current = [''];
    setSessionFilter(filter);
    setSessionQuery(native?.query ?? '');
    void loadSessions(
      false,
      {
        state: 'all',
        ...(route.flow ? { flow: route.flow } : {}),
        filter,
        query: native?.query ?? '',
        sort: sessionSort === 'asc' ? 'flow-asc' : 'flow-desc',
      },
      0,
    );
  });
  const finishMutationRoute = useEffectEvent(() => {
    if (
      !active ||
      disabled ||
      busy ||
      notice?.kind === 'unknown' ||
      !mutationRoute.current ||
      !navigation
    ) {
      return;
    }
    const target = mutationRoute.current;
    mutationRoute.current = null;
    const { id: _id, ...list } = target;
    const parent = returnRoute.current ?? list;
    // The action invalidated this list. Match the old X/detail behavior: return
    // to its URI, but require explicit Refresh rather than replaying a read.
    attempted.current.sessions = true;
    const filter = parent.flow
      ? { field: 'flow', operator: 'equals', value: parent.flow }
      : exactFlow(sessionFilter)
        ? null
        : sessionFilter;
    lastFilter.current = { ...lastFilter.current, flow: parent.flow ?? '', filter, after: '' };
    setSessionFilter(filter);
    loadedFlow.current = parent.flow ?? '';
    consumedRoute.current = JSON.stringify(parent);
    navigation.navigate(parent, true);
  });
  // biome-ignore lint/correctness/useExhaustiveDependencies: Completion wakes a queued route intent when React batches busy transitions; consumed routes, including failures, are never retried.
  useEffect(() => {
    if (active && !disabled && !busy && routeKey !== consumedRoute.current) {
      readRoute();
    }
  }, [routeKey, active, disabled, busy, readCompletion]);
  useEffect(() => {
    if (active && !disabled && !busy && notice?.kind !== 'unknown') {
      finishMutationRoute();
    }
  }, [active, disabled, busy, notice?.kind]);
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
    if (navigation && route) {
      const { id: _id, ...parent } = route;
      navigation.navigate(returnRoute.current ?? parent);
      return;
    }
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
          error instanceof RememberMeError && error.code === 'denied'
            ? 'denied'
            : resource === 'details' &&
                error instanceof RememberMeError &&
                error.code === 'not-found'
              ? 'not-found'
              : 'unavailable',
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
      flow: navigation ? (route?.flow ?? '') : (lastFilter.current.flow ?? ''),
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
            ...(route?.flow ? { flow: route.flow } : {}),
          });
    const pageIndex = index ?? (next ? sessionPage : 0);
    await run(async (signal, current) => {
      const result = await access.managementSessions(filters, signal);
      if (
        current === generation.current &&
        (!routeNow.current || routeNow.current.flow === (filters.flow || undefined))
      ) {
        lastFilter.current = filters;
        loadedFlow.current = filters.flow ?? '';
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
  async function show(item: Pick<SessionItem, 'flow' | 'id'>) {
    await run(async (signal, current) => {
      const result = await access.managementSession(item.flow, item.id, signal);
      if (
        current === generation.current &&
        (!routeNow.current ||
          (routeNow.current.flow === item.flow && uuidEqual(routeNow.current.id, item.id)))
      ) {
        setSelected(result);
      }
    }, 'details');
  }
  function openSession(item: Pick<SessionItem, 'flow' | 'id'>) {
    if (navigation) {
      returnRoute.current = navigation.location;
      navigation.navigate({
        managementFlow: navigation.location.managementFlow,
        page: 'sessions',
        flow: item.flow,
        id: item.id,
      });
    } else {
      void show(item);
    }
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
    mutationRoute.current = route?.id ? route : null;
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
  function sessionArtifactActions(item: SessionItem, compact: boolean) {
    const managementFlow = navigation?.location.managementFlow ?? access.snapshot().flow?.name;
    return (
      <SessionArtifactLinks
        item={item}
        scope={access.snapshot().scope}
        managementFlow={managementFlow}
        compact={compact}
        disabled={locked}
      />
    );
  }
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
  const integratedNavigation = useAdminDetail(
    'sessions',
    selected?.id ?? null,
    returnToSessions,
    selected ? [selected.flow] : [],
  );
  if (error === 'not-found' && view === 'sessions') {
    return (
      <section aria-label={t('managementTitle')}>
        <ManagementNotFound />
      </section>
    );
  }
  return (
    <section className="stack" aria-label={t('managementTitle')}>
      {!integratedNavigation && (
        <AdminBreadcrumbs
          items={
            view === 'server'
              ? [
                  {
                    label: t('workspaceBifroest'),
                    to: managementPath(access.snapshot().scope, {
                      managementFlow: access.snapshot().flow?.name ?? 'management',
                      page: 'server',
                    }),
                  },
                ]
              : [
                  {
                    label: t('workspaceBifroest'),
                    to: managementPath(access.snapshot().scope, {
                      managementFlow: access.snapshot().flow?.name ?? 'management',
                      page: 'server',
                    }),
                  },
                  {
                    label: t(view === 'version' ? 'workspaceVersion' : 'workspaceSessions'),
                    to: managementPath(access.snapshot().scope, {
                      managementFlow: access.snapshot().flow?.name ?? 'management',
                      page: view === 'version' ? 'version' : 'sessions',
                    }),
                    ...(selected ? { onClick: returnToSessions, disabled: locked } : {}),
                  },
                  ...(selected
                    ? [
                        {
                          label: selected.flow,
                          to: managementPath(access.snapshot().scope, {
                            managementFlow: access.snapshot().flow?.name ?? 'management',
                            page: 'sessions',
                            flow: selected.flow,
                          }),
                        },
                        {
                          label: uuidText(selected.id),
                          to: managementPath(access.snapshot().scope, {
                            managementFlow: access.snapshot().flow?.name ?? 'management',
                            page: 'sessions',
                            flow: selected.flow,
                            id: selected.id,
                          }),
                        },
                      ]
                    : []),
                ]
          }
        />
      )}
      <VersionPage
        visible={view === 'version'}
        version={version}
        buildVersion={buildVersion}
        loading={loading === 'version'}
        failed={versionFailed}
        disabled={locked}
        onRefresh={() => {
          void loadVersion(buildVersion !== null);
        }}
      />
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
        <FlowOverview
          scope={access.snapshot().scope}
          active={active && view === 'server'}
          rows={flows}
          locked={locked}
          busy={busy || !attempted.current.flows}
          disabled={disabled || notice?.kind === 'unknown'}
          pagination={{
            index: flowPage - 1,
            query: flowQuery,
            filter: flowFilter,
            direction: flowSort,
          }}
          actions={{
            refresh: () => {
              void loadFlows();
            },
            search: (query, filter) => {
              void loadFlows('', 0, query, flowSort, filter);
            },
            page: (index) => {
              const cursor = flowCursors.current[index];
              if (cursor !== undefined && index <= flowPage) {
                void loadFlows(cursor, index);
              }
            },
            query: (query) => {
              void loadFlows('', 0, query, flowSort);
            },
            sort: (direction) => {
              void loadFlows('', 0, flowQuery, direction);
            },
          }}
        />
      </div>
      {busy && sending.current && (
        <Button variant="default" onClick={cancel}>
          {t(sending.current ? 'managementStopWaiting' : 'managementCancel')}
        </Button>
      )}
      <section hidden={view !== 'sessions'} className="stack">
        <div
          hidden={(!route && selected !== null) || !!route?.id}
          className="stack"
          ref={listElement}
        >
          {(sessions?.skipped ?? 0) > 0 && (
            <Alert color="yellow">
              {t('managementPartial')} ({sessions?.skipped})
            </Alert>
          )}
          <AdminDataGrid<SessionItem>
            active={active && view === 'sessions' && selected === null}
            actionField="details"
            label={t('managementSessionsCaption')}
            rows={
              !route || loadedFlow.current === (route.flow ?? '') ? (sessions?.items ?? []) : []
            }
            onRefresh={() => {
              void refreshSessions();
            }}
            refreshLabel={m('refreshSessions')}
            detailsAvailable
            detailed={detailed}
            detailFields={['user', 'remote']}
            onOpen={openSession}
            openByID={
              <SessionTarget
                disabled={locked}
                value={target}
                onChange={setTarget}
                onOpen={(flow, id) => openSession({ flow, id })}
                onPrepare={(action, flow, id) => {
                  void prepare(action, { flow, id });
                }}
              />
            }
            openLabel={(item) => `${t('managementDetails')} ${item.id}`}
            getRowId={(item) => `${item.flow}/${item.id}`}
            columns={[
              { field: 'id', headerName: t('managementSessionId'), minWidth: 280 },
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
            rowActions={(item) => <>{sessionArtifactActions(item, true)}</>}
            busy={busy || !attempted.current.sessions}
            disabled={disabled || notice?.kind === 'unknown'}
            page={sessionPage - 1}
            hasNext={(sessions?.next ?? '') !== ''}
            query={sessionQuery}
            columnFilter={sessionFilter}
            onSearch={(query, filter) => {
              const flow = exactFlow(filter);
              if (navigation && route && flow !== route.flow) {
                setSessionQuery(query);
                setSessionFilter(filter);
                const { flow: _flow, id: _id, ...parent } = route;
                const next = { ...parent, ...(flow ? { flow } : {}) };
                nativeFilterIntent.current = { key: JSON.stringify(next), query, filter };
                navigation.navigate(next);
                return;
              }
              void loadSessions(
                false,
                {
                  state: 'all',
                  ...(route?.flow ? { flow: route.flow } : {}),
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
        {route?.id &&
          busy &&
          (!selected || !uuidEqual(selected.id, route.id) || selected.flow !== route.flow) && (
            <CircularProgress aria-label={m('detailsLoading')} />
          )}
        {selected !== null &&
          (!route || (uuidEqual(selected.id, route.id) && selected.flow === route.flow)) && (
            <SessionDetails
              item={selected}
              detailed={detailed}
              id={detailID}
              element={detailElement}
              actions={sessionArtifactActions(selected, false)}
              mutationDisabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
              onPrepare={(action, item) => {
                void prepare(action, item);
              }}
            />
          )}
      </section>
      <SessionActionDialog
        owner={access.snapshot()}
        active={active}
        preview={preview}
        typed={typed}
        busy={busy}
        sending={sending.current}
        disabled={disabled}
        onType={setTyped}
        onClose={closeConfirmation}
        onConfirm={() => {
          void confirmAction();
        }}
        onCancel={cancel}
      />
    </section>
  );
}

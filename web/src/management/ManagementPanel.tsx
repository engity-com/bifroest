import { useEffect, useEffectEvent, useId, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Modal, Paper, Select, Table, TextInput, Title } from '../ui/material';
import { t } from '../ui/messages';
import type { ActionPreview, SessionAction, SessionActionConfirmation } from './action';
import { m, sessionStateLabel } from './messages';
import type { FlowSummary, Page, SessionItem, SessionOptions, VersionInfo } from './protocol';

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
  view: 'sessions' | 'server';
}) {
  const [flows, setFlows] = useState<Page<FlowSummary> | null>(null);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [buildVersion, setBuildVersion] = useState<VersionInfo | null>(null);
  const [sessions, setSessions] = useState<Page<SessionItem> | null>(null);
  const [selected, setSelected] = useState<SessionItem | null>(null);
  const [flow, setFlow] = useState('');
  const [user, setUser] = useState('');
  const [state, setState] = useState('active');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<'denied' | 'unavailable' | null>(null);
  const [readCompletion, setReadCompletion] = useState(0);
  const [loading, setLoading] = useState<
    'sessions' | 'flows' | 'version' | 'build' | 'details' | null
  >(null);
  const [sessionPage, setSessionPage] = useState(1);
  const [flowPage, setFlowPage] = useState(1);
  const [versionFailed, setVersionFailed] = useState(false);
  const [flowsFailed, setFlowsFailed] = useState(false);
  const attempted = useRef({ sessions: false, version: false, flows: false });
  const detailElement = useRef<HTMLElement | null>(null);
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
    setFlowPage(1);
    setVersionFailed(false);
    setFlowsFailed(false);
    attempted.current = { sessions: false, version: false, flows: false };
    lastFilter.current = {};
    setFlow('');
    setUser('');
    setState('active');
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
      void loadSessions(false, { flow: '', user: '', state: 'active' });
    } else if (view === 'server' && !attempted.current.version) {
      attempted.current.version = true;
      void loadVersion();
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
      detailElement.current?.scrollIntoView({ block: 'nearest' });
    }
  });
  useEffect(() => {
    if (selected !== null) {
      focusDetails();
    }
  }, [selected]);
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
        if (resource === 'flows') {
          setFlowsFailed(true);
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
  async function loadFlows(after = '') {
    attempted.current.flows = true;
    await run(async (signal, current) => {
      const result = await access.managementFlows({ after }, signal);
      if (current === generation.current) {
        setFlows(result);
        setFlowsFailed(false);
        setFlowPage((page) => (after === '' ? 1 : page + 1));
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
      flow: lastFilter.current.flow ?? '',
      user: lastFilter.current.user ?? '',
      state: lastFilter.current.state ?? 'active',
    });
  }
  async function loadSessions(next = false, initial?: SessionOptions) {
    attempted.current.sessions = true;
    const filters: SessionOptions =
      initial ??
      (next
        ? { ...lastFilter.current, after: sessions?.next ?? '' }
        : { flow, user, state: state as NonNullable<SessionOptions['state']> });
    await run(async (signal, current) => {
      const result = await access.managementSessions(filters, signal);
      if (current === generation.current) {
        lastFilter.current = filters;
        setSessions(result);
        setSelected(null);
        setSessionPage((page) => (next ? page + 1 : 1));
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
  const isSelected = (item: SessionItem) => selected?.flow === item.flow && selected.id === item.id;
  return (
    <Paper withBorder p="lg" className="stack" aria-label={t('managementTitle')}>
      <div className="section-heading">
        <Title order={2}>
          {t(view === 'server' ? 'workspaceServer' : 'managementSessionsTitle')}
        </Title>
        <details className="context-help">
          <summary>{t('managementPolicyHelp')}</summary>
          <p>{t('managementReadOnly')}</p>
        </details>
      </div>
      <section hidden={view !== 'server'} className="stack">
        <div className="section-heading admin-toolbar">
          <Title order={3}>{t('managementVersionTitle')}</Title>
          <Button
            variant="default"
            disabled={locked}
            onClick={() => {
              void loadVersion();
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
        {version !== null && (
          <section aria-label={t('managementVersionTitle')}>
            <p className="server-version">{version.text}</p>
            <p className="caption subtle">{m('reported')}</p>
          </section>
        )}
        <details className="build-details">
          <summary>{m('build')}</summary>
          <div className="stack">
            <p>{m('buildHint')}</p>
            <Button disabled={locked} onClick={() => void loadVersion(true)}>
              {m('buildLoad')}
            </Button>
            {loading === 'build' && <p role="status">{m('buildLoading')}</p>}
            {buildVersion !== null && <pre>{buildVersion.text}</pre>}
          </div>
        </details>
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
        <div className="section-heading admin-toolbar">
          <Title order={3}>{t('managementFlowListTitle')}</Title>
          <Button
            variant="default"
            disabled={locked}
            onClick={() => {
              void loadFlows();
            }}
          >
            {m('flowsRefresh')}
          </Button>
        </div>
        {loading === 'flows' && <p role="status">{m('flowsLoading')}</p>}
        {flows === null && loading !== 'flows' && (
          <p className="empty-state">{m(flowsFailed ? 'flowsUnavailable' : 'flowsPending')}</p>
        )}
        {flows !== null && (
          <>
            <p className="caption subtle">
              {m('page')} {flowPage}. {m('snapshot')}
            </p>
            {flows.skipped > 0 && (
              <Alert color="yellow">
                {t('managementPartial')} ({flows.skipped})
              </Alert>
            )}
            <div className="table-scroll">
              <Table captionSide="top">
                <caption>{t('managementFlowsCaption')}</caption>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('managementFlow')}</Table.Th>
                    <Table.Th>{t('managementAuthorization')}</Table.Th>
                    <Table.Th>{t('managementEnvironment')}</Table.Th>
                    <Table.Th>{t('managementAuditlog')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {flows.items.map((item) => (
                    <Table.Tr key={item.name}>
                      <Table.Td>{item.name}</Table.Td>
                      <Table.Td>{item.authorization}</Table.Td>
                      <Table.Td>{item.environment}</Table.Td>
                      <Table.Td>{item.auditlog}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
            {flows.items.length === 0 && <p className="empty-state">{m('flowsEmpty')}</p>}
            {flows.next !== '' && (
              <div className="stack">
                <p className="caption subtle">{m('moreFlows')}</p>
                <Button
                  disabled={locked}
                  onClick={() => {
                    void loadFlows(flows.next);
                  }}
                >
                  {t('managementNextFlows')}
                </Button>
              </div>
            )}
          </>
        )}
      </div>
      {busy && (
        <Button variant="default" onClick={cancel}>
          {t(sending.current ? 'managementStopWaiting' : 'managementCancel')}
        </Button>
      )}
      <section hidden={view !== 'sessions'} className="stack">
        <form
          method="dialog"
          className="stack session-search"
          onSubmit={(event) => {
            event.preventDefault();
            void loadSessions();
          }}
        >
          <div className="admin-toolbar actions">
            <TextInput
              label={m('searchUser')}
              helperText={m('searchHint')}
              value={user}
              onChange={(event) => setUser(event.currentTarget.value)}
              disabled={locked}
              maxLength={256}
            />
            <Button type="submit" disabled={locked}>
              {m('search')}
            </Button>
            <Button
              type="button"
              variant="default"
              disabled={locked}
              onClick={() => void refreshSessions()}
            >
              {m('refreshSessions')}
            </Button>
          </div>
          <details className="session-filter-details">
            <summary>{m('filters')}</summary>
            <div className="session-filters">
              <TextInput
                label={t('managementFlowFilter')}
                value={flow}
                onChange={(event) => setFlow(event.currentTarget.value)}
                disabled={locked}
                maxLength={255}
              />
              <Select
                label={t('managementStateFilter')}
                value={state}
                onChange={(value) => setState(value ?? 'active')}
                data={['active', 'all', 'new', 'authorized', 'disposed'].map((value) => ({
                  value,
                  label: sessionStateLabel(value),
                }))}
                disabled={locked}
              />
            </div>
            <p className="caption subtle">{m('filterHint')}</p>
          </details>
        </form>
        {loading === 'sessions' && <p role="status">{m('sessionsLoading')}</p>}
        {loading === 'details' && <p role="status">{m('detailsLoading')}</p>}
        {sessions === null && loading !== 'sessions' && (
          <p className="empty-state">
            {m(attempted.current.sessions ? 'sessionsCleared' : 'sessionPending')}
          </p>
        )}
        {sessions !== null && (
          <>
            <p className="caption subtle">
              {m('appliedFilters')}: {lastFilter.current.user || m('anyUser')} ·{' '}
              {lastFilter.current.flow || m('anyFlow')} ·{' '}
              {sessionStateLabel(lastFilter.current.state ?? 'active')}. {m('page')} {sessionPage}.
            </p>
            <p className="caption subtle">{m('snapshot')}</p>
            {sessions.skipped > 0 && (
              <Alert color="yellow">
                {t('managementPartial')} ({sessions.skipped})
              </Alert>
            )}
            {sessions.items.some((item) => item.policyLimited) && (
              <Alert color="yellow">{t('managementLimited')}</Alert>
            )}
            <div className="table-scroll desktop-sessions">
              <Table captionSide="top" className="session-table">
                <caption>{t('managementSessionsCaption')}</caption>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{m('user')}</Table.Th>
                    <Table.Th>{t('managementFlow')}</Table.Th>
                    <Table.Th>{m('status')}</Table.Th>
                    <Table.Th>{m('started')}</Table.Th>
                    <Table.Th>{m('origin')}</Table.Th>
                    <Table.Th>{t('managementDetails')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {sessions.items.map((item) => (
                    <Table.Tr
                      key={`${item.flow}/${item.id}`}
                      className={isSelected(item) ? 'selected-row' : undefined}
                      aria-selected={isSelected(item)}
                    >
                      <Table.Td>{field(item, item.user)}</Table.Td>
                      <Table.Td>{item.flow}</Table.Td>
                      <Table.Td>{sessionStateLabel(item.state)}</Table.Td>
                      <Table.Td>{when(item.createdAt)}</Table.Td>
                      <Table.Td>{field(item, item.remote)}</Table.Td>
                      <Table.Td>
                        <Button
                          disabled={locked}
                          onClick={() => {
                            void show(item);
                          }}
                          aria-label={`${t('managementDetails')} ${item.id}`}
                          aria-controls={detailID}
                          aria-expanded={isSelected(item)}
                        >
                          {t('managementDetails')}
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
            <section className="stack mobile-sessions" aria-label={t('managementSessionsCaption')}>
              {sessions.items.map((item) => (
                <article
                  key={`${item.flow}/${item.id}`}
                  className={`session-card record-card stack${isSelected(item) ? ' selected-row' : ''}`}
                  aria-label={`${field(item, item.user)} · ${item.flow}`}
                >
                  <div className="section-heading">
                    <strong>{field(item, item.user)}</strong>
                    <span>{sessionStateLabel(item.state)}</span>
                  </div>
                  <dl className="metadata-grid">
                    <dt>{t('managementFlow')}</dt>
                    <dd>{item.flow}</dd>
                    <dt>{m('started')}</dt>
                    <dd>{when(item.createdAt)}</dd>
                    <dt>{m('origin')}</dt>
                    <dd>{field(item, item.remote)}</dd>
                  </dl>
                  <Button
                    variant="light"
                    disabled={locked}
                    onClick={() => {
                      void show(item);
                    }}
                    aria-label={`${t('managementDetails')} ${item.id}`}
                    aria-controls={detailID}
                    aria-expanded={isSelected(item)}
                  >
                    {t('managementDetails')}
                  </Button>
                </article>
              ))}
            </section>
            {sessions.items.length === 0 && <p className="empty-state">{m('noSessions')}</p>}
            {sessions.next !== '' && (
              <div className="stack">
                <p className="caption subtle">{m('moreSessions')}</p>
                <Button
                  disabled={locked}
                  onClick={() => {
                    void loadSessions(true);
                  }}
                >
                  {t('managementNextSessions')}
                </Button>
              </div>
            )}
          </>
        )}
        {selected !== null && (
          <section
            ref={detailElement}
            id={detailID}
            tabIndex={-1}
            aria-label={m('detailsTitle')}
            className="stack session-details record-card"
          >
            <div className="section-heading">
              <Title order={3}>
                {field(selected, selected.user)} · {selected.flow}
              </Title>
              <Button variant="subtle" onClick={() => setSelected(null)}>
                {t('close')}
              </Button>
            </div>
            {selected.policyLimited && <Alert color="yellow">{t('managementLimited')}</Alert>}
            <dl className="metadata-grid">
              <dt>{m('user')}</dt>
              <dd>{field(selected, selected.user)}</dd>
              <dt>{t('managementFlow')}</dt>
              <dd>{selected.flow}</dd>
              <dt>{m('status')}</dt>
              <dd>{sessionStateLabel(selected.state)}</dd>
              <dt>{m('started')}</dt>
              <dd>{when(selected.createdAt)}</dd>
              <dt>{m('origin')}</dt>
              <dd>{field(selected, selected.remote)}</dd>
              <dt>{t('managementSessionId')}</dt>
              <dd className="identifier">{selected.id}</dd>
              {selected.owner === null ? (
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
              )}
              {selected.lastAccessed !== undefined && (
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
            </dl>
            <div className="session-actions stack">
              <div className="record-card stack">
                <p>{m('disconnectHint')}</p>
                <Button
                  disabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
                  color="orange"
                  onClick={() => {
                    void prepare('disconnect', selected);
                  }}
                >
                  {m('disconnect')}
                </Button>
              </div>
              <div className="record-card stack">
                <p>{m('endHint')}</p>
                <Button
                  disabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
                  color="red"
                  onClick={() => {
                    void prepare('dispose', selected);
                  }}
                >
                  {m('end')}
                </Button>
              </div>
            </div>
          </section>
        )}
        <details className="advanced-action">
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
    </Paper>
  );
}

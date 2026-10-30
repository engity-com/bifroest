import { useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import {
  Alert,
  Button,
  Checkbox,
  Modal,
  Paper,
  Select,
  Table,
  TextInput,
  Title,
} from '../ui/material';
import { t } from '../ui/messages';
import type { ActionPreview, SessionAction, SessionActionConfirmation } from './action';
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
  const [longVersion, setLongVersion] = useState(true);
  const [sessions, setSessions] = useState<Page<SessionItem> | null>(null);
  const [selected, setSelected] = useState<SessionItem | null>(null);
  const [flow, setFlow] = useState('');
  const [user, setUser] = useState('');
  const [state, setState] = useState('active');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
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
    setLongVersion(true);
    setSessions(null);
    setSelected(null);
    setBusy(false);
    setError(false);
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
  function cancel() {
    if (sending.current && preview !== null) {
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
  }
  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (disabled || request.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
    setError(false);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (
        current === generation.current &&
        !(error instanceof RememberMeError && error.code === 'cancelled')
      ) {
        setError(true);
      }
    } finally {
      if (current === generation.current) {
        request.current = null;
        setBusy(false);
      }
    }
  }
  async function loadFlows(after = '') {
    await run(async (signal, current) => {
      const result = await access.managementFlows({ after }, signal);
      if (current === generation.current) {
        setFlows(result);
      }
    });
  }
  async function loadVersion() {
    await run(async (signal, current) => {
      const result = await access.managementVersion(longVersion, signal);
      if (current === generation.current) {
        setVersion(result);
      }
    });
  }
  async function loadSessions(next = false) {
    const filters: SessionOptions = next
      ? { ...lastFilter.current, after: sessions?.next ?? '' }
      : { flow, user, state: state as NonNullable<SessionOptions['state']> };
    await run(async (signal, current) => {
      const result = await access.managementSessions(filters, signal);
      if (current === generation.current) {
        lastFilter.current = filters;
        setSessions(result);
        setSelected(null);
      }
    });
  }
  async function show(item: SessionItem) {
    await run(async (signal, current) => {
      const result = await access.managementSession(item.flow, item.id, signal);
      if (current === generation.current) {
        setSelected(result);
      }
    });
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
    setError(false);
    onActionLock(true);
    try {
      await handle.confirm(controller.signal);
      if (current === generation.current) {
        setNotice({ kind: 'confirmed', preview: pinned });
        onActionLock(false);
      }
    } catch {
      if (current === generation.current) {
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
        <Title order={3}>{t('managementVersionTitle')}</Title>
        <Checkbox
          label={t('managementVersionLong')}
          checked={longVersion}
          disabled={locked}
          onChange={(event) => setLongVersion(event.currentTarget.checked)}
        />
        <Button
          disabled={locked}
          onClick={() => {
            void loadVersion();
          }}
        >
          {t('managementVersionLoad')}
        </Button>
        {version !== null && (
          <section aria-label={t('managementVersionTitle')}>
            <p>{t('managementVersionReported')}</p>
            <pre>{version.text}</pre>
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
            {notice.preview.action}: {notice.preview.target.flow}/{notice.preview.target.id}
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
          {t('managementFailed')}
        </Alert>
      )}
      <div hidden={view !== 'server'} className="stack">
        <Title order={3}>{t('managementFlowListTitle')}</Title>
        <div className="actions">
          <Button
            disabled={locked}
            onClick={() => {
              void loadFlows();
            }}
          >
            {t('managementFlows')}
          </Button>
        </div>
        {flows !== null && (
          <>
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
            {flows.next !== '' && (
              <Button
                disabled={locked}
                onClick={() => {
                  void loadFlows(flows.next);
                }}
              >
                {t('managementNextFlows')}
              </Button>
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
          className="session-filters"
          onSubmit={(event) => {
            event.preventDefault();
            void loadSessions();
          }}
        >
          <TextInput
            label={t('managementFlowFilter')}
            value={flow}
            onChange={(event) => setFlow(event.currentTarget.value)}
            disabled={locked}
            maxLength={255}
          />
          <TextInput
            label={t('managementUserFilter')}
            value={user}
            onChange={(event) => setUser(event.currentTarget.value)}
            disabled={locked}
            maxLength={256}
          />
          <Select
            label={t('managementStateFilter')}
            value={state}
            onChange={(value) => setState(value ?? 'active')}
            data={['active', 'all', 'new', 'authorized', 'disposed']}
            disabled={locked}
          />
          <Button type="submit" disabled={locked}>
            {t('managementLoadSessions')}
          </Button>
        </form>
        {sessions === null && <p className="empty-state">{t('managementSessionsEmpty')}</p>}
        {sessions !== null && (
          <>
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
                    <Table.Th>{t('managementSessionId')}</Table.Th>
                    <Table.Th>{t('managementFlow')}</Table.Th>
                    <Table.Th>{t('managementStateFilter')}</Table.Th>
                    <Table.Th>{t('managementUserFilter')}</Table.Th>
                    <Table.Th>{t('managementOwner')}</Table.Th>
                    <Table.Th>{t('managementCreated')}</Table.Th>
                    <Table.Th>{t('managementDetails')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {sessions.items.map((item) => (
                    <Table.Tr key={`${item.flow}/${item.id}`}>
                      <Table.Td>
                        <span className="identifier">{item.id}</span>
                      </Table.Td>
                      <Table.Td>{item.flow}</Table.Td>
                      <Table.Td>{item.state}</Table.Td>
                      <Table.Td>{item.user || '—'}</Table.Td>
                      <Table.Td>{ownerLabel(item)}</Table.Td>
                      <Table.Td>{when(item.createdAt)}</Table.Td>
                      <Table.Td>
                        <Button
                          disabled={locked}
                          onClick={() => {
                            void show(item);
                          }}
                          aria-label={`${t('managementDetails')} ${item.id}`}
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
                <article key={`${item.flow}/${item.id}`} className="session-card stack">
                  <div className="section-heading">
                    <strong>{item.flow}</strong>
                    <span>{item.state}</span>
                  </div>
                  <span className="identifier">{item.id}</span>
                  <dl className="metadata-grid">
                    <dt>{t('managementUserFilter')}</dt>
                    <dd>{item.user || '—'}</dd>
                    <dt>{t('managementOwner')}</dt>
                    <dd>{ownerLabel(item)}</dd>
                    <dt>{t('managementCreated')}</dt>
                    <dd>{when(item.createdAt)}</dd>
                  </dl>
                  <Button
                    variant="light"
                    disabled={locked}
                    onClick={() => {
                      void show(item);
                    }}
                    aria-label={`${t('managementDetails')} ${item.id}`}
                  >
                    {t('managementDetails')}
                  </Button>
                </article>
              ))}
            </section>
            {sessions.items.length === 0 && (
              <p className="empty-state">{t('managementNoSessions')}</p>
            )}
            {sessions.next !== '' && (
              <Button
                disabled={locked}
                onClick={() => {
                  void loadSessions(true);
                }}
              >
                {t('managementNextSessions')}
              </Button>
            )}
          </>
        )}
        {selected !== null && (
          <section aria-label={t('managementDetails')} className="stack session-details">
            <div className="section-heading">
              <Title order={3}>{t('managementDetails')}</Title>
              <Button variant="subtle" onClick={() => setSelected(null)}>
                {t('close')}
              </Button>
            </div>
            <span className="identifier">
              {selected.flow}/{selected.id}
            </span>
            {selected.policyLimited && <Alert color="yellow">{t('managementLimited')}</Alert>}
            <dl className="metadata-grid">
              <dt>{t('managementRemote')}</dt>
              <dd>{selected.remote}</dd>
              <dt>{t('managementOwner')}</dt>
              <dd>{ownerLabel(selected)}</dd>
              <dt>{t('managementValidUntil')}</dt>
              <dd>
                {selected.validUntil === undefined
                  ? t(selected.policyLimited ? 'managementWithheldOwner' : 'managementNoLimit')
                  : when(selected.validUntil)}
              </dd>
            </dl>
            <div className="actions">
              <Button
                disabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
                color="orange"
                onClick={() => {
                  void prepare('disconnect', selected);
                }}
              >
                {t('managementDisconnect')}
              </Button>
              <Button
                disabled={locked || selected.policyLimited || notice?.kind === 'unknown'}
                color="red"
                onClick={() => {
                  void prepare('dispose', selected);
                }}
              >
                {t('managementDispose')}
              </Button>
            </div>
          </section>
        )}
        <details className="advanced-action">
          <summary>{t('managementDirectAction')}</summary>
          <section aria-label={t('managementDirectAction')} className="stack">
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
                data={['disconnect', 'dispose']}
                disabled={locked}
              />
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
                disabled={busy || typed !== `${preview.target.flow}/${preview.target.id}`}
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

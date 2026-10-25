import { Alert, Button, Modal, Paper, Select, Table, TextInput, Title } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { t } from '../ui/messages';
import type { ActionPreview, SessionAction, SessionActionConfirmation } from './action';
import type { FlowSummary, Page, SessionItem, SessionOptions } from './protocol';

export function ManagementPanel({
  access,
  disabled,
  onActionLock,
}: {
  access: WebAccess;
  disabled: boolean;
  onActionLock: (locked: boolean) => void;
}) {
  const [flows, setFlows] = useState<Page<FlowSummary> | null>(null);
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
    setSessions(null);
    setSelected(null);
    setBusy(false);
    setError(false);
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
  async function prepare(action: SessionAction, item: SessionItem) {
    if (notice?.kind === 'unknown') {
      return;
    }
    await run(async (signal, current) => {
      const handle = await access.prepareSessionAction(action, item.flow, item.id, signal);
      if (current !== generation.current) {
        await handle.cancel();
        return;
      }
      confirmation.current = handle;
      setPreview(handle.snapshot());
      setTyped('');
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
      <Title order={2}>{t('managementTitle')}</Title>
      <Alert color="blue">{t('managementReadOnly')}</Alert>
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
      <div className="actions">
        <Button
          disabled={locked}
          onClick={() => {
            void loadFlows();
          }}
        >
          {t('managementFlows')}
        </Button>
        {busy && (
          <Button variant="default" onClick={cancel}>
            {t(sending.current ? 'managementStopWaiting' : 'managementCancel')}
          </Button>
        )}
      </div>
      {flows !== null && (
        <>
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
      <Title order={3}>{t('managementSessionsTitle')}</Title>
      <form
        method="dialog"
        className="stack"
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
          <Table captionSide="top">
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
                  <Table.Td>{item.id}</Table.Td>
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
        <section aria-label={t('managementDetails')} className="stack">
          <Title order={3}>{selected.id}</Title>
          {selected.policyLimited && <Alert color="yellow">{t('managementLimited')}</Alert>}
          <dl>
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
      <Modal
        lockScroll={false}
        opened={preview !== null}
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
            <p>
              {preview.target.owner === null
                ? t('managementUnknownOwner')
                : `${preview.target.owner.issuer} / ${preview.target.owner.subject}`}
            </p>
            <p>
              {t('managementCreated')}: {when(preview.target.createdAt)}
            </p>
            <p>
              {t('expires')}: {when(preview.expiresAt)}
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

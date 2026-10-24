import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Paper, Select, Table, TextInput, Title } from '@mantine/core';
import { RememberMeError } from '../remember';
import type { WebAccess } from '../remember';
import type { FlowSummary, Page, SessionItem, SessionOptions } from './protocol';
import { t } from '../ui/messages';

export function ManagementPanel({ access, disabled }: { access: WebAccess; disabled: boolean }) {
  const [flows, setFlows] = useState<Page<FlowSummary> | null>(null);
  const [sessions, setSessions] = useState<Page<SessionItem> | null>(null);
  const [selected, setSelected] = useState<SessionItem | null>(null);
  const [flow, setFlow] = useState(''), [user, setUser] = useState(''), [state, setState] = useState('active');
  const [busy, setBusy] = useState(false), [error, setError] = useState(false);
  const request = useRef<AbortController | null>(null), generation = useRef(0);
  const lastFilter = useRef<SessionOptions>({});
  useEffect(() => {
    generation.current++; request.current?.abort(); request.current = null;
    setFlows(null); setSessions(null); setSelected(null); setBusy(false); setError(false);
    return () => { generation.current++; request.current?.abort(); request.current = null; };
  }, [access]);
  function cancel() { generation.current++; request.current?.abort(); request.current = null; setBusy(false); }
  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (disabled || request.current !== null) return;
    const controller = new AbortController(), current = ++generation.current;
    request.current = controller; setBusy(true); setError(false);
    try { await action(controller.signal, current); }
    catch (error) { if (current === generation.current && !(error instanceof RememberMeError && error.code === 'cancelled')) setError(true); }
    finally { if (current === generation.current) { request.current = null; setBusy(false); } }
  }
  async function loadFlows(after = '') {
    await run(async (signal, current) => { const result = await access.managementFlows({ after }, signal); if (current === generation.current) setFlows(result); });
  }
  async function loadSessions(next = false) {
    const filters: SessionOptions = next ? { ...lastFilter.current, after: sessions?.next ?? '' } : { flow, user, state: state as NonNullable<SessionOptions['state']> };
    await run(async (signal, current) => { const result = await access.managementSessions(filters, signal); if (current === generation.current) { lastFilter.current = filters; setSessions(result); setSelected(null); } });
  }
  async function show(item: SessionItem) {
    await run(async (signal, current) => { const result = await access.managementSession(item.flow, item.id, signal); if (current === generation.current) setSelected(result); });
  }
  const locked = disabled || busy;
  const when = (value: string) => new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
  return <Paper withBorder p="lg" className="stack" aria-label={t('managementTitle')}>
    <Title order={2}>{t('managementTitle')}</Title>
    <Alert color="blue">{t('managementReadOnly')}</Alert>
    {error && <Alert role="status" color="red">{t('managementFailed')}</Alert>}
    <div className="actions"><Button disabled={locked} onClick={() => { void loadFlows(); }}>{t('managementFlows')}</Button>{busy && <Button variant="default" onClick={cancel}>{t('managementCancel')}</Button>}</div>
    {flows !== null && <><Table captionSide="top"><caption>{t('managementFlowsCaption')}</caption><Table.Thead><Table.Tr><Table.Th>{t('managementFlow')}</Table.Th><Table.Th>{t('managementAuthorization')}</Table.Th><Table.Th>{t('managementEnvironment')}</Table.Th><Table.Th>{t('managementAuditlog')}</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{flows.items.map(item => <Table.Tr key={item.name}><Table.Td>{item.name}</Table.Td><Table.Td>{item.authorization}</Table.Td><Table.Td>{item.environment}</Table.Td><Table.Td>{item.auditlog}</Table.Td></Table.Tr>)}</Table.Tbody></Table>{flows.next !== '' && <Button disabled={locked} onClick={() => { void loadFlows(flows.next); }}>{t('managementNextFlows')}</Button>}</>}
    <Title order={3}>{t('managementSessionsTitle')}</Title>
    <form method="dialog" className="stack" onSubmit={event => { event.preventDefault(); void loadSessions(); }}>
      <TextInput label={t('managementFlowFilter')} value={flow} onChange={event => setFlow(event.currentTarget.value)} disabled={locked} maxLength={255} />
      <TextInput label={t('managementUserFilter')} value={user} onChange={event => setUser(event.currentTarget.value)} disabled={locked} maxLength={256} />
      <Select label={t('managementStateFilter')} value={state} onChange={value => setState(value ?? 'active')} data={['active', 'all', 'new', 'authorized', 'disposed']} disabled={locked} />
      <Button type="submit" disabled={locked}>{t('managementLoadSessions')}</Button>
    </form>
    {sessions !== null && <>{sessions.skipped > 0 && <Alert color="yellow">{t('managementPartial')} ({sessions.skipped})</Alert>}<Table captionSide="top"><caption>{t('managementSessionsCaption')}</caption><Table.Thead><Table.Tr><Table.Th>{t('managementSessionId')}</Table.Th><Table.Th>{t('managementFlow')}</Table.Th><Table.Th>{t('managementStateFilter')}</Table.Th><Table.Th>{t('managementUserFilter')}</Table.Th><Table.Th>{t('managementOwner')}</Table.Th><Table.Th>{t('managementCreated')}</Table.Th><Table.Th>{t('managementDetails')}</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{sessions.items.map(item => <Table.Tr key={`${item.flow}/${item.id}`}><Table.Td>{item.id}</Table.Td><Table.Td>{item.flow}</Table.Td><Table.Td>{item.state}</Table.Td><Table.Td>{item.user || '—'}</Table.Td><Table.Td>{item.owner === null ? t('managementUnknownOwner') : `${item.owner.issuer} / ${item.owner.subject}`}</Table.Td><Table.Td>{when(item.createdAt)}</Table.Td><Table.Td><Button disabled={locked} onClick={() => { void show(item); }} aria-label={`${t('managementDetails')} ${item.id}`}>{t('managementDetails')}</Button></Table.Td></Table.Tr>)}</Table.Tbody></Table>{sessions.next !== '' && <Button disabled={locked} onClick={() => { void loadSessions(true); }}>{t('managementNextSessions')}</Button>}</>}
    {selected !== null && <section aria-label={t('managementDetails')}><Title order={3}>{selected.id}</Title><dl><dt>{t('managementRemote')}</dt><dd>{selected.remote}</dd><dt>{t('managementOwner')}</dt><dd>{selected.owner === null ? t('managementUnknownOwner') : `${selected.owner.issuer} / ${selected.owner.subject}`}</dd><dt>{t('managementValidUntil')}</dt><dd>{selected.validUntil === undefined ? t('managementNoLimit') : when(selected.validUntil)}</dd></dl></section>}
  </Paper>;
}

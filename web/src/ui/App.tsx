import { useEffect, useRef, useState } from 'react';
import { Alert, Anchor, Button, Checkbox, Modal, Paper, PasswordInput, SegmentedControl, TextInput, Title } from '@mantine/core';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import type { AccessSnapshot, LogoutResult, Scope, WebAccess } from '../remember';
import { t } from './messages';
import type { Message } from './messages';
import { TerminalPanel } from '../terminal/TerminalPanel';

export interface LinkMetadata { readonly scope: Scope; readonly requestUser: boolean; readonly publishedSlugs: readonly string[]; }
type Saved = 'loading' | 'missing' | 'ready' | 'pending' | 'unavailable';
type Notice = { key: Message; color: 'red' | 'yellow' | 'green' };

function errorNotice(error: unknown): Notice {
  const code = error instanceof RememberMeError ? error.code : 'unavailable';
  const key: Message = code === 'outcome-unknown' ? 'unknown' : code === 'already-remembered' ? 'already' : code === 'denied' ? 'denied' : code === 'rate-limited' ? 'limited' : code === 'cancelled' ? 'cancelled' : 'unavailable';
  return { key, color: code === 'denied' || code === 'unavailable' ? 'red' : 'yellow' };
}

export function App({ metadata, title = t('brand'), scheme, onScheme }: {
  metadata: LinkMetadata; title?: string; scheme: string; onScheme: (value: string) => void;
}) {
  const client = useRef(new BrowserClient(metadata.scope));
  const access = useRef<WebAccess | null>(null);
  const savedHandle = useRef<BrowserBinding | null>(null);
  const confirmationHandle = useRef<BrowserBinding | null>(null);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const [snapshot, setSnapshot] = useState<AccessSnapshot | null>(null);
  const [saved, setSaved] = useState<Saved>('loading');
  const [busy, setBusy] = useState(false);
  const [closing, setClosing] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirm, setConfirm] = useState<'revoke' | 'local' | null>(null);
  const [optIn, setOptIn] = useState(false);
  const [passwordKey, setPasswordKey] = useState(0);
  const [reauthenticate, setReauthenticate] = useState(false);
  const [rememberUncertain, setRememberUncertain] = useState(false);

  async function readSaved(current = generation.current) {
    try {
      const handle = await BrowserBinding.load(metadata.scope);
      if (current !== generation.current) return;
      savedHandle.current = handle;
      setSaved(handle === null ? 'missing' : handle.binding === null ? 'pending' : 'ready');
    } catch { if (current === generation.current) { savedHandle.current = null; setSaved('unavailable'); } }
  }
  useEffect(() => {
    void readSaved();
    return () => { generation.current++; operation.current?.abort(); };
  }, []);

  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (operation.current !== null) return;
    const controller = new AbortController(), current = ++generation.current;
    operation.current = controller;
    setBusy(true); setNotice(null);
    try { await action(controller.signal, current); }
    catch (error) { if (current === generation.current) setNotice(errorNotice(error)); }
    finally {
      if (current === generation.current) { operation.current = null; setBusy(false); await readSaved(current); }
    }
  }

  function cancel() {
    generation.current++;
    operation.current?.abort(); operation.current = null;
    setBusy(false); setNotice({ key: 'cancelled', color: 'yellow' });
    void readSaved();
  }

  async function login(form: HTMLFormElement) {
    const password = form.elements.namedItem('password') as HTMLInputElement;
    const user = (form.elements.namedItem('user') as HTMLInputElement | null)?.value ?? '';
    const secret = password.value;
    password.value = ''; // Never put the password in React state or persistent storage.
    setPasswordKey(value => value + 1); // Reset Mantine's internal uncontrolled input state too.
    const remember = optIn;
    await run(async (signal, current) => {
      const result = await client.current.password(user, secret, signal);
      if (current !== generation.current) return;
      access.current = result; setSnapshot(result.snapshot()); setClosing(false); setReauthenticate(false); setRememberUncertain(false);
      if (remember) {
        try {
          await result.remember({ explicitOptIn: true }, signal);
          if (current === generation.current) setNotice({ key: 'registered', color: 'green' });
        } catch (error) { if (current === generation.current) { setNotice(errorNotice(error)); setRememberUncertain(error instanceof RememberMeError && error.code === 'outcome-unknown'); } }
      }
    });
  }

  async function resume() {
    await run(async (signal, current) => {
      const result = await client.current.resume(signal);
      if (current !== generation.current) return;
      if (result === null) { setNotice({ key: 'denied', color: 'yellow' }); return; }
      access.current = result; setSnapshot(result.snapshot()); setClosing(false); setReauthenticate(false); setRememberUncertain(false);
    });
  }

  function cleanupNotice(result: LogoutResult, success: 'loggedOut' | 'remoteRevoked'): Notice {
    return result.localState === 'changed' ? { key: 'newerKept', color: 'yellow' } : result.localState === 'unavailable' ? { key: 'localCleanupFailed', color: 'yellow' } : { key: success, color: 'green' };
  }

  async function logout() {
    const selected = access.current;
    if (selected === null) return;
    const current = ++generation.current;
    operation.current?.abort(); operation.current = null;
    setClosing(true); setBusy(true); setNotice({ key: 'logoutPending', color: 'yellow' });
    try {
      const result = await selected.logout();
      if (current !== generation.current) return;
      access.current = null; setSnapshot(null); setClosing(false); setOptIn(false); setReauthenticate(false); setRememberUncertain(false);
      setNotice(cleanupNotice(result, 'loggedOut'));
    } catch { if (current === generation.current) setNotice({ key: 'logoutUnknown', color: 'red' }); }
    finally { if (current === generation.current) { setBusy(false); await readSaved(current); } }
  }

  async function forget() {
    const selected = confirm, handle = confirmationHandle.current;
    setConfirm(null);
    await run(async (signal, current) => {
      if (selected === 'revoke') {
        if (handle === null) throw new RememberMeError('changed');
        const result = await client.current.revokeSelection(handle, signal);
        if (current === generation.current) setNotice(cleanupNotice(result, 'remoteRevoked'));
      } else if (selected === 'local' && handle !== null) {
        await handle.forgetLocal();
        if (current === generation.current) setNotice({ key: 'localRemoved', color: 'yellow' });
      }
    });
  }

  function showConfirmation(value: 'revoke' | 'local') {
    confirmationHandle.current = savedHandle.current;
    setConfirm(value);
  }

  return <main className="workspace">
    <header className="header"><Title order={1}>{title}</Title><SegmentedControl aria-label={t('theme')} value={scheme} onChange={onScheme} data={[{ value: 'auto', label: t('auto') }, { value: 'light', label: t('light') }, { value: 'dark', label: t('dark') }]} /></header>
    <div className="stack">
      <Alert color="blue">{t('partial')}</Alert>
      {notice !== null && <Alert role="status" color={notice.color}>{t(notice.key)}</Alert>}
      {snapshot !== null ? <Paper withBorder p="lg" className="stack">
        <Title order={2}>{t(closing ? 'accessBlocked' : 'authenticated')} {snapshot.principal}</Title>
        <p>{t(snapshot.environment === 'management' ? 'management' : 'terminal')}</p>
        <p className="caption">{t('expires')}: <time dateTime={snapshot.expiresAt}>{new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(snapshot.expiresAt))}</time></p>
        <Button variant="default" disabled={closing || busy || rememberUncertain} onClick={() => { setReauthenticate(true); setOptIn(false); void readSaved(); }}>{t('reauthenticate')}</Button>
        <Button onClick={() => { void logout(); }} disabled={closing && busy} color="red">{t(closing ? 'retryLogout' : 'logout')}</Button>
      </Paper> : null}
      {snapshot !== null && snapshot.terminalAvailable && access.current !== null && <TerminalPanel access={access.current} disabled={closing || busy} />}
      {(snapshot === null || reauthenticate) && <>
        {saved === 'ready' && <Paper withBorder p="lg" className="stack"><p>{t('saved')}</p><div className="actions"><Button disabled={busy} onClick={() => { void resume(); }}>{t('useSaved')}</Button>{snapshot === null && <><Button variant="default" disabled={busy} onClick={() => showConfirmation('revoke')}>{t('forgetSaved')}</Button><Button variant="subtle" disabled={busy} onClick={() => showConfirmation('local')}>{t('removeLocalOnly')}</Button></>}</div></Paper>}
        {saved === 'pending' && <Alert color="yellow"><p>{t('pending')}</p>{snapshot === null && <Button variant="outline" disabled={busy} onClick={() => showConfirmation('local')}>{t('removeLocal')}</Button>}</Alert>}
        {saved === 'unavailable' && <Alert color="yellow">{t('storageUnavailable')}</Alert>}
        <Paper withBorder p="lg"><form method="post" action="/_bifroest/api/v1/login/password" className="stack" onSubmit={event => { event.preventDefault(); void login(event.currentTarget); }}>
          <Title order={2}>{t('login')}</Title>
          {metadata.requestUser && <TextInput name="user" label={t('user')} autoComplete="username" disabled={busy} />}
          <PasswordInput key={passwordKey} name="password" label={t('password')} autoComplete="current-password" visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }} disabled={busy} />
          <Checkbox checked={optIn} onChange={event => setOptIn(event.currentTarget.checked)} disabled={busy || saved !== 'missing'} label={t('remember')} description={t('rememberHint')} />
          <div className="actions"><Button type="submit" disabled={busy}>{t('login')}</Button>{busy && <Button type="button" variant="default" onClick={cancel}>{t('cancel')}</Button>}</div>
        </form></Paper>
      </>}
      {metadata.publishedSlugs.length > 0 && <nav aria-label={t('discovery')}><Title order={2}>{t('discovery')}</Title><ul>{metadata.publishedSlugs.map(slug => <li key={slug}><Anchor href={`/${slug}`}>{slug}</Anchor></li>)}</ul></nav>}
      <footer className="caption"><Anchor href="/_bifroest/files/third-party-licenses.txt">{t('notices')}</Anchor></footer>
    </div>
    <Modal lockScroll={false} opened={confirm !== null} onClose={() => setConfirm(null)} title={t(confirm === 'local' ? 'removeTitle' : 'forgetTitle')} closeButtonProps={{ 'aria-label': t('close') }}>
      <p>{t(confirm === 'local' ? 'removeWarning' : 'forgetWarning')}</p><div className="actions"><Button color="red" onClick={() => { void forget(); }}>{t(confirm === 'local' ? 'removeLocalOnly' : 'revoke')}</Button><Button variant="default" onClick={() => setConfirm(null)}>{t('cancel')}</Button></div>
    </Modal>
  </main>;
}

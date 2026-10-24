import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { Alert, Anchor, Button, Checkbox, Modal, Paper, PasswordInput, SegmentedControl, TextInput, Title } from '@mantine/core';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import type { AccessSnapshot, LogoutResult, Scope, WebAccess } from '../remember';
import type { LoginStep } from '../remember';
import { verificationLink } from '../login/links';
import { t } from './messages';
import type { Message } from './messages';
import { TerminalPanel } from '../terminal/TerminalPanel';

const ManagementPanel = lazy(async () => ({ default: (await import('../management/ManagementPanel')).ManagementPanel }));

export interface LinkMetadata { readonly scope: Scope; readonly requestUser: boolean; readonly publishedSlugs: readonly string[]; }
type Saved = 'loading' | 'missing' | 'ready' | 'pending' | 'unavailable';
type Notice = { key: Message; color: 'red' | 'yellow' | 'green' };

function errorNotice(error: unknown): Notice {
  const code = error instanceof RememberMeError ? error.code : 'unavailable';
  const key: Message = code === 'key-import' ? 'keyImportFailed' : code === 'login-unknown' ? 'loginUnknown' : code === 'invalid-step' ? 'loginInvalidStep' : code === 'busy' ? 'loginBusy' : code === 'outcome-unknown' ? 'unknown' : code === 'already-remembered' ? 'already' : code === 'denied' ? 'denied' : code === 'rate-limited' ? 'limited' : code === 'cancelled' ? 'cancelled' : 'unavailable';
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
  const [managementLocked, setManagementLocked] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirm, setConfirm] = useState<'revoke' | 'local' | null>(null);
  const [optIn, setOptIn] = useState(false);
  const [passwordKey, setPasswordKey] = useState(0);
  const [reauthenticate, setReauthenticate] = useState(false);
  const [rememberUncertain, setRememberUncertain] = useState(false);
  const [loginMethod, setLoginMethod] = useState('password');
  const [loginStep, setLoginStep] = useState<LoginStep | null>(null);
  const pendingResponse = useRef<((value: string) => void) | null>(null);
  const providerLink = loginStep?.kind === 'info' ? verificationLink(loginStep.message) : null;

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
    if (operation.current !== null || managementLocked) return;
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
    setLoginStep(null);
    void readSaved();
  }

  function requestStep(step: LoginStep, signal: AbortSignal): Promise<string> {
    const current = generation.current;
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        signal.removeEventListener('abort', aborted); pendingResponse.current = null;
        if (current === generation.current) setLoginStep(null);
      };
      const aborted = () => { cleanup(); reject(new RememberMeError('cancelled')); };
      if (signal.aborted) { aborted(); return; }
      signal.addEventListener('abort', aborted, { once: true });
      pendingResponse.current = value => { cleanup(); resolve(value); };
      setLoginStep(step);
    });
  }

  function answerStep(form: HTMLFormElement) {
    const field = form.elements.namedItem('answer') as HTMLInputElement | null;
    const value = field?.value ?? '';
    if (field !== null) field.value = '';
    pendingResponse.current?.(value);
  }

  async function login(form: HTMLFormElement) {
    const password = form.elements.namedItem('password') as HTMLInputElement | null;
    const user = (form.elements.namedItem('user') as HTMLInputElement | null)?.value ?? '';
    const secret = password?.value ?? '';
    if (password !== null) password.value = ''; // No answer/password in app state or persistent storage.
    const privateInput = form.querySelector<HTMLInputElement>('#key-private');
    const certificateInput = form.querySelector<HTMLInputElement>('#key-certificate');
    const passphraseInput = form.querySelector<HTMLInputElement>('#key-passphrase');
    let privateFile = privateInput?.files?.[0] ?? null;
    let certificateFile = certificateInput?.files?.[0] ?? null;
    let passphrase = passphraseInput?.value ?? '';
    if (privateInput !== null) privateInput.value = '';
    if (certificateInput !== null) certificateInput.value = '';
    if (passphraseInput !== null) passphraseInput.value = '';
    setPasswordKey(value => value + 1); // Reset Mantine's internal uncontrolled input state too.
    const remember = optIn;
    await run(async (signal, current) => {
      let result: WebAccess;
      if (loginMethod === 'key') {
        if (privateFile === null) throw new RememberMeError('key-import');
        const { WasmLoginKey } = await import('../login/wasm-key');
        let key: import('../login/wasm-key').WasmLoginKey;
        try { key = await WasmLoginKey.import(privateFile, passphrase, certificateFile, metadata.scope, user, signal); }
        finally { privateFile = null; certificateFile = null; passphrase = ''; }
        try { result = await client.current.publicKey(user, key, signal); }
        finally { key.close(); }
      } else result = loginMethod === 'interactive' ? await client.current.interactive(user, requestStep, signal) : await client.current.password(user, secret, signal);
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
    if (managementLocked) return;
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
        <Button variant="default" disabled={closing || busy || rememberUncertain || managementLocked} onClick={() => { setReauthenticate(true); setOptIn(false); void readSaved(); }}>{t('reauthenticate')}</Button>
        <Button onClick={() => { void logout(); }} disabled={closing && busy || managementLocked} color="red">{t(closing ? 'retryLogout' : 'logout')}</Button>
      </Paper> : null}
      {snapshot !== null && snapshot.terminalAvailable && access.current !== null && <TerminalPanel access={access.current} disabled={closing || busy} />}
      {snapshot !== null && snapshot.environment === 'management' && access.current !== null && <Suspense fallback={<Alert>{t('managementLoading')}</Alert>}><ManagementPanel key={generation.current} access={access.current} disabled={closing || busy} onActionLock={setManagementLocked} /></Suspense>}
      {(snapshot === null || reauthenticate) && <>
        {saved === 'ready' && <Paper withBorder p="lg" className="stack"><p>{t('saved')}</p><div className="actions"><Button disabled={busy} onClick={() => { void resume(); }}>{t('useSaved')}</Button>{snapshot === null && <><Button variant="default" disabled={busy} onClick={() => showConfirmation('revoke')}>{t('forgetSaved')}</Button><Button variant="subtle" disabled={busy} onClick={() => showConfirmation('local')}>{t('removeLocalOnly')}</Button></>}</div></Paper>}
        {saved === 'pending' && <Alert color="yellow"><p>{t('pending')}</p>{snapshot === null && <Button variant="outline" disabled={busy} onClick={() => showConfirmation('local')}>{t('removeLocal')}</Button>}</Alert>}
        {saved === 'unavailable' && <Alert color="yellow">{t('storageUnavailable')}</Alert>}
        <Paper withBorder p="lg"><form method={loginMethod === 'key' ? 'dialog' : 'post'} action={loginMethod === 'key' ? undefined : '/_bifroest/api/v1/login/password'} className="stack" onSubmit={event => { event.preventDefault(); void login(event.currentTarget); }}>
          <Title order={2}>{t('login')}</Title>
          <SegmentedControl aria-label={t('loginMethod')} value={loginMethod} onChange={setLoginMethod} disabled={busy} data={[{ value: 'password', label: t('passwordMethod') }, { value: 'interactive', label: t('interactiveMethod') }, { value: 'key', label: t('keyMethod') }]} />
          {metadata.requestUser && <TextInput name="user" label={t('user')} autoComplete="username" disabled={busy} />}
          {loginMethod === 'password' && <PasswordInput key={passwordKey} name="password" label={t('password')} autoComplete="current-password" visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }} disabled={busy} />}
          {loginMethod === 'key' && <>
            <Alert color="blue">{t('keyLocalOnly')}</Alert>
            <label className="stack" htmlFor="key-private">{t('keyPrivateFile')}<input key={`private:${passwordKey}`} id="key-private" type="file" required disabled={busy} /></label>
            <PasswordInput key={`passphrase:${passwordKey}`} id="key-passphrase" label={t('keyPassphrase')} autoComplete="off" visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }} disabled={busy} />
            <label className="stack" htmlFor="key-certificate">{t('keyCertificateFile')}<input key={`certificate:${passwordKey}`} id="key-certificate" type="file" disabled={busy} /></label>
          </>}
          <Checkbox checked={optIn} onChange={event => setOptIn(event.currentTarget.checked)} disabled={busy || saved !== 'missing'} label={t('remember')} description={t('rememberHint')} />
          <div className="actions"><Button type="submit" disabled={busy || managementLocked}>{t('login')}</Button>{busy && <Button type="button" variant="default" onClick={cancel}>{t('cancel')}</Button>}</div>
        </form></Paper>
      </>}
      {metadata.publishedSlugs.length > 0 && <nav aria-label={t('discovery')}><Title order={2}>{t('discovery')}</Title><ul>{metadata.publishedSlugs.map(slug => <li key={slug}><Anchor href={`/${slug}`}>{slug}</Anchor></li>)}</ul></nav>}
      <footer className="caption"><Anchor href="/_bifroest/files/third-party-licenses.txt">{t('notices')}</Anchor></footer>
    </div>
    <Modal lockScroll={false} opened={loginStep !== null} onClose={cancel} closeOnClickOutside={false} title={t('loginChallenge')} closeButtonProps={{ 'aria-label': t('cancel') }}>
      {loginStep !== null && <form method="post" action="/_bifroest/api/v1/login/reply" className="stack" onSubmit={event => { event.preventDefault(); answerStep(event.currentTarget); }}>
        <Alert color={loginStep.kind === 'error' ? 'red' : 'blue'}><p className="login-message">{loginStep.message}</p></Alert>
        {providerLink !== null && <Anchor href={providerLink} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{t('verificationLink')} ({new URL(providerLink).hostname})</Anchor>}
        {loginStep.kind === 'prompt' && (loginStep.echo ? <TextInput key={`${generation.current}:${loginStep.sequence}`} name="answer" label={t('loginResponse')} autoComplete="off" data-autofocus /> : <PasswordInput key={`${generation.current}:${loginStep.sequence}`} name="answer" label={t('loginResponse')} autoComplete="off" data-autofocus visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }} />)}
        <div className="actions"><Button type="submit">{t(loginStep.kind === 'prompt' ? 'loginReply' : 'loginContinue')}</Button><Button type="button" variant="default" onClick={cancel}>{t('cancel')}</Button></div>
      </form>}
    </Modal>
    <Modal lockScroll={false} opened={confirm !== null} onClose={() => setConfirm(null)} title={t(confirm === 'local' ? 'removeTitle' : 'forgetTitle')} closeButtonProps={{ 'aria-label': t('close') }}>
      <p>{t(confirm === 'local' ? 'removeWarning' : 'forgetWarning')}</p><div className="actions"><Button color="red" onClick={() => { void forget(); }}>{t(confirm === 'local' ? 'removeLocalOnly' : 'revoke')}</Button><Button variant="default" onClick={() => setConfirm(null)}>{t('cancel')}</Button></div>
    </Modal>
  </main>;
}

import {
  Alert,
  Anchor,
  Button,
  Checkbox,
  Modal,
  Paper,
  PasswordInput,
  Radio,
  SegmentedControl,
  TextInput,
  Title,
} from '@mantine/core';
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { verificationLink } from '../login/links';
import type { AccessSnapshot, LoginStep, LogoutResult, Scope, WebAccess } from '../remember';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import { TerminalWorkspace } from '../terminal/TerminalWorkspace';
import { LoginChallenge } from './LoginChallenge';
import type { Message } from './messages';
import { t } from './messages';

const ManagementPanel = lazy(async () => ({
  default: (await import('../management/ManagementPanel')).ManagementPanel,
}));
const ArtifactPanel = lazy(async () => ({
  default: (await import('../artifacts/ArtifactPanel')).ArtifactPanel,
}));

export interface LinkMetadata {
  readonly scope: Scope;
  readonly requestUser: boolean;
  readonly publishedSlugs: readonly string[];
}
type Saved = 'loading' | 'missing' | 'ready' | 'pending' | 'unavailable';
type Notice = { key: Message; color: 'red' | 'yellow' | 'green' };

function errorNotice(error: unknown): Notice {
  const code = error instanceof RememberMeError ? error.code : 'unavailable';
  const key: Message =
    code === 'key-import'
      ? 'keyImportFailed'
      : code === 'login-unknown'
        ? 'loginUnknown'
        : code === 'invalid-step'
          ? 'loginInvalidStep'
          : code === 'busy'
            ? 'loginBusy'
            : code === 'outcome-unknown'
              ? 'unknown'
              : code === 'already-remembered'
                ? 'already'
                : code === 'denied'
                  ? 'denied'
                  : code === 'rate-limited'
                    ? 'limited'
                    : code === 'cancelled'
                      ? 'cancelled'
                      : 'unavailable';
  return { key, color: code === 'denied' || code === 'unavailable' ? 'red' : 'yellow' };
}

export function App({
  metadata,
  title = t('brand'),
  scheme,
  onScheme,
}: {
  metadata: LinkMetadata;
  title?: string;
  scheme: string;
  onScheme: (value: string) => void;
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
  const [workspaceView, setWorkspaceView] = useState<'sessions' | 'artifacts' | 'server'>(
    'sessions',
  );
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirm, setConfirm] = useState<'revoke' | 'local' | null>(null);
  const [optIn, setOptIn] = useState(false);
  const [passwordKey, setPasswordKey] = useState(0);
  const [loginOpen, setLoginOpen] = useState(true);
  const [accountOpen, setAccountOpen] = useState(false);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [authorizationEvent, setAuthorizationEvent] = useState(0);
  const [workspaceEpoch, setWorkspaceEpoch] = useState(0);
  const [rememberUncertain, setRememberUncertain] = useState(false);
  const [loginMethod, setLoginMethod] = useState('password');
  const [loginStep, setLoginStep] = useState<LoginStep | null>(null);
  const pendingResponse = useRef<((value: string) => void) | null>(null);
  const providerLink = loginStep?.kind === 'info' ? verificationLink(loginStep.message) : null;

  const readSaved = useCallback(
    async (current = generation.current) => {
      try {
        const handle = await BrowserBinding.load(metadata.scope);
        if (current !== generation.current) {
          return;
        }
        savedHandle.current = handle;
        setSaved(handle === null ? 'missing' : handle.binding === null ? 'pending' : 'ready');
      } catch {
        if (current === generation.current) {
          savedHandle.current = null;
          setSaved('unavailable');
        }
      }
    },
    [metadata.scope],
  );
  useEffect(() => {
    void readSaved();
    return () => {
      generation.current++;
      operation.current?.abort();
    };
  }, [readSaved]);

  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (operation.current !== null || managementLocked) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    operation.current = controller;
    setBusy(true);
    setNotice(null);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (current === generation.current) {
        setNotice(errorNotice(error));
      }
    } finally {
      if (current === generation.current) {
        operation.current = null;
        setBusy(false);
        await readSaved(current);
      }
    }
  }

  function cancel() {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    setBusy(false);
    setNotice({ key: 'cancelled', color: 'yellow' });
    setLoginStep(null);
    void readSaved();
  }

  function requestStep(step: LoginStep, signal: AbortSignal): Promise<string> {
    const current = generation.current;
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        signal.removeEventListener('abort', aborted);
        pendingResponse.current = null;
        if (current === generation.current) {
          setLoginStep(null);
        }
      };
      const aborted = () => {
        cleanup();
        reject(new RememberMeError('cancelled'));
      };
      if (signal.aborted) {
        aborted();
        return;
      }
      signal.addEventListener('abort', aborted, { once: true });
      pendingResponse.current = (value) => {
        cleanup();
        resolve(value);
      };
      setLoginStep(step);
    });
  }

  function answerStep(form: HTMLFormElement) {
    const field = form.elements.namedItem('answer') as HTMLInputElement | null;
    const value = field?.value ?? '';
    if (field !== null) {
      field.value = '';
    }
    pendingResponse.current?.(value);
  }

  async function login(form: HTMLFormElement) {
    const password = form.elements.namedItem('password') as HTMLInputElement | null;
    const user = (form.elements.namedItem('user') as HTMLInputElement | null)?.value ?? '';
    const secret = password?.value ?? '';
    if (password !== null) {
      password.value = ''; // No answer/password in app state or persistent storage.
    }
    const privateInput = form.querySelector<HTMLInputElement>('#key-private');
    const certificateInput = form.querySelector<HTMLInputElement>('#key-certificate');
    const passphraseInput = form.querySelector<HTMLInputElement>('#key-passphrase');
    let privateFile = privateInput?.files?.[0] ?? null;
    let certificateFile = certificateInput?.files?.[0] ?? null;
    let passphrase = passphraseInput?.value ?? '';
    if (privateInput !== null) {
      privateInput.value = '';
    }
    if (certificateInput !== null) {
      certificateInput.value = '';
    }
    if (passphraseInput !== null) {
      passphraseInput.value = '';
    }
    setPasswordKey((value) => value + 1); // Reset Mantine's internal uncontrolled input state too.
    const remember = optIn;
    await run(async (signal, current) => {
      let result: WebAccess;
      if (loginMethod === 'key') {
        if (privateFile === null) {
          throw new RememberMeError('key-import');
        }
        const { WasmLoginKey } = await import('../login/wasm-key');
        let key: import('../login/wasm-key').WasmLoginKey;
        try {
          key = await WasmLoginKey.import(
            privateFile,
            passphrase,
            certificateFile,
            metadata.scope,
            user,
            signal,
          );
        } finally {
          privateFile = null;
          certificateFile = null;
          passphrase = '';
        }
        try {
          result = await client.current.publicKey(user, key, signal);
        } finally {
          key.close();
        }
      } else {
        result =
          loginMethod === 'interactive'
            ? await client.current.interactive(user, requestStep, signal)
            : await client.current.password(user, secret, signal);
      }
      if (current !== generation.current) {
        return;
      }
      access.current = result;
      setWorkspaceView('sessions');
      setSnapshot(result.snapshot());
      setClosing(false);
      setRememberUncertain(false);
      if (remember) {
        try {
          await result.remember({ explicitOptIn: true }, signal);
          if (current === generation.current) {
            setNotice({ key: 'registered', color: 'green' });
          }
        } catch (error) {
          if (current === generation.current) {
            setNotice(errorNotice(error));
            setRememberUncertain(
              error instanceof RememberMeError && error.code === 'outcome-unknown',
            );
          }
        }
      }
      if (current === generation.current) {
        setLoginOpen(false);
        setAuthorizationEvent((value) => value + 1);
      }
    });
  }

  async function resume() {
    await run(async (signal, current) => {
      const result = await client.current.resume(signal);
      if (current !== generation.current) {
        return;
      }
      if (result === null) {
        setNotice({ key: 'denied', color: 'yellow' });
        return;
      }
      access.current = result;
      setWorkspaceView('sessions');
      setSnapshot(result.snapshot());
      setClosing(false);
      setLoginOpen(false);
      setRememberUncertain(false);
      setAuthorizationEvent((value) => value + 1);
    });
  }

  function cleanupNotice(result: LogoutResult, success: 'loggedOut' | 'remoteRevoked'): Notice {
    return result.localState === 'changed'
      ? { key: 'newerKept', color: 'yellow' }
      : result.localState === 'unavailable'
        ? { key: 'localCleanupFailed', color: 'yellow' }
        : { key: success, color: 'green' };
  }

  async function logout() {
    if (managementLocked) {
      return;
    }
    const selected = access.current;
    if (selected === null) {
      return;
    }
    const current = ++generation.current;
    operation.current?.abort();
    operation.current = null;
    setClosing(true);
    setBusy(true);
    setNotice({ key: 'logoutPending', color: 'yellow' });
    try {
      const result = await selected.logout();
      if (current !== generation.current) {
        return;
      }
      access.current = null;
      setSnapshot(null);
      setClosing(false);
      setOptIn(false);
      setLoginOpen(true);
      setAccountOpen(false);
      setAuthorizationEvent(0);
      setWorkspaceEpoch((value) => value + 1);
      setRememberUncertain(false);
      setNotice(cleanupNotice(result, 'loggedOut'));
    } catch {
      if (current === generation.current) {
        setNotice({ key: 'logoutUnknown', color: 'red' });
      }
    } finally {
      if (current === generation.current) {
        setBusy(false);
        await readSaved(current);
      }
    }
  }

  async function forget() {
    const selected = confirm;
    const handle = confirmationHandle.current;
    setConfirm(null);
    await run(async (signal, current) => {
      if (selected === 'revoke') {
        if (handle === null) {
          throw new RememberMeError('changed');
        }
        const result = await client.current.revokeSelection(handle, signal);
        if (current === generation.current) {
          setNotice(cleanupNotice(result, 'remoteRevoked'));
        }
      } else if (selected === 'local' && handle !== null) {
        await handle.forgetLocal();
        if (current === generation.current) {
          setNotice({ key: 'localRemoved', color: 'yellow' });
        }
      }
    });
  }

  function showConfirmation(value: 'revoke' | 'local') {
    confirmationHandle.current = savedHandle.current;
    setConfirm(value);
  }

  function showLogin() {
    if (closing || busy || rememberUncertain || managementLocked) {
      return;
    }
    setAccountOpen(false);
    setLoginOpen(true);
    setOptIn(false);
    void readSaved();
  }
  function closeLogin() {
    if (operation.current !== null) {
      cancel();
    }
    setLoginOpen(false);
    setOptIn(false);
    setPasswordKey((value) => value + 1);
  }
  useEffect(() => {
    if (
      !loginOpen &&
      notice &&
      ['unknown', 'logoutUnknown', 'localCleanupFailed'].includes(notice.key)
    ) {
      setNoticeOpen(true);
    }
  }, [loginOpen, notice]);

  return (
    <>
      <TerminalWorkspace
        key={workspaceEpoch}
        access={snapshot === null ? null : access.current}
        authorizationEvent={authorizationEvent}
        blocked={closing || busy || rememberUncertain || managementLocked}
        focusBlocked={
          loginOpen || loginStep !== null || accountOpen || noticeOpen || confirm !== null
        }
        title={title}
        scope={metadata.scope.slug}
        onSignIn={showLogin}
        managementView={workspaceView}
        onManagementView={setWorkspaceView}
        notice={
          notice !== null && !loginOpen && !noticeOpen ? (
            <button
              type="button"
              className={`bar-notice bar-notice--${notice.color}`}
              onClick={() => setNoticeOpen(true)}
              aria-label={t('showNotice')}
              title={t(notice.key)}
            >
              <span role="status">{t(notice.key)}</span>
            </button>
          ) : null
        }
        account={
          <>
            {snapshot !== null && (
              <Button
                variant="subtle"
                onClick={() => setAccountOpen(true)}
                aria-label={t('account')}
              >
                <Title order={2} size="h5">
                  {t(closing ? 'accessBlocked' : 'authenticated')} {snapshot.principal}
                </Title>
              </Button>
            )}
            {!snapshot && (
              <Button
                variant="subtle"
                aria-label={t('openLogin')}
                disabled={closing || busy || rememberUncertain || managementLocked}
                onClick={showLogin}
              >
                {t('login')}
              </Button>
            )}
            {snapshot && (
              <Button
                onClick={() => {
                  void logout();
                }}
                disabled={(closing && busy) || managementLocked}
                variant="subtle"
                color="red"
                aria-label={t(closing ? 'retryLogout' : 'logout')}
                title={t(closing ? 'retryLogout' : 'logout')}
              >
                <span aria-hidden="true">↪</span>
              </Button>
            )}
            <Button
              variant="subtle"
              onClick={() => setAccountOpen(true)}
              aria-label={t('appearance')}
            >
              ⚙
            </Button>
          </>
        }
      >
        {snapshot !== null && snapshot.environment === 'management' && access.current !== null && (
          <Suspense fallback={<Alert>{t('managementLoading')}</Alert>}>
            <div hidden={workspaceView === 'artifacts'}>
              <ManagementPanel
                key={generation.current}
                access={access.current}
                disabled={closing || busy}
                onActionLock={setManagementLocked}
                view={workspaceView === 'server' ? 'server' : 'sessions'}
              />
            </div>
            <div hidden={workspaceView !== 'artifacts'}>
              <ArtifactPanel
                key={`artifacts:${generation.current}`}
                access={access.current}
                disabled={closing || busy || managementLocked}
              />
            </div>
          </Suspense>
        )}
      </TerminalWorkspace>
      <Modal
        classNames={{ content: 'confirmation-dialog login-dialog' }}
        lockScroll={false}
        opened={loginOpen && confirm === null}
        onClose={closeLogin}
        closeOnClickOutside={false}
        closeOnEscape={!busy}
        title={t(loginStep === null ? 'login' : 'loginChallenge')}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        {notice && (
          <Alert role="status" color={notice.color}>
            {t(notice.key)}
          </Alert>
        )}
        {loginStep !== null ? (
          <LoginChallenge
            key={`${generation.current}:${loginStep.sequence}`}
            step={loginStep}
            providerLink={providerLink}
            onAnswer={answerStep}
            onCancel={cancel}
          />
        ) : (
          <>
            <div className="stack">
              {saved === 'ready' && (
                <Paper withBorder p="lg" className="stack">
                  <p>{t('saved')}</p>
                  <div className="actions">
                    <Button
                      disabled={busy}
                      onClick={() => {
                        void resume();
                      }}
                    >
                      {t('useSaved')}
                    </Button>
                    {snapshot === null && (
                      <>
                        <Button
                          variant="default"
                          disabled={busy}
                          onClick={() => showConfirmation('revoke')}
                        >
                          {t('forgetSaved')}
                        </Button>
                        <Button
                          variant="subtle"
                          disabled={busy}
                          onClick={() => showConfirmation('local')}
                        >
                          {t('removeLocalOnly')}
                        </Button>
                      </>
                    )}
                  </div>
                </Paper>
              )}
              {saved === 'pending' && (
                <Alert color="yellow">
                  <p>{t('pending')}</p>
                  {snapshot === null && (
                    <Button
                      variant="outline"
                      disabled={busy}
                      onClick={() => showConfirmation('local')}
                    >
                      {t('removeLocal')}
                    </Button>
                  )}
                </Alert>
              )}
              {saved === 'unavailable' && <Alert color="yellow">{t('storageUnavailable')}</Alert>}
              <Paper withBorder p="lg" className="login-card">
                <form
                  method={loginMethod === 'key' ? 'dialog' : 'post'}
                  action={loginMethod === 'key' ? undefined : '/_bifroest/api/v1/login/password'}
                  className="stack"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void login(event.currentTarget);
                  }}
                >
                  <Radio.Group
                    label={t('loginMethod')}
                    value={loginMethod}
                    onChange={setLoginMethod}
                  >
                    <div className="login-methods">
                      <Radio value="password" label={t('passwordMethod')} disabled={busy} />
                      <Radio value="interactive" label={t('interactiveMethod')} disabled={busy} />
                      <Radio value="key" label={t('keyMethod')} disabled={busy} />
                    </div>
                  </Radio.Group>
                  {metadata.requestUser && (
                    <TextInput
                      name="user"
                      label={t('user')}
                      autoComplete="username"
                      disabled={busy}
                    />
                  )}
                  {loginMethod === 'password' && (
                    <PasswordInput
                      key={passwordKey}
                      name="password"
                      label={t('password')}
                      autoComplete="current-password"
                      visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
                      disabled={busy}
                    />
                  )}
                  {loginMethod === 'key' && (
                    <>
                      <Alert color="blue">{t('keyLocalOnly')}</Alert>
                      <label className="stack" htmlFor="key-private">
                        {t('keyPrivateFile')}
                        <input
                          key={`private:${passwordKey}`}
                          id="key-private"
                          type="file"
                          required
                          disabled={busy}
                        />
                      </label>
                      <PasswordInput
                        key={`passphrase:${passwordKey}`}
                        id="key-passphrase"
                        label={t('keyPassphrase')}
                        autoComplete="off"
                        visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
                        disabled={busy}
                      />
                      <label className="stack" htmlFor="key-certificate">
                        {t('keyCertificateFile')}
                        <input
                          key={`certificate:${passwordKey}`}
                          id="key-certificate"
                          type="file"
                          disabled={busy}
                        />
                      </label>
                    </>
                  )}
                  <Checkbox
                    checked={optIn}
                    onChange={(event) => setOptIn(event.currentTarget.checked)}
                    disabled={busy || saved !== 'missing'}
                    label={t('remember')}
                    description={t('rememberHint')}
                  />
                  <div className="actions">
                    <Button type="submit" disabled={busy || managementLocked}>
                      {t('login')}
                    </Button>
                    {busy && (
                      <Button type="button" variant="default" onClick={cancel}>
                        {t('cancel')}
                      </Button>
                    )}
                  </div>
                </form>
              </Paper>
            </div>
            {metadata.publishedSlugs.length > 0 && (
              <nav className="access-links" aria-label={t('discovery')}>
                <span className="caption subtle">{t('discovery')}</span>
                <ul className="actions">
                  {metadata.publishedSlugs.map((slug) => (
                    <li key={slug}>
                      {managementLocked ? (
                        <span aria-disabled="true">{slug}</span>
                      ) : (
                        <Anchor href={`/${slug}`}>{slug}</Anchor>
                      )}
                    </li>
                  ))}
                </ul>
              </nav>
            )}
            <footer className="caption workspace-footer">
              <SegmentedControl
                aria-label={t('theme')}
                value={scheme}
                onChange={onScheme}
                data={[
                  { value: 'auto', label: t('auto') },
                  { value: 'light', label: t('light') },
                  { value: 'dark', label: t('dark') },
                ]}
              />
              <details>
                <summary>{t('interfaceInformation')}</summary>
                <p>{t('partial')}</p>
              </details>
              <Anchor href="/_bifroest/files/third-party-licenses.txt">{t('notices')}</Anchor>
            </footer>
          </>
        )}
      </Modal>
      <Modal
        classNames={{ content: 'confirmation-dialog' }}
        lockScroll={false}
        opened={accountOpen}
        onClose={() => setAccountOpen(false)}
        title={t('account')}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        <div className="stack">
          {snapshot && (
            <>
              <p>{snapshot.principal}</p>
              <p className="caption">
                {t('expires')}:{' '}
                <time dateTime={snapshot.expiresAt}>
                  {new Intl.DateTimeFormat('en-US', {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                  }).format(new Date(snapshot.expiresAt))}
                </time>
              </p>
            </>
          )}
          {snapshot && (
            <Button
              variant="default"
              disabled={closing || busy || rememberUncertain || managementLocked}
              onClick={showLogin}
            >
              {t('reauthenticate')}
            </Button>
          )}
          <SegmentedControl
            aria-label={t('theme')}
            value={scheme}
            onChange={onScheme}
            data={[
              { value: 'auto', label: t('auto') },
              { value: 'light', label: t('light') },
              { value: 'dark', label: t('dark') },
            ]}
          />
          <details>
            <summary>{t('interfaceInformation')}</summary>
            <p>{t('partial')}</p>
            <p>{t('terminalFresh')}</p>
          </details>
          <nav aria-label={t('discovery')}>
            <ul>
              {metadata.publishedSlugs.map((slug) => (
                <li key={slug}>
                  {managementLocked ? (
                    <span aria-disabled="true">{slug}</span>
                  ) : (
                    <Anchor href={`/${slug}`}>{slug}</Anchor>
                  )}
                </li>
              ))}
            </ul>
          </nav>
          <Anchor href="/_bifroest/files/third-party-licenses.txt">{t('notices')}</Anchor>
        </div>
      </Modal>
      <Modal
        lockScroll={false}
        opened={noticeOpen && !loginOpen}
        onClose={() => setNoticeOpen(false)}
        title={t('showNotice')}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        {notice && (
          <Alert role="status" color={notice.color}>
            {t(notice.key)}
          </Alert>
        )}
      </Modal>
      <Modal
        classNames={{ content: 'confirmation-dialog' }}
        lockScroll={false}
        opened={confirm !== null}
        onClose={() => setConfirm(null)}
        title={t(confirm === 'local' ? 'removeTitle' : 'forgetTitle')}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        <p>{t(confirm === 'local' ? 'removeWarning' : 'forgetWarning')}</p>
        <div className="actions">
          <Button
            color="red"
            onClick={() => {
              void forget();
            }}
          >
            {t(confirm === 'local' ? 'removeLocalOnly' : 'revoke')}
          </Button>
          <Button variant="default" onClick={() => setConfirm(null)}>
            {t('cancel')}
          </Button>
        </div>
      </Modal>
    </>
  );
}

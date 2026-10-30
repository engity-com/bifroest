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
  Select,
  TextInput,
  Title,
} from '@mantine/core';
import { useCallback, useEffect, useRef, useState } from 'react';
import { verificationLink } from '../login/links';
import type { AccessSnapshot, LoginStep, LogoutResult, WebAccess } from '../remember';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import { maximumTabs, TerminalWorkspace } from '../terminal/TerminalWorkspace';
import { LoginChallenge, ProviderInformation } from './LoginChallenge';
import { type LinkMetadata, loadLinkMetadata } from './link-metadata';
import type { Message } from './messages';
import { t } from './messages';

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
  const link = useRef(metadata);
  const [loginMetadata, setLoginMetadata] = useState(metadata);
  const access = useRef<WebAccess | null>(null);
  // An independently confirmed primary may still be enrolling RememberMe. Keep
  // that owning grant recoverable without confusing it with an internal tab's
  // active selection (for example when a connecting tab is retired).
  const candidate = useRef<WebAccess | null>(null);
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
  const [loginOpen, setLoginOpen] = useState(true);
  const [accountOpen, setAccountOpen] = useState(false);
  const [appearanceOpen, setAppearanceOpen] = useState(false);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [authorizationEvent, setAuthorizationEvent] = useState<WebAccess | null>(null);
  const [retiredAccess, setRetiredAccess] = useState<WebAccess | null>(null);
  const [tabCount, setTabCount] = useState(0);
  const [rememberUncertain, setRememberUncertain] = useState(false);
  const [loginMethod, setLoginMethod] = useState('password');
  const [loginStep, setLoginStep] = useState<LoginStep | null>(null);
  const [loginUser, setLoginUser] = useState('');
  const [providerInformation, setProviderInformation] = useState<LoginStep | null>(null);
  const [loginPending, setLoginPending] = useState<'authentication' | 'remember' | null>(null);
  const pendingResponse = useRef<((value: string) => void) | null>(null);
  const providerLink = loginStep?.kind === 'info' ? verificationLink(loginStep.message) : null;

  const readSaved = useCallback(async (current = generation.current) => {
    const scope = link.current.scope;
    try {
      const handle = await BrowserBinding.load(scope);
      if (current !== generation.current || scope !== link.current.scope) {
        return;
      }
      savedHandle.current = handle;
      setSaved(handle === null ? 'missing' : handle.binding === null ? 'pending' : 'ready');
    } catch {
      if (current === generation.current && scope === link.current.scope) {
        savedHandle.current = null;
        setSaved('unavailable');
      }
    }
  }, []);
  useEffect(() => {
    void readSaved();
    return () => {
      generation.current++;
      operation.current?.abort();
    };
  }, [readSaved]);

  const selectAccess = useCallback((selected: WebAccess | null) => {
    if (candidate.current !== null && candidate.current !== selected) {
      return;
    }
    if (candidate.current === selected) {
      candidate.current = null;
    }
    access.current = selected;
    setSnapshot(selected?.snapshot() ?? null);
    if (selected === null) {
      setLoginOpen(true);
    }
  }, []);

  const linkChoices = [
    ...new Set([
      metadata.scope.slug,
      ...metadata.publishedSlugs,
      loginMetadata.scope.slug,
      ...loginMetadata.publishedSlugs,
      ...(snapshot ? [snapshot.scope.slug] : []),
    ]),
  ];

  async function chooseLink(slug: string) {
    if (closing || busy || rememberUncertain || managementLocked || !linkChoices.includes(slug)) {
      return;
    }
    if (slug === link.current.scope.slug) {
      void readSaved();
      return;
    }
    await run(async (signal, current) => {
      const next = await loadLinkMetadata({ origin: metadata.scope.origin, slug }, signal);
      if (current !== generation.current) {
        return;
      }
      link.current = next;
      client.current = new BrowserClient(next.scope);
      setLoginMetadata(next);
      setLoginUser('');
      setProviderInformation(null);
      setPasswordKey((value) => value + 1);
      setOptIn(false);
      savedHandle.current = null;
      setSaved('loading');
    });
  }

  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (operation.current !== null || managementLocked || rememberUncertain || closing) {
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
        setLoginPending(null);
        setProviderInformation(null);
        await readSaved(current);
      }
    }
  }

  function cancel() {
    const enrollmentMayHaveCommitted = loginPending === 'remember';
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    setBusy(false);
    setLoginPending(null);
    setNotice({ key: enrollmentMayHaveCommitted ? 'unknown' : 'cancelled', color: 'yellow' });
    if (enrollmentMayHaveCommitted) {
      setRememberUncertain(true);
      setLoginOpen(false);
    }
    setLoginStep(null);
    setProviderInformation(null);
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
      // Retain only the current attempt's explicit provider instructions, never
      // a prompt/answer. They remain available during subsequent device polling.
      setProviderInformation(
        step.kind === 'info' && verificationLink(step.message) !== null ? step : null,
      );
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
    setLoginUser(user);
    setProviderInformation(null);
    const selectedClient = client.current;
    const selectedScope = link.current.scope;
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
      setLoginPending('authentication');
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
            selectedScope,
            user,
            signal,
          );
        } finally {
          privateFile = null;
          certificateFile = null;
          passphrase = '';
        }
        try {
          result = await selectedClient.publicKey(user, key, signal);
        } finally {
          key.close();
        }
      } else {
        result =
          loginMethod === 'interactive'
            ? await selectedClient.interactive(user, requestStep, signal)
            : await selectedClient.password(user, secret, signal);
      }
      if (current !== generation.current) {
        return;
      }
      access.current = result;
      candidate.current = result;
      setSnapshot(result.snapshot());
      setClosing(false);
      setRememberUncertain(false);
      let uncertain = false;
      if (remember) {
        setLoginPending('remember');
        setProviderInformation(null);
        try {
          await result.remember({ explicitOptIn: true }, signal);
          if (current === generation.current) {
            setNotice({ key: 'registered', color: 'green' });
          }
        } catch (error) {
          if (current === generation.current) {
            setNotice(errorNotice(error));
            uncertain = error instanceof RememberMeError && error.code === 'outcome-unknown';
            setRememberUncertain(uncertain);
          }
        }
      }
      if (current === generation.current) {
        setProviderInformation(null);
        setLoginOpen(false);
        if (!uncertain) {
          setAuthorizationEvent(result);
        }
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
      candidate.current = result;
      setSnapshot(result.snapshot());
      setClosing(false);
      setLoginOpen(false);
      setRememberUncertain(false);
      setAuthorizationEvent(result);
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
      if (candidate.current === selected) {
        candidate.current = null;
      }
      setAuthorizationEvent((event) => (event === selected ? null : event));
      setSnapshot(null);
      setClosing(false);
      setOptIn(false);
      setAccountOpen(false);
      setRetiredAccess(selected);
      setLoginOpen(false); // The remaining active tab is selected by the workspace.
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

  function showLogin(scope = access.current?.snapshot().scope) {
    if (closing || busy || rememberUncertain || managementLocked) {
      return;
    }
    if (tabCount >= maximumTabs) {
      setNotice({ key: 'terminalTabLimit', color: 'yellow' });
      setNoticeOpen(true);
      return;
    }
    setAccountOpen(false);
    setLoginOpen(true);
    setOptIn(false);
    setLoginUser('');
    setProviderInformation(null);
    if (scope && scope.origin === metadata.scope.origin && scope.slug !== link.current.scope.slug) {
      void chooseLink(scope.slug);
      return;
    }
    void readSaved();
  }
  function closeLogin() {
    if (operation.current !== null) {
      cancel();
    }
    setLoginOpen(false);
    setOptIn(false);
    setPasswordKey((value) => value + 1);
    setProviderInformation(null);
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
        access={snapshot === null ? null : access.current}
        authorizationEvent={authorizationEvent}
        retiredAccess={retiredAccess}
        unavailableAccess={closing || rememberUncertain ? access.current : null}
        blocked={closing || busy || rememberUncertain || managementLocked}
        focusBlocked={
          loginOpen ||
          loginStep !== null ||
          accountOpen ||
          appearanceOpen ||
          noticeOpen ||
          confirm !== null
        }
        title={title}
        scope={snapshot?.scope.slug ?? loginMetadata.scope.slug}
        onSignIn={showLogin}
        onNewConnection={() => showLogin()}
        onSelectAccess={selectAccess}
        onActionLock={setManagementLocked}
        onTabCount={setTabCount}
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
                onClick={() => showLogin()}
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
                title={`${t(closing ? 'retryLogout' : 'logout')}: ${snapshot.scope.slug || '/'} · ${snapshot.principal}`}
              >
                <span aria-hidden="true">↪</span>
              </Button>
            )}
            <Button
              variant="subtle"
              onClick={() => setAppearanceOpen(true)}
              aria-label={t('appearance')}
            >
              ⚙
            </Button>
          </>
        }
      />
      <Modal
        classNames={{ content: 'confirmation-dialog login-dialog' }}
        lockScroll={false}
        opened={loginOpen && confirm === null}
        onClose={closeLogin}
        closeOnClickOutside={false}
        closeOnEscape={!busy}
        title={t(
          loginStep !== null || (loginPending !== null && loginMethod === 'interactive')
            ? 'loginChallenge'
            : 'login',
        )}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        <div className="login-context">
          <strong>
            {t('connectionLoginContext')}: {loginMetadata.scope.slug || '/'}
          </strong>
          {loginUser && busy && (
            <span>
              {t('connectionRequestedUser')}: {loginUser}
            </span>
          )}
          {snapshot && <p>{t('connectionExistingKept')}</p>}
        </div>
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
        ) : loginPending !== null && loginMethod === 'interactive' ? (
          <div className="stack" aria-busy="true">
            {providerInformation !== null && (
              <ProviderInformation
                step={providerInformation}
                providerLink={verificationLink(providerInformation.message)}
              />
            )}
            <p role="status">
              {t(loginPending === 'remember' ? 'loginRemembering' : 'loginWaiting')}
            </p>
            <Button variant="default" onClick={cancel}>
              {t('cancel')}
            </Button>
          </div>
        ) : (
          <>
            <div className="stack">
              <Select
                label={t('connectionLink')}
                value={loginMetadata.scope.slug}
                data={linkChoices.map((slug) => ({ value: slug, label: slug || '/' }))}
                disabled={busy}
                allowDeselect={false}
                onChange={(value) => {
                  if (value !== null) {
                    void chooseLink(value);
                  }
                }}
              />
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
                  key={loginMetadata.scope.slug}
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
                  {loginMetadata.requestUser && (
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
                    <Button type="submit" loading={busy} disabled={busy || managementLocked}>
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
              <Anchor
                href="/_bifroest/files/third-party-licenses.txt"
                target="_blank"
                rel="noopener noreferrer"
              >
                {t('notices')}
              </Anchor>
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
              <p>
                {t('connectionLoginContext')}: {snapshot.scope.slug || '/'}
              </p>
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
              disabled={
                closing || busy || rememberUncertain || managementLocked || tabCount >= maximumTabs
              }
              onClick={() => showLogin()}
            >
              {t('reauthenticate')}
            </Button>
          )}
          <p className="caption">{t('connectionLogoutScope')}</p>
        </div>
      </Modal>
      <Modal
        classNames={{ content: 'confirmation-dialog' }}
        lockScroll={false}
        opened={appearanceOpen}
        onClose={() => setAppearanceOpen(false)}
        title={t('appearance')}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        <div className="stack">
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
          <Anchor
            href="/_bifroest/files/third-party-licenses.txt"
            target="_blank"
            rel="noopener noreferrer"
          >
            {t('notices')}
          </Anchor>
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

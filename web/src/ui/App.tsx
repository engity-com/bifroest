import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlineOutlined';
import DescriptionIcon from '@mui/icons-material/Description';
import LogoutIcon from '@mui/icons-material/Logout';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import PaletteIcon from '@mui/icons-material/Palette';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useCallback, useEffect, useRef, useState } from 'react';
import { type KeyLoginDiagnostic, keyLoginDiagnostic, keyLoginError } from '../login/diagnostic';
import { verificationLink } from '../login/links';
import type { AccessSnapshot, LoginStep, LogoutResult, WebAccess } from '../remember';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import type { AuthenticationView } from '../terminal/AuthenticationTerminal';
import { maximumTabs, TerminalWorkspace } from '../terminal/TerminalWorkspace';
import { type LinkMetadata, loadLinkMetadata } from './link-metadata';
import {
  ActionIcon,
  Alert,
  Button,
  Checkbox,
  Group,
  Menu,
  Modal,
  PasswordInput,
  SegmentedControl,
  Select,
  Stack,
  Text,
  TextInput,
  Tooltip,
  VisuallyHidden,
} from './material';
import type { Message } from './messages';
import { t } from './messages';

type Saved = 'loading' | 'missing' | 'ready' | 'pending' | 'unavailable';
type Notice = {
  key: Message;
  color: 'red' | 'yellow' | 'green';
  context?: AccessSnapshot;
  diagnostic?: KeyLoginDiagnostic;
};

function errorNotice(error: unknown): Notice {
  const code = error instanceof RememberMeError ? error.code : 'unavailable';
  const diagnostic = keyLoginDiagnostic(error);
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
                      : diagnostic
                        ? 'keyUnavailable'
                        : 'unavailable';
  return {
    key,
    color: code === 'denied' || code === 'unavailable' ? 'red' : 'yellow',
    ...(diagnostic ? { diagnostic } : {}),
  };
}

function NoticeBody({ notice }: { notice: Notice }) {
  return (
    <>
      {t(notice.key)}
      {notice.diagnostic && (
        <details className="login-diagnostic">
          <summary>{t('keyDiagnosticDetails')}</summary>
          <p>{t(keyDiagnosticMessages[notice.diagnostic.phase])}</p>
          <code>
            key/{notice.diagnostic.phase}/{notice.diagnostic.code}
          </code>
          <p>{t('keyDiagnosticPrivacy')}</p>
        </details>
      )}
    </>
  );
}
const keyDiagnosticMessages = {
  module: 'keyDiagnosticModule',
  'wasm-download': 'keyDiagnosticDownload',
  'file-read': 'keyDiagnosticFile',
  'worker-start': 'keyDiagnosticWorker',
  'key-import': 'keyDiagnosticImport',
  'browser-crypto': 'keyDiagnosticCrypto',
  challenge: 'keyDiagnosticChallenge',
  sign: 'keyDiagnosticSign',
  signature: 'keyDiagnosticSignature',
  authentication: 'keyDiagnosticAuthentication',
} as const satisfies Record<KeyLoginDiagnostic['phase'], Message>;

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
  const [applicationMenuOpen, setApplicationMenuOpen] = useState(false);
  const [appearanceOpen, setAppearanceOpen] = useState(false);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [authorizationEvent, setAuthorizationEvent] = useState<WebAccess | null>(null);
  const [retiredAccess, setRetiredAccess] = useState<WebAccess | null>(null);
  const [tabCount, setTabCount] = useState(0);
  const [rememberUncertain, setRememberUncertain] = useState(false);
  const [loginMethod, setLoginMethod] = useState('password');
  const [loginStep, setLoginStep] = useState<LoginStep | null>(null);
  const [providerInformation, setProviderInformation] = useState<LoginStep | null>(null);
  const [loginPending, setLoginPending] = useState<'authentication' | 'remember' | null>(null);
  const [terminalLogin, setTerminalLogin] = useState<{
    id: number;
    scope: LinkMetadata['scope'];
    user: string;
  } | null>(null);
  const pendingResponse = useRef<{
    step: LoginStep;
    generation: number;
    answer: (value: string) => void;
  } | null>(null);

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
      setAuthorizationEvent(null);
      setLoginOpen(false);
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
    setTerminalLogin(null);
    setNotice({
      key: enrollmentMayHaveCommitted ? 'unknown' : 'cancelled',
      color: 'yellow',
      ...(enrollmentMayHaveCommitted && candidate.current
        ? { context: candidate.current.snapshot() }
        : {}),
    });
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
        if (pendingResponse.current?.step === step) {
          pendingResponse.current = null;
        }
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
      pendingResponse.current = {
        step,
        generation: current,
        answer: (value) => {
          if (
            current !== generation.current ||
            signal.aborted ||
            pendingResponse.current?.step !== step
          ) {
            return;
          }
          cleanup();
          resolve(value);
        },
      };
      setLoginStep(step);
      // Retain only the current attempt's explicit provider instructions, never
      // a prompt/answer. They remain available during subsequent device polling.
      setProviderInformation(
        step.kind === 'info' && verificationLink(step.message) !== null ? step : null,
      );
    });
  }

  async function login(form: HTMLFormElement) {
    const password = form.elements.namedItem('password') as HTMLInputElement | null;
    const user = (form.elements.namedItem('user') as HTMLInputElement | null)?.value ?? '';
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
    setPasswordKey((value) => value + 1); // Also discard the input's internal uncontrolled state.
    const remember = optIn;
    await run(async (signal, current) => {
      setLoginPending('authentication');
      if (loginMethod === 'interactive') {
        setTerminalLogin({ id: current, scope: selectedScope, user });
        setLoginOpen(false);
      }
      let result: WebAccess;
      if (loginMethod === 'key') {
        if (privateFile === null) {
          throw new RememberMeError('key-import');
        }
        let key: import('../login/wasm-key').WasmLoginKey;
        try {
          const { WasmLoginKey } = await import('../login/wasm-key').catch((error) => {
            throw keyLoginError(error, 'module', 'unavailable');
          });
          key = await WasmLoginKey.import(
            privateFile,
            passphrase,
            certificateFile,
            selectedScope,
            user,
            signal,
          );
        } catch (error) {
          throw keyLoginError(error, 'key-import');
        } finally {
          privateFile = null;
          certificateFile = null;
          passphrase = '';
        }
        try {
          result = await selectedClient.publicKey(user, key, signal);
        } catch (error) {
          throw keyLoginError(error, 'authentication', 'unavailable');
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
            setNotice({ key: 'registered', color: 'green', context: result.snapshot() });
          }
        } catch (error) {
          if (current === generation.current) {
            setNotice({ ...errorNotice(error), context: result.snapshot() });
            uncertain = error instanceof RememberMeError && error.code === 'outcome-unknown';
            setRememberUncertain(uncertain);
          }
        }
      }
      if (current === generation.current) {
        setTerminalLogin(null);
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

  async function logout(selected = access.current) {
    if (managementLocked) {
      return;
    }
    if (selected === null) {
      return;
    }
    const current = ++generation.current;
    operation.current?.abort();
    operation.current = null;
    setClosing(true);
    setBusy(true);
    setNotice({ key: 'logoutPending', color: 'yellow', context: selected.snapshot() });
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
      setTerminalLogin(null);
      setNoticeOpen(false);
      setClosing(false);
      setOptIn(false);
      setApplicationMenuOpen(false);
      setRetiredAccess(selected);
      setLoginOpen(false); // The remaining active tab is selected by the workspace.
      setRememberUncertain(false);
      setNotice({ ...cleanupNotice(result, 'loggedOut'), context: selected.snapshot() });
    } catch {
      if (current === generation.current) {
        setNotice({ key: 'logoutUnknown', color: 'red', context: selected.snapshot() });
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
    setApplicationMenuOpen(false);
    setLoginOpen(true);
    setTerminalLogin(null);
    setOptIn(false);
    setProviderInformation(null);
    setNotice(null);
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
        authentication={
          terminalLogin === null
            ? null
            : ({
                ...terminalLogin,
                step: loginStep,
                pending: busy,
                remembering: loginPending === 'remember',
                message: !busy && notice ? t(notice.key) : null,
                provider: providerInformation,
                onAnswer: (value) => {
                  const pending = pendingResponse.current;
                  if (pending?.generation === terminalLogin.id && pending.step === loginStep) {
                    pending.answer(value);
                  }
                },
                onCancel: () => {
                  if (generation.current === terminalLogin.id) {
                    cancel();
                  }
                },
              } satisfies AuthenticationView)
        }
        authorizationEvent={authorizationEvent}
        retiredAccess={retiredAccess}
        unavailableAccess={closing || rememberUncertain ? access.current : null}
        blocked={closing || busy || rememberUncertain || managementLocked}
        focusBlocked={
          loginOpen ||
          (loginStep !== null && terminalLogin === null) ||
          applicationMenuOpen ||
          appearanceOpen ||
          noticeOpen ||
          confirm !== null
        }
        title={title}
        onSignIn={showLogin}
        onNewConnection={() => showLogin()}
        onSelectAccess={selectAccess}
        onActionLock={setManagementLocked}
        onTabCount={setTabCount}
        onLogout={(selected) => {
          void logout(selected);
        }}
        notice={
          notice !== null && !loginOpen && !noticeOpen ? (
            <Tooltip label={t(notice.key)}>
              <ActionIcon
                variant="subtle"
                color={notice.color}
                size="lg"
                onClick={() => setNoticeOpen(true)}
                aria-label={t('showNotice')}
              >
                {notice.color === 'green' ? <CheckCircleIcon /> : <WarningAmberIcon />}
              </ActionIcon>
            </Tooltip>
          ) : null
        }
        utilities={
          <Menu
            opened={applicationMenuOpen}
            onChange={setApplicationMenuOpen}
            position="bottom-end"
          >
            <Menu.Target>
              <ActionIcon variant="subtle" color="gray" size="lg" aria-label={t('applicationMenu')}>
                <MoreVertIcon />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item
                icon={<PaletteIcon fontSize="small" />}
                onClick={() => setAppearanceOpen(true)}
              >
                {t('appearance')}
              </Menu.Item>
              <Menu.Item
                component="a"
                icon={<DescriptionIcon fontSize="small" />}
                href="/_bifroest/files/third-party-licenses.txt"
                target="_blank"
                rel="noopener noreferrer"
              >
                {t('notices')}
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        }
      />
      <Modal
        classNames={{ content: 'confirmation-dialog login-dialog' }}
        size="sm"
        padding="lg"
        centered
        lockScroll={false}
        opened={loginOpen && terminalLogin === null && confirm === null}
        onClose={closeLogin}
        closeOnClickOutside={false}
        closeOnEscape={!busy}
        title={t('login')}
        closeButtonProps={{ 'aria-label': t('close') }}
      >
        {notice && loginOpen && (
          <Alert role="status" color={notice.color}>
            <NoticeBody notice={notice} />
          </Alert>
        )}
        <Stack gap="sm">
          {linkChoices.length > 1 ? (
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
          ) : (
            loginMetadata.scope.slug && (
              <Text size="sm" c="dimmed">
                {loginMetadata.scope.slug}
              </Text>
            )
          )}
          {saved === 'ready' && (
            <Group justify="space-between" gap="xs">
              <Button
                variant="light"
                size="xs"
                disabled={busy}
                onClick={() => {
                  void resume();
                }}
              >
                {t('useSaved')}
              </Button>
              {snapshot === null && (
                <Menu>
                  <Menu.Target>
                    <ActionIcon
                      variant="subtle"
                      color="gray"
                      size="sm"
                      disabled={busy}
                      aria-label={t('savedOptions')}
                    >
                      <MoreVertIcon fontSize="small" />
                    </ActionIcon>
                  </Menu.Target>
                  <Menu.Dropdown>
                    <Menu.Item
                      icon={<LogoutIcon fontSize="small" />}
                      onClick={() => showConfirmation('revoke')}
                    >
                      {t('forgetSaved')}
                    </Menu.Item>
                    <Menu.Item
                      icon={<DeleteOutlineIcon fontSize="small" />}
                      onClick={() => showConfirmation('local')}
                    >
                      {t('removeLocalOnly')}
                    </Menu.Item>
                  </Menu.Dropdown>
                </Menu>
              )}
            </Group>
          )}
          {saved === 'pending' && (
            <Alert color="yellow">
              <p>{t('pending')}</p>
              {snapshot === null && (
                <Button variant="outline" disabled={busy} onClick={() => showConfirmation('local')}>
                  {t('removeLocal')}
                </Button>
              )}
            </Alert>
          )}
          {saved === 'unavailable' && <Alert color="yellow">{t('storageUnavailable')}</Alert>}
          <form
            key={loginMetadata.scope.slug}
            method={loginMethod === 'key' ? 'dialog' : 'post'}
            action={loginMethod === 'key' ? undefined : '/_bifroest/api/v1/login/password'}
            className="login-form"
            onSubmit={(event) => {
              event.preventDefault();
              void login(event.currentTarget);
            }}
          >
            <SegmentedControl
              aria-label={t('loginMethod')}
              value={loginMethod}
              onChange={setLoginMethod}
              disabled={busy}
              fullWidth
              data={[
                {
                  value: 'password',
                  label: (
                    <>
                      <span aria-hidden="true">{t('loginPasswordTab')}</span>
                      <VisuallyHidden>{t('passwordMethod')}</VisuallyHidden>
                    </>
                  ),
                },
                {
                  value: 'interactive',
                  label: (
                    <>
                      <span aria-hidden="true">{t('loginInteractiveTab')}</span>
                      <VisuallyHidden>{t('interactiveMethod')}</VisuallyHidden>
                    </>
                  ),
                },
                {
                  value: 'key',
                  label: (
                    <>
                      <span aria-hidden="true">{t('loginKeyTab')}</span>
                      <VisuallyHidden>{t('keyMethod')}</VisuallyHidden>
                    </>
                  ),
                },
              ]}
            />
            {loginMetadata.requestUser && (
              <TextInput
                name="user"
                label={t('user')}
                autoComplete="username"
                data-autofocus
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
                <Text size="xs" c="dimmed">
                  {t('keyLocalHint')}
                </Text>
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
            {saved === 'missing' && (
              <Checkbox
                checked={optIn}
                onChange={(event) => setOptIn(event.currentTarget.checked)}
                disabled={busy || saved !== 'missing'}
                label={t('remember')}
                size="sm"
              />
            )}
            <Group justify="flex-end" gap="xs">
              <Button type="submit" loading={busy} disabled={busy || managementLocked}>
                {t('login')}
              </Button>
              {busy && (
                <Button type="button" variant="default" onClick={cancel}>
                  {t('cancel')}
                </Button>
              )}
            </Group>
          </form>
        </Stack>
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
          <Stack
            gap="sm"
            className="access-notice"
            data-access-principal={notice.context?.principal}
          >
            {notice.context && (
              <Text size="sm" c="dimmed">
                {notice.context.scope.slug || '/'} · {notice.context.principal}
              </Text>
            )}
            <Alert role="status" color={notice.color}>
              <NoticeBody notice={notice} />
            </Alert>
            {snapshot && (rememberUncertain || closing) && (
              <Button
                color="red"
                variant="light"
                disabled={busy || managementLocked}
                onClick={() => {
                  void logout();
                }}
              >
                {t(closing ? 'retryLogout' : 'logout')}
              </Button>
            )}
          </Stack>
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

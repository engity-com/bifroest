import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useCallback, useEffect, useEffectEvent, useLayoutEffect, useRef, useState } from 'react';
import { keyLoginError } from '../login/diagnostic';
import { LoginDialog, type SavedAccessState as Saved } from '../login/LoginDialog';
import { verificationLink } from '../login/links';
import type { AccessSnapshot, LoginStep, LogoutResult, WebAccess } from '../remember';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import type { AuthenticationView } from '../terminal/AuthenticationTerminal';
import { ConnectionWorkspace } from '../workspace/ConnectionWorkspace';
import { type ConnectionView, maximumTabs, type WorkspaceControls } from '../workspace/model';
import {
  ApplicationNoticeDialog,
  BulkConfirmationDialog,
  SavedAccessConfirmationDialog,
} from './ApplicationDialogs';
import { ApplicationMenu } from './ApplicationMenu';
import { errorNotice, type ApplicationNotice as Notice } from './ApplicationNotice';
import { reportUiError } from './error-report';
import {
  type LinkMetadata,
  linkSlugs,
  loadLinkMetadata,
  loginOptionFor,
  loginOptionKey,
} from './link-metadata';
import type { ManagementLocation } from './management-location';
import { ActionIcon, Tooltip } from './material';
import { t } from './messages';
import { preferredUsername, saveSuccessfulUsername } from './preferences';
import { type ProfileResetResult, resetPeerContexts, resetProfile } from './profile-reset';
import { observeProfileResets } from './profile-reset-peers';
import { useSlugRoute } from './slug-router';
import { ThemeSwitcher } from './ThemeSwitcher';

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
  const [loginUser, setLoginUser] = useState(() =>
    metadata.loginOptions[0]?.requestUser ? preferredUsername(metadata.scope) : '',
  );
  const access = useRef<WebAccess | null>(null);
  // An independently confirmed primary may still be enrolling RememberMe. Keep
  // that owning grant recoverable without confusing it with an internal tab's
  // active selection (for example when a connecting tab is retired).
  const candidate = useRef<WebAccess | null>(null);
  const savedHandle = useRef<BrowserBinding | null>(null);
  const confirmationHandle = useRef<BrowserBinding | null>(null);
  const operation = useRef<AbortController | null>(null);
  const routeOperation = useRef<AbortController | null>(null);
  const automaticSelection = useRef<string | null>(null);
  const seenRoute = useRef<{ key: string; revision: number } | null>(null);
  const generation = useRef(0);
  const [snapshot, setSnapshot] = useState<AccessSnapshot | null>(null);
  const [saved, setSaved] = useState<Saved>('loading');
  const [busy, setBusy] = useState(false);
  const [routing, setRouting] = useState(false);
  const [routeFailed, setRouteFailed] = useState(false);
  const [routeRevision, setRouteRevision] = useState(0);
  const [closing, setClosing] = useState(false);
  const [managementLocked, setManagementLocked] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirm, setConfirm] = useState<'revoke' | 'local' | null>(null);
  const [optIn, setOptIn] = useState(false);
  const [passwordKey, setPasswordKey] = useState(0);
  const [loginOpen, setLoginOpen] = useState(true);
  const [applicationMenuOpen, setApplicationMenuOpen] = useState(false);
  const [bulkConfirm, setBulkConfirm] = useState<'close' | 'reset' | null>(null);
  const workspaceControls = useRef<WorkspaceControls | null>(null);
  const registerWorkspaceControls = useCallback((controls: WorkspaceControls | null) => {
    workspaceControls.current = controls;
  }, []);
  const peerResetting = useRef(false);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [authorizationEvent, setAuthorizationEvent] = useState<WebAccess | null>(null);
  const [retiredAccess, setRetiredAccess] = useState<WebAccess | null>(null);
  const [tabCount, setTabCount] = useState(0);
  const views = useRef<readonly ConnectionView[]>([]);
  const [activeView, setActiveView] = useState<number | null>(null);
  const [tabScopes, setTabScopes] = useState<readonly LinkMetadata['scope'][]>([]);
  const registerViews = useCallback((next: readonly ConnectionView[]) => {
    views.current = next;
    setTabScopes(next.map((view) => view.scope));
  }, []);
  const [rememberUncertain, setRememberUncertain] = useState(false);
  const [loginChoice, setLoginChoice] = useState(() =>
    metadata.loginOptions[0] ? loginOptionKey(metadata.loginOptions[0]) : '',
  );
  const selectedLoginOption = loginOptionFor(loginMetadata, loginChoice);
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

  const routeBlocked = useCallback(() => {
    setNotice((current) =>
      current &&
      (rememberUncertain ||
        closing ||
        ['unknown', 'logoutUnknown', 'localCleanupFailed', 'logoutPending'].includes(current.key))
        ? current
        : { key: 'slugNavigationBlocked', color: 'yellow' },
    );
    setNoticeOpen(true);
  }, [closing, rememberUncertain]);
  const slugRoute = useSlugRoute(
    busy ||
      closing ||
      managementLocked ||
      rememberUncertain ||
      confirm !== null ||
      bulkConfirm !== null,
    routeBlocked,
    [
      metadata.scope.slug,
      ...metadata.publishedSlugs,
      loginMetadata.scope.slug,
      ...loginMetadata.publishedSlugs,
      ...tabScopes.map((scope) => scope.slug),
    ].filter(
      (slug) =>
        slug !== '' ||
        metadata.rootAvailable ||
        loginMetadata.rootAvailable ||
        tabScopes.some((scope) => scope.slug === ''),
    ),
    views.current,
  );
  const routeOrigin = slugRoute.scope?.origin ?? null;
  const routeSlug = slugRoute.scope?.slug ?? null;
  const metadataReady =
    !slugRoute.canonicalizing &&
    !routing &&
    !routeFailed &&
    routeOrigin === loginMetadata.scope.origin &&
    routeSlug === loginMetadata.scope.slug;
  const activeUsesLoginScope =
    snapshot !== null &&
    snapshot.scope.origin === loginMetadata.scope.origin &&
    snapshot.scope.slug === loginMetadata.scope.slug;

  const readSaved = useCallback(async (current = generation.current) => {
    const scope = link.current.scope;
    try {
      const handle = await BrowserBinding.load(scope);
      if (current !== generation.current || scope !== link.current.scope) {
        return;
      }
      savedHandle.current = handle;
      setSaved(handle === null ? 'missing' : handle.binding === null ? 'pending' : 'ready');
    } catch (error) {
      if (current === generation.current && scope === link.current.scope) {
        reportUiError('remember-storage', error);
        savedHandle.current = null;
        setSaved('unavailable');
      }
    }
  }, []);

  useLayoutEffect(() => {
    if (seenRoute.current?.key === slugRoute.key && seenRoute.current.revision === routeRevision) {
      return;
    }
    // Normalize before discovery: the replacement must not abort/reissue a
    // public read or apply a pending target to an old owner behind sign-in.
    if (slugRoute.canonicalizing) {
      routeOperation.current?.abort();
      routeOperation.current = null;
      setRouting(false);
      setLoginOpen(true);
      return;
    }
    const initial = seenRoute.current === null;
    const retry = seenRoute.current !== null && seenRoute.current.revision !== routeRevision;
    seenRoute.current = { key: slugRoute.key, revision: routeRevision };
    const selected = views.current.find(
      (view) =>
        view.id === slugRoute.view &&
        view.scope.origin === routeOrigin &&
        view.scope.slug === routeSlug,
    );
    if (selected) {
      if (
        slugRoute.management &&
        (selected.access.snapshot().environment !== 'management' ||
          (slugRoute.management.managementFlow !== '' &&
            (selected.access.snapshot().flow?.name ?? 'management') !==
              slugRoute.management.managementFlow))
      ) {
        setNotice({ key: 'managementRouteMismatch', color: 'red' });
        setLoginOpen(true);
        return;
      }
      if (selected.navigation && slugRoute.management) {
        selected.navigation.current = slugRoute.management;
      }
      // View navigation only selects a still-owned local view. In particular it
      // must not enter routing/blocked, reload discovery or touch saved access.
      if (routeOperation.current !== null) {
        generation.current++;
        routeOperation.current.abort();
        routeOperation.current = null;
      }
      access.current = selected.access;
      if (candidate.current === selected.access) {
        candidate.current = null;
      }
      setSnapshot(selected.access.snapshot());
      setActiveView(selected.id);
      setLoginOpen(false);
      setTerminalLogin(null);
      setRouting(false);
      setRouteFailed(false);
      return;
    }
    // Active/uncertain operations are blocked by the router. A stopped local
    // authentication console has no operation left to cancel and must not keep
    // the new route behind an old generation's unresponsive close callback.
    if (operation.current === null) {
      setTerminalLogin(null);
      setLoginStep(null);
      pendingResponse.current = null;
    }
    routeOperation.current?.abort();
    routeOperation.current = null;
    if (
      !retry &&
      routeOrigin === link.current.scope.origin &&
      routeSlug === link.current.scope.slug
    ) {
      setRouting(false);
      setRouteFailed(false);
      if (!initial) {
        setLoginOpen(true);
        setPasswordKey((value) => value + 1);
        setOptIn(false);
        void readSaved();
      }
      return;
    }
    const current = ++generation.current;
    setLoginOpen(true);
    setPasswordKey((value) => value + 1);
    setOptIn(false);
    setProviderInformation(null);
    // Retiring the last tab can rediscover its scope after sign-in was opened
    // for another link. Do not erase that exact scope's completed logout receipt
    // (or local-cleanup warning) while loading its public metadata.
    setNotice((previous) =>
      previous?.context?.scope.origin === routeOrigin &&
      previous.context.scope.slug === routeSlug &&
      ['loggedOut', 'newerKept', 'localCleanupFailed'].includes(previous.key)
        ? previous
        : null,
    );
    savedHandle.current = null;
    setSaved('loading');
    if (routeOrigin === null || routeSlug === null) {
      setRouting(false);
      setRouteFailed(true);
      reportUiError('application', new RememberMeError('unavailable'));
      return;
    }
    const controller = new AbortController();
    routeOperation.current = controller;
    setRouting(true);
    setRouteFailed(false);
    void loadLinkMetadata({ origin: routeOrigin, slug: routeSlug }, controller.signal)
      .then((next) => {
        if (current !== generation.current || controller.signal.aborted) {
          return;
        }
        link.current = next;
        client.current = new BrowserClient(next.scope);
        setLoginMetadata(next);
        const option = next.loginOptions[0] ?? null;
        setLoginChoice(option ? loginOptionKey(option) : '');
        setLoginUser(option?.requestUser ? preferredUsername(next.scope) : '');
        void readSaved(current);
      })
      .catch((error) => {
        if (current !== generation.current || controller.signal.aborted) {
          return;
        }
        setRouteFailed(true);
        reportUiError('application', error);
      })
      .finally(() => {
        if (current === generation.current && routeOperation.current === controller) {
          routeOperation.current = null;
          setRouting(false);
        }
      });
    return () => {
      controller.abort();
    };
  }, [
    slugRoute.key,
    slugRoute.canonicalizing,
    slugRoute.view,
    slugRoute.management,
    routeOrigin,
    routeSlug,
    routeRevision,
    readSaved,
  ]);
  useEffect(() => {
    void readSaved();
    return () => {
      generation.current++;
      operation.current?.abort();
      routeOperation.current?.abort();
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

  const selectView = useCallback(
    (selected: ConnectionView | null, replace = false) => {
      if (selected === null || (replace && (routing || loginOpen))) {
        // Lifecycle fallback behind an existing login intent must not replace the
        // requested login URL. User/History activation is committed by the route.
        setActiveView(selected?.id ?? null);
        if (selected === null && (loginOpen || routing || operation.current !== null)) {
          return;
        }
        selectAccess(selected?.access ?? null);
        return;
      }
      const flow = selected.access.snapshot().flow;
      const managementFlow = flow?.name ?? 'management';
      let target = selected.navigation?.current ?? undefined;
      if (!target && selected.access.snapshot().environment === 'management') {
        target =
          slugRoute.view === null &&
          slugRoute.scope?.slug === selected.scope.slug &&
          slugRoute.management &&
          (slugRoute.management.managementFlow === '' ||
            slugRoute.management.managementFlow === managementFlow)
            ? { ...slugRoute.management, managementFlow }
            : { managementFlow, page: 'server' };
      }
      void slugRoute.activate(selected.scope.slug, selected.id, replace, target, selected.routeId);
    },
    [
      routing,
      loginOpen,
      selectAccess,
      slugRoute.activate,
      slugRoute.management,
      slugRoute.scope?.slug,
      slugRoute.view,
    ],
  );

  const linkChoices = linkSlugs(metadata, loginMetadata, routeSlug, tabScopes);
  const soleLink = linkChoices.length === 1 ? linkChoices[0] : undefined;
  const automaticDirectorySlug =
    metadataReady &&
    loginOpen &&
    routeSlug === '' &&
    slugRoute.view === null &&
    !loginMetadata.rootAvailable &&
    soleLink !== undefined &&
    loginMetadata.publishedSlugs.includes(soleLink)
      ? soleLink
      : null;
  useEffect(() => {
    if (
      automaticDirectorySlug === null ||
      automaticSelection.current === slugRoute.key ||
      operation.current !== null ||
      busy ||
      closing ||
      managementLocked ||
      rememberUncertain ||
      confirm !== null
    ) {
      return;
    }
    // This selects only an access link, never credentials, a saved grant or an
    // execution. Do not leave an otherwise empty directory in browser history.
    automaticSelection.current = slugRoute.key;
    void slugRoute.navigate(automaticDirectorySlug, true);
  }, [
    automaticDirectorySlug,
    slugRoute.key,
    slugRoute.navigate,
    busy,
    closing,
    managementLocked,
    rememberUncertain,
    confirm,
  ]);

  function selectLoginOption(choice: string) {
    const option = loginOptionFor(link.current, choice);
    if (busy || managementLocked || option === null) {
      return;
    }
    if (option.requestUser && !selectedLoginOption?.requestUser) {
      setLoginUser(preferredUsername(link.current.scope));
    }
    setLoginChoice(choice);
    setPasswordKey((value) => value + 1);
    setProviderInformation(null);
  }

  async function chooseLink(slug: string) {
    if (closing || busy || rememberUncertain || managementLocked || !linkChoices.includes(slug)) {
      return;
    }
    if (slug === routeSlug && slugRoute.view === null && metadataReady) {
      void readSaved();
      return;
    }
    await slugRoute.navigate(slug);
  }

  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (
      operation.current !== null ||
      routeOperation.current !== null ||
      !metadataReady ||
      managementLocked ||
      rememberUncertain ||
      closing
    ) {
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
      reportUiError('application', new RememberMeError('outcome-unknown'));
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
    if (!metadataReady) {
      return;
    }
    const password = form.elements.namedItem('password') as HTMLInputElement | null;
    const selectedLink = link.current;
    const option = loginOptionFor(selectedLink, loginChoice);
    if (option === null) {
      setNotice({ key: 'noLoginMethods', color: 'yellow' });
      return;
    }
    const userInput = form.elements.namedItem('user') as HTMLInputElement | null;
    const user = option.requestUser ? (userInput?.value ?? '') : '';
    if (option.requestUser && user.trim().length === 0) {
      setNotice({ key: 'userRequired', color: 'yellow' });
      reportUiError('application', undefined, 'user-required');
      userInput?.reportValidity();
      return;
    }
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
      if (option.method === 'keyboard-interactive') {
        setTerminalLogin({ id: current, scope: selectedScope, user });
        setLoginOpen(false);
      }
      let result: WebAccess;
      if (option.method === 'public-key') {
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
          option.method === 'keyboard-interactive'
            ? await selectedClient.interactive(user, requestStep, signal)
            : // None uses the existing no-secret login adapter, not an automatic
              // login or a grant created by discovery. The server still authorizes.
              await selectedClient.password(user, option.method === 'none' ? '' : secret, signal);
      }
      if (current !== generation.current) {
        return;
      }
      if (option.requestUser) {
        saveSuccessfulUsername(selectedScope, user);
      }
      access.current = result;
      candidate.current = result;
      setSnapshot(result.snapshot());
      if (
        slugRoute.management &&
        (result.snapshot().environment !== 'management' ||
          (slugRoute.management.managementFlow !== '' &&
            result.snapshot().flow?.name !== slugRoute.management.managementFlow))
      ) {
        setNotice({ key: 'managementRouteMismatch', color: 'red', context: result.snapshot() });
        setTerminalLogin(null);
        setLoginOpen(true);
        return;
      }
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
        reportUiError('application', new RememberMeError('denied'));
        setNotice({ key: 'denied', color: 'yellow' });
        return;
      }
      access.current = result;
      candidate.current = result;
      setSnapshot(result.snapshot());
      if (
        slugRoute.management &&
        (result.snapshot().environment !== 'management' ||
          (slugRoute.management.managementFlow !== '' &&
            result.snapshot().flow?.name !== slugRoute.management.managementFlow))
      ) {
        setNotice({ key: 'managementRouteMismatch', color: 'red', context: result.snapshot() });
        setLoginOpen(true);
        return;
      }
      setClosing(false);
      setLoginOpen(false);
      setRememberUncertain(false);
      setAuthorizationEvent(result);
    });
  }

  function cleanupNotice(result: LogoutResult, success: 'loggedOut' | 'remoteRevoked'): Notice {
    if (result.localState === 'unavailable') {
      reportUiError('remember-storage', new RememberMeError('unavailable'));
    }
    return result.localState === 'changed'
      ? { key: 'newerKept', color: 'yellow' }
      : result.localState === 'unavailable'
        ? { key: 'localCleanupFailed', color: 'yellow' }
        : { key: success, color: 'green' };
  }

  async function logout(selected = access.current) {
    if (managementLocked || routeOperation.current !== null) {
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
      setClosing(false);
      setOptIn(false);
      setApplicationMenuOpen(false);
      setRetiredAccess(selected);
      setLoginOpen(false); // The remaining active tab is selected by the workspace.
      setRememberUncertain(false);
      setNotice({ ...cleanupNotice(result, 'loggedOut'), context: selected.snapshot() });
    } catch (error) {
      if (current === generation.current) {
        reportUiError('logout', error, 'logout-unknown');
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
  function resetAccesses() {
    return [
      ...new Set([
        ...views.current.map((view) => view.access),
        ...(access.current ? [access.current] : []),
        ...(candidate.current ? [candidate.current] : []),
        ...(retiredAccess ? [retiredAccess] : []),
      ]),
    ];
  }
  function resetViews() {
    candidate.current = null;
    access.current = null;
    savedHandle.current = null;
    confirmationHandle.current = null;
    pendingResponse.current = null;
    setSnapshot(null);
    setAuthorizationEvent(null);
    setRetiredAccess(null);
    setRememberUncertain(false);
    setTerminalLogin(null);
    setLoginStep(null);
    setLoginPending(null);
    setProviderInformation(null);
    setLoginOpen(false);
    setLoginUser('');
    setSaved('missing');
    setLoginChoice(
      loginMetadata.loginOptions[0] ? loginOptionKey(loginMetadata.loginOptions[0]) : '',
    );
    return workspaceControls.current?.closeAll({ resetConfirmed: true }) ?? true;
  }
  const receiveReset = useEffectEvent(
    async (covered: readonly string[]): Promise<ProfileResetResult> => {
      if (peerResetting.current) {
        return { localCleared: false, remoteUnconfirmed: 1, viewsClosed: false };
      }
      peerResetting.current = true;
      const selected = resetAccesses();
      const interrupted = operation.current !== null;
      const current = ++generation.current;
      operation.current?.abort();
      operation.current = null;
      routeOperation.current?.abort();
      routeOperation.current = null;
      setBulkConfirm(null);
      setConfirm(null);
      setApplicationMenuOpen(false);
      setBusy(true);
      setClosing(true);
      setPasswordKey((value) => value + 1);
      setOptIn(false);
      try {
        const raw = await resetPeerContexts({
          covered,
          accesses: selected,
          closeViews: resetViews,
        });
        const result = { ...raw, remoteUnconfirmed: raw.remoteUnconfirmed + (interrupted ? 1 : 0) };
        if (current === generation.current) {
          if (!result.localCleared) {
            setSaved('unavailable');
          }
          const complete =
            result.localCleared && result.remoteUnconfirmed === 0 && result.viewsClosed;
          setNotice({
            key: complete ? 'resetComplete' : 'resetPartial',
            color: complete ? 'green' : 'yellow',
            reset: result,
          });
          setNoticeOpen(true);
        }
        return result;
      } finally {
        peerResetting.current = false;
        if (current === generation.current) {
          setBusy(false);
          setClosing(false);
        }
      }
    },
  );
  useEffect(() => observeProfileResets((covered) => receiveReset(covered)), []);
  async function confirmBulk() {
    if (managementLocked || busy || routing || closing || bulkConfirm === null) {
      return;
    }
    const action = bulkConfirm;
    setBulkConfirm(null);
    setApplicationMenuOpen(false);
    if (action === 'close') {
      workspaceControls.current?.closeAll();
      return;
    }
    const selected = resetAccesses();
    peerResetting.current = true;
    const current = ++generation.current;
    operation.current?.abort();
    operation.current = null;
    routeOperation.current?.abort();
    routeOperation.current = null;
    setBusy(true);
    setClosing(true);
    setNotice(null);
    setPasswordKey((value) => value + 1);
    setOptIn(false);
    try {
      const result = await resetProfile({
        explicitConfirmation: true,
        accesses: selected,
        closeViews: resetViews,
      });
      if (current === generation.current) {
        if (!result.localCleared) {
          setSaved('unavailable');
        }
        const complete =
          result.localCleared && result.remoteUnconfirmed === 0 && result.viewsClosed;
        setNotice({
          key: complete ? 'resetComplete' : 'resetPartial',
          color: complete ? 'green' : 'yellow',
          reset: result,
        });
        setNoticeOpen(true);
      }
    } catch (error) {
      if (current === generation.current) {
        setNotice(errorNotice(error));
        setNoticeOpen(true);
      }
    } finally {
      peerResetting.current = false;
      if (current === generation.current) {
        setBusy(false);
        setClosing(false);
      }
    }
  }

  function showLogin(scope = access.current?.snapshot().scope ?? slugRoute.scope ?? undefined) {
    if (closing || busy || rememberUncertain || managementLocked) {
      return;
    }
    if (tabCount >= maximumTabs) {
      setNotice({ key: 'terminalTabLimit', color: 'yellow' });
      setNoticeOpen(true);
      return;
    }
    setApplicationMenuOpen(false);
    setTerminalLogin(null);
    setOptIn(false);
    setProviderInformation(null);
    setNotice(null);
    if (
      scope &&
      scope.origin === metadata.scope.origin &&
      (scope.slug !== routeSlug || slugRoute.view !== null)
    ) {
      // Explicit sign-in clears the local view intent, even for the same URL.
      // Its route effect may discover metadata for a previously selected tab.
      // Open the form only from that committed effect, after its password reset,
      // or input entered into an earlier form could be discarded by the commit.
      void slugRoute.navigate(scope.slug);
      return;
    }
    setLoginOpen(true);
    if (routing) {
      return;
    }
    setLoginUser(
      loginOptionFor(link.current, loginChoice)?.requestUser
        ? preferredUsername(link.current.scope)
        : '',
    );
    void readSaved();
  }
  function closeLogin() {
    const selected = views.current.find((view) => view.id === activeView);
    if (selected && !busy && !closing && !rememberUncertain && !managementLocked) {
      void slugRoute.activate(
        selected.scope.slug,
        selected.id,
        true,
        selected.navigation?.current ?? undefined,
        selected.routeId,
      );
    }
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

  // A requested completion/cleanup notice owns focus even when retiring the
  // last tab also opens sign-in. Do not stack a new login above its receipt.
  const ownedNoticeOpen = noticeOpen && (!!notice?.context || !!notice?.reset);
  return (
    <>
      <ConnectionWorkspace
        activeView={activeView}
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
        blocked={closing || busy || routing || rememberUncertain || managementLocked}
        focusBlocked={
          loginOpen ||
          slugRoute.canonicalizing ||
          (loginStep !== null && terminalLogin === null) ||
          applicationMenuOpen ||
          bulkConfirm !== null ||
          noticeOpen ||
          confirm !== null
        }
        title={title}
        onSignIn={showLogin}
        onNewConnection={() => showLogin()}
        onSelectView={selectView}
        onViewsChange={registerViews}
        onWorkspaceControls={registerWorkspaceControls}
        managementLocation={slugRoute.management}
        onManagementNavigate={(
          owner: ConnectionView,
          next: ManagementLocation,
          replace = false,
        ) => {
          if (
            !managementLocked &&
            !busy &&
            !closing &&
            !routing &&
            owner.id === activeView &&
            (owner.access.snapshot().flow?.name ?? 'management') === next.managementFlow
          ) {
            void slugRoute.activate(owner.scope.slug, owner.id, replace, next, owner.routeId);
          }
        }}
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
          <>
            <ThemeSwitcher scheme={scheme} onScheme={onScheme} />
            <ApplicationMenu
              opened={applicationMenuOpen}
              onChange={setApplicationMenuOpen}
              closeDisabled={
                tabCount === 0 ||
                busy ||
                closing ||
                routing ||
                managementLocked ||
                rememberUncertain
              }
              resetDisabled={busy || closing || routing || managementLocked}
              onCloseAll={() => setBulkConfirm('close')}
              onReset={() => setBulkConfirm('reset')}
            />
          </>
        }
      />
      <BulkConfirmationDialog
        action={bulkConfirm}
        disabled={busy || closing || routing || managementLocked}
        onClose={() => setBulkConfirm(null)}
        onConfirm={() => {
          void confirmBulk();
        }}
      />
      <LoginDialog
        state={{
          open: loginOpen && terminalLogin === null && confirm === null && !ownedNoticeOpen,
          metadata: loginMetadata,
          ready: metadataReady,
          route: { slug: routeSlug, origin: routeOrigin, failed: routeFailed, links: linkChoices },
          saved,
          activeUsesScope: activeUsesLoginScope,
          notice: loginOpen ? notice : null,
          choice: loginChoice,
          user: loginUser,
          optIn,
          inputRevision: passwordKey,
          busy,
          managementLocked,
          rememberUncertain,
        }}
        actions={{
          close: closeLogin,
          chooseLink: (slug) => {
            void chooseLink(slug);
          },
          chooseMethod: selectLoginOption,
          changeUser: setLoginUser,
          changeOptIn: setOptIn,
          submit: (form) => {
            void login(form);
          },
          cancel,
          resume: () => {
            void resume();
          },
          confirmSaved: showConfirmation,
          retryMetadata: () => setRouteRevision((value) => value + 1),
          showNotice: () => setNoticeOpen(true),
        }}
      />
      <ApplicationNoticeDialog
        opened={(noticeOpen && !loginOpen) || ownedNoticeOpen}
        notice={notice}
        logoutPending={closing}
        logoutDisabled={busy || managementLocked}
        onClose={() => setNoticeOpen(false)}
        onLogout={
          snapshot && (rememberUncertain || closing)
            ? () => {
                void logout();
              }
            : undefined
        }
      />
      <SavedAccessConfirmationDialog
        action={confirm}
        scope={confirmationHandle.current?.scope}
        onClose={() => setConfirm(null)}
        onConfirm={() => {
          void forget();
        }}
      />
    </>
  );
}

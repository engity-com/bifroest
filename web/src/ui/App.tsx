import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import {
    useCallback,
    useEffect,
    useEffectEvent,
    useLayoutEffect,
    useRef,
    useState,
    useSyncExternalStore,
} from 'react';
import { AuthorizationHandoff } from '../application/authorization-handoff';
import type { ManagementLocation } from '../application/management-location';
import { ApplicationNavigation } from '../application/navigation';
import type { ProfileResetResult } from '../application/reset-contracts';
import { ApplicationResetOwner, type ResetBoundary } from '../application/reset-owner';
import { LoginAttempt } from '../login/attempt';
import { allowsSavedLogin, loginChoiceFor, savedLoginChoice } from '../login/choice';
import { LoginDialog, type SavedAccessState as Saved } from '../login/LoginDialog';
import { verificationLink } from '../login/links';
import type { AccessSnapshot, LogoutResult, WebAccess } from '../remember';
import { BrowserBinding, BrowserClient, RememberMeError } from '../remember';
import { rememberMeEnabled } from '../remember/policy';
import type { AuthenticationView } from '../terminal/authentication-view';
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
    type DiscoveryFailure,
    type LinkMetadata,
    linkSlugs,
    loadLinkMetadata,
    loginOptionFor,
} from './link-metadata';
import { ActionIcon, Tooltip } from './material';
import { t } from './messages';
import { preferredUsername, saveSuccessfulUsername } from './preferences';
import { resetPeerContexts, resetProfile } from './profile-reset';
import { observeProfileResets } from './profile-reset-peers';
import { useSlugRoute } from './slug-router';
import { ThemeSwitcher } from './ThemeSwitcher';

export function App({
    metadata,
    initialDiscoveryFailure,
    title = t('brand'),
    scheme,
    onScheme,
}: {
    metadata: LinkMetadata;
    initialDiscoveryFailure?: DiscoveryFailure | undefined;
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
    const [handoff] = useState(() => new AuthorizationHandoff<WebAccess>());
    const handoffState = useSyncExternalStore(handoff.subscribe, handoff.getSnapshot);
    const savedHandle = useRef<BrowserBinding | null>(null);
    const confirmationHandle = useRef<BrowserBinding | null>(null);
    const operation = useRef<AbortController | null>(null);
    const [navigation] = useState(
        () => new ApplicationNavigation(loadLinkMetadata, initialDiscoveryFailure),
    );
    const navigationState = useSyncExternalStore(navigation.subscribe, navigation.getSnapshot);
    const routing = navigationState.phase === 'loading';
    const routeFailed = navigationState.phase === 'failed';
    const automaticSelection = useRef<string | null>(null);
    const generation = useRef(0);
    const [snapshot, setSnapshot] = useState<AccessSnapshot | null>(null);
    const [saved, setSaved] = useState<Saved>('loading');
    const [busy, setBusy] = useState(false);
    const [routeRevision, setRouteRevision] = useState(0);
    const [closing, setClosing] = useState(false);
    const [managementLocked, setManagementLocked] = useState(false);
    const [notice, setNotice] = useState<Notice | null>(null);
    const [confirm, setConfirm] = useState<'revoke' | 'local' | null>(null);
    const [optIn, setOptIn] = useState<boolean | null>(null);
    const [passwordKey, setPasswordKey] = useState(0);
    const [loginOpen, setLoginOpen] = useState(true);
    const [editingRoute, setEditingRoute] = useState<string | null>(null);
    const [applicationMenuOpen, setApplicationMenuOpen] = useState(false);
    const [bulkConfirm, setBulkConfirm] = useState<'close' | 'reset' | null>(null);
    const workspaceControls = useRef<WorkspaceControls | null>(null);
    const registerWorkspaceControls = useCallback((controls: WorkspaceControls | null) => {
        workspaceControls.current = controls;
    }, []);
    const [resetOwner] = useState(() => new ApplicationResetOwner());
    const [noticeOpen, setNoticeOpen] = useState(false);
    const authorizationEvent = handoff.event;
    const [retiredAccess, setRetiredAccess] = useState<WebAccess | null>(null);
    const [tabCount, setTabCount] = useState(0);
    const views = useRef<readonly ConnectionView[]>([]);
    const [activeView, setActiveView] = useState<number | null>(null);
    const [viewLocations, setViewLocations] = useState<ReadonlyMap<number, ManagementLocation>>(
        () => new Map(),
    );
    const [tabScopes, setTabScopes] = useState<readonly LinkMetadata['scope'][]>([]);
    const registerViews = useCallback((next: readonly ConnectionView[]) => {
        views.current = next;
        setTabScopes(next.map((view) => view.scope));
        const owners = new Set(next.map((view) => view.id));
        setViewLocations((previous) =>
            [...previous.keys()].every((owner) => owners.has(owner))
                ? previous
                : new Map([...previous].filter(([owner]) => owners.has(owner))),
        );
    }, []);
    const rememberUncertain = handoffState.phase === 'uncertain';
    const [loginChoice, setLoginChoice] = useState<string | null>(null);
    const effectiveLoginChoice = loginChoiceFor(loginMetadata, saved === 'ready', loginChoice);
    const selectedLoginOption = loginOptionFor(loginMetadata, effectiveLoginChoice);
    useEffect(() => {
        void BrowserBinding.initialize().catch((error) => reportUiError('remember-storage', error));
    }, []);
    const [attempt] = useState(() => new LoginAttempt());
    const attemptState = useSyncExternalStore(attempt.subscribe, attempt.getSnapshot);
    const loginStep = attemptState.prompt;
    const providerInformation = attemptState.provider;
    const deviceLogin = busy && providerInformation?.device ? providerInformation : null;
    const loginPending =
        attemptState.phase === 'enrolling'
            ? 'remember'
            : attemptState.phase === 'authenticating'
              ? 'authentication'
              : null;
    const [terminalLogin, setTerminalLogin] = useState<{
        id: number;
        scope: LinkMetadata['scope'];
        user: string;
    } | null>(null);

    const routeBlocked = useCallback(() => {
        setNotice((current) =>
            current &&
            (rememberUncertain ||
                closing ||
                ['unknown', 'logoutUnknown', 'localCleanupFailed', 'logoutPending'].includes(
                    current.key,
                ))
                ? current
                : { key: 'slugNavigationBlocked', color: 'yellow' },
        );
        // A login dialog already presents this warning inline. Do not queue a
        // second modal that would unexpectedly open after sign-in completes.
        const preserveCurrent =
            notice !== null &&
            (rememberUncertain ||
                closing ||
                ['unknown', 'logoutUnknown', 'localCleanupFailed', 'logoutPending'].includes(
                    notice.key,
                ));
        setNoticeOpen(!loginOpen || preserveCurrent);
    }, [closing, rememberUncertain, loginOpen, notice]);
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
    const slugEditing = editingRoute === slugRoute.key;
    const routeUsername = useRef(slugRoute.user);
    routeUsername.current = slugRoute.user;
    const previousUserRoute = useRef<{ key: string; user: string | null } | null>(null);
    const metadataReady =
        !slugEditing &&
        !slugRoute.canonicalizing &&
        !routing &&
        !routeFailed &&
        routeOrigin === loginMetadata.scope.origin &&
        routeSlug === loginMetadata.scope.slug;
    const activeUsesLoginScope =
        snapshot !== null &&
        snapshot.scope.origin === loginMetadata.scope.origin &&
        snapshot.scope.slug === loginMetadata.scope.slug;

    // Commit the route's initial hint before exposing an editable form. A passive
    // effect could run after the first input event and restore the previous actor.
    useLayoutEffect(() => {
        if (
            !loginOpen ||
            !metadataReady ||
            busy ||
            closing ||
            managementLocked ||
            rememberUncertain
        ) {
            return;
        }
        const previous = previousUserRoute.current;
        const fromRoute = previous?.key !== slugRoute.key || previous.user !== slugRoute.user;
        if (!fromRoute) {
            return;
        }
        const user =
            slugRoute.user ??
            (previous?.key === slugRoute.key
                ? ''
                : selectedLoginOption?.requestUser
                  ? preferredUsername(loginMetadata.scope)
                  : '');
        setLoginUser(user);
        previousUserRoute.current = { key: slugRoute.key, user: slugRoute.user };
        // Publish a newly prefilled hint once. Never echo an older local render
        // back into the route after a newer input event has already updated it.
        if (selectedLoginOption?.requestUser && user !== (slugRoute.user ?? '')) {
            void slugRoute.changeUser(user);
        }
    }, [
        loginOpen,
        metadataReady,
        busy,
        closing,
        managementLocked,
        rememberUncertain,
        slugRoute.key,
        slugRoute.user,
        slugRoute.changeUser,
        selectedLoginOption?.requestUser,
        loginMetadata.scope,
    ]);

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
                setSaved('missing');
            }
        }
    }, []);

    useLayoutEffect(() => {
        return navigation.reconcile(
            {
                key: slugRoute.key,
                revision: routeRevision,
                canonicalizing: slugRoute.canonicalizing,
                scope:
                    routeOrigin === null || routeSlug === null
                        ? null
                        : { origin: routeOrigin, slug: routeSlug },
                view: slugRoute.view,
                management: slugRoute.management,
            },
            {
                views: views.current,
                metadataScope: link.current.scope,
                canonicalizing: () => setLoginOpen(true),
                mismatch: () => {
                    setNotice({ key: 'managementRouteMismatch', color: 'red' });
                    setLoginOpen(true);
                },
                invalidateDiscovery: () => {
                    generation.current++;
                },
                activate: (selected, location) => {
                    if (location) {
                        setViewLocations((previous) =>
                            new Map(previous).set(selected.id, Object.freeze({ ...location })),
                        );
                    }
                    access.current = selected.access;
                    handoff.acknowledge(selected.access);
                    setSnapshot(selected.access.snapshot());
                    setActiveView(selected.id);
                    setLoginOpen(false);
                    setTerminalLogin(null);
                },
                releaseStoppedAuthentication: () => {
                    if (operation.current === null) {
                        setTerminalLogin(null);
                        attempt.cancel();
                    }
                },
                reuse: (initial) => {
                    if (!initial) {
                        setLoginOpen(true);
                        setLoginChoice(null);
                        setPasswordKey((value) => value + 1);
                        setOptIn(null);
                        void readSaved();
                    }
                },
                discover: (scope) => {
                    const current = ++generation.current;
                    setLoginOpen(true);
                    setPasswordKey((value) => value + 1);
                    setOptIn(null);
                    attempt.clearProvider();
                    // Keep an exact scope's authoritative logout/cleanup receipt.
                    setNotice((previous) =>
                        previous?.context !== undefined &&
                        scope !== null &&
                        previous.context.scope.origin === scope.origin &&
                        previous.context.scope.slug === scope.slug &&
                        ['loggedOut', 'newerKept', 'localCleanupFailed'].includes(previous.key)
                            ? previous
                            : null,
                    );
                    savedHandle.current = null;
                    setSaved('loading');
                    return {
                        current: () => current === generation.current,
                        accepted: (next) => {
                            link.current = next;
                            client.current = new BrowserClient(next.scope);
                            setLoginMetadata(next);
                            const option = next.loginOptions[0] ?? null;
                            setLoginChoice(null);
                            setLoginUser(
                                routeUsername.current ??
                                    (option?.requestUser ? preferredUsername(next.scope) : ''),
                            );
                            void readSaved(current);
                        },
                        failed: (error) => reportUiError('application', error),
                    };
                },
            },
        );
    }, [
        slugRoute.key,
        slugRoute.canonicalizing,
        slugRoute.view,
        slugRoute.management,
        routeOrigin,
        routeSlug,
        routeRevision,
        readSaved,
        attempt,
        navigation,
        handoff,
    ]);
    useEffect(() => {
        void readSaved();
        return () => {
            generation.current++;
            operation.current?.abort();
            navigation.retire();
            attempt.cancel();
        };
    }, [readSaved, attempt, navigation]);

    const selectAccess = useCallback(
        (selected: WebAccess | null) => {
            if (!handoff.acknowledge(selected)) {
                return;
            }
            access.current = selected;
            setSnapshot(selected?.snapshot() ?? null);
            if (selected === null) {
                handoff.clear();
                setLoginOpen(false);
            }
        },
        [handoff],
    );

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
            let target = viewLocations.get(selected.id);
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
            void slugRoute.activate(
                selected.scope.slug,
                selected.id,
                replace,
                target,
                selected.routeId,
                selected.access.snapshot().requestingUser ?? '',
            );
        },
        [
            routing,
            loginOpen,
            selectAccess,
            slugRoute.activate,
            slugRoute.management,
            slugRoute.scope?.slug,
            slugRoute.view,
            viewLocations,
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
        const savedChoice =
            choice === savedLoginChoice && saved === 'ready' && allowsSavedLogin(link.current);
        if (busy || managementLocked || (option === null && !savedChoice)) {
            return;
        }
        if (choice === effectiveLoginChoice) {
            setLoginChoice(choice);
            return;
        }
        if (option?.requestUser && !selectedLoginOption?.requestUser) {
            const user = slugRoute.user ?? preferredUsername(link.current.scope);
            setLoginUser(user);
            void slugRoute.changeUser(user, true);
        }
        setLoginChoice(choice);
        setOptIn(null);
        setPasswordKey((value) => value + 1);
        attempt.clearProvider();
    }

    async function chooseLink(slug: string) {
        if (closing || busy || rememberUncertain || managementLocked) {
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
            navigation.busy ||
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
                attempt.clearProvider();
                await readSaved(current);
            }
        }
    }

    function cancel() {
        const enrollmentMayHaveCommitted = attempt.cancel();
        generation.current++;
        operation.current?.abort();
        operation.current = null;
        setBusy(false);
        setTerminalLogin(null);
        setNotice({
            key: enrollmentMayHaveCommitted ? 'unknown' : 'cancelled',
            color: 'yellow',
            ...(enrollmentMayHaveCommitted && handoff.candidate
                ? { context: handoff.candidate.snapshot() }
                : {}),
        });
        if (enrollmentMayHaveCommitted) {
            reportUiError('application', new RememberMeError('outcome-unknown'));
            handoff.uncertain();
            setLoginOpen(false);
        }
        void readSaved();
    }

    async function login(form: HTMLFormElement) {
        if (!metadataReady) {
            return;
        }
        const password = form.elements.namedItem('password') as HTMLInputElement | null;
        const selectedLink = link.current;
        const option = loginOptionFor(selectedLink, effectiveLoginChoice);
        if (option === null) {
            setNotice({ key: 'noLoginMethods', color: 'yellow' });
            return;
        }
        const userInput = form.elements.namedItem('user') as HTMLInputElement | null;
        const user = option.requestUser ? (userInput?.value ?? '') : '';
        if (option.requestUser && user.trim().length === 0) {
            reportUiError('application', undefined, 'user-required');
            return;
        }
        attempt.clearProvider();
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
        const remember = rememberMeEnabled(option.rememberMe, optIn ?? undefined);
        const oidcWindow =
            option.method === 'oidc' ? window.open('/login/#waiting', '_blank') : null;
        if (oidcWindow) {
            oidcWindow.opener = null;
        }
        let oidcNavigated = false;
        try {
            await run(async (signal, current) => {
                let completed: Awaited<ReturnType<LoginAttempt['start']>>;
                const submission = {
                    method: option.method,
                    user,
                    password: secret,
                    scope: selectedScope,
                    privateFile,
                    certificateFile,
                    passphrase,
                    remember,
                };
                privateFile = null;
                certificateFile = null;
                passphrase = '';
                try {
                    completed = await attempt.start(selectedClient, submission, {
                        signal,
                        current: () => current === generation.current,
                        onInteraction: (step) => {
                            setTerminalLogin(
                                step.device ? null : { id: current, scope: selectedScope, user },
                            );
                            setLoginOpen(step.device !== undefined);
                        },
                        onOidcLink: (url) => {
                            if (oidcWindow && !oidcWindow.closed) {
                                try {
                                    oidcWindow.location.replace(url);
                                    oidcNavigated = true;
                                } catch {
                                    /* Keep the fallback link available. */
                                }
                            }
                        },
                        admit: (result) => {
                            if (option.requestUser) {
                                saveSuccessfulUsername(selectedScope, user);
                            }
                            access.current = result;
                            setSnapshot(result.snapshot());
                            if (
                                !handoff.offer(
                                    result,
                                    slugRoute.management?.managementFlow ?? null,
                                    remember,
                                )
                            ) {
                                setNotice({
                                    key: 'managementRouteMismatch',
                                    color: 'red',
                                    context: result.snapshot(),
                                });
                                setTerminalLogin(null);
                                setLoginOpen(true);
                                return false;
                            }
                            setClosing(false);
                            return true;
                        },
                    });
                } finally {
                    privateFile = null;
                    certificateFile = null;
                    passphrase = '';
                }
                if (completed.kind === 'mismatch') {
                    return;
                }
                const result = completed.access;
                if (completed.enrollment === 'registered') {
                    setNotice({ key: 'registered', color: 'green', context: result.snapshot() });
                } else if (completed.error !== undefined) {
                    const notice = errorNotice(completed.error);
                    setNotice(notice === null ? null : { ...notice, context: result.snapshot() });
                }
                if (current === generation.current) {
                    handoff.complete(result, completed.enrollment);
                    setTerminalLogin(null);
                    attempt.clearProvider();
                    setLoginOpen(false);
                }
            });
        } finally {
            if (!oidcNavigated && oidcWindow && !oidcWindow.closed) {
                oidcWindow.close();
            }
        }
    }

    async function resume() {
        await run(async (signal, current) => {
            let result: WebAccess | null;
            try {
                result = await client.current.resume(signal);
            } catch (error) {
                if (error instanceof RememberMeError && error.code === 'unavailable') {
                    await readSaved(current);
                    if (current === generation.current && savedHandle.current === null) {
                        reportUiError('remember-storage', error);
                        return;
                    }
                }
                throw error;
            }
            if (current !== generation.current) {
                return;
            }
            if (result === null) {
                return;
            }
            access.current = result;
            setSnapshot(result.snapshot());
            if (!handoff.offer(result, slugRoute.management?.managementFlow ?? null, false)) {
                setNotice({
                    key: 'managementRouteMismatch',
                    color: 'red',
                    context: result.snapshot(),
                });
                setLoginOpen(true);
                return;
            }
            setClosing(false);
            setLoginOpen(false);
            handoff.complete(result, 'none');
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
        if (managementLocked || navigation.busy) {
            return;
        }
        if (selected === null) {
            return;
        }
        const current = ++generation.current;
        attempt.cancel();
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
            handoff.release(selected);
            setSnapshot(null);
            setTerminalLogin(null);
            setClosing(false);
            setOptIn(null);
            setApplicationMenuOpen(false);
            setRetiredAccess(selected);
            setLoginOpen(false); // The remaining active tab is selected by the workspace.
            attempt.retire();
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
                ...(handoff.candidate ? [handoff.candidate] : []),
                ...(retiredAccess ? [retiredAccess] : []),
            ]),
        ];
    }
    function resetViews() {
        handoff.clear();
        access.current = null;
        savedHandle.current = null;
        confirmationHandle.current = null;
        setSnapshot(null);
        setRetiredAccess(null);
        setTerminalLogin(null);
        attempt.retire();
        setLoginOpen(false);
        setLoginUser('');
        setSaved('missing');
        setLoginChoice(null);
        return workspaceControls.current?.closeAll({ resetConfirmed: true }) ?? true;
    }
    function resetBoundary(): ResetBoundary {
        return {
            accesses: resetAccesses(),
            closeViews: resetViews,
            local: resetProfile,
            peer: resetPeerContexts,
            begin: () => {
                const interrupted = operation.current !== null;
                const current = ++generation.current;
                attempt.cancel();
                operation.current?.abort();
                operation.current = null;
                navigation.retire();
                setBulkConfirm(null);
                setConfirm(null);
                setApplicationMenuOpen(false);
                setBusy(true);
                setClosing(true);
                setPasswordKey((value) => value + 1);
                setOptIn(null);
                return {
                    interrupted,
                    completed: (result) => {
                        if (current !== generation.current) {
                            return;
                        }
                        if (!result.localCleared) {
                            setSaved('unavailable');
                        }
                        const complete =
                            result.localCleared &&
                            result.remoteUnconfirmed === 0 &&
                            result.viewsClosed;
                        setNotice({
                            key: complete ? 'resetComplete' : 'resetPartial',
                            color: complete ? 'green' : 'yellow',
                            reset: result,
                        });
                        setNoticeOpen(true);
                    },
                    failed: (error) => {
                        if (current === generation.current) {
                            setNotice(errorNotice(error));
                            setNoticeOpen(true);
                        }
                    },
                    finish: () => {
                        if (current === generation.current) {
                            setBusy(false);
                            setClosing(false);
                        }
                    },
                };
            },
        };
    }
    const receiveReset = useEffectEvent(
        (covered: readonly string[]): Promise<ProfileResetResult> =>
            resetOwner.run({ kind: 'peer', covered }, resetBoundary()),
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
        setNotice(null);
        await resetOwner.run({ kind: 'local' }, resetBoundary());
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
        setOptIn(null);
        setLoginChoice(null);
        attempt.clearProvider();
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
            link.current.loginOptions[0]?.requestUser ? preferredUsername(link.current.scope) : '',
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
                viewLocations.get(selected.id),
                selected.routeId,
                selected.access.snapshot().requestingUser ?? '',
            );
        }
        if (operation.current !== null) {
            cancel();
        }
        setLoginOpen(false);
        setOptIn(null);
        setPasswordKey((value) => value + 1);
        attempt.clearProvider();
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
                                  if (
                                      generation.current === terminalLogin.id &&
                                      loginStep !== null
                                  ) {
                                      attempt.answer(loginStep, value);
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
                viewLocations={viewLocations}
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
                        void slugRoute.activate(
                            owner.scope.slug,
                            owner.id,
                            replace,
                            next,
                            owner.routeId,
                            owner.access.snapshot().requestingUser ?? '',
                        );
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
                                {notice.color === 'green' ? (
                                    <CheckCircleIcon />
                                ) : (
                                    <WarningAmberIcon />
                                )}
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
                    open:
                        loginOpen && terminalLogin === null && confirm === null && !ownedNoticeOpen,
                    metadata: loginMetadata,
                    ready: metadataReady,
                    route: {
                        slug: routeSlug,
                        origin: routeOrigin,
                        failed: routeFailed,
                        invalid: navigationState.failure === 'invalid-slug' || routeOrigin === null,
                        editing: slugEditing,
                        links: linkChoices,
                    },
                    saved,
                    activeUsesScope: activeUsesLoginScope,
                    notice: loginOpen ? notice : null,
                    choice: effectiveLoginChoice,
                    user: loginUser,
                    optIn: rememberMeEnabled(selectedLoginOption?.rememberMe, optIn ?? undefined),
                    inputRevision: passwordKey,
                    busy,
                    managementLocked,
                    rememberUncertain,
                    oidcLink: providerInformation
                        ? verificationLink(providerInformation.message)
                        : null,
                    device: deviceLogin,
                    deviceReady: deviceLogin !== null && loginStep === deviceLogin,
                }}
                actions={{
                    close: closeLogin,
                    chooseLink: (slug) => {
                        void chooseLink(slug);
                    },
                    editLink: (editing) => setEditingRoute(editing ? slugRoute.key : null),
                    chooseMethod: selectLoginOption,
                    changeUser: (user) => {
                        setLoginUser(user);
                        // Commit the hint with the discrete input update, not a
                        // later router transition that can replay an older actor.
                        void slugRoute.changeUser(user, true);
                    },
                    changeOptIn: setOptIn,
                    submit: (form) => {
                        void login(form);
                    },
                    cancel,
                    continueDevice: () => {
                        if (deviceLogin && loginStep === deviceLogin) {
                            attempt.answer(deviceLogin, '');
                        }
                    },
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

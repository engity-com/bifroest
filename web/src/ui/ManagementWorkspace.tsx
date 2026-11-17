import FactCheckIcon from '@mui/icons-material/FactCheck';
import HomeOutlinedIcon from '@mui/icons-material/HomeOutlined';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import MenuIcon from '@mui/icons-material/Menu';
import PeopleOutlineIcon from '@mui/icons-material/PeopleOutlineOutlined';
import {
    Box,
    Drawer,
    IconButton,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
} from '@mui/material';
import {
    lazy,
    Suspense,
    useCallback,
    useEffect,
    useId,
    useLayoutEffect,
    useRef,
    useState,
} from 'react';
import { type ManagementLocation, managementRoot } from '../application/management-location';
import { ArtifactSecretsContext, useTabArtifactSecrets } from '../artifacts/session-secrets';
import type { WebAccess } from '../remember';
import type { ConnectionActions } from '../terminal/connection-actions';
import type { TerminalState } from '../terminal/socket';
import { AdminBreadcrumbs } from './AdminBreadcrumbs';
import { accessMessages } from './access-messages';
import { type AdminDetail, AdminDetailContext, type AdminSection } from './admin-navigation';
import { reportUiError } from './error-report';
import { hashPath } from './hash-route';
import { LeftPanelCloseIcon } from './LeftPanelCloseIcon';
import { managementCrumbs } from './management-crumbs';
import { ManagementNavigationContext } from './management-navigation';
import { Alert, Button } from './material';
import { t } from './messages';
import { preferredKeepAlive } from './preferences';
import { RouterAnchor } from './RouterAnchor';
import { useAccessStatus } from './use-access-status';

const ManagementPanel = lazy(async () => ({
    default: (await import('../management/ManagementPanel')).ManagementPanel,
}));
const ArtifactPanel = lazy(async () => ({
    default: (await import('../artifacts/ArtifactPanel')).ArtifactPanel,
}));

// One fixed access per mounted management tab. Switching or adding unrelated
// connections must neither rebind this view nor destroy its local evidence.
export function ManagementWorkspace({
    access,
    owner,
    active,
    disabled,
    onActionLock,
    onReauthenticate,
    reauthenticationBlocked = false,
    signal,
    onState,
    onConnectionActions,
    onTitle,
    location,
    onNavigate,
    routeId,
}: {
    access: WebAccess;
    owner: number;
    active: boolean;
    disabled: boolean;
    onActionLock: (owner: number, locked: boolean) => void;
    onReauthenticate: () => void;
    reauthenticationBlocked?: boolean;
    signal: AbortSignal;
    onState?: (id: number, state: TerminalState) => void;
    onConnectionActions?: (id: number, actions: ConnectionActions | null) => void;
    onTitle?: (id: number, title: string) => void;
    location?: ManagementLocation | null;
    onNavigate?: (owner: number, location: ManagementLocation, replace?: boolean) => void;
    routeId?: string;
}) {
    const root: ManagementLocation = {
        managementFlow: access.snapshot().flow?.name ?? 'management',
        page: 'server',
    };
    const [ownRoute, setOwnRoute] = useState<{ access: WebAccess; route: ManagementLocation }>({
        access,
        route: root,
    });
    const route = location ?? (ownRoute.access === access ? ownRoute.route : root);
    const view = route.page;
    const sectionTitle = t(
        view === 'server'
            ? 'workspaceOverview'
            : view === 'version'
              ? 'workspaceVersion'
              : view === 'sessions'
                ? 'workspaceSessions'
                : view === 'recordings'
                  ? 'workspaceRecordings'
                  : 'workspaceAuditlogs',
    );
    useEffect(() => {
        onTitle?.(owner, sectionTitle);
    }, [onTitle, owner, sectionTitle]);
    const secrets = useTabArtifactSecrets(access, signal);
    useLayoutEffect(() => {
        if (signal.aborted) {
            return;
        }
        try {
            const preference = preferredKeepAlive(access.snapshot().scope);
            const channel = access.openManagement(
                (state) => onState?.(owner, state),
                preference === undefined ? {} : { keepAlive: preference },
            );
            const stop = () => channel.disconnect();
            signal.addEventListener('abort', stop, { once: true });
            onConnectionActions?.(owner, channel);
            return () => {
                signal.removeEventListener('abort', stop);
                channel.disconnect();
                onConnectionActions?.(owner, null);
            };
        } catch (error) {
            reportUiError('management-channel', error);
            onState?.(owner, { phase: 'interrupted', reason: 'access-required' });
        }
    }, [access, owner, signal, onState, onConnectionActions]);
    const navigationID = useId();
    const pane = useRef<HTMLElement | null>(null);
    const header = useRef<HTMLElement | null>(null);
    const [wide, setWide] = useState(false);
    const [collapsed, setCollapsed] = useState(false);
    const [temporaryOpen, setTemporaryOpen] = useState(false);
    // Embedded panels still use this capability to avoid a second breadcrumb;
    // the owned route, rather than a late detail effect, is authoritative here.
    const publishDetail = useCallback(
        (_section: AdminSection, _detail: AdminDetail | null) => {},
        [],
    );
    useLayoutEffect(() => {
        if (!pane.current) {
            return;
        }
        let previous: boolean | undefined;
        const update = () => {
            const width = pane.current?.clientWidth ?? 0;
            // Hidden background panes have no responsive layout. Their zero
            // width must not erase this view's navigation choices.
            if (width === 0) {
                return;
            }
            if (header.current) {
                pane.current?.style.setProperty(
                    '--admin-header-height',
                    `${header.current.offsetHeight}px`,
                );
            }
            const next = width > 1136;
            if (previous !== next) {
                const changed = previous !== undefined;
                previous = next;
                setWide(next);
                // Initial measurement is not a breakpoint transition and must
                // not cancel an early explicit navigation-open gesture.
                if (changed) {
                    setCollapsed(false);
                    setTemporaryOpen(false);
                }
            }
        };
        const observer = new ResizeObserver(update);
        observer.observe(pane.current);
        if (header.current) {
            observer.observe(header.current);
        }
        update();
        return () => observer.disconnect();
    }, []);
    const [locked, setLocked] = useState(false);
    const status = useAccessStatus(access, true);
    const remoteDisabled = status !== 'active';
    const lock = useCallback(
        (value: boolean) => {
            setLocked(value);
            if (value) {
                setOwnRoute((current) => ({
                    access,
                    route: { managementFlow: current.route.managementFlow, page: 'sessions' },
                }));
            }
            onActionLock(owner, value);
        },
        [onActionLock, owner, access],
    );
    const navigate = (next: typeof view) => {
        if (active && !disabled && !locked) {
            const target = managementRoot(route.managementFlow, next);
            if (location && onNavigate) {
                onNavigate(owner, target);
            } else {
                setOwnRoute({ access, route: target });
            }
            setTemporaryOpen(false);
        }
    };
    useLayoutEffect(() => {
        if (!active) {
            setTemporaryOpen(false);
        }
    }, [active]);
    const routeNavigate = (next: ManagementLocation, replace = false) => {
        if (active && !disabled && !locked) {
            if (location && onNavigate) {
                onNavigate(owner, next, replace);
            } else {
                setOwnRoute({ access, route: next });
            }
        }
    };
    const href = (target: ManagementLocation) =>
        hashPath(access.snapshot().scope, routeId ?? '-', target);
    const crumbs = managementCrumbs(route, routeNavigate, disabled || locked, href);
    const drawerOpen = wide ? !collapsed : active && temporaryOpen;
    return (
        <AdminDetailContext.Provider value={publishDetail}>
            <ManagementNavigationContext.Provider
                value={{ location: route, navigate: routeNavigate, href }}
            >
                <ArtifactSecretsContext.Provider value={secrets}>
                    <Box
                        ref={pane}
                        component="section"
                        className="admin-shell"
                        aria-label={t('workspaceManagement')}
                        data-admin-drawer={wide ? 'persistent' : 'temporary'}
                        onKeyDown={(event) => {
                            if (event.key === 'Escape' && !wide && temporaryOpen) {
                                setTemporaryOpen(false);
                            }
                        }}
                    >
                        <Drawer
                            variant="persistent"
                            open={drawerOpen}
                            onClose={() => setTemporaryOpen(false)}
                            ModalProps={{
                                container: () => pane.current,
                                disablePortal: true,
                                disableScrollLock: true,
                                keepMounted: true,
                            }}
                            sx={
                                wide
                                    ? {
                                          width: drawerOpen ? 232 : 0,
                                          flexShrink: 0,
                                          transition: 'width .15s',
                                          overflow: 'hidden',
                                          '& .MuiDrawer-paper': {
                                              position: 'relative',
                                              width: 232,
                                              height: '100%',
                                              boxSizing: 'border-box',
                                          },
                                      }
                                    : {
                                          position: 'absolute',
                                          inset: 0,
                                          top: 'var(--admin-header-height, 56px)',
                                          zIndex: 3,
                                          pointerEvents: drawerOpen ? 'auto' : 'none',
                                          '& .MuiBackdrop-root': { position: 'absolute' },
                                          '& .MuiDrawer-paper': {
                                              position: 'absolute',
                                              width: 232,
                                              height: '100%',
                                              backgroundColor:
                                                  'color-mix(in srgb, var(--app-background, #202020) 88%, transparent)',
                                              backdropFilter: 'saturate(1.8) blur(5px)',
                                              boxSizing: 'border-box',
                                          },
                                      }
                            }
                        >
                            <nav
                                id={`${navigationID}-navigation`}
                                aria-label={t('workspaceNavigation')}
                            >
                                <List>
                                    {(['server', 'sessions', 'auditlogs', 'version'] as const).map(
                                        (section) => (
                                            <ListItemButton
                                                key={section}
                                                component={RouterAnchor}
                                                to={href(
                                                    managementRoot(route.managementFlow, section),
                                                )}
                                                selected={
                                                    view === section ||
                                                    (section === 'auditlogs' &&
                                                        view === 'recordings')
                                                }
                                                disabled={disabled || locked || !active}
                                                aria-current={
                                                    view === section ||
                                                    (section === 'auditlogs' &&
                                                        view === 'recordings')
                                                        ? 'page'
                                                        : undefined
                                                }
                                                onClick={(event) => {
                                                    if (!active || disabled || locked) {
                                                        event.preventDefault();
                                                        return;
                                                    }
                                                    if (
                                                        !event.ctrlKey &&
                                                        !event.metaKey &&
                                                        !event.shiftKey &&
                                                        !event.altKey &&
                                                        event.button === 0
                                                    ) {
                                                        event.preventDefault();
                                                        navigate(section);
                                                    }
                                                }}
                                            >
                                                <ListItemIcon>
                                                    {section === 'server' ? (
                                                        <HomeOutlinedIcon />
                                                    ) : section === 'version' ? (
                                                        <InfoOutlinedIcon />
                                                    ) : section === 'sessions' ? (
                                                        <PeopleOutlineIcon />
                                                    ) : (
                                                        <FactCheckIcon />
                                                    )}
                                                </ListItemIcon>
                                                <ListItemText
                                                    primary={t(
                                                        section === 'server'
                                                            ? 'workspaceOverview'
                                                            : section === 'version'
                                                              ? 'workspaceVersion'
                                                              : section === 'sessions'
                                                                ? 'workspaceSessions'
                                                                : 'workspaceAuditlogs',
                                                    )}
                                                />
                                            </ListItemButton>
                                        ),
                                    )}
                                </List>
                            </nav>
                        </Drawer>
                        {!wide && drawerOpen && (
                            <Box
                                component="button"
                                className="admin-drawer-backdrop"
                                type="button"
                                aria-label={t('adminNavigationCollapse')}
                                onClick={() => setTemporaryOpen(false)}
                                sx={{
                                    position: 'absolute',
                                    inset: 0,
                                    top: 'var(--admin-header-height, 56px)',
                                    border: 0,
                                    bgcolor: 'rgba(0,0,0,.25)',
                                    zIndex: 2,
                                }}
                            />
                        )}
                        <div className="admin-main">
                            <header className="admin-page-heading" ref={header}>
                                <IconButton
                                    aria-label={t(
                                        drawerOpen
                                            ? 'adminNavigationCollapse'
                                            : 'adminNavigationOpen',
                                    )}
                                    aria-expanded={drawerOpen}
                                    aria-controls={`${navigationID}-navigation`}
                                    disabled={disabled || locked || !active}
                                    onClick={() => {
                                        if (!active || disabled || locked) {
                                            return;
                                        }
                                        if (wide) {
                                            setCollapsed((value) => !value);
                                        } else {
                                            setTemporaryOpen((value) => !value);
                                        }
                                    }}
                                >
                                    {drawerOpen ? <LeftPanelCloseIcon /> : <MenuIcon />}
                                </IconButton>
                                <AdminBreadcrumbs items={crumbs} />
                            </header>
                            <div className="admin-content" data-playback-bounds="true">
                                {remoteDisabled && (
                                    <Alert
                                        color="yellow"
                                        action={
                                            <Button
                                                variant="subtle"
                                                disabled={
                                                    disabled ||
                                                    locked ||
                                                    reauthenticationBlocked ||
                                                    !active
                                                }
                                                onClick={() => {
                                                    if (
                                                        !disabled &&
                                                        !locked &&
                                                        !reauthenticationBlocked &&
                                                        active
                                                    ) {
                                                        onReauthenticate();
                                                    }
                                                }}
                                            >
                                                {accessMessages.reauthenticate}
                                            </Button>
                                        }
                                    >
                                        {status === 'expired'
                                            ? accessMessages.expiredNotice
                                            : accessMessages.closedNotice}
                                    </Alert>
                                )}
                                <Suspense fallback={<Alert>{t('managementLoading')}</Alert>}>
                                    <div
                                        hidden={
                                            view !== 'sessions' &&
                                            view !== 'server' &&
                                            view !== 'version'
                                        }
                                        id={`${navigationID}-management-panel`}
                                    >
                                        <ManagementPanel
                                            access={access}
                                            active={
                                                active &&
                                                (view === 'server' ||
                                                    view === 'sessions' ||
                                                    view === 'version')
                                            }
                                            disabled={disabled || remoteDisabled}
                                            onActionLock={lock}
                                            view={
                                                view === 'server'
                                                    ? 'server'
                                                    : view === 'version'
                                                      ? 'version'
                                                      : 'sessions'
                                            }
                                        />
                                    </div>
                                    <div
                                        hidden={view !== 'auditlogs' && view !== 'recordings'}
                                        id={`${navigationID}-auditlogs-panel`}
                                    >
                                        <ArtifactPanel
                                            view="auditlogs"
                                            access={access}
                                            disabled={disabled || locked}
                                            remoteDisabled={remoteDisabled}
                                            active={
                                                active &&
                                                (view === 'auditlogs' || view === 'recordings')
                                            }
                                        />
                                    </div>
                                </Suspense>
                            </div>
                        </div>
                    </Box>
                </ArtifactSecretsContext.Provider>
            </ManagementNavigationContext.Provider>
        </AdminDetailContext.Provider>
    );
}

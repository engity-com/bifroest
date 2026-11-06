import FactCheckIcon from '@mui/icons-material/FactCheck';
import HomeOutlinedIcon from '@mui/icons-material/HomeOutlined';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import MenuIcon from '@mui/icons-material/Menu';
import PeopleOutlineIcon from '@mui/icons-material/PeopleOutlineOutlined';
import ScreenshotMonitorIcon from '@mui/icons-material/ScreenshotMonitor';
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
import { ArtifactSecretsContext, useTabArtifactSecrets } from '../artifacts/session-secrets';
import type { WebAccess } from '../remember';
import type { ConnectionActions } from '../terminal/connection-actions';
import type { TerminalState } from '../terminal/socket';
import { AdminBreadcrumbs } from './AdminBreadcrumbs';
import { accessMessages } from './access-messages';
import { type AdminDetail, AdminDetailContext, type AdminSection } from './admin-navigation';
import { reportUiError } from './error-report';
import { LeftPanelCloseIcon } from './LeftPanelCloseIcon';
import type { ManagementLocation } from './management-location';
import { ManagementNavigationContext } from './management-navigation';
import { Alert, Button } from './material';
import { t } from './messages';
import { preferredKeepAlive } from './preferences';
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
}) {
  const [legacyView, setView] = useState<AdminSection | 'server' | 'version'>('server');
  const view = location?.page ?? legacyView;
  const retainedRoutes = useRef<{
    access: WebAccess;
    pages: Partial<Record<ManagementLocation['page'], ManagementLocation>>;
  }>({ access, pages: {} });
  if (retainedRoutes.current.access !== access) {
    retainedRoutes.current = { access, pages: {} };
  }
  if (location) {
    retainedRoutes.current.pages[location.page] = location;
  }
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
  const [details, setDetails] = useState<Partial<Record<AdminSection, AdminDetail | null>>>({});
  const publishDetail = useCallback(
    (section: AdminSection, detail: AdminDetail | null) =>
      setDetails((current) =>
        current[section]?.label === detail?.label &&
        current[section]?.back === detail?.back &&
        JSON.stringify(current[section]?.parents) === JSON.stringify(detail?.parents)
          ? current
          : { ...current, [section]: detail },
      ),
    [],
  );
  useEffect(() => {
    if (!pane.current) {
      return;
    }
    let previous: boolean | undefined;
    const update = () => {
      if (header.current) {
        pane.current?.style.setProperty(
          '--admin-header-height',
          `${header.current.offsetHeight}px`,
        );
      }
      const next = (pane.current?.clientWidth ?? 0) > 1136;
      if (previous !== next) {
        previous = next;
        setWide(next);
        setCollapsed(false);
        setTemporaryOpen(false);
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
        setView('sessions');
      }
      onActionLock(owner, value);
    },
    [onActionLock, owner],
  );
  const navigate = (next: typeof view) => {
    if (active && !disabled && !locked) {
      if (location && onNavigate) {
        onNavigate(
          owner,
          retainedRoutes.current.pages[next] ?? {
            managementFlow: location.managementFlow,
            page: next,
          },
        );
      } else {
        setView(next);
      }
      setTemporaryOpen(false);
    }
  };
  useEffect(() => {
    if (!active) {
      setTemporaryOpen(false);
    }
  }, [active]);
  const detail = view === 'server' || view === 'version' ? null : details[view];
  const legacyCrumbs = [
    {
      label: t('workspaceBifroest'),
    },
    ...[
      {
        label: sectionTitle,
        ...(detail
          ? {
              onClick: () => {
                if (!disabled && !locked) {
                  detail.back();
                }
              },
              disabled: disabled || locked,
            }
          : {}),
      },
    ],
    ...(detail?.parents.map((label) => ({ label })) ?? []),
    ...(detail ? [{ label: detail.label }] : []),
  ];
  const routeNavigate = (next: ManagementLocation, replace = false) => {
    if (active && !disabled && !locked) {
      onNavigate?.(owner, next, replace);
    }
  };
  const crumbs = location
    ? [
        { label: t('workspaceBifroest') },
        {
          label: sectionTitle,
          ...(location.flow || location.id || location.auditlog
            ? {
                onClick: () =>
                  routeNavigate({ managementFlow: location.managementFlow, page: location.page }),
              }
            : {}),
        },
        ...(location.auditlog
          ? [
              {
                label: location.auditlog,
                ...(location.flow || location.id
                  ? {
                      onClick: () =>
                        routeNavigate({
                          managementFlow: location.managementFlow,
                          page: 'auditlogs',
                          ...(location.auditlog ? { auditlog: location.auditlog } : {}),
                        }),
                    }
                  : {}),
              },
            ]
          : []),
        ...(location.flow
          ? [
              {
                label: location.flow,
                ...(location.id
                  ? {
                      onClick: () => {
                        const { id: _id, ...parent } = location;
                        routeNavigate(parent);
                      },
                    }
                  : {}),
              },
            ]
          : []),
        ...(location.id ? [{ label: location.id }] : []),
      ]
    : legacyCrumbs;
  const drawerOpen = wide ? !collapsed : active && temporaryOpen;
  return (
    <AdminDetailContext.Provider value={publishDetail}>
      <ManagementNavigationContext.Provider
        value={location ? { location, navigate: routeNavigate } : null}
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
              <nav id={`${navigationID}-navigation`} aria-label={t('workspaceNavigation')}>
                <List>
                  {(['server', 'sessions', 'recordings', 'auditlogs', 'version'] as const).map(
                    (section) => (
                      <ListItemButton
                        key={section}
                        component="button"
                        type="button"
                        selected={view === section}
                        disabled={disabled || locked}
                        aria-current={view === section ? 'page' : undefined}
                        onClick={() => navigate(section)}
                      >
                        <ListItemIcon>
                          {section === 'server' ? (
                            <HomeOutlinedIcon />
                          ) : section === 'version' ? (
                            <InfoOutlinedIcon />
                          ) : section === 'sessions' ? (
                            <PeopleOutlineIcon />
                          ) : section === 'recordings' ? (
                            <ScreenshotMonitorIcon />
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
                                  : section === 'recordings'
                                    ? 'workspaceRecordings'
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
                  aria-label={t(drawerOpen ? 'adminNavigationCollapse' : 'adminNavigationOpen')}
                  aria-expanded={drawerOpen}
                  aria-controls={`${navigationID}-navigation`}
                  disabled={disabled || locked}
                  onClick={() =>
                    wide ? setCollapsed((value) => !value) : setTemporaryOpen((value) => !value)
                  }
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
                        disabled={disabled || locked || reauthenticationBlocked || !active}
                        onClick={() => {
                          if (!disabled && !locked && !reauthenticationBlocked && active) {
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
                    hidden={view !== 'sessions' && view !== 'server' && view !== 'version'}
                    id={`${navigationID}-management-panel`}
                  >
                    <ManagementPanel
                      access={access}
                      active={
                        active && (view === 'server' || view === 'sessions' || view === 'version')
                      }
                      disabled={disabled || remoteDisabled}
                      onActionLock={lock}
                      view={
                        view === 'server' ? 'server' : view === 'version' ? 'version' : 'sessions'
                      }
                    />
                  </div>
                  <div hidden={view !== 'recordings'} id={`${navigationID}-recordings-panel`}>
                    <ArtifactPanel
                      view="recordings"
                      access={access}
                      disabled={disabled || locked}
                      remoteDisabled={remoteDisabled}
                      active={active && view === 'recordings'}
                    />
                  </div>
                  <div hidden={view !== 'auditlogs'} id={`${navigationID}-auditlogs-panel`}>
                    <ArtifactPanel
                      view="auditlogs"
                      access={access}
                      disabled={disabled || locked}
                      remoteDisabled={remoteDisabled}
                      active={active && view === 'auditlogs'}
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

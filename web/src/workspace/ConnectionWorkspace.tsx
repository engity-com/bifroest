import AddIcon from '@mui/icons-material/Add';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import CloseIcon from '@mui/icons-material/Close';
import LoginIcon from '@mui/icons-material/Login';
import { Box, CircularProgress, IconButton, Tab, Tabs } from '@mui/material';
import type { ReactNode } from 'react';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { Scope, WebAccess } from '../remember';
import { newViewID } from '../shared/uuid';
import {
  AuthenticationTerminal,
  type AuthenticationView,
} from '../terminal/AuthenticationTerminal';
import { ConnectionSettings } from '../terminal/ConnectionSettings';
import { ConnectionTab } from '../terminal/ConnectionTab';
import type { ConnectionActions } from '../terminal/connection-actions';
import type { TerminalState } from '../terminal/socket';
import type { TerminalActions } from '../terminal/TerminalPanel';
import { TerminalPanel, terminalStatus } from '../terminal/TerminalPanel';
import { tabTitle } from '../terminal/tab-title';
import { bookmarkPath, hashPath } from '../ui/hash-route';
import { ManagementWorkspace } from '../ui/ManagementWorkspace';
import type { ManagementLocation } from '../ui/management-location';
import { ActionIcon, Button, Menu, Modal } from '../ui/material';
import { t } from '../ui/messages';
import { adjustTerminalFontSize, terminalZoomKey } from '../ui/terminal-font';
import { canCloseView, ownerLocks } from '../ui/workspace-state';
import { ConnectionTabMenu } from './ConnectionTabMenu';
import { type ConnectionView, maximumTabs, type WorkspaceControls } from './model';

interface ShellTab extends ConnectionView {
  readonly navigation: { current: ManagementLocation | null };
  readonly kind: 'terminal' | 'management';
  readonly cancellation: AbortController;
  readonly state: TerminalState;
  readonly inputClosed: boolean;
  readonly title?: string;
}
export function ConnectionWorkspace({
  authentication,
  activeView: active,
  authorizationEvent,
  retiredAccess,
  unavailableAccess,
  blocked,
  focusBlocked,
  title,
  utilities,
  notice,
  onSignIn,
  onNewConnection,
  onSelectView,
  onViewsChange,
  onActionLock,
  onTabCount,
  onLogout,
  managementLocation = null,
  onManagementNavigate,
  onWorkspaceControls,
}: {
  authentication: AuthenticationView | null;
  activeView: number | null;
  authorizationEvent: WebAccess | null;
  retiredAccess: WebAccess | null;
  unavailableAccess: WebAccess | null;
  blocked: boolean;
  focusBlocked: boolean;
  title: string;
  utilities: ReactNode;
  notice: ReactNode;
  onSignIn: (scope?: Scope) => void;
  onNewConnection: () => void;
  onSelectView: (view: ConnectionView | null, replace?: boolean) => void;
  onViewsChange: (views: readonly ConnectionView[]) => void;
  onActionLock: (locked: boolean) => void;
  onTabCount: (count: number) => void;
  onLogout: (access: WebAccess) => void;
  managementLocation?: ManagementLocation | null;
  onManagementNavigate?: (
    owner: ConnectionView,
    location: ManagementLocation,
    replace?: boolean,
  ) => void;
  onWorkspaceControls?: (controls: WorkspaceControls | null) => void;
}) {
  const [tabs, setTabs] = useState<readonly ShellTab[]>([]);
  const current = useRef<readonly ShellTab[]>([]);
  const nextID = useRef(0);
  const lastAuthorization = useRef<WebAccess | null>(null);
  const actionOwners = useRef<ReadonlySet<number>>(new Set());
  const [actionsLocked, setActionsLocked] = useState(false);
  const lastRetired = useRef<WebAccess | null>(null);
  const tabList = useRef<HTMLDivElement | null>(null);
  const controls = useRef(new Map<number, TerminalActions>());
  const connectionControls = useRef(new Map<number, ConnectionActions>());
  const [closing, setClosing] = useState<number | null>(null);
  const [limit, setLimit] = useState(false);
  const [menuTab, setMenuTab] = useState<number | null>(null);
  const [newMenuOpen, setNewMenuOpen] = useState(false);
  const [focusTerminal, setFocusTerminal] = useState(true);
  const [settingsTab, setSettingsTab] = useState<number | null>(null);
  const [copyLink, setCopyLink] = useState<string | null>(null);
  const selectView = useRef(onSelectView);
  const activeId = useRef(active);
  activeId.current = active;
  useLayoutEffect(() => {
    selectView.current = onSelectView;
  }, [onSelectView]);
  useEffect(() => {
    if (blocked || focusBlocked || authentication !== null) {
      setSettingsTab(null);
    }
  }, [blocked, focusBlocked, authentication]);
  useEffect(() => {
    if (
      settingsTab !== null &&
      !tabs.some((tab) => tab.id === settingsTab && tab.state.phase === 'connected')
    ) {
      setSettingsTab(null);
    }
  }, [settingsTab, tabs]);
  const updateTabs = useCallback(
    (next: readonly ShellTab[]) => {
      const structural =
        next.length !== current.current.length ||
        next.some((tab, index) => tab.id !== current.current[index]?.id);
      current.current = next;
      if (structural) {
        onViewsChange(next);
      }
      setTabs(next);
    },
    [onViewsChange],
  );
  useEffect(
    () => onTabCount(tabs.length + (authentication ? 1 : 0)),
    [tabs.length, authentication, onTabCount],
  );
  const lockOwner = useCallback(
    (owner: number, locked: boolean) => {
      actionOwners.current = ownerLocks(actionOwners.current, owner, locked);
      setActionsLocked(actionOwners.current.size > 0);
      if (locked) {
        // Retire any older close intent. It must not outlive this action and
        // later unmount its owner/unknown warning through a stale confirmation.
        setClosing(null);
        setLimit(false);
        setMenuTab(null);
        setNewMenuOpen(false);
        const tab = current.current.find((entry) => entry.id === owner);
        if (tab) {
          selectView.current(tab);
        }
      }
      onActionLock(actionOwners.current.size > 0);
    },
    // Route callbacks change with URL/view state, not with the management
    // access owner. Keep that callback out of the actor-bound lock identity.
    [onActionLock],
  );
  const onState = useCallback(
    (id: number, state: TerminalState) => {
      if (state.phase === 'exited' && state.status === 0) {
        const ended = current.current.find((tab) => tab.id === id);
        if (!ended) {
          return;
        }
        ended.cancellation.abort();
        const remaining = current.current.filter((tab) => tab.id !== id);
        updateTabs(remaining);
        if (activeId.current === id) {
          selectView.current(remaining.at(-1) ?? null, true);
        }
        if (remaining.length === 0) {
          lastAuthorization.current = null;
        }
        setClosing((value) => (value === id ? null : value));
        setMenuTab((value) => (value === id ? null : value));
        return;
      }
      updateTabs(current.current.map((tab) => (tab.id === id ? { ...tab, state } : tab)));
    },
    [updateTabs],
  );
  const onActions = useCallback((id: number, actions: TerminalActions | null) => {
    if (actions) {
      controls.current.set(id, actions);
      connectionControls.current.set(id, actions);
    } else {
      controls.current.delete(id);
      connectionControls.current.delete(id);
    }
  }, []);
  const onTitle = useCallback(
    (id: number, value: string) => {
      const title = tabTitle(value);
      if (current.current.find((tab) => tab.id === id)?.title === title) {
        return;
      }
      updateTabs(current.current.map((tab) => (tab.id === id ? { ...tab, title } : tab)));
    },
    [updateTabs],
  );
  const onConnectionActions = useCallback((id: number, actions: ConnectionActions | null) => {
    if (actions) {
      connectionControls.current.set(id, actions);
    } else {
      connectionControls.current.delete(id);
    }
  }, []);
  const open = useCallback(
    (selected: WebAccess, replace = false) => {
      if (current.current.length >= maximumTabs) {
        setLimit(true);
        return;
      }
      const tab: ShellTab = {
        id: ++nextID.current,
        routeId: newViewID(),
        kind: selected.snapshot().terminalAvailable ? 'terminal' : 'management',
        access: selected,
        scope: Object.freeze({ ...selected.snapshot().scope }),
        cancellation: new AbortController(),
        state: { phase: 'connecting' },
        inputClosed: false,
        navigation: { current: null },
        title: selected.snapshot().terminalAvailable
          ? (selected.snapshot().flow?.title ?? t('terminalTitle'))
          : t('workspaceOverview'),
      };
      updateTabs([...current.current, tab]);
      onSelectView(tab, replace);
      setFocusTerminal(true);
      setLimit(false);
    },
    [updateTabs, onSelectView],
  );
  useEffect(() => {
    if (!authorizationEvent || blocked || authorizationEvent === lastAuthorization.current) {
      return;
    }
    lastAuthorization.current = authorizationEvent;
    if (authorizationEvent === retiredAccess) {
      return;
    }
    const snapshot = authorizationEvent.snapshot();
    if (snapshot.terminalAvailable || snapshot.environment === 'management') {
      open(authorizationEvent, true);
    } else {
      onSelectView(null);
    }
  }, [authorizationEvent, retiredAccess, blocked, open, onSelectView]);
  useEffect(() => {
    if (retiredAccess === null || retiredAccess === lastRetired.current) {
      return;
    }
    lastRetired.current = retiredAccess;
    const removed = current.current.filter((tab) => tab.access === retiredAccess);
    for (const tab of removed) {
      tab.cancellation.abort();
    }
    const remaining = current.current.filter((tab) => tab.access !== retiredAccess);
    updateTabs(remaining);
    const next = remaining.at(-1);
    onSelectView(next ?? null, true);
    setClosing(null);
    setLimit(false);
    setMenuTab(null);
    setNewMenuOpen(false);
    // IDs are never reused within this app generation, including after logout.
  }, [retiredAccess, onSelectView, updateTabs]);
  useEffect(() => {
    if (!blocked) {
      return;
    }
    // Do not let an unstarted/connecting old grant dispatch later during login
    // cancellation or an actor change. Already running shells remain owned.
    const pending = current.current.filter(
      (tab) => tab.kind === 'terminal' && tab.state.phase === 'connecting',
    );
    for (const tab of pending) {
      tab.cancellation.abort();
    }
    if (pending.length) {
      const remaining = current.current.filter((tab) => !pending.includes(tab));
      updateTabs(remaining);
      if (pending.some((tab) => tab.id === active)) {
        const next = remaining.at(-1);
        if (next) {
          onSelectView(next, true);
        }
      }
    }
  }, [blocked, active, onSelectView, updateTabs]);
  useEffect(
    () => () => {
      for (const tab of current.current) {
        tab.cancellation.abort();
      }
    },
    [],
  );

  const closingTab = tabs.find((tab) => tab.id === closing);
  useLayoutEffect(() => {
    onWorkspaceControls?.({
      closeAll: (options = {}) => {
        if (actionOwners.current.size > 0 || (!options.resetConfirmed && blocked)) {
          return false;
        }
        for (const tab of current.current) {
          tab.cancellation.abort();
        }
        updateTabs([]);
        lastAuthorization.current = null;
        if (options.resetConfirmed) {
          lastRetired.current = null;
        }
        setClosing(null);
        setMenuTab(null);
        setSettingsTab(null);
        setNewMenuOpen(false);
        setLimit(false);
        selectView.current(null, true);
        return true;
      },
    });
    return () => onWorkspaceControls?.(null);
  }, [onWorkspaceControls, blocked, updateTabs]);
  useLayoutEffect(() => {
    const showActive = () => {
      const list = tabList.current;
      const header = list?.closest<HTMLElement>('.application-tabs');
      if (list && header) {
        const siblings = [...header.children].filter((node) => !node.contains(list));
        const reserved = siblings.reduce(
          (width, node) => width + node.getBoundingClientRect().width,
          0,
        );
        const gaps =
          (Number.parseFloat(getComputedStyle(header).columnGap) || 0) *
          Math.max(0, header.children.length - 1);
        const arrows = [...list.querySelectorAll('.MuiTabs-scrollButtons')].reduce(
          (width, node) => width + node.getBoundingClientRect().width,
          0,
        );
        // Use the space AVAILABLE to Tabs, not its current intrinsic width.
        // Otherwise a short first label can permanently constrain later titles.
        const available = header.clientWidth - reserved - gaps - arrows;
        tabList.current?.style.setProperty(
          '--connection-tab-width',
          `${Math.max(48, Math.min(320, available))}px`,
        );
      }
      if (active === null || !tabs.some((tab) => tab.id === active)) {
        return;
      }
      document
        .getElementById(`terminal-tab-${active}`)
        ?.scrollIntoView({ inline: 'nearest', block: 'nearest' });
    };
    showActive();
    const observer = new ResizeObserver(showActive);
    if (tabList.current) {
      observer.observe(tabList.current);
      const scroller = tabList.current.querySelector('.MuiTabs-scroller');
      if (scroller) {
        observer.observe(scroller);
      }
      const header = tabList.current.closest('.application-tabs');
      if (header) {
        observer.observe(header);
      }
    }
    return () => observer.disconnect();
  }, [active, tabs]);
  const remove = (id: number) => {
    if (!canCloseView(blocked, focusBlocked, actionOwners.current)) {
      return;
    }
    const tab = current.current.find((entry) => entry.id === id);
    tab?.cancellation.abort();
    const remaining = current.current.filter((entry) => entry.id !== id);
    updateTabs(remaining);
    if (active === id) {
      const next = remaining.at(-1);
      onSelectView(next ?? null, true);
      if (!next) {
        lastAuthorization.current = null;
      }
    }
    setClosing(null);
    setLimit(false);
    setMenuTab(null);
  };
  const requestClose = (tab: ShellTab) => {
    if (!canCloseView(blocked, focusBlocked, actionOwners.current)) {
      return;
    }
    if (
      tab.kind === 'management' ||
      ['connecting', 'connected', 'finishing'].includes(tab.state.phase)
    ) {
      setClosing(tab.id);
    } else {
      remove(tab.id);
    }
  };
  const duplicateAccess = (selectedAccess: WebAccess) => {
    if (blocked || focusBlocked || settingsTab !== null || actionOwners.current.size > 0) {
      return;
    }
    if (
      selectedAccess.status() !== 'active' ||
      selectedAccess.snapshot().environment === 'management'
    ) {
      onSignIn(selectedAccess.snapshot().scope);
      return;
    }
    if (selectedAccess.snapshot().terminalAvailable) {
      open(selectedAccess);
    }
  };

  useEffect(() => {
    const available = () =>
      !blocked &&
      !focusBlocked &&
      authentication === null &&
      settingsTab === null &&
      actionOwners.current.size === 0 &&
      closing === null &&
      !limit;
    const key = (event: KeyboardEvent) => {
      if (
        !available() ||
        event.defaultPrevented ||
        event.isComposing ||
        event.altKey ||
        event.metaKey ||
        !event.ctrlKey ||
        [
          ...document.querySelectorAll<HTMLElement>(
            '[role="dialog"],[role="menu"],[role="listbox"]',
          ),
        ].some((element) => element.checkVisibility({ visibilityProperty: true }))
      ) {
        return;
      }
      const selected = current.current.find((tab) => tab.id === active);
      if (event.key === 'Tab') {
        if (current.current.length < 2) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        const index = current.current.findIndex((tab) => tab.id === active);
        const next =
          current.current[
            (index + (event.shiftKey ? -1 : 1) + current.current.length) % current.current.length
          ];
        if (next) {
          setFocusTerminal(true);
          selectView.current(next);
        }
        return;
      }
      if (
        selected?.kind === 'management' &&
        event.key.toLowerCase() === 'd' &&
        !event.shiftKey &&
        !(
          event.target instanceof Element &&
          event.target.closest(
            'input,textarea,select,[contenteditable]:not([contenteditable="false"]),[role="textbox"]',
          )
        )
      ) {
        event.preventDefault();
        event.stopPropagation();
        remove(selected.id);
        return;
      }
      const zoom = terminalZoomKey(event);
      if (selected?.kind === 'terminal' && zoom) {
        event.preventDefault();
        event.stopPropagation();
        adjustTerminalFontSize(zoom);
      }
    };
    const wheel = (event: WheelEvent) => {
      if (
        !available() ||
        !event.ctrlKey ||
        event.deltaY === 0 ||
        !(
          event.target instanceof Element &&
          event.target.closest('[data-connection-active="true"] .terminal-surface')
        )
      ) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      adjustTerminalFontSize(event.deltaY < 0 ? 1 : -1);
    };
    window.addEventListener('keydown', key, true);
    window.addEventListener('wheel', wheel, { capture: true, passive: false });
    return () => {
      window.removeEventListener('keydown', key, true);
      window.removeEventListener('wheel', wheel, true);
    };
  });

  const operate = (id: number, action: (tab: ShellTab) => void) => {
    if (blocked || focusBlocked || settingsTab !== null || actionOwners.current.size > 0) {
      return;
    }
    const tab = current.current.find((entry) => entry.id === id);
    if (tab) {
      action(tab);
    }
  };
  const showTabMenu = (id: number, opened: boolean) => {
    if (opened) {
      operate(id, (tab) => {
        setFocusTerminal(false);
        onSelectView(tab);
        setNewMenuOpen(false);
        setMenuTab(id);
      });
    } else {
      setMenuTab((value) => (value === id ? null : value));
      requestAnimationFrame(() => {
        const element = document.getElementById(`terminal-tab-${id}`);
        if (element?.getAttribute('aria-selected') === 'true') {
          element.focus();
        }
      });
    }
  };
  const reauthenticate = (id: number) => {
    if (authentication !== null || tabs.length >= maximumTabs) {
      return;
    }
    operate(id, (tab) => onSignIn(tab.scope));
  };
  const showConnectionMenu = () => {
    if (blocked || focusBlocked || settingsTab !== null || actionOwners.current.size > 0) {
      return;
    }
    setMenuTab(null);
    setNewMenuOpen(true);
  };
  const available = tabs
    .filter((tab, index) => tabs.findIndex((entry) => entry.access === tab.access) === index)
    .filter((tab) => tab.access.status() === 'active' && tab.access.snapshot().terminalAvailable);
  const menuOwner = tabs.find((tab) => tab.id === menuTab);
  const settingsOwner = tabs.find((tab) => tab.id === settingsTab);
  const settingsActions = settingsOwner
    ? connectionControls.current.get(settingsOwner.id)
    : undefined;

  return (
    <main className="workspace terminal-workspace" aria-label={title}>
      <header className="application-bar">
        <div className="application-tabs">
          <ConnectionTabMenu
            owner={
              menuOwner
                ? {
                    principal: menuOwner.access.snapshot().principal,
                    slug: menuOwner.access.snapshot().scope.slug,
                    kind: menuOwner.kind,
                    phase: menuOwner.state.phase,
                    inputClosed: menuOwner.inputClosed,
                  }
                : null
            }
            blocked={blocked}
            focusBlocked={focusBlocked}
            atLimit={tabs.length >= maximumTabs}
            onChange={(opened) => {
              if (!opened && menuTab !== null) {
                showTabMenu(menuTab, false);
              }
            }}
            actions={{
              duplicate: () => {
                if (menuOwner) {
                  operate(menuOwner.id, (entry) => duplicateAccess(entry.access));
                }
              },
              reauthenticate: () => {
                if (menuOwner) {
                  reauthenticate(menuOwner.id);
                }
              },
              copyLink: () => {
                if (menuOwner) {
                  operate(menuOwner.id, (entry) => {
                    const path = bookmarkPath(entry.scope, entry.navigation.current ?? undefined);
                    const url = new URL(path, entry.scope.origin).href;
                    void Promise.resolve()
                      .then(() => navigator.clipboard.writeText(url))
                      .catch(() => setCopyLink(url));
                  });
                }
              },
              settings: () => {
                if (menuOwner) {
                  operate(menuOwner.id, (tab) => {
                    setClosing(null);
                    setLimit(false);
                    setSettingsTab(tab.id);
                    setFocusTerminal(false);
                  });
                }
              },
              eof: () => {
                if (menuOwner) {
                  operate(menuOwner.id, (entry) => {
                    if (controls.current.get(entry.id)?.eof()) {
                      updateTabs(
                        current.current.map((item) =>
                          item.id === entry.id ? { ...item, inputClosed: true } : item,
                        ),
                      );
                    }
                  });
                }
              },
              signal: (value) => {
                if (menuOwner) {
                  operate(menuOwner.id, (entry) => {
                    controls.current.get(entry.id)?.signal(value);
                  });
                }
              },
              disconnect: () => {
                if (menuOwner) {
                  operate(menuOwner.id, (entry) => {
                    controls.current.get(entry.id)?.disconnect();
                  });
                }
              },
              logout: () => {
                if (menuOwner) {
                  operate(menuOwner.id, (entry) => onLogout(entry.access));
                }
              },
              close: () => {
                if (menuOwner) {
                  operate(menuOwner.id, requestClose);
                }
              },
            }}
          >
            <Tabs
              ref={tabList}
              className="terminal-tab-list"
              aria-label={t('connectionTabs')}
              value={authentication ? 'authentication' : (active ?? false)}
              variant="scrollable"
              scrollButtons="auto"
              allowScrollButtonsMobile
              selectionFollowsFocus
              onChange={(event, id: number) => {
                // ConnectionTab already handles clicks (including an already
                // selected tab). MUI also emits onChange for that click: do not
                // push the same activation twice. Focus selection is keyboard.
                if (event.type === 'click') {
                  return;
                }
                operate(id, (tab) => {
                  setFocusTerminal(false);
                  onSelectView(tab);
                });
              }}
            >
              {tabs.map((tab) => (
                <ConnectionTab
                  key={tab.id}
                  id={tab.id}
                  value={tab.id}
                  href={hashPath(
                    tab.scope,
                    tab.routeId ?? null,
                    tab.navigation.current ?? undefined,
                  )}
                  kind={tab.kind}
                  access={tab.access}
                  scope={tab.scope.slug}
                  principal={tab.access.snapshot().principal}
                  {...(tab.title === undefined ? {} : { title: tab.title })}
                  state={tab.state}
                  active={authentication === null && active === tab.id}
                  disabled={blocked || focusBlocked || settingsTab !== null}
                  onSelect={() =>
                    operate(tab.id, (entry) => {
                      setFocusTerminal(true);
                      onSelectView(entry);
                    })
                  }
                  onMenu={(value) => showTabMenu(tab.id, value)}
                  onClose={() => operate(tab.id, requestClose)}
                />
              ))}
              {authentication && (
                <Tab
                  value="authentication"
                  component="div"
                  id="authentication-tab"
                  aria-label={`${t('authenticationTab')} ${authentication.user}`}
                  aria-controls="authentication-pane"
                  label={
                    <Box
                      component="span"
                      sx={{ display: 'inline-flex', alignItems: 'center', gap: 1 }}
                    >
                      {authentication.pending ? (
                        <CircularProgress size={14} />
                      ) : (
                        <LoginIcon fontSize="small" />
                      )}
                      {authentication.user || t('login')}
                      <IconButton
                        component="span"
                        role="button"
                        size="small"
                        tabIndex={-1}
                        aria-label={t('cancelAuthentication')}
                        onClick={(event) => {
                          event.stopPropagation();
                          authentication.onCancel();
                        }}
                      >
                        <CloseIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  }
                />
              )}
            </Tabs>
          </ConnectionTabMenu>
          <Menu
            position="bottom-start"
            opened={newMenuOpen}
            onChange={(value) => {
              if (value) {
                showConnectionMenu();
              } else {
                setNewMenuOpen(false);
              }
            }}
          >
            <Menu.ContextMenu>
              <ActionIcon.Group className="connection-add">
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  size="lg"
                  aria-label={t('connectionNew')}
                  disabled={blocked || settingsTab !== null || tabs.length >= maximumTabs}
                  title={t('connectionNew')}
                  onClick={() => {
                    setNewMenuOpen(false);
                    onNewConnection();
                  }}
                >
                  <AddIcon />
                </ActionIcon>
                <Menu.Target>
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="lg"
                    aria-label={t('connectionOptions')}
                    disabled={blocked || settingsTab !== null}
                  >
                    <ArrowDropDownIcon />
                  </ActionIcon>
                </Menu.Target>
              </ActionIcon.Group>
            </Menu.ContextMenu>
            <Menu.Dropdown>
              <Menu.Item
                icon={<AddIcon fontSize="small" />}
                disabled={blocked || tabs.length >= maximumTabs}
                onClick={onNewConnection}
              >
                {t('connectionNew')}
              </Menu.Item>
              {available.length > 0 && <Menu.Label>{t('connectionAvailable')}</Menu.Label>}
              {available.map((tab) => (
                <Menu.Item
                  key={tab.id}
                  icon={<LoginIcon fontSize="small" />}
                  disabled={blocked || tabs.length >= maximumTabs}
                  onClick={() => operate(tab.id, (entry) => duplicateAccess(entry.access))}
                >
                  {tab.access.snapshot().scope.slug || '/'} · {tab.access.snapshot().principal}
                  {available.filter(
                    (entry) =>
                      entry.access.snapshot().scope.slug === tab.access.snapshot().scope.slug &&
                      entry.access.snapshot().principal === tab.access.snapshot().principal,
                  ).length > 1 && <span className="subtle"> #{tab.id}</span>}
                </Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
          <div className="workspace-utilities">
            {notice}
            {utilities}
          </div>
        </div>
      </header>
      <div className="workspace-body">
        {tabs.map((tab) => (
          <div
            className={tab.kind === 'terminal' ? 'terminal-pane' : 'management-workspace'}
            id={`terminal-pane-${tab.id}`}
            role="tabpanel"
            aria-labelledby={`terminal-tab-${tab.id}`}
            hidden={authentication !== null || active !== tab.id}
            data-terminal-active={
              authentication === null && tab.kind === 'terminal' && active === tab.id
            }
            data-connection-active={authentication === null && active === tab.id}
            data-terminal-exit-status={
              tab.kind === 'terminal' && tab.state.phase === 'exited' ? tab.state.status : undefined
            }
            data-terminal-ended={
              (tab.kind === 'terminal' && tab.state.phase === 'exited') || undefined
            }
            data-playback-bounds={tab.kind === 'management' ? true : undefined}
            data-connection-principal={tab.access.snapshot().principal}
            data-connection-scope={tab.access.snapshot().scope.slug}
            key={tab.id}
          >
            {tab.kind === 'terminal' ? (
              <TerminalPanel
                id={tab.id}
                access={tab.access}
                signal={tab.cancellation.signal}
                active={authentication === null && active === tab.id}
                inputAllowed={
                  !blocked &&
                  !focusBlocked &&
                  settingsTab === null &&
                  closing === null &&
                  !limit &&
                  menuTab === null &&
                  !newMenuOpen
                }
                focusOnActivate={focusTerminal}
                onState={onState}
                onActions={onActions}
                onTitle={onTitle}
              />
            ) : (
              <ManagementWorkspace
                owner={tab.id}
                {...(tab.routeId ? { routeId: tab.routeId } : {})}
                access={tab.access}
                signal={tab.cancellation.signal}
                onState={onState}
                onConnectionActions={onConnectionActions}
                onTitle={onTitle}
                location={active === tab.id ? managementLocation : tab.navigation.current}
                onNavigate={(owner, location, replace) => {
                  if (
                    !blocked &&
                    !focusBlocked &&
                    actionOwners.current.size === 0 &&
                    owner === tab.id
                  ) {
                    onManagementNavigate?.(tab, location, replace);
                  }
                }}
                active={
                  authentication === null &&
                  active === tab.id &&
                  !focusBlocked &&
                  closing === null &&
                  !limit &&
                  menuTab === null &&
                  !newMenuOpen
                }
                disabled={unavailableAccess === tab.access}
                onActionLock={lockOwner}
                onReauthenticate={() => reauthenticate(tab.id)}
                reauthenticationBlocked={
                  blocked ||
                  focusBlocked ||
                  actionsLocked ||
                  authentication !== null ||
                  settingsTab !== null ||
                  closing !== null ||
                  limit ||
                  menuTab !== null ||
                  newMenuOpen ||
                  tabs.length >= maximumTabs
                }
              />
            )}
            {authentication === null &&
              tab.kind === 'terminal' &&
              active === tab.id &&
              tab.state.phase !== 'exited' && (
                <span
                  role="status"
                  className={
                    tab.state.phase === 'connected'
                      ? 'terminal-state terminal-state--quiet'
                      : 'terminal-state'
                  }
                  data-terminal-phase={tab.state.phase}
                >
                  {t(terminalStatus(tab.state))}
                </span>
              )}
          </div>
        ))}
        {authentication && (
          <div
            id="authentication-pane"
            className="terminal-pane"
            role="tabpanel"
            aria-labelledby="authentication-tab"
            data-auth-terminal-active="true"
          >
            <AuthenticationTerminal
              key={authentication.id}
              view={authentication}
              active={!focusBlocked}
            />
          </div>
        )}
      </div>
      {settingsOwner && settingsActions && !blocked && !focusBlocked && authentication === null && (
        <ConnectionSettings
          key={settingsOwner.id}
          access={settingsOwner.access}
          signal={settingsOwner.cancellation.signal}
          actions={settingsActions}
          onClose={() => {
            setSettingsTab(null);
            setFocusTerminal(true);
          }}
        />
      )}
      <Modal
        opened={copyLink !== null}
        onClose={() => setCopyLink(null)}
        title={t('connectionCopyPermanentLink')}
      >
        <input
          aria-label={t('connectionCopyPermanentLink')}
          value={copyLink ?? ''}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
        />
      </Modal>
      <Modal
        opened={closing !== null && !blocked}
        onClose={() => setClosing(null)}
        title={t(closingTab?.kind === 'management' ? 'managementCloseTitle' : 'terminalCloseTitle')}
        closeOnClickOutside={false}
        lockScroll={false}
      >
        {closingTab && (
          <p>
            {t(closingTab.kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')}{' '}
            {closingTab.id} · {closingTab.access.snapshot().scope.slug || '/'} ·{' '}
            {closingTab.access.snapshot().principal}
          </p>
        )}
        <p>
          {t(closingTab?.kind === 'management' ? 'managementCloseWarning' : 'terminalCloseWarning')}
        </p>
        <div className="actions">
          <Button
            color="red"
            disabled={!canCloseView(blocked, focusBlocked, actionOwners.current)}
            onClick={() => {
              if (closing !== null) {
                remove(closing);
              }
            }}
          >
            {t(closingTab?.kind === 'management' ? 'close' : 'terminalCloseConfirm')}
          </Button>
          <Button variant="default" onClick={() => setClosing(null)}>
            {t('cancel')}
          </Button>
        </div>
      </Modal>
      <Modal
        opened={limit}
        onClose={() => setLimit(false)}
        title={t('terminalTabs')}
        lockScroll={false}
      >
        <p>{t('terminalTabLimit')}</p>
      </Modal>
    </main>
  );
}

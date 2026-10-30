import { ActionIcon, Button, Menu, Modal } from '@mantine/core';
import type { ReactNode } from 'react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { Scope, WebAccess } from '../remember';
import { ManagementWorkspace } from '../ui/ManagementWorkspace';
import { t } from '../ui/messages';
import { canCloseView, ownerLocks } from '../ui/workspace-state';
import { ConnectionTab } from './ConnectionTab';
import type { TerminalState } from './socket';
import type { TerminalActions } from './TerminalPanel';
import { TerminalPanel, terminalStatus } from './TerminalPanel';

interface ShellTab {
  readonly id: number;
  readonly kind: 'terminal' | 'management';
  readonly access: WebAccess;
  readonly cancellation: AbortController;
  readonly state: TerminalState;
  readonly inputClosed: boolean;
}
export const maximumTabs = 8;

export function TerminalWorkspace({
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
  onSelectAccess,
  onActionLock,
  onTabCount,
  onLogout,
}: {
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
  onSelectAccess: (access: WebAccess | null) => void;
  onActionLock: (locked: boolean) => void;
  onTabCount: (count: number) => void;
  onLogout: (access: WebAccess) => void;
}) {
  const [tabs, setTabs] = useState<readonly ShellTab[]>([]);
  const current = useRef<readonly ShellTab[]>([]);
  const nextID = useRef(0);
  const lastAuthorization = useRef<WebAccess | null>(null);
  const actionOwners = useRef<ReadonlySet<number>>(new Set());
  const lastRetired = useRef<WebAccess | null>(null);
  const tabList = useRef<HTMLDivElement | null>(null);
  const controls = useRef(new Map<number, TerminalActions>());
  const [active, setActive] = useState<number | null>(null);
  const [closing, setClosing] = useState<number | null>(null);
  const [limit, setLimit] = useState(false);
  const [menuTab, setMenuTab] = useState<number | null>(null);
  const [newMenuOpen, setNewMenuOpen] = useState(false);
  const [focusTerminal, setFocusTerminal] = useState(true);
  const updateTabs = useCallback((next: readonly ShellTab[]) => {
    current.current = next;
    setTabs(next);
  }, []);
  useEffect(() => onTabCount(tabs.length), [tabs.length, onTabCount]);
  const lockOwner = useCallback(
    (owner: number, locked: boolean) => {
      actionOwners.current = ownerLocks(actionOwners.current, owner, locked);
      if (locked) {
        // Retire any older close intent. It must not outlive this action and
        // later unmount its owner/unknown warning through a stale confirmation.
        setClosing(null);
        setLimit(false);
        setMenuTab(null);
        setNewMenuOpen(false);
        const tab = current.current.find((entry) => entry.id === owner);
        if (tab) {
          setActive(owner);
          onSelectAccess(tab.access);
        }
      }
      onActionLock(actionOwners.current.size > 0);
    },
    [onActionLock, onSelectAccess],
  );
  const onState = useCallback(
    (id: number, state: TerminalState) => {
      updateTabs(current.current.map((tab) => (tab.id === id ? { ...tab, state } : tab)));
    },
    [updateTabs],
  );
  const onActions = useCallback((id: number, actions: TerminalActions | null) => {
    if (actions) {
      controls.current.set(id, actions);
    } else {
      controls.current.delete(id);
    }
  }, []);
  const open = useCallback(
    (selected: WebAccess) => {
      if (current.current.length >= maximumTabs) {
        setLimit(true);
        return;
      }
      const tab: ShellTab = {
        id: ++nextID.current,
        kind: selected.snapshot().terminalAvailable ? 'terminal' : 'management',
        access: selected,
        cancellation: new AbortController(),
        state: { phase: 'connecting' },
        inputClosed: false,
      };
      updateTabs([...current.current, tab]);
      setActive(tab.id);
      onSelectAccess(selected);
      setFocusTerminal(true);
      setLimit(false);
    },
    [updateTabs, onSelectAccess],
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
      open(authorizationEvent);
    } else {
      setActive(null);
    }
  }, [authorizationEvent, retiredAccess, blocked, open]);
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
    setActive(next?.id ?? null);
    onSelectAccess(next?.access ?? null);
    setClosing(null);
    setLimit(false);
    setMenuTab(null);
    setNewMenuOpen(false);
    if (!next) {
      nextID.current = 0;
    }
  }, [retiredAccess, onSelectAccess, updateTabs]);
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
        setActive(next?.id ?? null);
        if (next) {
          onSelectAccess(next.access);
        }
      }
    }
  }, [blocked, active, onSelectAccess, updateTabs]);
  useEffect(
    () => () => {
      for (const tab of current.current) {
        tab.cancellation.abort();
      }
    },
    [],
  );

  const closingTab = tabs.find((tab) => tab.id === closing);
  useEffect(() => {
    const showActive = () => {
      if (active === null) {
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
    }
    return () => observer.disconnect();
  }, [active]);
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
      setActive(next?.id ?? null);
      onSelectAccess(next?.access ?? null);
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
    if (blocked || focusBlocked || actionOwners.current.size > 0) {
      return;
    }
    if (Date.parse(selectedAccess.snapshot().expiresAt) <= Date.now()) {
      onSignIn(selectedAccess.snapshot().scope);
      return;
    }
    if (
      selectedAccess.snapshot().terminalAvailable ||
      selectedAccess.snapshot().environment === 'management'
    ) {
      open(selectedAccess);
    }
  };

  const operate = (id: number, action: (tab: ShellTab) => void) => {
    if (blocked || focusBlocked || actionOwners.current.size > 0) {
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
        setActive(id);
        onSelectAccess(tab.access);
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
  const showConnectionMenu = () => {
    if (blocked || focusBlocked || actionOwners.current.size > 0) {
      return;
    }
    setMenuTab(null);
    setNewMenuOpen(true);
  };
  const available = tabs
    .filter((tab, index) => tabs.findIndex((entry) => entry.access === tab.access) === index)
    .filter((tab) => Date.parse(tab.access.snapshot().expiresAt) > Date.now());
  const keyboardTab = (event: React.KeyboardEvent, index: number) => {
    if (blocked || focusBlocked) {
      return;
    }
    const next =
      event.key === 'ArrowRight'
        ? (index + 1) % tabs.length
        : event.key === 'ArrowLeft'
          ? (index + tabs.length - 1) % tabs.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? tabs.length - 1
              : -1;
    const tab = tabs[next];
    if (tab) {
      event.preventDefault();
      setFocusTerminal(false);
      setActive(tab.id);
      onSelectAccess(tab.access);
      document.getElementById(`terminal-tab-${tab.id}`)?.focus();
    }
  };

  return (
    <main className="workspace terminal-workspace" aria-label={title}>
      <header className="application-bar">
        <div className="application-tabs">
          <div
            ref={tabList}
            className="terminal-tab-list"
            role="tablist"
            aria-label={t('connectionTabs')}
          >
            {tabs.map((tab, index) => (
              <ConnectionTab
                key={tab.id}
                id={tab.id}
                kind={tab.kind}
                scope={tab.access.snapshot().scope.slug}
                principal={tab.access.snapshot().principal}
                state={tab.state}
                inputClosed={tab.inputClosed}
                active={active === tab.id}
                disabled={blocked || focusBlocked}
                full={tabs.length >= maximumTabs}
                opened={menuTab === tab.id}
                onSelect={() =>
                  operate(tab.id, (entry) => {
                    setFocusTerminal(true);
                    setActive(entry.id);
                    onSelectAccess(entry.access);
                  })
                }
                onMenu={(value) => showTabMenu(tab.id, value)}
                onKeyboard={(event) => keyboardTab(event, index)}
                onDuplicate={() => operate(tab.id, (entry) => duplicateAccess(entry.access))}
                onClose={() => operate(tab.id, requestClose)}
                onLogout={() => operate(tab.id, (entry) => onLogout(entry.access))}
                onRenew={() => operate(tab.id, (entry) => onSignIn(entry.access.snapshot().scope))}
                onEof={() =>
                  operate(tab.id, (entry) => {
                    if (controls.current.get(entry.id)?.eof()) {
                      updateTabs(
                        current.current.map((item) =>
                          item.id === entry.id ? { ...item, inputClosed: true } : item,
                        ),
                      );
                    }
                  })
                }
                onSignal={(signal) =>
                  operate(tab.id, (entry) => {
                    controls.current.get(entry.id)?.signal(signal);
                  })
                }
                onDisconnect={() =>
                  operate(tab.id, (entry) => {
                    controls.current.get(entry.id)?.disconnect();
                  })
                }
              />
            ))}
          </div>
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
                  disabled={blocked || tabs.length >= maximumTabs}
                  title={t('connectionNew')}
                  onClick={() => {
                    setNewMenuOpen(false);
                    onNewConnection();
                  }}
                >
                  +
                </ActionIcon>
                <Menu.Target>
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="lg"
                    aria-label={t('connectionOptions')}
                    disabled={blocked}
                  >
                    ⌄
                  </ActionIcon>
                </Menu.Target>
              </ActionIcon.Group>
            </Menu.ContextMenu>
            <Menu.Dropdown>
              <Menu.Item disabled={blocked || tabs.length >= maximumTabs} onClick={onNewConnection}>
                {t('connectionNew')}
              </Menu.Item>
              {available.length > 0 && <Menu.Label>{t('connectionAvailable')}</Menu.Label>}
              {available.map((tab) => (
                <Menu.Item
                  key={tab.id}
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
            hidden={active !== tab.id}
            data-terminal-active={tab.kind === 'terminal' && active === tab.id}
            data-connection-active={active === tab.id}
            data-connection-principal={tab.access.snapshot().principal}
            data-connection-scope={tab.access.snapshot().scope.slug}
            key={tab.id}
          >
            {tab.kind === 'terminal' ? (
              <TerminalPanel
                id={tab.id}
                access={tab.access}
                signal={tab.cancellation.signal}
                active={active === tab.id}
                inputAllowed={
                  !blocked &&
                  !focusBlocked &&
                  closing === null &&
                  !limit &&
                  menuTab === null &&
                  !newMenuOpen
                }
                focusOnActivate={focusTerminal}
                onState={onState}
                onActions={onActions}
              />
            ) : (
              <ManagementWorkspace
                owner={tab.id}
                access={tab.access}
                active={
                  active === tab.id &&
                  !focusBlocked &&
                  closing === null &&
                  !limit &&
                  menuTab === null &&
                  !newMenuOpen
                }
                disabled={unavailableAccess === tab.access}
                onActionLock={lockOwner}
              />
            )}
            {tab.kind === 'terminal' && active === tab.id && (
              <span
                role="status"
                className={
                  tab.state.phase === 'connected'
                    ? 'terminal-state terminal-state--quiet'
                    : 'terminal-state'
                }
                data-terminal-phase={tab.state.phase}
                data-terminal-exit-status={
                  tab.state.phase === 'exited' ? tab.state.status : undefined
                }
              >
                {t(terminalStatus(tab.state))}
                {tab.state.phase === 'exited' ? ` ${tab.state.status}` : ''}
              </span>
            )}
          </div>
        ))}
      </div>
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

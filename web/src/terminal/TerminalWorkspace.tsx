import { Button, Menu, Modal } from '@mantine/core';
import type { ReactNode } from 'react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { Scope, WebAccess } from '../remember';
import { ManagementWorkspace } from '../ui/ManagementWorkspace';
import { t } from '../ui/messages';
import { canCloseView, ownerLocks } from '../ui/workspace-state';
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
  access,
  authorizationEvent,
  retiredAccess,
  unavailableAccess,
  blocked,
  focusBlocked,
  title,
  scope,
  account,
  notice,
  onSignIn,
  onNewConnection,
  onSelectAccess,
  onActionLock,
  onTabCount,
}: {
  access: WebAccess | null;
  authorizationEvent: WebAccess | null;
  retiredAccess: WebAccess | null;
  unavailableAccess: WebAccess | null;
  blocked: boolean;
  focusBlocked: boolean;
  title: string;
  scope: string;
  account: ReactNode;
  notice: ReactNode;
  onSignIn: (scope?: Scope) => void;
  onNewConnection: () => void;
  onSelectAccess: (access: WebAccess | null) => void;
  onActionLock: (locked: boolean) => void;
  onTabCount: (count: number) => void;
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
  const [toolsOpen, setToolsOpen] = useState(false);
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

  const selected = tabs.find((tab) => tab.id === active);
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
      if (next) {
        onSelectAccess(next.access);
      }
    }
    setClosing(null);
    setLimit(false);
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
  const newTab = () => {
    if (blocked) {
      return;
    }
    if (!access || Date.parse(access.snapshot().expiresAt) <= Date.now()) {
      onSignIn(access?.snapshot().scope);
      return;
    }
    if (access.snapshot().terminalAvailable || access.snapshot().environment === 'management') {
      open(access);
    }
  };
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
    <main className="workspace terminal-workspace">
      <header className="application-bar">
        <div className="application-brand">
          <h1 title={title}>{title}</h1>
          <span>{scope || '/'}</span>
        </div>
        <div className="application-status">
          {selected?.kind === 'terminal' ? (
            <>
              <span className={`connection-dot connection-dot--${selected.state.phase}`} />
              <span
                role="status"
                data-terminal-phase={selected.state.phase}
                data-terminal-exit-status={
                  selected.state.phase === 'exited' ? selected.state.status : undefined
                }
              >
                {t(terminalStatus(selected.state))}
                {selected.state.phase === 'exited' ? ` ${selected.state.status}` : ''}
              </span>
              <span className="terminal-owner">{selected.access.snapshot().principal}</span>
            </>
          ) : (
            <span role="status">
              {t(
                selected?.kind === 'management'
                  ? 'workspaceManagement'
                  : access
                    ? 'terminalNoTab'
                    : 'terminalSignedOut',
              )}
            </span>
          )}
        </div>
        <div className="application-account">
          {notice}
          {account}
        </div>
        <div className="application-tabs">
          <div
            ref={tabList}
            className="terminal-tab-list"
            role="tablist"
            aria-label={t('connectionTabs')}
          >
            {tabs.map((tab, index) => (
              <div className="terminal-tab" key={tab.id}>
                <button
                  id={`terminal-tab-${tab.id}`}
                  type="button"
                  role="tab"
                  aria-label={`${t(tab.kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')} ${tab.id} ${tab.access.snapshot().principal}`}
                  aria-describedby={`connection-scope-${tab.id}`}
                  aria-controls={`terminal-pane-${tab.id}`}
                  aria-selected={active === tab.id}
                  tabIndex={active === tab.id ? 0 : -1}
                  disabled={blocked || focusBlocked}
                  onKeyDown={(event) => keyboardTab(event, index)}
                  onClick={() => {
                    setFocusTerminal(true);
                    setActive(tab.id);
                    onSelectAccess(tab.access);
                  }}
                >
                  <span
                    className={`connection-dot connection-dot--${tab.kind === 'terminal' ? tab.state.phase : 'connected'}`}
                  />
                  <span id={`connection-scope-${tab.id}`} className="tab-scope">
                    {tab.access.snapshot().scope.slug || '/'}
                  </span>
                  <span className="tab-owner">{tab.access.snapshot().principal}</span>
                  <span>
                    {t(tab.kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')}
                    {tab.kind === 'terminal' ? ` ${tab.id}` : ''}
                  </span>
                </button>
                <button
                  type="button"
                  className="terminal-tab-close"
                  aria-label={`${t(tab.kind === 'terminal' ? 'terminalCloseTab' : 'managementCloseTab')} ${tab.id}`}
                  disabled={blocked || focusBlocked}
                  onClick={() => requestClose(tab)}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
          {(access?.snapshot().terminalAvailable ||
            access?.snapshot().environment === 'management') && (
            <Button
              variant="subtle"
              className="new-terminal"
              aria-label={t(
                access.snapshot().terminalAvailable ? 'terminalNewTab' : 'managementOpenTab',
              )}
              title={`${t(access.snapshot().terminalAvailable ? 'terminalNewTab' : 'managementOpenTab')}: ${access.snapshot().scope.slug || '/'} · ${access.snapshot().principal}`}
              disabled={blocked || tabs.length >= maximumTabs}
              onClick={newTab}
            >
              {t(access.snapshot().terminalAvailable ? 'terminalNewTab' : 'managementOpenTab')}
            </Button>
          )}
          <Button
            variant="light"
            className="new-connection"
            aria-label={t('connectionNew')}
            disabled={blocked || tabs.length >= maximumTabs}
            onClick={onNewConnection}
          >
            + {t('connectionNew')}
          </Button>
          {selected?.kind === 'terminal' && (
            <Menu position="bottom-end" opened={toolsOpen} onChange={setToolsOpen}>
              <Menu.Target>
                <Button variant="subtle" disabled={blocked} aria-label={t('terminalActions')}>
                  ⋯
                </Button>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Item
                  disabled={selected.state.phase !== 'connected' || selected.inputClosed}
                  onClick={() => {
                    if (controls.current.get(selected.id)?.eof()) {
                      updateTabs(
                        current.current.map((tab) =>
                          tab.id === selected.id ? { ...tab, inputClosed: true } : tab,
                        ),
                      );
                    }
                  }}
                >
                  {t('terminalEof')}
                </Menu.Item>
                <Menu.Item
                  disabled={selected.state.phase !== 'connected'}
                  onClick={() => controls.current.get(selected.id)?.signal('INT')}
                >
                  {t('terminalInterrupt')}
                </Menu.Item>
                <Menu.Item
                  disabled={selected.state.phase !== 'connected'}
                  onClick={() => controls.current.get(selected.id)?.signal('TERM')}
                >
                  {t('terminalTerminate')}
                </Menu.Item>
                <Menu.Item
                  disabled={!['connecting', 'connected'].includes(selected.state.phase)}
                  onClick={() => controls.current.get(selected.id)?.disconnect()}
                >
                  {t('terminalDisconnect')}
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          )}
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
            key={tab.id}
          >
            {tab.kind === 'terminal' ? (
              <TerminalPanel
                id={tab.id}
                access={tab.access}
                signal={tab.cancellation.signal}
                active={active === tab.id}
                inputAllowed={!blocked && !focusBlocked && closing === null && !limit && !toolsOpen}
                focusOnActivate={focusTerminal}
                onState={onState}
                onActions={onActions}
              />
            ) : (
              <ManagementWorkspace
                owner={tab.id}
                access={tab.access}
                active={active === tab.id && !focusBlocked && closing === null && !limit}
                disabled={unavailableAccess === tab.access}
                onActionLock={lockOwner}
              />
            )}
          </div>
        ))}
        {!selected && (
          <div className="workspace-empty">
            <h2>{t('terminalNoTab')}</h2>
            <p>{t(access ? 'terminalNewTabHint' : 'terminalSignInHint')}</p>
          </div>
        )}
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

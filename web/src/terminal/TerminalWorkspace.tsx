import { Button, Menu, Modal } from '@mantine/core';
import type { ReactNode } from 'react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { t } from '../ui/messages';
import type { TerminalState } from './socket';
import type { TerminalActions } from './TerminalPanel';
import { TerminalPanel, terminalStatus } from './TerminalPanel';

interface ShellTab {
  readonly id: number;
  readonly access: WebAccess;
  readonly cancellation: AbortController;
  readonly state: TerminalState;
  readonly inputClosed: boolean;
}
const maximumTabs = 8;

export function TerminalWorkspace({
  access,
  authorizationEvent,
  blocked,
  focusBlocked,
  title,
  scope,
  account,
  notice,
  managementView,
  onManagementView,
  children,
  onSignIn,
}: {
  access: WebAccess | null;
  authorizationEvent: number;
  blocked: boolean;
  focusBlocked: boolean;
  title: string;
  scope: string;
  account: ReactNode;
  notice: ReactNode;
  managementView: 'sessions' | 'artifacts' | 'server';
  onManagementView: (view: 'sessions' | 'artifacts' | 'server') => void;
  children: ReactNode;
  onSignIn: () => void;
}) {
  const [tabs, setTabs] = useState<readonly ShellTab[]>([]);
  const current = useRef<readonly ShellTab[]>([]);
  const nextID = useRef(0);
  const lastAuthorization = useRef(0);
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
        access: selected,
        cancellation: new AbortController(),
        state: { phase: 'connecting' },
        inputClosed: false,
      };
      updateTabs([...current.current, tab]);
      setActive(tab.id);
      setFocusTerminal(true);
      setLimit(false);
    },
    [updateTabs],
  );
  useEffect(() => {
    if (!access || blocked || authorizationEvent === lastAuthorization.current) {
      return;
    }
    lastAuthorization.current = authorizationEvent;
    if (access.snapshot().terminalAvailable) {
      open(access);
    } else {
      setActive(null);
    }
  }, [access, authorizationEvent, blocked, open]);
  useEffect(() => {
    if (!blocked) {
      return;
    }
    // Do not let an unstarted/connecting old grant dispatch later during login
    // cancellation or an actor change. Already running shells remain owned.
    const pending = current.current.filter((tab) => tab.state.phase === 'connecting');
    for (const tab of pending) {
      tab.cancellation.abort();
    }
    if (pending.length) {
      const remaining = current.current.filter((tab) => !pending.includes(tab));
      updateTabs(remaining);
      setActive((value) =>
        remaining.some((tab) => tab.id === value) ? value : (remaining.at(-1)?.id ?? null),
      );
    }
  }, [blocked, updateTabs]);
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
    if (active !== null) {
      document
        .getElementById(`terminal-tab-${active}`)
        ?.scrollIntoView({ inline: 'nearest', block: 'nearest' });
    }
  }, [active]);
  const remove = (id: number) => {
    const tab = current.current.find((entry) => entry.id === id);
    tab?.cancellation.abort();
    const remaining = current.current.filter((entry) => entry.id !== id);
    updateTabs(remaining);
    if (active === id) {
      setActive(remaining.at(-1)?.id ?? null);
    }
    setClosing(null);
    setLimit(false);
  };
  const requestClose = (tab: ShellTab) => {
    if (['connecting', 'connected', 'finishing'].includes(tab.state.phase)) {
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
      onSignIn();
      return;
    }
    if (access.snapshot().terminalAvailable) {
      open(access);
    }
  };
  const keyboardTab = (event: React.KeyboardEvent, index: number) => {
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
          {selected ? (
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
                access?.snapshot().environment === 'management'
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
        <div className="application-tabs" hidden={!tabs.length && !access}>
          <div className="terminal-tab-list" role="tablist" aria-label={t('terminalTabs')}>
            {tabs.map((tab, index) => (
              <div className="terminal-tab" key={tab.id}>
                <button
                  id={`terminal-tab-${tab.id}`}
                  type="button"
                  role="tab"
                  aria-controls={`terminal-pane-${tab.id}`}
                  aria-selected={active === tab.id}
                  tabIndex={active === tab.id ? 0 : -1}
                  onKeyDown={(event) => keyboardTab(event, index)}
                  onClick={() => {
                    setFocusTerminal(true);
                    setActive(tab.id);
                  }}
                >
                  <span className={`connection-dot connection-dot--${tab.state.phase}`} />
                  {t('terminalTitle')} {tab.id}
                  <span className="tab-owner">{tab.access.snapshot().principal}</span>
                </button>
                <button
                  type="button"
                  className="terminal-tab-close"
                  aria-label={`${t('terminalCloseTab')} ${tab.id}`}
                  disabled={blocked}
                  onClick={() => requestClose(tab)}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
          {access?.snapshot().terminalAvailable && (
            <Button
              variant="subtle"
              className="new-terminal"
              aria-label={t('terminalNewTab')}
              title={t('terminalNewTab')}
              disabled={blocked || tabs.length >= maximumTabs}
              onClick={newTab}
            >
              +
            </Button>
          )}
          {access?.snapshot().environment === 'management' && (
            <nav className="workspace-nav" aria-label={t('workspaceNavigation')}>
              {(['sessions', 'artifacts', 'server'] as const).map((view) => (
                <Button
                  key={view}
                  variant={active === null && managementView === view ? 'light' : 'subtle'}
                  aria-current={active === null && managementView === view ? 'page' : undefined}
                  disabled={blocked}
                  onClick={() => {
                    setActive(null);
                    onManagementView(view);
                  }}
                >
                  {t(
                    view === 'sessions'
                      ? 'workspaceSessions'
                      : view === 'artifacts'
                        ? 'workspaceArtifacts'
                        : 'workspaceServer',
                  )}
                </Button>
              ))}
            </nav>
          )}
          {selected && (
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
            className="terminal-pane"
            id={`terminal-pane-${tab.id}`}
            role="tabpanel"
            aria-labelledby={`terminal-tab-${tab.id}`}
            hidden={active !== tab.id}
            data-terminal-active={active === tab.id}
            key={tab.id}
          >
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
          </div>
        ))}
        <div
          className="management-workspace"
          hidden={active !== null || access?.snapshot().environment !== 'management'}
        >
          {children}
        </div>
        {!selected && access?.snapshot().environment !== 'management' && (
          <div className="workspace-empty">
            <h2>{t('terminalNoTab')}</h2>
            <p>{t(access ? 'terminalNewTabHint' : 'terminalSignInHint')}</p>
          </div>
        )}
      </div>
      <Modal
        opened={closing !== null}
        onClose={() => setClosing(null)}
        title={t('terminalCloseTitle')}
        closeOnClickOutside={false}
        lockScroll={false}
      >
        {closingTab && (
          <p>
            {t('terminalTitle')} {closingTab.id} · {closingTab.access.snapshot().principal}
          </p>
        )}
        <p>{t('terminalCloseWarning')}</p>
        <div className="actions">
          <Button
            color="red"
            onClick={() => {
              if (closing !== null) {
                remove(closing);
              }
            }}
          >
            {t('terminalCloseConfirm')}
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

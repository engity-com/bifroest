import type { WebAccess } from '../remember';
import { newViewID } from '../shared/uuid';
import type { ConnectionActions, TerminalActions } from '../terminal/connection-actions';
import type { TerminalState } from '../terminal/socket';
import { tabTitle } from '../terminal/tab-title';
import { WorkspaceConnections } from './connections';
import type { WorkspaceBoundary } from './contracts';
import {
    type ConnectionView,
    initialWorkspaceState,
    maximumTabs,
    type WorkspaceControls,
    type WorkspaceState,
    type WorkspaceTab,
} from './model';
import { canCloseView, canOperate, keyboardAvailable } from './policy';
import { type WorkspaceEvent, workspaceTransition } from './state';

// One mounted workspace's application model. No React, DOM, authentication,
// storage or reconnect implementation enters this controller.
export class WorkspaceController {
    #state = initialWorkspaceState();
    #nextID = 0;
    #mounted = false;
    #lease = 0;
    readonly #listeners = new Set<() => void>();
    readonly #connections = new WorkspaceConnections();
    readonly #accepted = new WeakSet<WebAccess>();
    readonly #retired = new WeakSet<WebAccess>();

    constructor(
        private readonly boundary: () => WorkspaceBoundary,
        private readonly labels: { terminal: string; management: string },
    ) {}

    readonly getSnapshot = (): WorkspaceState => this.#state;
    readonly subscribe = (listener: () => void): (() => void) => {
        this.#listeners.add(listener);
        return () => {
            this.#listeners.delete(listener);
        };
    };

    mount(): () => void {
        const lease = ++this.#lease;
        this.#mounted = true;
        // Effect replay cannot resurrect an aborted connection or replay a grant.
        if (
            this.#state.tabs.some((tab) => tab.signal.aborted && tab.state.phase !== 'disconnected')
        ) {
            for (const tab of this.#state.tabs) {
                if (tab.signal.aborted) {
                    this.#dispatch({ type: 'state', id: tab.id, state: { phase: 'disconnected' } });
                }
            }
        }
        return () => {
            if (this.#lease === lease) {
                this.#mounted = false;
                this.#connections.abortAll();
            }
        };
    }

    #dispatch(event: WorkspaceEvent, after?: () => void): void {
        const previous = this.#state;
        const next = workspaceTransition(previous, event);
        this.#state = next;
        const remaining = new Set(next.tabs.map((tab) => tab.id));
        for (const tab of previous.tabs) {
            if (!remaining.has(tab.id)) {
                this.#connections.abort(tab.id);
            }
        }
        const structural =
            previous.tabs.length !== next.tabs.length ||
            next.tabs.some((tab, index) => tab.id !== previous.tabs[index]?.id);
        if (structural) {
            this.boundary().onViewsChange(this.#state.tabs);
        }
        after?.();
        for (const listener of this.#listeners) {
            listener();
        }
    }

    #operate(id: number, action: (tab: WorkspaceTab) => void): void {
        if (!this.#mounted || !canOperate(this.#state, this.boundary())) {
            return;
        }
        const tab = this.#state.tabs.find((entry) => entry.id === id);
        if (tab) {
            action(tab);
        }
    }

    #open(access: WebAccess, replace: boolean): void {
        if (this.#state.tabs.length >= maximumTabs) {
            this.#dispatch({ type: 'limit', visible: true });
            return;
        }
        const id = ++this.#nextID;
        const snapshot = access.snapshot();
        const tab: WorkspaceTab = Object.freeze<WorkspaceTab>({
            id,
            routeId: newViewID(),
            access,
            scope: Object.freeze({ ...snapshot.scope }),
            kind: snapshot.terminalAvailable ? 'terminal' : 'management',
            signal: this.#connections.create(id),
            state: { phase: 'connecting' },
            inputClosed: false,
            title: snapshot.terminalAvailable
                ? (snapshot.flow?.title ?? this.labels.terminal)
                : this.labels.management,
        });
        this.#dispatch({ type: 'opened', tab }, () => {
            this.boundary().onSelectView(tab, replace);
        });
    }

    acceptAuthorization(access: WebAccess | null, retired: WebAccess | null): void {
        if (!this.#mounted || !access || this.boundary().blocked || this.#accepted.has(access)) {
            return;
        }
        this.#accepted.add(access);
        if (access === retired || this.#retired.has(access)) {
            return;
        }
        const snapshot = access.snapshot();
        if (snapshot.terminalAvailable || snapshot.environment === 'management') {
            this.#open(access, true);
        } else {
            this.boundary().onSelectView(null);
        }
    }

    retireAccess(access: WebAccess | null): void {
        if (!this.#mounted || !access || this.#retired.has(access)) {
            return;
        }
        this.#retired.add(access);
        this.#dispatch(
            {
                type: 'removed',
                ids: this.#state.tabs.filter((tab) => tab.access === access).map((tab) => tab.id),
                dismiss: true,
            },
            () => {
                this.boundary().onSelectView(this.#state.tabs.at(-1) ?? null, true);
            },
        );
    }

    reconcileBlocked(): void {
        if (!this.#mounted || !this.boundary().blocked) {
            return;
        }
        const pending = this.#state.tabs.filter(
            (tab) => tab.kind === 'terminal' && tab.state.phase === 'connecting',
        );
        if (pending.length === 0) {
            return;
        }
        const ids = new Set(pending.map((tab) => tab.id));
        this.#dispatch({ type: 'removed', ids: [...ids] }, () => {
            if (ids.has(this.boundary().activeView ?? -1)) {
                const next = this.#state.tabs.at(-1);
                if (next) {
                    this.boundary().onSelectView(next, true);
                }
            }
        });
    }

    reconcileSettings(): void {
        const boundary = this.boundary();
        if (
            this.#mounted &&
            this.#state.settings !== null &&
            (boundary.blocked || boundary.focusBlocked || boundary.authenticating)
        ) {
            this.#dispatch({ type: 'settings', owner: null });
        }
    }

    readonly stateChanged = (id: number, state: TerminalState): void => {
        if (!this.#mounted || !this.#connections.active(id)) {
            return;
        }
        this.#dispatch({ type: 'state', id, state }, () => {
            if (
                state.phase === 'exited' &&
                state.status === 0 &&
                this.boundary().activeView === id
            ) {
                this.boundary().onSelectView(this.#state.tabs.at(-1) ?? null, true);
            }
        });
    };

    readonly titleChanged = (id: number, value: string): void => {
        const title = tabTitle(value);
        if (
            !this.#mounted ||
            !this.#connections.active(id) ||
            this.#state.tabs.find((tab) => tab.id === id)?.title === title
        ) {
            return;
        }
        this.#dispatch({ type: 'title', id, title });
    };

    readonly terminalActions = (id: number, actions: TerminalActions | null): void => {
        this.#connections.registerTerminal(id, actions);
    };
    readonly connectionActions = (id: number, actions: ConnectionActions | null): void => {
        this.#connections.registerConnection(id, actions);
    };
    settingsActions(id: number): ConnectionActions | null {
        return this.#connections.connection(id);
    }

    readonly lockOwner = (owner: number, locked: boolean): void => {
        if (!this.#mounted || (locked && !this.#connections.active(owner))) {
            return;
        }
        this.#dispatch({ type: 'owner-lock', owner, locked }, () => {
            if (locked) {
                const tab = this.#state.tabs.find((entry) => entry.id === owner);
                if (tab) {
                    this.boundary().onSelectView(tab);
                }
            }
            this.boundary().onActionLock(this.#state.actionOwners.size > 0);
        });
    };

    select(id: number, focusTerminal = true): void {
        this.#operate(id, (tab) => {
            this.#dispatch({ type: 'focus', terminal: focusTerminal }, () =>
                this.boundary().onSelectView(tab),
            );
        });
    }

    cycle(backward: boolean): void {
        if (
            !this.#mounted ||
            !keyboardAvailable(this.#state, this.boundary()) ||
            this.#state.tabs.length < 2
        ) {
            return;
        }
        const index = this.#state.tabs.findIndex((tab) => tab.id === this.boundary().activeView);
        const next =
            this.#state.tabs[
                (index + (backward ? -1 : 1) + this.#state.tabs.length) % this.#state.tabs.length
            ];
        if (next) {
            this.select(next.id);
        }
    }

    duplicate(id: number): void {
        this.#operate(id, (tab) => {
            if (
                tab.access.status() !== 'active' ||
                tab.access.snapshot().environment === 'management'
            ) {
                this.boundary().onSignIn(tab.scope);
            } else if (tab.access.snapshot().terminalAvailable) {
                this.#open(tab.access, false);
            }
        });
    }

    reauthenticate(id: number): void {
        if (this.boundary().authenticating || this.#state.tabs.length >= maximumTabs) {
            return;
        }
        this.#operate(id, (tab) => this.boundary().onSignIn(tab.scope));
    }

    newConnection(): void {
        if (
            !this.#mounted ||
            !canOperate(this.#state, this.boundary()) ||
            this.#state.tabs.length >= maximumTabs
        ) {
            return;
        }
        this.#dispatch({ type: 'menu', menu: null }, () => this.boundary().onNewConnection());
    }

    logout(id: number): void {
        this.#operate(id, (tab) => this.boundary().onLogout(tab.access));
    }

    requestClose(id: number): void {
        this.#operate(id, (tab) => {
            if (
                !canCloseView(
                    this.boundary().blocked,
                    this.boundary().focusBlocked,
                    this.#state.actionOwners,
                )
            ) {
                return;
            }
            if (
                tab.kind === 'management' ||
                ['connecting', 'connected', 'finishing'].includes(tab.state.phase)
            ) {
                this.#dispatch({ type: 'closing', owner: id });
            } else {
                this.#remove(id);
            }
        });
    }

    #remove(id: number): void {
        if (
            !this.#mounted ||
            !canCloseView(
                this.boundary().blocked,
                this.boundary().focusBlocked,
                this.#state.actionOwners,
            )
        ) {
            return;
        }
        this.#dispatch({ type: 'removed', ids: [id], dismiss: true }, () => {
            if (this.boundary().activeView === id) {
                this.boundary().onSelectView(this.#state.tabs.at(-1) ?? null, true);
            }
        });
    }

    confirmClose(): void {
        if (this.#state.closing !== null) {
            this.#remove(this.#state.closing);
        }
    }
    closeManagementShortcut(id: number): void {
        if (
            keyboardAvailable(this.#state, this.boundary()) &&
            this.#state.tabs.some((tab) => tab.id === id && tab.kind === 'management')
        ) {
            this.#remove(id);
        }
    }
    cancelClose(): void {
        if (this.#mounted) {
            this.#dispatch({ type: 'closing', owner: null });
        }
    }
    dismissLimit(): void {
        if (this.#mounted) {
            this.#dispatch({ type: 'limit', visible: false });
        }
    }
    closeCopyLink(): void {
        if (this.#mounted) {
            this.#dispatch({ type: 'copy-link', url: null });
        }
    }
    showCopyLink(id: number, url: string): void {
        if (this.copyTarget(id)) {
            this.#dispatch({ type: 'copy-link', url });
        }
    }
    copyTarget(id: number): ConnectionView | null {
        return this.#mounted && canOperate(this.#state, this.boundary())
            ? (this.#state.tabs.find((tab) => tab.id === id) ?? null)
            : null;
    }
    navigationTarget(id: number): ConnectionView | null {
        const boundary = this.boundary();
        return this.#mounted &&
            !boundary.blocked &&
            !boundary.focusBlocked &&
            !boundary.authenticating &&
            boundary.activeView === id &&
            this.#state.actionOwners.size === 0
            ? (this.#state.tabs.find((tab) => tab.id === id && tab.kind === 'management') ?? null)
            : null;
    }

    openTabMenu(id: number): void {
        this.#operate(id, (tab) => {
            this.#dispatch({ type: 'menu', menu: { kind: 'tab', owner: id } }, () =>
                this.boundary().onSelectView(tab),
            );
        });
    }
    closeTabMenu(id: number): void {
        if (this.#mounted && this.#state.menu?.kind === 'tab' && this.#state.menu.owner === id) {
            this.#dispatch({ type: 'menu', menu: null });
        }
    }
    openNewMenu(): void {
        if (this.#mounted && canOperate(this.#state, this.boundary())) {
            this.#dispatch({ type: 'menu', menu: { kind: 'new' } });
        }
    }
    closeNewMenu(): void {
        if (this.#mounted && this.#state.menu?.kind === 'new') {
            this.#dispatch({ type: 'menu', menu: null });
        }
    }
    openSettings(id: number): void {
        this.#operate(id, (tab) => {
            if (tab.state.phase === 'connected') {
                this.#dispatch({ type: 'settings', owner: id });
            }
        });
    }
    closeSettings(): void {
        if (this.#mounted) {
            this.#dispatch({ type: 'settings', owner: null });
        }
    }

    eof(id: number): void {
        this.#operate(id, (tab) => {
            if (
                tab.kind === 'terminal' &&
                !tab.inputClosed &&
                tab.state.phase === 'connected' &&
                this.#connections.terminal(id)?.eof()
            ) {
                this.#dispatch({ type: 'input-closed', id });
            }
        });
    }
    signal(id: number, value: 'INT' | 'TERM'): void {
        this.#operate(id, (tab) => {
            if (tab.kind === 'terminal' && tab.state.phase === 'connected') {
                this.#connections.terminal(id)?.signal(value);
            }
        });
    }
    disconnect(id: number): void {
        this.#operate(id, (tab) => {
            if (tab.kind === 'terminal' && ['connecting', 'connected'].includes(tab.state.phase)) {
                this.#connections.terminal(id)?.disconnect();
            }
        });
    }

    readonly controls: WorkspaceControls = {
        closeAll: (options = {}) => {
            if (
                !this.#mounted ||
                this.#state.actionOwners.size > 0 ||
                (!options.resetConfirmed && this.boundary().blocked)
            ) {
                return false;
            }
            this.#dispatch({ type: 'cleared' }, () => this.boundary().onSelectView(null, true));
            return true;
        },
    };
}

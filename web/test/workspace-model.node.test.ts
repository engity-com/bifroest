import { describe, expect, it, vi } from 'vitest';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import type { TerminalActions } from '../src/terminal/connection-actions';
import { WorkspaceConnections } from '../src/workspace/connections';
import type { WorkspaceBoundary } from '../src/workspace/contracts';
import { WorkspaceController } from '../src/workspace/controller';
import { initialWorkspaceState, maximumTabs } from '../src/workspace/model';
import { workspacePolicy } from '../src/workspace/policy';
import { workspaceTransition } from '../src/workspace/state';

function permission(slug = 'Original', terminal = true, expires = '2100-01-01T00:00:00Z') {
    const scope = { origin: 'https://app.example.org', slug };
    const transport = vi.fn(() => {
        throw new Error('Unexpected network access');
    });
    const access = new WebAccess(
        new Http(scope, transport),
        {
            scope,
            principal: slug,
            expiresAt: expires,
            accessToken: `bwa1.${'A'.repeat(43)}`,
            environment: terminal ? 'terminal' : 'management',
            terminalAvailable: terminal,
        },
        null,
    );
    return { access, transport };
}

function workspace() {
    const boundary: WorkspaceBoundary = {
        activeView: null,
        blocked: false,
        focusBlocked: false,
        authenticating: false,
        onSignIn: vi.fn(),
        onNewConnection: vi.fn(),
        onSelectView: vi.fn((view) => {
            Object.assign(boundary, { activeView: view?.id ?? null });
        }),
        onViewsChange: vi.fn(),
        onActionLock: vi.fn(),
        onLogout: vi.fn(),
    };
    const controller = new WorkspaceController(() => boundary, {
        terminal: 'Terminal',
        management: 'Management',
    });
    const unmount = controller.mount();
    const change = (input: Partial<WorkspaceBoundary>) => Object.assign(boundary, input);
    const open = (access = permission().access) => {
        controller.acceptAuthorization(access, null);
        const tab = controller.getSnapshot().tabs.at(-1);
        if (!tab) {
            throw new Error('Expected workspace tab');
        }
        return tab;
    };
    return { controller, boundary, change, open, unmount };
}

describe('DOM-independent workspace ownership', () => {
    it('runs without React or a document and publishes structure only for added/removed views', () => {
        expect(typeof document).toBe('undefined');
        const w = workspace();
        const { access, transport } = permission('Exact/Slug');
        const listener = vi.fn();
        const unsubscribe = w.controller.subscribe(listener);
        const first = w.open(access);
        expect(first.access).toBe(access);
        expect(first.scope).toEqual(access.snapshot().scope);
        expect(first.scope).not.toBe(access.snapshot().scope);
        expect(w.boundary.onViewsChange).toHaveBeenCalledTimes(1);
        w.controller.stateChanged(first.id, { phase: 'connected' });
        w.controller.titleChanged(first.id, 'Owned title');
        expect(w.boundary.onViewsChange).toHaveBeenCalledTimes(1);
        expect(w.controller.getSnapshot().tabs[0]?.title).toBe('Owned title');
        expect(listener).toHaveBeenCalledTimes(3);
        unsubscribe();
        w.controller.titleChanged(first.id, 'Another title');
        expect(listener).toHaveBeenCalledTimes(3);
        expect(transport).not.toHaveBeenCalled();
        w.unmount();
        expect(first.signal.aborted).toBe(true);
    });

    it('aborts once on confirmed exit 0, selects the last survivor, and ignores late callbacks', () => {
        const w = workspace();
        const first = w.open();
        const last = w.open(permission('Second').access);
        const abort = vi.fn();
        last.signal.addEventListener('abort', abort);
        w.controller.stateChanged(last.id, { phase: 'exited', status: 0 });
        expect(abort).toHaveBeenCalledTimes(1);
        expect(w.boundary.activeView).toBe(first.id);
        w.controller.stateChanged(last.id, { phase: 'connected' });
        w.controller.titleChanged(last.id, 'Late title');
        expect(w.controller.getSnapshot().tabs).toEqual([first]);
        w.controller.stateChanged(first.id, { phase: 'exited', status: 0 });
        expect(w.boundary.onSelectView).toHaveBeenLastCalledWith(null, true);
        w.unmount();
        expect(abort).toHaveBeenCalledTimes(1);
    });

    it('retains nonzero and interrupted terminal output until an explicit close', () => {
        const w = workspace();
        const tab = w.open();
        w.controller.stateChanged(tab.id, { phase: 'exited', status: 7 });
        expect(w.controller.getSnapshot().tabs[0]?.state).toEqual({ phase: 'exited', status: 7 });
        expect(tab.signal.aborted).toBe(false);
        w.controller.requestClose(tab.id);
        expect(tab.signal.aborted).toBe(true);
        const next = w.open(permission('Interrupted').access);
        w.controller.stateChanged(next.id, { phase: 'interrupted', reason: 'connection-lost' });
        expect(next.signal.aborted).toBe(false);
        expect(w.controller.getSnapshot().tabs).toHaveLength(1);
        w.unmount();
    });

    it('does not replay an accepted or retired grant after rerenders, close-all or lifecycle replay', () => {
        const w = workspace();
        const access = permission().access;
        const tab = w.open(access);
        w.controller.acceptAuthorization(null, null);
        w.controller.acceptAuthorization(access, null);
        expect(w.controller.getSnapshot().tabs).toHaveLength(1);
        w.unmount();
        w.controller.stateChanged(tab.id, { phase: 'connected' });
        const unmountAgain = w.controller.mount();
        w.controller.acceptAuthorization(access, null);
        expect(w.controller.getSnapshot().tabs).toHaveLength(1);
        expect(w.controller.getSnapshot().tabs[0]?.state.phase).toBe('disconnected');
        w.controller.controls.closeAll({ resetConfirmed: true });
        w.controller.acceptAuthorization(access, null);
        expect(w.controller.getSnapshot().tabs).toHaveLength(0);
        const retired = permission('Retired').access;
        w.controller.retireAccess(retired);
        w.controller.acceptAuthorization(retired, null);
        expect(w.controller.getSnapshot().tabs).toHaveLength(0);
        unmountAgain();
    });

    it('defers blocked authorization and aborts only connecting terminals, never running or management owners', () => {
        const w = workspace();
        const running = w.open();
        w.controller.stateChanged(running.id, { phase: 'connected' });
        const management = w.open(permission('Management', false).access);
        const pending = w.open(permission('Pending').access);
        const delayed = permission('Delayed').access;
        w.change({ blocked: true });
        w.controller.acceptAuthorization(delayed, null);
        w.controller.reconcileBlocked();
        expect(pending.signal.aborted).toBe(true);
        expect(running.signal.aborted).toBe(false);
        expect(management.signal.aborted).toBe(false);
        expect(w.controller.getSnapshot().tabs.map((tab) => tab.id)).toEqual([
            running.id,
            management.id,
        ]);
        w.change({ blocked: false });
        w.controller.acceptAuthorization(delayed, null);
        expect(w.controller.getSnapshot().tabs.at(-1)?.access).toBe(delayed);
        w.unmount();
    });

    it('retires only the exact access owner, preserves other tabs and never reuses an ID', () => {
        const w = workspace();
        const access = permission().access;
        const first = w.open(access);
        w.controller.duplicate(first.id);
        const duplicate = w.controller.getSnapshot().tabs.at(-1);
        const other = w.open(permission().access);
        w.controller.retireAccess(access);
        expect(first.signal.aborted).toBe(true);
        expect(duplicate?.signal.aborted).toBe(true);
        expect(other.signal.aborted).toBe(false);
        expect(w.controller.getSnapshot().tabs).toEqual([other]);
        w.controller.controls.closeAll();
        expect(w.open().id).toBeGreaterThan(other.id);
        w.unmount();
    });

    it('caps tabs at the unchanged maximum without opening a connection beyond it', () => {
        const w = workspace();
        const first = w.open();
        for (let i = 1; i <= maximumTabs; i++) {
            w.controller.duplicate(first.id);
        }
        expect(w.controller.getSnapshot().tabs).toHaveLength(maximumTabs);
        expect(w.controller.getSnapshot().limit).toBe(true);
        w.controller.newConnection();
        expect(w.boundary.onNewConnection).not.toHaveBeenCalled();
        w.unmount();
    });

    it('requires explicit scope-bound authentication for a management or expired grant, without network access', () => {
        const w = workspace();
        for (const p of [
            permission('Management', false),
            permission('Expired', true, '2000-01-01T00:00:00Z'),
        ]) {
            const tab = w.open(p.access);
            const count = w.controller.getSnapshot().tabs.length;
            w.controller.duplicate(tab.id);
            expect(w.controller.getSnapshot().tabs).toHaveLength(count);
            expect(w.boundary.onSignIn).toHaveBeenLastCalledWith(tab.scope);
            expect(p.transport).not.toHaveBeenCalled();
        }
        w.unmount();
    });
});

describe('workspace guards at command time', () => {
    it.each(['blocked', 'focusBlocked', 'owner'] as const)(
        'rejects stale close/duplicate/logout intents after %s arrives',
        (guard) => {
            const w = workspace();
            const tab = w.open(permission('Management', false).access);
            w.controller.requestClose(tab.id);
            expect(w.controller.getSnapshot().closing).toBe(tab.id);
            if (guard === 'owner') {
                w.controller.lockOwner(tab.id, true);
            } else {
                w.change({ [guard]: true });
            }
            w.controller.confirmClose();
            w.controller.duplicate(tab.id);
            w.controller.logout(tab.id);
            w.controller.reauthenticate(tab.id);
            w.controller.newConnection();
            expect(tab.signal.aborted).toBe(false);
            expect(w.controller.getSnapshot().tabs).toHaveLength(1);
            expect(w.boundary.onSignIn).not.toHaveBeenCalled();
            expect(w.boundary.onLogout).not.toHaveBeenCalled();
            expect(w.boundary.onNewConnection).not.toHaveBeenCalled();
            w.unmount();
        },
    );

    it('does not let sibling registration/cleanup release another owner lock or revive a stale confirmation', () => {
        const w = workspace();
        const first = w.open(permission('First', false).access);
        const second = w.open(permission('Second', false).access);
        w.controller.requestClose(first.id);
        w.controller.lockOwner(first.id, true);
        w.controller.lockOwner(second.id, false);
        expect([...w.controller.getSnapshot().actionOwners]).toEqual([first.id]);
        expect(w.controller.controls.closeAll({ resetConfirmed: true })).toBe(false);
        w.controller.lockOwner(second.id, true);
        w.controller.lockOwner(first.id, false);
        expect([...w.controller.getSnapshot().actionOwners]).toEqual([second.id]);
        w.controller.lockOwner(second.id, false);
        w.controller.confirmClose();
        expect(w.controller.getSnapshot().tabs).toHaveLength(2);
        expect(w.controller.getSnapshot().closing).toBeNull();
        expect(w.boundary.onActionLock).toHaveBeenLastCalledWith(false);
        w.unmount();
    });

    it('keeps an owning management action active while terminal input and unrelated navigation are blocked', () => {
        const w = workspace();
        const tab = w.open(permission('Management', false).access);
        w.controller.lockOwner(tab.id, true);
        w.change({ blocked: true });
        const policy = workspacePolicy(w.controller.getSnapshot(), w.boundary);
        expect(policy.managementActive).toBe(true);
        expect(policy.terminalInputAllowed).toBe(false);
        expect(policy.reauthenticationBlocked).toBe(true);
        expect(w.controller.navigationTarget(tab.id)).toBeNull();
        w.controller.lockOwner(tab.id, false);
        expect(w.controller.controls.closeAll()).toBe(false);
        expect(w.controller.controls.closeAll({ resetConfirmed: true })).toBe(true);
        w.unmount();
    });

    it('invalidates settings when the connection ends and rechecks all terminal action capabilities', () => {
        const w = workspace();
        const tab = w.open();
        const actions: TerminalActions = {
            eof: vi.fn(() => true),
            signal: vi.fn(() => true),
            disconnect: vi.fn(),
            keepAliveSettings: vi.fn(),
            setKeepAlive: vi.fn(),
        };
        w.controller.terminalActions(tab.id, actions);
        w.controller.stateChanged(tab.id, { phase: 'connected' });
        w.controller.openSettings(tab.id);
        w.controller.eof(tab.id);
        expect(actions.eof).not.toHaveBeenCalled();
        w.controller.closeSettings();
        w.controller.eof(tab.id);
        w.controller.eof(tab.id);
        expect(actions.eof).toHaveBeenCalledTimes(1);
        expect(w.controller.getSnapshot().tabs[0]?.inputClosed).toBe(true);
        w.change({ focusBlocked: true });
        w.controller.signal(tab.id, 'INT');
        w.controller.disconnect(tab.id);
        expect(actions.signal).not.toHaveBeenCalled();
        expect(actions.disconnect).not.toHaveBeenCalled();
        w.change({ focusBlocked: false });
        w.controller.openSettings(tab.id);
        w.controller.stateChanged(tab.id, { phase: 'disconnected' });
        expect(w.controller.getSnapshot().settings).toBeNull();
        w.unmount();
    });

    it('ignores late clipboard failure and capability registration for a removed view', () => {
        const w = workspace();
        const tab = w.open();
        w.controller.controls.closeAll();
        w.controller.showCopyLink(tab.id, 'https://app.example.org/Original');
        expect(w.controller.getSnapshot().copyLink).toBeNull();
        expect(w.controller.copyTarget(tab.id)).toBeNull();
        expect(w.controller.settingsActions(tab.id)).toBeNull();
        w.unmount();
    });
});

it('uses pure immutable transitions and clears stale owner dialogs without clearing unrelated locks', () => {
    const w = workspace();
    const tab = w.open();
    w.controller.stateChanged(tab.id, { phase: 'connected' });
    const initial = initialWorkspaceState();
    const current = w.controller.getSnapshot().tabs[0];
    if (!current) {
        throw new Error('Expected connected tab');
    }
    const opened = workspaceTransition(initial, { type: 'opened', tab: current });
    const settings = workspaceTransition(opened, { type: 'settings', owner: tab.id });
    const locked = workspaceTransition(settings, { type: 'owner-lock', owner: 99, locked: true });
    const removed = workspaceTransition(locked, { type: 'removed', ids: [tab.id] });
    expect(initial.tabs).toEqual([]);
    expect(opened.settings).toBeNull();
    expect(settings.tabs[0]?.state.phase).toBe('connected');
    expect(removed.settings).toBeNull();
    expect([...removed.actionOwners]).toEqual([99]);
    expect(locked.tabs).toHaveLength(1);
    w.unmount();
});

it('releases owned capabilities before synchronous abort callbacks and never accepts late registration', () => {
    const owned = new WorkspaceConnections();
    const signal = owned.create(1);
    const callback = vi.fn(() => expect(owned.active(1)).toBe(false));
    signal.addEventListener('abort', callback);
    owned.abort(1);
    owned.abort(1);
    owned.registerConnection(1, {
        disconnect() {},
        keepAliveSettings: vi.fn(),
        setKeepAlive: vi.fn(),
    });
    expect(owned.connection(1)).toBeNull();
    expect(callback).toHaveBeenCalledTimes(1);
});

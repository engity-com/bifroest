import type { TerminalState } from '../terminal/socket';
import type { WorkspaceMenu, WorkspaceState, WorkspaceTab } from './model';
import { ownerLocks } from './policy';

export type WorkspaceEvent =
    | { type: 'opened'; tab: WorkspaceTab }
    | { type: 'removed'; ids: readonly number[]; dismiss?: boolean }
    | { type: 'cleared' }
    | { type: 'state'; id: number; state: TerminalState }
    | { type: 'title'; id: number; title: string }
    | { type: 'input-closed'; id: number }
    | { type: 'owner-lock'; owner: number; locked: boolean }
    | { type: 'focus'; terminal: boolean }
    | { type: 'menu'; menu: WorkspaceMenu }
    | { type: 'settings'; owner: number | null }
    | { type: 'closing'; owner: number | null }
    | { type: 'limit'; visible: boolean }
    | { type: 'copy-link'; url: string | null };

// Pure transitions. Connection cancellation and parent notifications belong to
// the controller; DOM effects and rendering never participate in these rules.
export function workspaceTransition(
    previous: WorkspaceState,
    event: WorkspaceEvent,
): WorkspaceState {
    let next: WorkspaceState;
    switch (event.type) {
        case 'opened':
            next = {
                ...previous,
                tabs: [...previous.tabs, event.tab],
                focusTerminal: true,
                limit: false,
            };
            break;
        case 'removed':
            next = {
                ...previous,
                tabs: previous.tabs.filter((tab) => !event.ids.includes(tab.id)),
                ...(event.dismiss ? { closing: null, menu: null, limit: false } : {}),
            };
            break;
        case 'cleared':
            next = {
                ...previous,
                tabs: [],
                closing: null,
                settings: null,
                menu: null,
                limit: false,
            };
            break;
        case 'state':
            next =
                event.state.phase === 'exited' && event.state.status === 0
                    ? { ...previous, tabs: previous.tabs.filter((tab) => tab.id !== event.id) }
                    : {
                          ...previous,
                          tabs: previous.tabs.map((tab) =>
                              tab.id === event.id ? { ...tab, state: event.state } : tab,
                          ),
                      };
            break;
        case 'title':
            next = {
                ...previous,
                tabs: previous.tabs.map((tab) =>
                    tab.id === event.id ? { ...tab, title: event.title } : tab,
                ),
            };
            break;
        case 'input-closed':
            next = {
                ...previous,
                tabs: previous.tabs.map((tab) =>
                    tab.id === event.id ? { ...tab, inputClosed: true } : tab,
                ),
            };
            break;
        case 'owner-lock':
            next = {
                ...previous,
                actionOwners: ownerLocks(previous.actionOwners, event.owner, event.locked),
                ...(event.locked ? { closing: null, menu: null, limit: false } : {}),
            };
            break;
        case 'focus':
            next = { ...previous, focusTerminal: event.terminal };
            break;
        case 'menu':
            next = {
                ...previous,
                menu: event.menu,
                ...(event.menu?.kind === 'tab' ? { focusTerminal: false } : {}),
            };
            break;
        case 'settings':
            next = {
                ...previous,
                settings: event.owner,
                focusTerminal: event.owner === null,
                ...(event.owner !== null ? { closing: null, limit: false } : {}),
            };
            break;
        case 'closing':
            next = { ...previous, closing: event.owner };
            break;
        case 'limit':
            next = { ...previous, limit: event.visible };
            break;
        case 'copy-link':
            next = { ...previous, copyLink: event.url };
            break;
    }
    // Removed owners cannot leave stale dialogs/menus behind. Action locks are
    // intentionally NOT pruned here: only their owner's cleanup may release one.
    if (next.closing !== null && !next.tabs.some((tab) => tab.id === next.closing)) {
        next = { ...next, closing: null };
    }
    if (next.menu?.kind === 'tab') {
        const owner = next.menu.owner;
        if (!next.tabs.some((tab) => tab.id === owner)) {
            next = { ...next, menu: null };
        }
    }
    if (
        next.settings !== null &&
        !next.tabs.some((tab) => tab.id === next.settings && tab.state.phase === 'connected')
    ) {
        next = { ...next, settings: null };
    }
    return Object.freeze({ ...next, tabs: Object.freeze([...next.tabs]) });
}

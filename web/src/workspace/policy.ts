import type { WorkspaceBoundary } from './contracts';
import { maximumTabs, type WorkspaceState } from './model';

// Owner IDs identify mounted management views, not users/roles or permissions.
// Clearing one view's preparation/cleanup must not release another view's lock.
export function ownerLocks(
    previous: ReadonlySet<number>,
    owner: number,
    locked: boolean,
): ReadonlySet<number> {
    const next = new Set(previous);
    if (locked) {
        next.add(owner);
    } else {
        next.delete(owner);
    }
    return next;
}

export function canCloseView(
    blocked: boolean,
    focusBlocked: boolean,
    owners: ReadonlySet<number>,
): boolean {
    return !blocked && !focusBlocked && owners.size === 0;
}

export function canOperate(state: WorkspaceState, boundary: WorkspaceBoundary): boolean {
    return (
        !boundary.blocked &&
        !boundary.focusBlocked &&
        state.settings === null &&
        state.actionOwners.size === 0
    );
}

export function keyboardAvailable(state: WorkspaceState, boundary: WorkspaceBoundary): boolean {
    return (
        !boundary.blocked &&
        !boundary.focusBlocked &&
        !boundary.authenticating &&
        state.settings === null &&
        state.actionOwners.size === 0 &&
        state.closing === null &&
        !state.limit
    );
}

export function workspacePolicy(state: WorkspaceState, boundary: WorkspaceBoundary) {
    const noOverlay = state.closing === null && !state.limit && state.menu === null;
    return {
        tabSelectionBlocked: boundary.blocked || boundary.focusBlocked || state.settings !== null,
        addBlocked: !canOperate(state, boundary) || state.tabs.length >= maximumTabs,
        optionsBlocked: !canOperate(state, boundary),
        terminalInputAllowed:
            !boundary.blocked && !boundary.focusBlocked && state.settings === null && noOverlay,
        // An owning management action must stay active while its application lock
        // blocks unrelated work. This deliberately differs from terminal input.
        managementActive: !boundary.authenticating && !boundary.focusBlocked && noOverlay,
        reauthenticationBlocked:
            boundary.blocked ||
            boundary.focusBlocked ||
            state.actionOwners.size > 0 ||
            boundary.authenticating ||
            state.settings !== null ||
            !noOverlay ||
            state.tabs.length >= maximumTabs,
        settingsVisible: !boundary.blocked && !boundary.focusBlocked && !boundary.authenticating,
        closeAllowed: canCloseView(boundary.blocked, boundary.focusBlocked, state.actionOwners),
    };
}

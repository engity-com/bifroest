import type { Scope, WebAccess } from '../remember';
import type { TerminalState } from '../terminal/socket';

// Shared contracts describe an owned connection view, not a terminal component.
export interface ConnectionView {
    readonly id: number;
    readonly routeId?: string;
    readonly access: WebAccess;
    readonly scope: Scope;
}

export interface WorkspaceTab extends ConnectionView {
    readonly kind: 'terminal' | 'management';
    readonly signal: AbortSignal;
    readonly state: TerminalState;
    readonly inputClosed: boolean;
    readonly title?: string;
}

export type WorkspaceMenu =
    | { readonly kind: 'tab'; readonly owner: number }
    | { readonly kind: 'new' }
    | null;

export interface WorkspaceState {
    readonly tabs: readonly WorkspaceTab[];
    readonly actionOwners: ReadonlySet<number>;
    readonly menu: WorkspaceMenu;
    readonly closing: number | null;
    readonly settings: number | null;
    readonly copyLink: string | null;
    readonly limit: boolean;
    readonly focusTerminal: boolean;
}

export function initialWorkspaceState(): WorkspaceState {
    return {
        tabs: [],
        actionOwners: new Set(),
        menu: null,
        closing: null,
        settings: null,
        copyLink: null,
        limit: false,
        focusTerminal: true,
    };
}

export const maximumTabs = 8;

export interface WorkspaceControls {
    closeAll(options?: { resetConfirmed?: boolean }): boolean;
}

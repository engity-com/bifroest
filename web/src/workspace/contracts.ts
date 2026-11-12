import type { ReactNode } from 'react';
import type { Scope, WebAccess } from '../remember';
import type { AuthenticationView } from '../terminal/authentication-view';
import type { ManagementLocation } from '../ui/management-location';
import type { ConnectionView, WorkspaceControls } from './model';

export interface WorkspaceCallbacks {
    onSignIn(scope?: Scope): void;
    onNewConnection(): void;
    onSelectView(view: ConnectionView | null, replace?: boolean): void;
    onViewsChange(views: readonly ConnectionView[]): void;
    onActionLock(locked: boolean): void;
    onLogout(access: WebAccess): void;
}

// Current committed input boundary, not another copy of the workspace model.
export interface WorkspaceBoundary extends WorkspaceCallbacks {
    readonly activeView: number | null;
    readonly blocked: boolean;
    readonly focusBlocked: boolean;
    readonly authenticating: boolean;
}

export interface ConnectionWorkspaceProps extends WorkspaceCallbacks {
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
    onTabCount(count: number): void;
    managementLocation?: ManagementLocation | null;
    viewLocations?: ReadonlyMap<number, ManagementLocation>;
    onManagementNavigate?(
        owner: ConnectionView,
        location: ManagementLocation,
        replace?: boolean,
    ): void;
    onWorkspaceControls?(controls: WorkspaceControls | null): void;
}

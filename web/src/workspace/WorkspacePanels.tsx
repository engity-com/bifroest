import type { WebAccess } from '../remember';
import { AuthenticationTerminal } from '../terminal/AuthenticationTerminal';
import type { AuthenticationView } from '../terminal/authentication-view';
import { TerminalPanel, terminalStatus } from '../terminal/TerminalPanel';
import { ManagementWorkspace } from '../ui/ManagementWorkspace';
import type { ManagementLocation } from '../ui/management-location';
import { t } from '../ui/messages';
import type { ConnectionWorkspaceProps } from './contracts';
import type { WorkspaceController } from './controller';
import type { WorkspaceState } from './model';
import type { workspacePolicy } from './policy';

export function WorkspacePanels({
    state,
    controller,
    policy,
    active,
    authentication,
    focusBlocked,
    unavailableAccess,
    managementLocation,
    onManagementNavigate,
    locations,
}: {
    state: WorkspaceState;
    controller: WorkspaceController;
    policy: ReturnType<typeof workspacePolicy>;
    active: number | null;
    authentication: AuthenticationView | null;
    focusBlocked: boolean;
    unavailableAccess: WebAccess | null;
    managementLocation: ConnectionWorkspaceProps['managementLocation'];
    onManagementNavigate: ConnectionWorkspaceProps['onManagementNavigate'];
    locations: ReadonlyMap<number, ManagementLocation> | undefined;
}) {
    return (
        <div className="workspace-body">
            {state.tabs.map((tab) => (
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
                        tab.kind === 'terminal' && tab.state.phase === 'exited'
                            ? tab.state.status
                            : undefined
                    }
                    data-terminal-ended={
                        (tab.kind === 'terminal' && tab.state.phase === 'exited') || undefined
                    }
                    data-playback-bounds={tab.kind === 'management' ? true : undefined}
                    data-connection-principal={tab.access.snapshot().principal}
                    data-connection-scope={tab.scope.slug}
                    key={tab.id}
                >
                    {tab.kind === 'terminal' ? (
                        <TerminalPanel
                            id={tab.id}
                            access={tab.access}
                            signal={tab.signal}
                            active={authentication === null && active === tab.id}
                            inputAllowed={policy.terminalInputAllowed}
                            focusOnActivate={state.focusTerminal}
                            onState={controller.stateChanged}
                            onActions={controller.terminalActions}
                            onTitle={controller.titleChanged}
                        />
                    ) : (
                        <ManagementWorkspace
                            owner={tab.id}
                            {...(tab.routeId ? { routeId: tab.routeId } : {})}
                            access={tab.access}
                            signal={tab.signal}
                            onState={controller.stateChanged}
                            onConnectionActions={controller.connectionActions}
                            onTitle={controller.titleChanged}
                            location={
                                active === tab.id
                                    ? (managementLocation ?? null)
                                    : (locations?.get(tab.id) ?? null)
                            }
                            onNavigate={(owner, location, replace) => {
                                const target =
                                    owner === tab.id ? controller.navigationTarget(owner) : null;
                                if (target) {
                                    onManagementNavigate?.(target, location, replace);
                                }
                            }}
                            active={active === tab.id && policy.managementActive}
                            disabled={unavailableAccess === tab.access}
                            onActionLock={controller.lockOwner}
                            onReauthenticate={() => controller.reauthenticate(tab.id)}
                            reauthenticationBlocked={policy.reauthenticationBlocked}
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
    );
}

import type { ConnectionWorkspaceProps } from './contracts';
import { workspacePolicy } from './policy';
import { useWorkspace } from './use-workspace';
import { useWorkspaceKeyboard } from './use-workspace-keyboard';
import { WorkspaceDialogs } from './WorkspaceDialogs';
import { WorkspacePanels } from './WorkspacePanels';
import { WorkspaceTabBar } from './WorkspaceTabBar';

export function ConnectionWorkspace(props: ConnectionWorkspaceProps) {
    const { controller, state, boundary } = useWorkspace(props);
    const policy = workspacePolicy(state, boundary);
    useWorkspaceKeyboard(controller, boundary);
    return (
        <main className="workspace terminal-workspace" aria-label={props.title}>
            <WorkspaceTabBar
                state={state}
                controller={controller}
                policy={policy}
                active={props.activeView}
                authentication={props.authentication}
                blocked={props.blocked}
                focusBlocked={props.focusBlocked}
                notice={props.notice}
                utilities={props.utilities}
                locations={props.viewLocations}
            />
            <WorkspacePanels
                state={state}
                controller={controller}
                policy={policy}
                active={props.activeView}
                authentication={props.authentication}
                focusBlocked={props.focusBlocked}
                unavailableAccess={props.unavailableAccess}
                managementLocation={props.managementLocation}
                onManagementNavigate={props.onManagementNavigate}
                locations={props.viewLocations}
            />
            <WorkspaceDialogs
                state={state}
                controller={controller}
                policy={policy}
                blocked={props.blocked}
            />
        </main>
    );
}

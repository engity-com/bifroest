import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore } from 'react';
import { t } from '../ui/messages';
import type { ConnectionWorkspaceProps, WorkspaceBoundary } from './contracts';
import { WorkspaceController } from './controller';

// React adapts committed parent input and external events to one local model.
// There is no second tabs ref/state pair or grant store here.
export function useWorkspace(props: ConnectionWorkspaceProps) {
    const boundary: WorkspaceBoundary = {
        activeView: props.activeView,
        blocked: props.blocked,
        focusBlocked: props.focusBlocked,
        authenticating: props.authentication !== null,
        onSignIn: props.onSignIn,
        onNewConnection: props.onNewConnection,
        onSelectView: props.onSelectView,
        onViewsChange: props.onViewsChange,
        onActionLock: props.onActionLock,
        onLogout: props.onLogout,
    };
    const committed = useRef(boundary);
    useLayoutEffect(() => {
        committed.current = boundary;
    });
    const [controller] = useState(
        () =>
            new WorkspaceController(() => committed.current, {
                terminal: t('terminalTitle'),
                management: t('workspaceOverview'),
            }),
    );
    const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot);
    useLayoutEffect(() => controller.mount(), [controller]);
    useLayoutEffect(() => {
        props.onWorkspaceControls?.(controller.controls);
        return () => props.onWorkspaceControls?.(null);
    }, [controller, props.onWorkspaceControls]);
    useEffect(() => {
        if (!props.blocked) {
            controller.acceptAuthorization(props.authorizationEvent, props.retiredAccess);
        }
    }, [controller, props.authorizationEvent, props.retiredAccess, props.blocked]);
    useEffect(() => {
        controller.retireAccess(props.retiredAccess);
    }, [controller, props.retiredAccess]);
    useEffect(() => {
        if (props.blocked) {
            controller.reconcileBlocked();
        }
    }, [controller, props.blocked]);
    useEffect(() => {
        if (props.blocked || props.focusBlocked || props.authentication !== null) {
            controller.reconcileSettings();
        }
    }, [controller, props.blocked, props.focusBlocked, props.authentication]);
    useEffect(() => {
        props.onTabCount(state.tabs.length + (props.authentication ? 1 : 0));
    }, [state.tabs.length, props.authentication, props.onTabCount]);
    return { controller, state, boundary };
}

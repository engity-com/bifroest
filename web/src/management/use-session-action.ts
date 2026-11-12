import { useEffect, useLayoutEffect, useMemo, useRef, useSyncExternalStore } from 'react';
import {
    type SessionActionBoundary,
    SessionActionOwner,
    type SessionActionPort,
} from './session-action-owner';

export function useSessionAction(
    port: SessionActionPort,
    active: boolean,
    boundary: SessionActionBoundary,
) {
    const committed = useRef(boundary);
    useLayoutEffect(() => {
        committed.current = boundary;
    });
    const owner = useMemo(() => new SessionActionOwner(port, () => committed.current), [port]);
    const state = useSyncExternalStore(owner.subscribe, owner.getSnapshot);
    useLayoutEffect(() => owner.mount(), [owner]);
    useEffect(() => {
        if (!active) {
            owner.cancelPreparation();
        }
    }, [owner, active]);
    return { owner, state };
}

import { useLayoutEffect, useMemo, useRef, useSyncExternalStore } from 'react';
import {
    type ManagementReadBoundary,
    ManagementReadModel,
    type ManagementReadPort,
} from './read-model';

export function useManagementReads(port: ManagementReadPort, boundary: ManagementReadBoundary) {
    const committed = useRef(boundary);
    useLayoutEffect(() => {
        committed.current = boundary;
    });
    const model = useMemo(() => new ManagementReadModel(port, () => committed.current), [port]);
    const state = useSyncExternalStore(model.subscribe, model.getSnapshot);
    useLayoutEffect(() => model.mount(), [model]);
    return { model, state };
}

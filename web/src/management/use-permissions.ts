import { createContext, useCallback, useMemo, useSyncExternalStore } from 'react';
import type { WebAccess } from '../remember';
import type { ManagementPermission } from './permissions';

export const ManagementPermissionContext = createContext<
    ((permission: ManagementPermission) => boolean) | null
>(null);

export function useManagementPermissions(access: WebAccess) {
    const subscribe = useCallback(
        (changed: () => void) => access.subscribeStatus(changed),
        [access],
    );
    const snapshot = useCallback(() => access.managementCapabilities(), [access]);
    const capabilities = useSyncExternalStore(subscribe, snapshot);
    return useMemo(
        () => (permission: ManagementPermission) => capabilities.includes(permission),
        [capabilities],
    );
}

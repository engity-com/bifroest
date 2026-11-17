import { createContext, useContext } from 'react';
import type { ManagementLocation } from '../application/management-location';

export interface ManagementNavigation {
    readonly location: ManagementLocation;
    href?(location: ManagementLocation): string;
    navigate(location: ManagementLocation, replace?: boolean): void;
}
export const ManagementNavigationContext = createContext<ManagementNavigation | null>(null);
export function useManagementNavigation(): ManagementNavigation | null {
    return useContext(ManagementNavigationContext);
}

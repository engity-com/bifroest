import { createContext, useContext } from 'react';
import type { ManagementLocation } from './management-location';

export interface ManagementNavigation {
  readonly location: ManagementLocation;
  navigate(location: ManagementLocation, replace?: boolean): void;
}
export const ManagementNavigationContext = createContext<ManagementNavigation | null>(null);
export function useManagementNavigation(): ManagementNavigation | null {
  return useContext(ManagementNavigationContext);
}

import type { Scope, WebAccess } from '../remember';
import type { ManagementLocation } from '../ui/management-location';

// Shared contracts describe an owned connection view, not a terminal component.
export interface ConnectionView {
  readonly id: number;
  readonly routeId?: string;
  readonly access: WebAccess;
  readonly scope: Scope;
  readonly navigation?: { current: ManagementLocation | null };
}

export const maximumTabs = 8;

export interface WorkspaceControls {
  closeAll(options?: { resetConfirmed?: boolean }): boolean;
}

import { createContext, useContext } from 'react';
import type { Scope } from '../remember/protocol';
export interface AuditViewState {
  readonly scope: Scope;
  readonly sensitive: boolean;
  readonly toggleSensitive: () => void;
  readonly local: boolean;
  readonly running: boolean;
  readonly provenance: string | undefined;
}
export const AuditViewContext = createContext<AuditViewState | null>(null);
export const useAuditView = () => useContext(AuditViewContext);

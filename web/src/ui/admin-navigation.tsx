import { createContext, useCallback, useContext, useEffect, useRef } from 'react';

export interface AdminDetail {
  readonly label: string;
  readonly back: () => void;
}
export type AdminSection = 'sessions' | 'artifacts';
export const AdminDetailContext = createContext<
  ((section: AdminSection, detail: AdminDetail | null) => void) | null
>(null);

// Paths and callbacks stay inside one actor-owned management tab. The callback
// ref follows local state without making every render rewrite the parent's path.
export function useAdminDetail(
  section: AdminSection,
  label: string | null,
  onBack: () => void,
): boolean {
  const publish = useContext(AdminDetailContext);
  const current = useRef(onBack);
  current.current = onBack;
  const back = useCallback(() => current.current(), []);
  useEffect(() => {
    publish?.(section, label === null ? null : { label, back });
  }, [publish, section, label, back]);
  return publish !== null;
}

import { createContext, useCallback, useContext, useEffect, useRef } from 'react';

export interface AdminDetail {
    readonly label: string;
    readonly back: () => void;
    readonly parents: readonly string[];
}
export type AdminSection = 'sessions' | 'recordings' | 'auditlogs';
export const AdminDetailContext = createContext<
    ((section: AdminSection, detail: AdminDetail | null) => void) | null
>(null);

// Paths and callbacks stay inside one actor-owned management tab. The callback
// ref follows local state without making every render rewrite the parent's path.
export function useAdminDetail(
    section: AdminSection,
    label: string | null,
    onBack: () => void,
    parents: readonly string[] = [],
): boolean {
    const publish = useContext(AdminDetailContext);
    const current = useRef(onBack);
    current.current = onBack;
    const back = useCallback(() => current.current(), []);
    const parentKey = JSON.stringify(parents);
    useEffect(() => {
        publish?.(
            section,
            label === null ? null : { label, back, parents: JSON.parse(parentKey) as string[] },
        );
    }, [publish, section, label, back, parentKey]);
    return publish !== null;
}

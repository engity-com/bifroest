import { useContext, useRef, useState } from 'react';
import type { AuditlogSummary } from '../management/protocol';
import type { WebAccess } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { AdminDetailContext } from '../ui/admin-navigation';
import { bookmarkPath } from '../ui/hash-route';
import { managementCrumbs } from '../ui/management-crumbs';
import type { ManagementLocation } from '../ui/management-location';
import { ManagementNavigationContext, useManagementNavigation } from '../ui/management-navigation';
import { ArtifactEvidencePanel } from './ArtifactEvidencePanel';
import { AuditSourceContext } from './AuditSourceContext';
import { AuditWorkspace } from './AuditWorkspace';
import type { ArtifactPanelProps } from './evidence-view';

// Routing/composition only. Both pages retain their own selection, workers,
// result and plaintext; the tab provider owns their shared volatile key cache.
export function ArtifactPanel(props: ArtifactPanelProps) {
    const external = useManagementNavigation();
    const embedded = useContext(AdminDetailContext) !== null;
    const [sourceHint, setSourceHint] = useState<{
        access: WebAccess;
        source: AuditlogSummary | null;
    }>({ access: props.access, source: null });
    const root: ManagementLocation = {
        managementFlow: props.access.snapshot().flow?.name ?? 'management',
        page: props.view ?? 'auditlogs',
    };
    const [, setLocalRoute] = useState(root);
    const retained = useRef({ access: props.access, route: root });
    if (retained.current.access !== props.access) {
        retained.current = { access: props.access, route: root };
    }
    if (
        external &&
        (external.location.page === 'auditlogs' || external.location.page === 'recordings')
    ) {
        retained.current = { access: props.access, route: external.location };
    }
    const route = retained.current.route;
    const navigate = (next: ManagementLocation, replace?: boolean) => {
        if (external) {
            external.navigate(next, replace);
        } else {
            retained.current = { access: props.access, route: next };
            setLocalRoute(next);
        }
    };
    return (
        <AuditSourceContext.Provider
            value={{
                access: props.access,
                source: sourceHint.access === props.access ? sourceHint.source : null,
                select: (source) => setSourceHint({ access: props.access, source }),
            }}
        >
            <ManagementNavigationContext.Provider
                value={{
                    location: route,
                    navigate,
                    href:
                        external?.href ??
                        ((target) => bookmarkPath(props.access.snapshot().scope, target)),
                }}
            >
                {!embedded && (
                    <AdminBreadcrumbs items={managementCrumbs(route, navigate, props.disabled)} />
                )}
                <div hidden={route.page !== 'auditlogs'}>
                    <AuditWorkspace
                        {...props}
                        active={(props.active ?? true) && route.page === 'auditlogs'}
                        Evidence={ArtifactEvidencePanel}
                    />
                </div>
                <div hidden={route.page !== 'recordings'}>
                    <ArtifactEvidencePanel
                        {...props}
                        view="recordings"
                        hideBreadcrumbs
                        active={(props.active ?? true) && route.page === 'recordings'}
                    />
                </div>
            </ManagementNavigationContext.Provider>
        </AuditSourceContext.Provider>
    );
}

import { type ManagementLocation, managementRoot } from '../application/management-location';
import { uuidText } from '../shared/uuid';
import type { AdminCrumb } from './AdminBreadcrumbs';
import { t } from './messages';

// Hints are displayable opaque identities, never proof of an event's flow.
export function managementCrumbs(
    route: ManagementLocation,
    navigate: (next: ManagementLocation) => void,
    disabled = false,
    href?: (next: ManagementLocation) => string,
): AdminCrumb[] {
    const overview: ManagementLocation = { managementFlow: route.managementFlow, page: 'server' };
    const crumb = (label: string, next: ManagementLocation): AdminCrumb => ({
        label,
        target: next,
        onClick: () => navigate(next),
        disabled,
        ...(href ? { to: href(next) } : {}),
    });
    if (route.page === 'auditlogs' || route.page === 'recordings') {
        const source = route.page === 'auditlogs' ? route.auditlog : route.auditlogHint;
        const detail = route.id ?? route.eventHint ?? route.recordingHint;
        const root: ManagementLocation = {
            managementFlow: route.managementFlow,
            page: 'auditlogs',
        };
        const { id: _id, eventHint: _event, recordingHint: _recording, ...list } = route;
        return [
            crumb(t('workspaceBifroest'), overview),
            crumb(t('workspaceAuditlogs'), root),
            ...(source
                ? [
                      crumb(source, {
                          managementFlow: route.managementFlow,
                          page: 'auditlogs',
                          auditlog: source,
                      }),
                      crumb(
                          t(
                              route.page === 'recordings'
                                  ? 'workspaceRecordings'
                                  : 'workspaceEvents',
                          ),
                          list,
                      ),
                      ...(detail ? [crumb(uuidText(detail), route)] : []),
                  ]
                : []),
        ];
    }
    const page =
        route.page === 'server'
            ? 'workspaceOverview'
            : route.page === 'sessions'
              ? 'workspaceSessions'
              : 'workspaceVersion';
    const detail = route.id ?? route.eventHint ?? route.recordingHint;
    const { id: _id, eventHint: _event, recordingHint: _recording, ...list } = route;
    const { sessionId: _session, ...flowList } = list;
    const root = managementRoot(route.managementFlow, route.page);
    return [
        crumb(t('workspaceBifroest'), overview),
        crumb(t(page), root),
        ...(route.flow ? [crumb(route.flow, flowList)] : []),
        ...(detail ? [crumb(uuidText(detail), route)] : []),
    ];
}

import type { AdminCrumb } from './AdminBreadcrumbs';
import type { ManagementLocation } from './management-location';
import { t } from './messages';

// Hints are displayable opaque identities, never proof of an event's flow.
export function managementCrumbs(
  route: ManagementLocation,
  navigate: (next: ManagementLocation) => void,
  disabled = false,
): AdminCrumb[] {
  const page =
    route.page === 'server'
      ? 'workspaceOverview'
      : route.page === 'sessions'
        ? 'workspaceSessions'
        : route.page === 'recordings'
          ? 'workspaceRecordings'
          : route.page === 'auditlogs'
            ? 'workspaceAuditlogs'
            : 'workspaceVersion';
  const detail = route.id ?? route.eventHint ?? route.recordingHint;
  const { id: _id, eventHint: _event, recordingHint: _recording, ...list } = route;
  const { sessionId: _session, ...flowList } = list;
  const { flow: _flow, ...sourceList } = flowList;
  const root: ManagementLocation = {
    managementFlow: route.managementFlow,
    page: route.page,
    ...(route.page === 'recordings' && route.auditlogHint
      ? { auditlogHint: route.auditlogHint }
      : {}),
  };
  const crumb = (label: string, next?: ManagementLocation): AdminCrumb => ({
    label,
    ...(next ? { onClick: () => navigate(next), disabled } : {}),
  });
  return [
    crumb(t('workspaceBifroest')),
    crumb(t(page), route.auditlog || route.flow || route.sessionId || detail ? root : undefined),
    ...(route.auditlog
      ? [crumb(route.auditlog, route.flow || route.sessionId || detail ? sourceList : undefined)]
      : []),
    ...(route.flow ? [crumb(route.flow, route.sessionId || detail ? flowList : undefined)] : []),
    ...(route.sessionId
      ? [crumb(`${t('managementSessionId')}: ${route.sessionId}`, detail ? list : undefined)]
      : []),
    ...(detail ? [crumb(detail)] : []),
  ];
}

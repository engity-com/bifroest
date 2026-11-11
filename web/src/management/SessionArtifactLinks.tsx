import type { Scope } from '../remember';
import { ManagementJump, relationFlow, relationID } from '../ui/ManagementJump';
import type { SessionItem } from './protocol';

export function SessionArtifactLinks({
  item,
  scope,
  managementFlow,
  compact,
  disabled,
}: {
  item: SessionItem;
  scope: Scope;
  managementFlow: string | undefined;
  compact: boolean;
  disabled: boolean;
}) {
  if (
    !managementFlow ||
    !item.auditlog ||
    item.policyLimited ||
    !relationFlow(item.flow) ||
    !relationID(item.id)
  ) {
    return null;
  }
  return (
    <>
      <ManagementJump
        scope={scope}
        compact={compact}
        disabled={disabled}
        label="showRecordings"
        target={{
          managementFlow,
          page: 'recordings',
          flow: item.flow,
          sessionId: item.id,
          auditlogHint: item.auditlog,
        }}
      />
      <ManagementJump
        scope={scope}
        compact={compact}
        disabled={disabled}
        label="showAuditlogs"
        target={{
          managementFlow,
          page: 'auditlogs',
          flow: item.flow,
          sessionId: item.id,
          auditlog: item.auditlog,
        }}
      />
    </>
  );
}

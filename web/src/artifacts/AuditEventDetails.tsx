import { Fragment } from 'react';
import type { Scope } from '../remember/protocol';
import { ManagementJump, recordingRelation, sessionRelation } from '../ui/ManagementJump';
import { useManagementNavigation } from '../ui/management-navigation';
import { t } from '../ui/messages';

export type AuditEventBody = Readonly<Record<string, unknown>>;
export function AuditEventActions({
  event,
  scope,
  sensitive,
  compact = false,
  disabled = false,
}: {
  event: AuditEventBody;
  scope: Scope | undefined;
  sensitive: boolean;
  compact?: boolean;
  disabled?: boolean;
}) {
  const navigation = useManagementNavigation();
  const route = navigation?.location;
  if (!sensitive || !scope || !route) {
    return null;
  }
  return (
    <>
      <ManagementJump
        scope={scope}
        target={sessionRelation(route.managementFlow, event.flow, event.sessionId)}
        label="showSession"
        compact={compact}
        disabled={disabled}
      />
      <ManagementJump
        scope={scope}
        target={recordingRelation(route.managementFlow, route.auditlog ?? '', event.recordingId)}
        label="showRecording"
        compact={compact}
        disabled={disabled}
      />
    </>
  );
}

export function AuditEventDetails({
  id,
  recordedAt,
  event,
  scope,
  sensitive,
  provenance,
  envelope = {},
}: {
  id: string;
  recordedAt: string | Date;
  event: AuditEventBody;
  scope: Scope | undefined;
  sensitive: boolean;
  provenance: string;
  envelope?: Readonly<Record<string, unknown>>;
}) {
  const navigation = useManagementNavigation();
  const route = navigation?.location;
  const labels: Record<string, string> = {
    name: t('auditEventName'),
    domain: 'Domain',
    outcome: t('auditEventOutcome'),
    flow: t('recordingFilterFlow'),
    sessionId: t('managementSessionId'),
    recordingId: t('artifactRecordingID'),
    reason: t('auditEventReason'),
  };
  const display = (name: string, value: unknown) => {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    const target =
      name === 'sessionId' && route
        ? sessionRelation(route.managementFlow, event.flow, value)
        : name === 'recordingId' && route
          ? recordingRelation(route.managementFlow, route.auditlog ?? '', value)
          : null;
    return scope && target ? (
      <ManagementJump
        scope={scope}
        target={target}
        label={name === 'sessionId' ? 'showSession' : 'showRecording'}
      >
        {text}
      </ManagementJump>
    ) : (
      text
    );
  };
  return (
    <section
      className="stack record-card audit-event-details"
      aria-label={t('auditEventDetails')}
      tabIndex={-1}
    >
      <strong>{t('detailsTitle')}</strong>
      <p className="caption subtle">{provenance}</p>
      <dl className="metadata-grid">
        <dt>{t('artifactEventID')}</dt>
        <dd className="identifier">{id}</dd>
        <dt>{t('auditRecordedAt')}</dt>
        <dd>{new Date(recordedAt).toLocaleString()}</dd>
        {Object.entries(event)
          .filter(([name]) => sensitive || ['name', 'domain', 'outcome'].includes(name))
          .map(([name, value]) => (
            <Fragment key={name}>
              <dt>{labels[name] ?? name}</dt>
              <dd className="identifier">{display(name, value)}</dd>
            </Fragment>
          ))}
        {!sensitive && (
          <>
            <dt>{t('recordingFilterFlow')}</dt>
            <dd>{t('auditPrivateNotice')}</dd>
          </>
        )}
        {Object.entries(envelope)
          .filter(([name]) => !['id', 'event', 'recordedAt'].includes(name))
          .map(([name, value]) => (
            <Fragment key={name}>
              <dt>{labels[name] ?? name}</dt>
              <dd className="identifier">{display(name, value)}</dd>
            </Fragment>
          ))}
        {sensitive &&
          scope &&
          route &&
          (sessionRelation(route.managementFlow, event.flow, event.sessionId) ||
            recordingRelation(route.managementFlow, route.auditlog ?? '', event.recordingId)) && (
            <>
              <dt>{t('adminGridActions')}</dt>
              <dd className="actions">
                <AuditEventActions event={event} scope={scope} sensitive={sensitive} />
              </dd>
            </>
          )}
      </dl>
    </section>
  );
}

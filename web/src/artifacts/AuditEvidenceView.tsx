import { AuditEvents } from './AuditEvents';
import type { AuditEventIndex, AuditEventRow } from './audit-events';
import type { VerifiedArtifact } from './evidence-protocol';

// Only a completed local verification output can enter the audit renderer.
// Server overview/transport, key selection and verification stay outside it.
export function AuditEvidenceView({
    verified,
    index,
    privateFieldsKnown,
    active,
    selected,
    onSelect,
}: {
    verified: VerifiedArtifact | null;
    index: AuditEventIndex | null;
    privateFieldsKnown: boolean;
    active: boolean;
    selected: AuditEventRow | null;
    onSelect(value: AuditEventRow | null): void;
}) {
    if (
        !verified?.output ||
        verified.metadata.kind !== 'audit' ||
        verified.metadata.outputFormat !== 'jsonl'
    ) {
        return null;
    }
    return (
        <AuditEvents
            source={verified.output}
            initialIndex={index ?? undefined}
            privateFieldsKnown={privateFieldsKnown}
            active={active}
            selected={selected}
            onSelect={onSelect}
        />
    );
}

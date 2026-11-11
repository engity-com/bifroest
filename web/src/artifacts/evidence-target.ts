import { uuidEqual } from '../shared/uuid';
import type { ArtifactRequest } from './protocol';

export interface EvidenceTarget {
    readonly page: string;
    readonly id?: string;
    readonly auditlog?: string;
    readonly auditlogHint?: string;
    readonly recordingHint?: string;
}
export function matchesEvidenceTarget(
    request: ArtifactRequest,
    target: EvidenceTarget | null,
    standalone: boolean,
): boolean {
    if (!target) {
        return standalone;
    }
    return request.kind === 'audit'
        ? target.page === 'auditlogs' && target.auditlog === request.auditlog
        : target.page === 'recordings' &&
              uuidEqual(target.id ?? target.recordingHint, request.id) &&
              target.auditlogHint === request.auditlog;
}

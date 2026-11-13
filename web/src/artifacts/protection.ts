import type { ProgressListener } from '../management/progress';
import type { EvidenceMetadata, EvidenceOptions } from './evidence-protocol';
import type { ReceivedArtifact } from './protocol';
import { verifyArtifact } from './verify';

// Discover protection from the local signed header, not a user-selected format.
// This verifies integrity but does not independently pin the signer's identity.
export async function inspectProtection(
    received: ReceivedArtifact,
    signal: AbortSignal,
    auditScope: 'complete' | 'captured-prefix' = 'complete',
    progress?: ProgressListener,
): Promise<EvidenceMetadata> {
    const options: EvidenceOptions = {
        producer: '',
        allowUntrusted: true,
        recipient: 'Recipient' in received.metadata ? received.metadata.Recipient : '',
        level: 'outer',
        export: false,
        sensitive: false,
        auditScope: received.request.kind === 'audit' ? auditScope : '',
        ...(received.request.kind === 'recording' ? { recipientFromHeader: true } : {}),
    };
    return (await verifyArtifact(received, options, null, signal, progress)).metadata;
}

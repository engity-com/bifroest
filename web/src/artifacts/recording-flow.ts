import { resourceID, uuidEqual } from '../shared/uuid';
import type { VerifiedArtifact } from './evidence-protocol';
// UI provenance only. These bytes have ALREADY passed the native full verifier;
// this bounded read is not a parser/verifier replacement or a new trust anchor.
export async function verifiedRecordingFlow(verified: VerifiedArtifact): Promise<string> {
  return (await verifiedRecordingContext(verified)).flow;
}
export async function verifiedRecordingContext(
  verified: VerifiedArtifact,
): Promise<{ flow: string; sessionId: string }> {
  if (
    verified.request.kind !== 'recording' ||
    verified.output === null ||
    verified.metadata.validation !== 'private' ||
    verified.metadata.outputFormat !== 'cast'
  ) {
    return { flow: '', sessionId: '' };
  }
  const header = await verified.output.slice(0, 64 << 10).text();
  const line = header.split('\n', 3).find((line) => line.startsWith('# bifroest:metadata:v1 '));
  if (!line) {
    return { flow: '', sessionId: '' };
  }
  try {
    const metadata = JSON.parse(line.slice('# bifroest:metadata:v1 '.length)) as Record<
      string,
      unknown
    >;
    const flow = metadata.flow;
    const valid =
      uuidEqual(metadata.recordingId, verified.request.id) &&
      typeof flow === 'string' &&
      flow.isWellFormed() &&
      flow.length <= 255 &&
      !/[\p{Cc}\p{Cf}]/u.test(flow);
    return {
      flow: valid ? flow : '',
      sessionId: valid && resourceID(metadata.sessionId) ? metadata.sessionId : '',
    };
  } catch {
    return { flow: '', sessionId: '' };
  }
}

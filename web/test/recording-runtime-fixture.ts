import { EvidenceError } from '../src/artifacts/evidence-protocol';
import type { openRecording } from '../src/artifacts/open-recording';
import type { RecordingRuntime, verifyArtifact } from '../src/artifacts/verify';

export function recordingRuntimeFixture(
    open: typeof openRecording,
    check: typeof verifyArtifact,
    signal: AbortSignal,
): RecordingRuntime {
    let closed = false;
    signal.addEventListener(
        'abort',
        () => {
            closed = true;
        },
        { once: true },
    );
    return {
        available: () => !closed && !signal.aborted,
        dispose: () => {
            closed = true;
        },
        receive: async () => {
            throw new EvidenceError('input');
        },
        open: async (image, key, operation) => {
            if (closed || signal.aborted || operation.aborted) {
                throw new EvidenceError('cancelled');
            }
            return open(image, key, operation);
        },
        verify: async (image, options, key, progress, operation) => {
            if (closed || signal.aborted || operation?.aborted) {
                throw new EvidenceError('cancelled');
            }
            return check(image, options, key, operation ?? signal, progress);
        },
    };
}

import { type ProgressListener, readProgress } from '../management/progress';
import { object } from '../remember/http';
import { EvidenceError } from './evidence-protocol';

export function evidenceRPC(
    worker: Worker,
    kind: 'ready' | 'batch-ready' | 'verified' | 'prepared' | 'opened' | 'received',
    signal: AbortSignal,
    input?: unknown,
    transfer: Transferable[] = [],
    progress?: ProgressListener,
): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
        const cleanup = () => {
            worker.removeEventListener('message', received);
            worker.removeEventListener('error', failed);
            worker.removeEventListener('messageerror', failed);
            signal.removeEventListener('abort', aborted);
        };
        const failed = (event?: Event) => {
            event?.preventDefault();
            cleanup();
            reject(new EvidenceError('worker'));
        };
        const aborted = () => {
            cleanup();
            reject(
                new EvidenceError(
                    signal.reason instanceof DOMException && signal.reason.name === 'TimeoutError'
                        ? 'worker-timeout'
                        : 'cancelled',
                ),
            );
        };
        const received = (event: MessageEvent) => {
            try {
                if (event.data?.kind === 'progress') {
                    const body = object(event.data, ['kind', 'phase', 'completed', 'total']);
                    if (kind === 'ready' || kind === 'batch-ready' || signal.aborted) {
                        throw new Error();
                    }
                    progress?.(
                        readProgress({
                            phase: body.phase,
                            completed: body.completed,
                            total: body.total,
                        }),
                    );
                    return;
                }
                if (event.data?.kind === 'failed') {
                    const body = object(event.data, ['kind', 'code']);
                    if (
                        ![
                            'input',
                            'key',
                            'limit',
                            'verification',
                            'unavailable',
                            'worker',
                            'module-fetch',
                            'module-decode',
                            'runtime',
                            'protocol',
                        ].includes(String(body.code))
                    ) {
                        throw new Error();
                    }
                    cleanup();
                    reject(new EvidenceError(body.code as EvidenceError['code']));
                    return;
                }
                const body = object(
                    event.data,
                    kind === 'ready' || kind === 'batch-ready'
                        ? ['kind']
                        : kind === 'received'
                          ? ['kind', 'metadata', 'files']
                          : ['kind', 'metadata', 'output'],
                );
                if (body.kind !== kind || signal.aborted) {
                    throw new Error();
                }
                cleanup();
                resolve(body);
            } catch {
                cleanup();
                reject(new EvidenceError('protocol'));
            }
        };
        worker.addEventListener('message', received);
        worker.addEventListener('error', failed);
        worker.addEventListener('messageerror', failed);
        signal.addEventListener('abort', aborted, { once: true });
        if (signal.aborted) {
            aborted();
            return;
        }
        try {
            if (input !== undefined) {
                worker.postMessage(input, transfer);
            }
        } catch {
            failed();
        }
    });
}
